// Package conductor wires the control plane together: configuration, the
// SQLite registry, the launchers, the scheduler and the HTTP API.
//
// Serve runs until its context is cancelled, then stops accepting API
// requests, stops planning new runs, and waits for in-flight runs up to
// server.shutdownGraceSeconds before cancelling them.
//
// Exactly one Conductor process may operate a registry: Serve takes an
// exclusive advisory lock next to the database file before it opens the
// database or changes any state, and exits (ExitFatal) when another
// process holds it. Without that lock a second process would mark the
// first one's in-flight runs failed at its own startup recovery and both
// would plan and dispatch runs against the same targets.
package conductor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/api"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher/acajob"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/scheduler"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/internal/fslock"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Exit codes of Serve.
const (
	ExitOK     = 0
	ExitConfig = 1
	ExitFatal  = 2
)

// Options configure Serve.
type Options struct {
	ConfigPath string
	Logger     *slog.Logger
	// Listening, when set, is called with the bound address once the API
	// accepts connections (tests use it to learn an ephemeral port).
	Listening func(addr net.Addr)
	// LookupEnv is passed to the local-process launcher.
	LookupEnv func(string) (string, bool)
}

// LockPath returns the path of the ownership lock Serve holds for the
// database at dbPath.
func LockPath(dbPath string) string { return dbPath + ".lock" }

// Serve runs the Conductor until ctx is done and returns the exit code.
func Serve(ctx context.Context, opts Options) int {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		log.Error("configuration rejected", "path", opts.ConfigPath, "error", err.Error())
		return ExitConfig
	}
	// Ownership first: nothing below may run, and no state may change,
	// unless this process is the only Conductor on this registry.
	lock, err := fslock.TryExclusive(LockPath(cfg.Database.Path))
	if err != nil {
		if errors.Is(err, fslock.ErrLocked) {
			log.Error("another conductor process owns this database; refusing to start", "path", cfg.Database.Path, "lock", LockPath(cfg.Database.Path))
		} else {
			log.Error("database ownership lock could not be taken", "lock", LockPath(cfg.Database.Path), "error", err.Error())
		}
		return ExitFatal
	}
	defer lock.Unlock()
	reg, err := sqlite.Open(cfg.Database.Path)
	if err != nil {
		log.Error("registry could not be opened", "path", cfg.Database.Path, "error", err.Error())
		return ExitFatal
	}
	defer reg.Close()
	version, _ := reg.Version(ctx)
	log.Info("registry opened", "path", cfg.Database.Path, "schemaVersion", version)

	verifier, err := buildVerifier(cfg)
	if err != nil {
		log.Error("result signing keys rejected", "error", err.Error())
		return ExitConfig
	}
	if verifier != nil {
		log.Info("result signing enforced", "keys", len(cfg.ResultSigning.PublicKeys))
	}
	signer, err := loadSigner(cfg)
	if err != nil {
		log.Error("job signing key could not be loaded", "error", err.Error())
		return ExitConfig
	}
	if signer != nil {
		log.Info("job signing enabled", "keyId", signer.KeyID(), "validitySeconds", cfg.JobSigning.ValiditySeconds)
	}
	launchers, err := buildLaunchers(cfg, signer, verifier, log, opts.LookupEnv)
	if err != nil {
		log.Error("launchers could not be built", "error", err.Error())
		return ExitConfig
	}
	sched := scheduler.New(scheduler.Options{
		Registry:          reg,
		Launchers:         launchers,
		Tick:              time.Duration(cfg.Scheduler.TickSeconds) * time.Second,
		MaxConcurrentRuns: cfg.Scheduler.MaxConcurrentRuns,
		RetryBackoff:      time.Duration(cfg.Scheduler.RetryBackoffSeconds) * time.Second,
		MaxRetryBackoff:   time.Duration(cfg.Scheduler.MaxRetryBackoffSeconds) * time.Second,
		Logger:            log.With("component", "scheduler"),
	})
	if n, err := sched.Recover(ctx); err != nil {
		log.Error("in-flight runs could not be recovered", "error", err.Error())
		return ExitFatal
	} else if n > 0 {
		log.Warn("runs left in flight by a previous process were marked failed", "count", n)
	}

	// Bind before anything else is started, and verify the bound address
	// is loopback: config already requires it, this is defense in depth
	// for the localhost-dev authentication mode.
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		log.Error("listen failed", "listen", cfg.Server.Listen, "error", err.Error())
		return ExitFatal
	}
	defer ln.Close()
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !tcpAddr.IP.IsLoopback() {
		log.Error("refusing to serve on a non-loopback address in localhost-dev mode", "addr", ln.Addr().String())
		return ExitConfig
	}
	names := make([]string, 0, len(cfg.ExecutionBindings))
	for name := range cfg.ExecutionBindings {
		names = append(names, name)
	}
	handler := api.New(api.Options{
		Registry:  reg,
		Scheduler: sched,
		Bindings:  api.Bindings{Execution: sortStrings(names), ACME: cfg.ACMEBindings, DNS: cfg.DNSBindings, Store: cfg.StoreBindings},
		Auth:      api.LocalhostDev{Port: fmt.Sprint(tcpAddr.Port)},
		Logger:    log.With("component", "api"),
	})
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 * 1024,
		ErrorLog:          slog.NewLogLogger(log.With("component", "http").Handler(), slog.LevelWarn),
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("http server: %w", err)
		}
	}()
	loopCtx, stopLoop := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = sched.Run(loopCtx)
	}()
	log.Info("conductor listening", "addr", ln.Addr().String(), "auth", cfg.Server.Auth.Mode, "tickSeconds", cfg.Scheduler.TickSeconds, "maxConcurrentRuns", cfg.Scheduler.MaxConcurrentRuns)
	if opts.Listening != nil {
		opts.Listening(ln.Addr())
	}

	code := ExitOK
	select {
	case <-ctx.Done():
		log.Info("shutdown requested")
	case err := <-errs:
		log.Error("fatal", "error", err.Error())
		code = ExitFatal
	}
	stopLoop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn("http shutdown", "error", err.Error())
	}
	cancel()
	grace := time.Duration(cfg.Server.ShutdownGraceSeconds) * time.Second
	if n := sched.InFlight(); n > 0 {
		log.Info("waiting for in-flight runs", "inflight", n, "graceSeconds", cfg.Server.ShutdownGraceSeconds)
	}
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), grace)
	sched.Drain(drainCtx)
	cancelDrain()
	wg.Wait()
	log.Info("conductor stopped")
	return code
}

// buildVerifier builds the Result verifier from the configuration's
// trusted Runner keys, if any.
func buildVerifier(cfg *config.Config) (*launcher.Verifier, error) {
	if cfg.ResultSigning == nil {
		return nil, nil
	}
	return launcher.NewVerifier(cfg.ResultSigning.Keys(), time.Duration(cfg.ResultSigning.ClockSkewSeconds)*time.Second)
}

// loadSigner reads the job signing key named by the configuration, if
// any. The key file is the only secret the Conductor reads; it is read
// once, here, and handed to the launchers through a Signer.
func loadSigner(cfg *config.Config) (*launcher.Signer, error) {
	if cfg.JobSigning == nil {
		return nil, nil
	}
	f, err := os.Open(cfg.JobSigning.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16*1024))
	if err != nil {
		return nil, err
	}
	key, err := v1alpha1.ParseSigningPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.JobSigning.PrivateKeyFile, err)
	}
	return launcher.NewSigner(key, time.Duration(cfg.JobSigning.ValiditySeconds)*time.Second)
}

func buildLaunchers(cfg *config.Config, signer *launcher.Signer, verifier *launcher.Verifier, log *slog.Logger, lookup func(string) (string, bool)) (map[string]launcher.Launcher, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	out := map[string]launcher.Launcher{}
	for name, b := range cfg.ExecutionBindings {
		switch b.Type {
		case config.ExecutionLocalProcess:
			lp := b.LocalProcess
			if err := os.MkdirAll(lp.WorkDir, 0o700); err != nil {
				return nil, fmt.Errorf("execution binding %q: work directory: %w", name, err)
			}
			out[name] = &launcher.LocalProcess{
				RunnerBinary: lp.RunnerBinary, RunnerConfig: lp.RunnerConfig, WorkDir: lp.WorkDir,
				Timeout: time.Duration(lp.TimeoutSeconds) * time.Second, PassthroughEnv: lp.PassthroughEnv,
				Signer: signer, Verifier: verifier, Logger: log.With("component", "launcher", "executionBinding", name), LookupEnv: lookup,
			}
		case config.ExecutionAzureContainerAppsJob:
			a := b.AzureContainerAppsJob
			if err := os.MkdirAll(a.ExchangeDir, 0o700); err != nil {
				return nil, fmt.Errorf("execution binding %q: exchange directory: %w", name, err)
			}
			l, err := acajob.New(acajob.Config{
				SubscriptionID: a.SubscriptionID, ResourceGroup: a.ResourceGroup, JobName: a.JobName,
				Cloud: a.Cloud, Credential: a.Credential, ManagedIdentityClientID: a.ManagedIdentityClientID,
				ExchangeDir:  a.ExchangeDir,
				ClaimTimeout: time.Duration(a.ClaimTimeoutSeconds) * time.Second,
				Timeout:      time.Duration(a.TimeoutSeconds) * time.Second,
				PollInterval: time.Duration(a.PollIntervalSeconds) * time.Second,
				ResultGrace:  time.Duration(a.ResultGraceSeconds) * time.Second,
			}, signer, verifier, &acajob.Options{Logger: log.With("component", "launcher", "executionBinding", name)})
			if err != nil {
				return nil, fmt.Errorf("execution binding %q: %w", name, err)
			}
			out[name] = l
		default:
			return nil, fmt.Errorf("execution binding %q: unsupported type %q", name, b.Type)
		}
	}
	return out, nil
}

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
