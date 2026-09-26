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
	"crypto/tls"
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
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launchers"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/migration"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/oidc"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/scheduler"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/internal/fslock"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
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
	// Launchers provides the execution binding types this Conductor can
	// build (internal/conductor/launchers). Required: a configuration
	// naming a type the registry does not provide is refused at start.
	Launchers *launchers.Registry
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
	if opts.Launchers == nil {
		log.Error("no launcher registry: the binary registers no execution binding types")
		return ExitConfig
	}
	if err := opts.Launchers.Validate(cfg); err != nil {
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
	built, err := opts.Launchers.Build(cfg, launchers.BuildDeps{Signer: signer, Verifier: verifier, Logger: log})
	if err != nil {
		log.Error("launchers could not be built", "error", err.Error())
		return ExitConfig
	}
	if !cfg.IssuanceEnabled() {
		log.Warn("issuance disabled: the conductor plans and starts no runs", "targetSource", cfg.Migration.TargetSource)
	}
	sched := scheduler.New(scheduler.Options{
		Registry:          reg,
		Launchers:         built,
		Tick:              time.Duration(cfg.Scheduler.TickSeconds) * time.Second,
		MaxConcurrentRuns: cfg.Scheduler.MaxConcurrentRuns,
		RetryBackoff:      time.Duration(cfg.Scheduler.RetryBackoffSeconds) * time.Second,
		MaxRetryBackoff:   time.Duration(cfg.Scheduler.MaxRetryBackoffSeconds) * time.Second,
		Logger:            log.With("component", "scheduler"),
		IssuanceDisabled:  !cfg.IssuanceEnabled(),
	})
	if n, err := sched.Recover(ctx); err != nil {
		log.Error("in-flight runs could not be recovered", "error", err.Error())
		return ExitFatal
	} else if n > 0 {
		log.Warn("runs left in flight by a previous process were marked failed", "count", n)
	}

	// The TLS certificate and key are read once, before anything listens,
	// so a wrong path is a startup error and not a first-connection
	// surprise.
	var tlsConfig *tls.Config
	if t := cfg.Server.TLS; t != nil {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			log.Error("TLS certificate could not be loaded", "certFile", t.CertFile, "keyFile", t.KeyFile, "error", err.Error())
			return ExitConfig
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	// Bind before anything else is started. In localhost-dev mode verify
	// the bound address is loopback: config already requires it, this is
	// defense in depth for that authentication mode.
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		log.Error("listen failed", "listen", cfg.Server.Listen, "error", err.Error())
		return ExitFatal
	}
	defer ln.Close()
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		log.Error("listener is not TCP", "addr", ln.Addr().String())
		return ExitFatal
	}
	if cfg.Server.Auth.Mode == config.AuthLocalhostDev && !tcpAddr.IP.IsLoopback() {
		log.Error("refusing to serve on a non-loopback address in localhost-dev mode", "addr", ln.Addr().String())
		return ExitConfig
	}
	auth, uiOpts, err := buildAuth(ctx, cfg, tcpAddr.Port, log)
	if err != nil {
		log.Error("authentication could not be configured", "mode", cfg.Server.Auth.Mode, "error", err.Error())
		return ExitConfig
	}
	names := make([]string, 0, len(cfg.ExecutionBindings))
	for name := range cfg.ExecutionBindings {
		names = append(names, name)
	}
	migOpts, shadow := buildMigration(cfg, reg, names, log)
	handler := api.New(api.Options{
		Registry:             reg,
		Scheduler:            sched,
		Bindings:             api.Bindings{Execution: sortStrings(names), ACME: cfg.ACMEBindings, DNS: cfg.DNSBindings, Store: cfg.StoreBindings},
		Auth:                 auth,
		Logger:               log.With("component", "api"),
		UI:                   uiOpts,
		Migration:            migOpts,
		ProvisioningKey:      cfg.AccountProvisioning.Key(),
		ProvisioningBindings: cfg.AccountProvisioning.EABBindings(),
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
	serve := srv.Serve
	if tlsConfig != nil {
		srv.TLSConfig = tlsConfig
		serve = func(l net.Listener) error { return srv.ServeTLS(l, "", "") }
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("http server: %w", err)
		}
	}()
	loopCtx, stopLoop := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = sched.Run(loopCtx)
	}()
	if shadow != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = shadow.Run(loopCtx)
		}()
	}
	log.Info("conductor listening", "addr", ln.Addr().String(), "auth", cfg.Server.Auth.Mode, "tls", cfg.Server.TLS != nil, "behindTlsProxy", cfg.Server.BehindTLSProxy, "tickSeconds", cfg.Scheduler.TickSeconds, "maxConcurrentRuns", cfg.Scheduler.MaxConcurrentRuns, "targetSource", cfg.Migration.TargetSource)
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

// buildMigration composes the migration tooling from the configuration:
// the API's view of it, and the shadow comparison loop under target
// source shadow (nil otherwise). Without a profile there is no migrator,
// and the API says so.
func buildMigration(cfg *config.Config, reg *sqlite.DB, executionNames []string, log *slog.Logger) (*api.MigrationOptions, *migration.Shadow) {
	m := cfg.Migration
	opts := &api.MigrationOptions{TargetSource: m.TargetSource, Source: m.Source}
	if m.Profile == nil {
		return opts, nil
	}
	opts.Migrator = &migration.Migrator{
		Registry: reg, Profile: *m.Profile,
		Bindings: migration.Bindings{Execution: executionNames, DNS: cfg.DNSBindings, Store: cfg.StoreBindings},
	}
	if m.TargetSource != config.TargetSourceShadow {
		return opts, nil
	}
	shadow := &migration.Shadow{
		Migrator: opts.Migrator, Source: *m.Source,
		Interval: time.Duration(m.CompareIntervalSeconds) * time.Second,
		Logger:   log.With("component", "migration"),
	}
	opts.Latest = shadow.Latest
	log.Info("shadow comparison enabled", "source", m.Source.Describe(), "intervalSeconds", m.CompareIntervalSeconds)
	return opts, shadow
}

// buildAuth builds the Authenticator for the configured mode and the
// options the GUI needs to sign in. In oidc mode the provider's discovery
// document and keys are fetched once now, so a wrong issuer is reported
// in the log at start; a provider that is merely unreachable is a
// warning, and keys are fetched again on demand.
func buildAuth(ctx context.Context, cfg *config.Config, port int, log *slog.Logger) (api.Authenticator, *api.UIOptions, error) {
	switch cfg.Server.Auth.Mode {
	case config.AuthLocalhostDev:
		return api.LocalhostDev{Port: fmt.Sprint(port)}, &api.UIOptions{AuthMode: config.AuthLocalhostDev}, nil
	case config.AuthOIDC:
		o := cfg.Server.Auth.OIDC
		a, err := oidc.New(oidc.Config{
			Issuer: o.Issuer, Audience: o.Audience,
			PrincipalClaim: o.PrincipalClaim, RolesClaim: o.RolesClaim,
			AdminValues: o.Roles.Admin, ViewerValues: o.Roles.Viewer,
			ClockSkew: time.Duration(o.ClockSkewSeconds) * time.Second,
			KeyCache:  time.Duration(o.KeyCacheSeconds) * time.Second,
		}, &oidc.Options{Logger: log.With("component", "oidc")})
		if err != nil {
			return nil, nil, err
		}
		if err := a.Prime(ctx); err != nil {
			log.Warn("identity provider not reachable at start; tokens are refused until it is", "issuer", o.Issuer, "error", err.Error())
		}
		ui := &api.UIOptions{
			AuthMode: config.AuthOIDC, Issuer: o.Issuer, ClientID: o.ClientID, Scopes: o.Scopes,
			Endpoints: func(ctx context.Context) (api.UIAuthEndpoints, error) {
				ep, err := a.Endpoints(ctx)
				if err != nil {
					return api.UIAuthEndpoints{}, err
				}
				return api.UIAuthEndpoints{Authorization: ep.Authorization, Token: ep.Token}, nil
			},
		}
		return a, ui, nil
	default:
		return nil, nil, fmt.Errorf("unsupported authentication mode %q", cfg.Server.Auth.Mode)
	}
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

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
