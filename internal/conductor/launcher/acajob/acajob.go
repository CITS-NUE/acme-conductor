// Package acajob is the Azure Container Apps Job launcher (Phase 4). The
// Runner runs as a *scheduled* Container Apps Job whose executions start on
// the platform's own cadence; the Conductor never starts one. For each run
// the Conductor offers a signed JobSpec in an exchange directory both
// containers mount, the next execution takes it (internal/exchange), the
// Conductor learns which execution did from the marker the Runner leaves,
// watches that execution until it ends, and reads the signed Result back
// from the same directory.
//
// Why the Conductor does not start executions: the platform's start
// operation accepts an execution template that can replace the image, the
// command and the environment of the Job's containers, so an identity
// holding Microsoft.App/jobs/start/action can run any image under the
// Job's managed identity. Nothing this code refrains from doing would
// protect against a compromise of the Conductor's identity; only not
// holding that permission does (docs/adr/0014, threat model T1/T10). The
// Conductor's identity therefore needs three permissions on the Job:
// read an execution, list executions, stop an execution — none of which
// lets it choose what runs — and nothing else, never a DNS, Key Vault or
// storage data permission. The Runner's identity is attached to the Job
// in infrastructure (deploy/azure), so no credential ever travels through
// this launcher.
//
// Transport. Both documents cross a file share that other principals may
// be able to write, so neither direction is trusted on its own: the job
// is a SignedCertificateReconcileJob and the Result must be a
// SignedCertificateReconcileResult that verifies against the Runners'
// public keys (docs/adr/0015); the launcher refuses to be built without a
// signer and a verifier. The execution name the Runner records is
// validated and confirmed against the platform before it is used. The
// directory holds nothing else and is removed when the execution ends.
//
// This is the only package of the Conductor binary that imports an Azure
// SDK; the scheduler sees it through launcher.Launcher only.
package acajob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v3"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher"
	"github.com/CITS-NUE/acme-conductor/internal/exchange"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Type is the launcher type name.
const Type = config.ExecutionAzureContainerAppsJob

// Defaults.
const (
	DefaultPollInterval = 10 * time.Second
	DefaultResultGrace  = 30 * time.Second
	// DefaultClaimTimeout bounds how long Start waits for a scheduled
	// execution to take the offered job.
	DefaultClaimTimeout = 5 * time.Minute
	// DefaultExecutionGrace bounds how long Start waits, once the job has
	// been taken, for the Runner to record its execution name.
	DefaultExecutionGrace = 60 * time.Second
	// DefaultStopGrace bounds how long Wait keeps polling for a terminal
	// status after it asked the platform to stop the execution.
	DefaultStopGrace = 90 * time.Second
	// maxConsecutivePollErrors ends the polling of a Wait whose status
	// reads keep failing (the platform is unreachable) before the launcher
	// timeout would; the execution is then stopped like a timed-out one.
	maxConsecutivePollErrors = 30
)

// Config configures a Launcher. It mirrors config.AzureContainerAppsJob.
type Config struct {
	SubscriptionID          string
	ResourceGroup           string
	JobName                 string
	Cloud                   string
	Credential              string
	ManagedIdentityClientID string
	ExchangeDir             string
	ClaimTimeout            time.Duration
	ExecutionGrace          time.Duration
	Timeout                 time.Duration
	PollInterval            time.Duration
	ResultGrace             time.Duration
	StopGrace               time.Duration
}

// Options are injection points for tests.
type Options struct {
	// Credential replaces the credential selected by Config.Credential.
	Credential azcore.TokenCredential
	// ClientOptions configures the SDK clients (transport, cloud, retry).
	ClientOptions *arm.ClientOptions
	Logger        *slog.Logger
}

// Launcher implements launcher.Launcher for Container Apps Jobs.
type Launcher struct {
	cfg      Config
	signer   *launcher.Signer
	verifier *launcher.Verifier
	jobs     *armappcontainers.JobsClient
	api      *armappcontainers.ContainerAppsAPIClient
	log      *slog.Logger
}

// CloudConfiguration maps a config cloud name to the SDK's configuration.
func CloudConfiguration(name string) (cloud.Configuration, error) {
	switch name {
	case "", config.CloudPublic:
		return cloud.AzurePublic, nil
	case config.CloudChina:
		return cloud.AzureChina, nil
	case config.CloudGovernment:
		return cloud.AzureGovernment, nil
	}
	return cloud.Configuration{}, fmt.Errorf("unknown cloud %q", name)
}

// newCredential builds the token credential for the configured kind.
// Nothing is contacted until the first token request.
func newCredential(kind, clientID string, c cloud.Configuration) (azcore.TokenCredential, error) {
	switch kind {
	case config.CredentialManagedIdentity:
		opts := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: azcore.ClientOptions{Cloud: c}}
		if clientID != "" {
			opts.ID = azidentity.ClientID(clientID)
		}
		cred, err := azidentity.NewManagedIdentityCredential(opts)
		if err != nil {
			return nil, fmt.Errorf("managed identity credential: %w", err)
		}
		return cred, nil
	case "", config.CredentialDefault:
		cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: azcore.ClientOptions{Cloud: c}})
		if err != nil {
			return nil, fmt.Errorf("default azure credential: %w", err)
		}
		return cred, nil
	}
	return nil, fmt.Errorf("unknown credential kind %q", kind)
}

// New builds a Launcher. signer and verifier are mandatory: this launcher
// never hands a Runner an unsigned job and never accepts an unsigned
// Result, because both travel over a shared volume.
func New(cfg Config, signer *launcher.Signer, verifier *launcher.Verifier, opts *Options) (*Launcher, error) {
	if opts == nil {
		opts = &Options{}
	}
	if signer == nil {
		return nil, errors.New("a job signer is required: jobs travel over a shared volume")
	}
	if verifier == nil {
		return nil, errors.New("a result verifier is required: results travel over a shared volume")
	}
	if cfg.SubscriptionID == "" || cfg.ResourceGroup == "" || cfg.JobName == "" {
		return nil, errors.New("subscription id, resource group and job name are required")
	}
	if !filepath.IsAbs(cfg.ExchangeDir) {
		return nil, errors.New("exchange directory must be an absolute path")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.ClaimTimeout <= 0 {
		cfg.ClaimTimeout = DefaultClaimTimeout
	}
	if cfg.ExecutionGrace <= 0 {
		cfg.ExecutionGrace = DefaultExecutionGrace
	}
	if cfg.ResultGrace < 0 {
		cfg.ResultGrace = DefaultResultGrace
	}
	if cfg.StopGrace <= 0 {
		cfg.StopGrace = DefaultStopGrace
	}
	cl, err := CloudConfiguration(cfg.Cloud)
	if err != nil {
		return nil, err
	}
	clientOpts := opts.ClientOptions
	if clientOpts == nil {
		clientOpts = &arm.ClientOptions{ClientOptions: azcore.ClientOptions{Cloud: cl}}
	}
	cred := opts.Credential
	if cred == nil {
		cred, err = newCredential(cfg.Credential, cfg.ManagedIdentityClientID, cl)
		if err != nil {
			return nil, err
		}
	}
	jobs, err := armappcontainers.NewJobsClient(cfg.SubscriptionID, cred, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("jobs client: %w", err)
	}
	api, err := armappcontainers.NewContainerAppsAPIClient(cfg.SubscriptionID, cred, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("executions client: %w", err)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Launcher{cfg: cfg, signer: signer, verifier: verifier, jobs: jobs, api: api, log: logger}, nil
}

// Type implements launcher.Launcher.
func (l *Launcher) Type() string { return Type }

// Start implements launcher.Launcher: it offers the signed job in the
// exchange directory and waits for a scheduled execution to take it and
// record its execution name, which is then confirmed with the platform.
// A cancelled context or an expired ClaimTimeout withdraws the offer.
func (l *Launcher) Start(ctx context.Context, spec *v1alpha1.JobSpec) (launcher.Execution, error) {
	data, err := launcher.JobDocument(spec, l.signer)
	if err != nil {
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: err}
	}
	root := l.cfg.ExchangeDir
	if err := exchange.Publish(root, spec.RunID, data); err != nil {
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("offer job: %w", err)}
	}
	log := l.log.With("runId", spec.RunID, "targetId", spec.Target.ID)
	log.Info("job offered to the runner job", "job", l.cfg.JobName)

	name, err := l.awaitClaim(ctx, log, spec.RunID)
	if err != nil {
		return nil, err
	}
	log = log.With("execution", name)
	dir := exchange.ClaimedDir(root, spec.RunID)
	e := &execution{
		l: l, id: Type + ":" + name, name: name, parent: ctx, dir: dir,
		cleanup: func() { _ = exchange.Remove(root, spec.RunID) }, spec: spec, log: log,
	}
	// From here on a Runner holds the job and is working: whatever the
	// confirmation below finds, the run is only ever ended through Wait,
	// which stops the execution before the directory is removed. The one
	// exception is the platform stating that no such execution exists.
	if err := l.confirm(ctx, e); err != nil {
		return nil, err
	}
	log.Info("job taken by an execution")
	return e, nil
}

// confirmAttempts bounds how many times Start asks the platform about the
// execution a Runner recorded before it watches it unconfirmed.
const confirmAttempts = 5

// confirm checks with the platform that the name a Runner recorded is an
// execution of this Job. The marker is untrusted content from the share,
// so a name the platform does not know ends the run at start (nothing of
// this Job is running under it). Any other failure to read the execution
// — the platform unreachable, the context cancelled — does not: the
// Runner may well be running, so the execution is returned unconfirmed
// and Wait, whose polling retries and whose every non-terminal exit
// stops the execution, takes it from there.
func (l *Launcher) confirm(ctx context.Context, e *execution) error {
	var last error
	for attempt := 1; attempt <= confirmAttempts; attempt++ {
		_, err := l.api.JobExecution(ctx, l.cfg.ResourceGroup, l.cfg.JobName, e.name, nil)
		if err == nil {
			return nil
		}
		var re *azcore.ResponseError
		if errors.As(err, &re) && re.StatusCode == 404 {
			e.cleanup()
			return &launcher.Error{Reason: launcher.ReasonStart, Err: describe("confirm execution", err)}
		}
		last = describe("confirm execution", err)
		e.log.Warn("execution could not be confirmed", "attempt", attempt, "error", last.Error())
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(l.cfg.PollInterval):
		}
		if ctx.Err() != nil {
			break
		}
	}
	e.log.Warn("watching the execution unconfirmed", "error", last.Error())
	return nil
}

// awaitClaim waits until an execution has taken the job and recorded its
// name, and returns that name. Waiting ends with the claim timeout or the
// context: the offer is then withdrawn — unless an execution took it in
// the meantime, in which case its name is still awaited for a bounded
// grace. Every exit without a name leaves nothing of the run in the
// exchange directory.
func (l *Launcher) awaitClaim(ctx context.Context, log *slog.Logger, runID string) (string, error) {
	root := l.cfg.ExchangeDir
	claimDeadline := time.Now().Add(l.cfg.ClaimTimeout)
	var markerDeadline time.Time
	for {
		name, err := exchange.ReadExecution(root, runID)
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			_ = exchange.Remove(root, runID)
			return "", &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("execution marker: %w", err)}
		}
		state, serr := exchange.StateOf(root, runID)
		if serr != nil {
			return "", &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("exchange directory: %w", serr)}
		}
		switch state {
		case exchange.StateAbsent:
			return "", &launcher.Error{Reason: launcher.ReasonStart, Err: errors.New("the offered job disappeared from the exchange directory")}
		case exchange.StatePending:
			if ctx.Err() != nil || !time.Now().Before(claimDeadline) {
				withdrawn, werr := exchange.Withdraw(root, runID)
				if werr != nil {
					// A real failure of the share, not a lost race: the
					// offer may still be pending, but waiting on a share
					// that cannot be written would never end. The run
					// fails; the pending directory is reported so an
					// operator can remove it.
					return "", &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("offered job could not be withdrawn (pending/%s may remain): %w", exchange.RunDirName(runID), werr)}
				}
				if withdrawn {
					if ctx.Err() != nil {
						return "", &launcher.Error{Reason: launcher.ReasonCancelled, Err: errors.New("run was cancelled before a runner took the job")}
					}
					return "", &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("no execution took the job within %s", l.cfg.ClaimTimeout)}
				}
				// Taken at the last moment: the next iteration sees the
				// claimed state and waits for the execution name.
				continue
			}
		case exchange.StateClaimed:
			if markerDeadline.IsZero() {
				markerDeadline = time.Now().Add(l.cfg.ExecutionGrace)
			} else if !time.Now().Before(markerDeadline) {
				_ = exchange.Remove(root, runID)
				return "", &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("an execution took the job but recorded no execution name within %s", l.cfg.ExecutionGrace)}
			}
		}
		select {
		case <-ctx.Done():
			// Re-check once so a cancellation withdraws a pending offer.
			if state == exchange.StateClaimed {
				_ = exchange.Remove(root, runID)
				return "", &launcher.Error{Reason: launcher.ReasonCancelled, Err: errors.New("run was cancelled while waiting for the execution name")}
			}
		case <-time.After(l.cfg.PollInterval):
		}
	}
}

type execution struct {
	l       *Launcher
	id      string
	name    string
	parent  context.Context
	dir     string
	cleanup func()
	spec    *v1alpha1.JobSpec
	log     *slog.Logger

	once sync.Once
	res  *v1alpha1.Result
	err  error
}

func (e *execution) ID() string { return e.id }

func (e *execution) Wait() (*v1alpha1.Result, error) {
	e.once.Do(func() { e.res, e.err = e.wait() })
	return e.res, e.err
}

// terminal reports whether a status is final.
func terminal(s *armappcontainers.JobExecutionRunningState) bool {
	if s == nil {
		return false
	}
	switch *s {
	case armappcontainers.JobExecutionRunningStateSucceeded, armappcontainers.JobExecutionRunningStateFailed,
		armappcontainers.JobExecutionRunningStateStopped, armappcontainers.JobExecutionRunningStateDegraded:
		return true
	}
	return false
}

func (e *execution) wait() (*v1alpha1.Result, error) {
	l := e.l
	// The run directory is removed only once the execution is known to
	// have ended: a Runner that may still be working keeps its result
	// path, and the directory is reported for an operator to remove.
	var status *armappcontainers.JobExecutionRunningState
	defer func() {
		if terminal(status) {
			e.cleanup()
			return
		}
		e.log.Warn("run directory kept: the execution has not been seen to end", "dir", e.dir)
	}()
	runCtx, cancel := context.WithCancel(e.parent)
	if l.cfg.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(e.parent, l.cfg.Timeout)
	}
	defer cancel()

	var pollErr error
	status, pollErr = e.poll(runCtx)
	stopped := false
	if !terminal(status) {
		// Cancelled, timed out, or the status could not be read any more:
		// in every case the execution may still be running, so ask the
		// platform to stop it before the run directory is removed, then
		// give it a bounded while to reach a terminal status and report
		// what the Runner managed to write (normally Cancelled).
		stopped = true
		cause := "status could not be read"
		if runCtx.Err() != nil {
			cause = runCtx.Err().Error()
		} else if pollErr != nil {
			cause = pollErr.Error()
		}
		stopCtx, cancelStop := context.WithTimeout(context.WithoutCancel(e.parent), l.cfg.StopGrace)
		e.log.Warn("stopping job execution", "cause", cause)
		if err := e.stop(stopCtx); err != nil {
			e.log.Error("job execution could not be stopped", "error", err.Error())
		}
		var stopPollErr error
		status, stopPollErr = e.poll(stopCtx)
		if pollErr == nil {
			pollErr = stopPollErr
		}
		cancelStop()
	}
	statusText := "unknown"
	if status != nil {
		statusText = string(*status)
	}
	e.log.Info("job execution ended", "status", statusText)

	res, rerr := e.readResult(runCtx, terminal(status))
	if rerr == nil {
		if res.RunID != e.spec.RunID || res.TargetID != e.spec.Target.ID {
			return nil, &launcher.Error{Reason: launcher.ReasonMismatch, Err: fmt.Errorf("result names run %s target %s", res.RunID, res.TargetID)}
		}
		// The platform's verdict and the Runner's must agree: the Runner
		// exits 0 exactly when it wrote a succeeded Result. A disagreement
		// means the file on the share is not what the execution produced.
		if status != nil {
			switch {
			case *status == armappcontainers.JobExecutionRunningStateSucceeded && res.Status != v1alpha1.StatusSucceeded,
				*status == armappcontainers.JobExecutionRunningStateFailed && res.Status != v1alpha1.StatusFailed:
				return nil, &launcher.Error{Reason: launcher.ReasonMismatch, Err: fmt.Errorf("execution status %s but result status %s", *status, res.Status)}
			}
		}
		return res, nil
	}
	cause := rerr
	if pollErr != nil {
		cause = fmt.Errorf("%v (status: %w)", rerr, pollErr)
	}
	switch {
	case stopped && errors.Is(runCtx.Err(), context.DeadlineExceeded) && e.parent.Err() == nil:
		return nil, &launcher.Error{Reason: launcher.ReasonTimeout, Err: cause}
	case e.parent.Err() != nil:
		return nil, &launcher.Error{Reason: launcher.ReasonCancelled, Err: cause}
	}
	return nil, &launcher.Error{Reason: launcher.ReasonNoResult, Err: cause}
}

// poll reads the execution's status until it is terminal or ctx ends. It
// returns the last status read and the last read error, if any.
func (e *execution) poll(ctx context.Context) (*armappcontainers.JobExecutionRunningState, error) {
	var last *armappcontainers.JobExecutionRunningState
	var lastErr error
	failures := 0
	for {
		resp, err := e.l.api.JobExecution(ctx, e.l.cfg.ResourceGroup, e.l.cfg.JobName, e.name, nil)
		if err != nil {
			if ctx.Err() != nil {
				return last, ctx.Err()
			}
			failures++
			lastErr = describe("read execution", err)
			e.log.Warn("job execution status could not be read", "attempt", failures, "error", lastErr.Error())
			if failures >= maxConsecutivePollErrors {
				return last, lastErr
			}
		} else {
			failures, lastErr = 0, nil
			if resp.Properties != nil {
				last = resp.Properties.Status
			}
			if terminal(last) {
				return last, nil
			}
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(e.l.cfg.PollInterval):
		}
	}
}

// stop asks the platform to stop the execution.
func (e *execution) stop(ctx context.Context) error {
	poller, err := e.l.jobs.BeginStopExecution(ctx, e.l.cfg.ResourceGroup, e.l.cfg.JobName, e.name, nil)
	if err != nil {
		return describe("stop execution", err)
	}
	if _, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: e.l.cfg.PollInterval}); err != nil {
		return describe("stop execution", err)
	}
	return nil
}

// readResult reads result.json from the run directory. When the
// execution ended normally the file may lag behind the status on a file
// share, so its absence is retried for ResultGrace; otherwise one read is
// made.
func (e *execution) readResult(ctx context.Context, ended bool) (*v1alpha1.Result, error) {
	path := filepath.Join(e.dir, exchange.ResultFile)
	deadline := time.Now().Add(e.l.cfg.ResultGrace)
	for {
		res, err := launcher.ReadResultFile(path, e.l.verifier)
		if err == nil {
			return res, nil
		}
		if !ended || !errors.Is(err, os.ErrNotExist) || !time.Now().Before(deadline) {
			return nil, err
		}
		wait := e.l.cfg.PollInterval
		if wait > time.Second {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			// The run context may already be done (a stop); the grace
			// period still applies, so keep waiting on wall-clock time.
			time.Sleep(wait)
		case <-time.After(wait):
		}
	}
}

// describe reduces an SDK error to fixed wording: an ARM response becomes
// its status and error code, a transport failure its kind, anything else
// the Go type of the innermost error. Response bodies are never wrapped
// in, so nothing the platform echoes back can reach a log line or, via a
// caller, a record.
func describe(op string, err error) error {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		code := re.ErrorCode
		if code == "" {
			code = "no error code"
		}
		return fmt.Errorf("%s: HTTP %d (%s)", op, re.StatusCode, code)
	}
	var af *azidentity.AuthenticationFailedError
	if errors.As(err, &af) {
		return fmt.Errorf("%s: authentication failed", op)
	}
	if fmt.Sprintf("%T", err) == "*azidentity.credentialUnavailableError" {
		return fmt.Errorf("%s: credential unavailable", op)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", op, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", op, context.Canceled)
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return fmt.Errorf("%s: request timed out", op)
		}
		return fmt.Errorf("%s: connection failed", op)
	}
	inner := err
	for {
		u, ok := inner.(interface{ Unwrap() error })
		if !ok || u.Unwrap() == nil {
			break
		}
		inner = u.Unwrap()
	}
	return fmt.Errorf("%s: %T", op, inner)
}
