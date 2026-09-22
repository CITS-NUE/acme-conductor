// Package acajob is the Azure Container Apps Job launcher (Phase 4). It
// starts one execution of a pre-provisioned Container Apps Job per run,
// hands the Runner a signed JobSpec over a file share both containers
// mount, watches the execution until it ends, and reads the Result back
// from the same share.
//
// This is the only package of the Conductor binary that imports an Azure
// SDK; the scheduler sees it through launcher.Launcher only. The
// Conductor's identity needs four permissions on the Job resource (read
// it, start an execution, read an execution, stop an execution) and
// nothing else — never a DNS, Key Vault or storage data permission
// (docs/threat-model.md, T10). The Runner's identity is attached to the
// Job in infrastructure (deploy/azure), so no credential ever travels
// through this launcher.
//
// Transport. The Conductor writes <exchangeDir>/run-<runId>/job.json — a
// SignedCertificateReconcileJob, never a bare JobSpec, because a share is
// not a transport the Conductor owns (docs/adr/0015) — and starts the
// execution with the Runner's arguments pointing at the same path as the
// Runner container sees it. The Runner writes result.json next to it. The
// directory holds nothing else and is removed when the execution ends.
package acajob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
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
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Type is the launcher type name.
const Type = config.ExecutionAzureContainerAppsJob

// Defaults.
const (
	DefaultPollInterval = 10 * time.Second
	DefaultResultGrace  = 30 * time.Second
	// DefaultStopGrace bounds how long Wait keeps polling for a terminal
	// status after it asked the platform to stop the execution.
	DefaultStopGrace = 90 * time.Second
	// maxConsecutivePollErrors ends a Wait whose status reads keep failing
	// (the platform is unreachable) before the launcher timeout would.
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
	ContainerName           string
	ExchangeDir             string
	RunnerExchangeDir       string
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
	cfg    Config
	signer *launcher.Signer
	jobs   *armappcontainers.JobsClient
	api    *armappcontainers.ContainerAppsAPIClient
	log    *slog.Logger
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

// New builds a Launcher. signer is mandatory: this launcher never hands a
// Runner an unsigned job.
func New(cfg Config, signer *launcher.Signer, opts *Options) (*Launcher, error) {
	if opts == nil {
		opts = &Options{}
	}
	if signer == nil {
		return nil, errors.New("a job signer is required: jobs travel over a shared volume")
	}
	if cfg.SubscriptionID == "" || cfg.ResourceGroup == "" || cfg.JobName == "" {
		return nil, errors.New("subscription id, resource group and job name are required")
	}
	if !filepath.IsAbs(cfg.ExchangeDir) || !filepath.IsAbs(cfg.RunnerExchangeDir) {
		return nil, errors.New("exchange directories must be absolute paths")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
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
	return &Launcher{cfg: cfg, signer: signer, jobs: jobs, api: api, log: logger}, nil
}

// Type implements launcher.Launcher.
func (l *Launcher) Type() string { return Type }

// Start implements launcher.Launcher.
func (l *Launcher) Start(ctx context.Context, spec *v1alpha1.JobSpec) (launcher.Execution, error) {
	data, err := launcher.JobDocument(spec, l.signer)
	if err != nil {
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: err}
	}
	if err := os.MkdirAll(l.cfg.ExchangeDir, 0o700); err != nil {
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("create exchange directory: %w", err)}
	}
	runDir := "run-" + spec.RunID
	dir := filepath.Join(l.cfg.ExchangeDir, runDir)
	// The run id is unique, so an existing directory is a leftover of an
	// earlier attempt and is refused rather than reused.
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("create run directory: %w", err)}
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.WriteFile(filepath.Join(dir, launcher.JobFile), data, 0o600); err != nil {
		cleanup()
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: fmt.Errorf("write job: %w", err)}
	}
	// Paths as the Runner container sees them (always slash-separated).
	runnerJob := path.Join(l.cfg.RunnerExchangeDir, runDir, launcher.JobFile)
	runnerResult := path.Join(l.cfg.RunnerExchangeDir, runDir, launcher.ResultFile)

	template, err := l.executionTemplate(ctx, []string{"reconcile", "--job", runnerJob, "--result", runnerResult})
	if err != nil {
		cleanup()
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: err}
	}
	poller, err := l.jobs.BeginStart(ctx, l.cfg.ResourceGroup, l.cfg.JobName, &armappcontainers.JobsClientBeginStartOptions{Template: template})
	if err != nil {
		cleanup()
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: describe("start execution", err)}
	}
	resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: l.cfg.PollInterval})
	if err != nil {
		cleanup()
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: describe("start execution", err)}
	}
	if resp.Name == nil || *resp.Name == "" {
		cleanup()
		return nil, &launcher.Error{Reason: launcher.ReasonStart, Err: errors.New("start execution: platform returned no execution name")}
	}
	name := *resp.Name
	log := l.log.With("runId", spec.RunID, "targetId", spec.Target.ID, "execution", name)
	log.Info("job execution started", "job", l.cfg.JobName)
	return &execution{
		l: l, id: Type + ":" + name, name: name, parent: ctx, dir: dir, cleanup: cleanup, spec: spec, log: log,
	}, nil
}

// executionTemplate reads the Job's template and returns the execution
// template for one run: every container copied as configured in
// infrastructure (name, image, command, environment, resources), with the
// Runner container's arguments replaced by args. Nothing else about the
// execution — identity, volumes, secrets — is expressible here, which is
// the point: the Conductor can choose what run a Runner executes, not
// what the Runner is.
func (l *Launcher) executionTemplate(ctx context.Context, args []string) (*armappcontainers.JobExecutionTemplate, error) {
	job, err := l.jobs.Get(ctx, l.cfg.ResourceGroup, l.cfg.JobName, nil)
	if err != nil {
		return nil, describe("read job", err)
	}
	if job.Properties == nil || job.Properties.Template == nil || len(job.Properties.Template.Containers) == 0 {
		return nil, errors.New("read job: the job template has no containers")
	}
	containers := job.Properties.Template.Containers
	target := -1
	for i, c := range containers {
		if c == nil || c.Name == nil {
			continue
		}
		if l.cfg.ContainerName == "" || *c.Name == l.cfg.ContainerName {
			if target >= 0 && l.cfg.ContainerName == "" {
				return nil, errors.New("read job: the job template has several containers; set containerName")
			}
			target = i
		}
	}
	if target < 0 {
		return nil, fmt.Errorf("read job: container %q is not in the job template", l.cfg.ContainerName)
	}
	tmpl := &armappcontainers.JobExecutionTemplate{}
	for i, c := range containers {
		if c == nil {
			continue
		}
		ec := &armappcontainers.JobExecutionContainer{
			Name: c.Name, Image: c.Image, Command: c.Command, Args: c.Args, Env: c.Env, Resources: c.Resources,
		}
		if i == target {
			ec.Args = make([]*string, len(args))
			for j := range args {
				a := args[j]
				ec.Args[j] = &a
			}
		}
		tmpl.Containers = append(tmpl.Containers, ec)
	}
	for _, c := range job.Properties.Template.InitContainers {
		if c == nil {
			continue
		}
		tmpl.InitContainers = append(tmpl.InitContainers, &armappcontainers.JobExecutionContainer{
			Name: c.Name, Image: c.Image, Command: c.Command, Args: c.Args, Env: c.Env, Resources: c.Resources,
		})
	}
	return tmpl, nil
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
	defer e.cleanup()
	l := e.l
	runCtx, cancel := context.WithCancel(e.parent)
	if l.cfg.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(e.parent, l.cfg.Timeout)
	}
	defer cancel()

	status, pollErr := e.poll(runCtx)
	stopped := false
	if !terminal(status) && runCtx.Err() != nil {
		// Cancelled or timed out: ask the platform to stop the execution,
		// then give it a bounded while to reach a terminal status and
		// report what the Runner managed to write (normally Cancelled).
		stopped = true
		stopCtx, cancelStop := context.WithTimeout(context.WithoutCancel(e.parent), l.cfg.StopGrace)
		e.log.Warn("stopping job execution", "cause", runCtx.Err().Error())
		if err := e.stop(stopCtx); err != nil {
			e.log.Error("job execution could not be stopped", "error", err.Error())
		}
		status, pollErr = e.poll(stopCtx)
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
	path := filepath.Join(e.dir, launcher.ResultFile)
	deadline := time.Now().Add(e.l.cfg.ResultGrace)
	for {
		res, err := readResultFile(path)
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

func readResultFile(path string) (*v1alpha1.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, v1alpha1.MaxDocumentSize+1))
	if err != nil {
		return nil, err
	}
	return v1alpha1.DecodeResult(bytes.NewReader(data))
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
