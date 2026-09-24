// Package runner implements the one-shot reconcile of acme-runner.
//
// One invocation handles exactly one JobSpec for one target:
//
//  1. read the JobSpec and decode it strictly (validation);
//  2. load the trusted runner configuration and authorize the job against
//     it (authorization, independent of anything the JobSpec claims);
//  3. ask the Certificate Store for the current certificate and decide
//     whether anything needs to be done;
//  4. if so, run lego once in a fresh temporary work directory, verify what
//     it produced, and store the bundle;
//  5. destroy the work directory (and with it the only local copy of the
//     private key) and emit a Result.
//
// The Runner has no server, no scheduler and no database. Every failure is
// translated into a stable ErrorCode plus a summary produced from a
// Runner-owned template; raw output of lego never reaches the Result.
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/exchange"
	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/internal/runner/lego"
	"github.com/CITS-NUE/acme-conductor/internal/runner/stores"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
	"github.com/CITS-NUE/acme-conductor/pkg/store"
)

// staleMargin is added to a run's sweep deadline on top of the lego
// timeout and the termination grace period, to cover the store and state
// work around the lego invocation.
const staleMargin = 5 * time.Minute

// persistTimeout bounds the publication of ACME account state after lego
// has finished; it is independent of the run's own cancellation.
const persistTimeout = 30 * time.Second

// classifyCtx turns a failure whose cause is the run's own context ending
// into the contract's Cancelled or Timeout code, so a lock or store wait
// interrupted by SIGTERM is reported as a cancellation rather than as an
// internal or store failure.
func classifyCtx(ctx context.Context, f *failure) *failure {
	switch {
	case errors.Is(f.err, context.Canceled) && ctx.Err() != nil:
		return fail(v1alpha1.ErrorCodeCancelled, "run was cancelled by signal while waiting for "+f.summary, f.err)
	case errors.Is(f.err, context.DeadlineExceeded) && ctx.Err() != nil:
		return fail(v1alpha1.ErrorCodeTimeout, "run deadline passed while waiting for "+f.summary, f.err)
	}
	return f
}

// EnvExecutionName is the variable Azure Container Apps sets to the name
// of the job execution a container runs in.
const EnvExecutionName = "CONTAINER_APP_JOB_EXECUTION_NAME"

// clockSkewTolerance is how far in the future a certificate's NotBefore may
// lie and still be treated as valid now. CAs backdate NotBefore by about an
// hour; a larger offset indicates a wrong clock or a malformed certificate.
const clockSkewTolerance = 5 * time.Minute

// Exit codes of a reconcile.
const (
	// ExitSucceeded: a Result with status "succeeded" was written.
	ExitSucceeded = 0
	// ExitFailed: a Result with status "failed" was written.
	ExitFailed = 1
	// ExitNoResult: the job could not even be identified, so no Result was
	// written; details are on stderr only.
	ExitNoResult = 2
)

// Options configure one reconcile.
type Options struct {
	ConfigPath string
	JobPath    string
	// ResultPath is where the Result is written atomically. Empty means
	// stdout only.
	ResultPath string
	// ExchangeDir, when set, selects the claim mode used on platforms that
	// start Runners on their own (docs/adr/0014): instead of JobPath and
	// ResultPath the Runner takes the oldest pending job from the exchange
	// directory (internal/exchange), records its platform execution name
	// there, and writes the Result next to the job. When nothing is
	// pending the Runner exits 0 without a Result.
	ExchangeDir string
	// ExecutionName is the platform execution name recorded for a claimed
	// job; empty selects the CONTAINER_APP_JOB_EXECUTION_NAME variable.
	ExecutionName string
	// Stores provides the Certificate Store types this Runner can open
	// (internal/runner/stores). Required: a configuration naming a type
	// the registry does not provide is refused before any job is handled.
	Stores *stores.Registry
	// Stdout receives the single-line JSON Result.
	Stdout io.Writer
	Logger *slog.Logger
	// Now, LookupEnv and GracePeriod are injection points for tests.
	Now         func() time.Time
	LookupEnv   func(string) (string, bool)
	GracePeriod time.Duration
}

func (o *Options) defaults() {
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LookupEnv == nil {
		o.LookupEnv = os.LookupEnv
	}
}

// failure is a classified error: a stable code, a summary built from a
// Runner-owned template, and the underlying error for the log only.
type failure struct {
	code    v1alpha1.ErrorCode
	summary string
	err     error
}

func (f *failure) Error() string {
	if f.err != nil {
		return fmt.Sprintf("%s: %s: %v", f.code, f.summary, f.err)
	}
	return fmt.Sprintf("%s: %s", f.code, f.summary)
}

func fail(code v1alpha1.ErrorCode, summary string, err error) *failure {
	return &failure{code: code, summary: summary, err: err}
}

// outcome is what a successful reconcile knows about the stored certificate.
type outcome struct {
	action      v1alpha1.ResultAction
	info        *store.Info
	objectRef   string
	storeType   string
	legoOutcome *lego.Outcome
}

// Reconcile runs one job and returns the process exit code.
func Reconcile(ctx context.Context, opts Options) int {
	opts.defaults()
	started := opts.Now().UTC()
	log := opts.Logger

	if opts.ExchangeDir != "" {
		// Claim mode is for a shared transport, on which the Conductor
		// accepts signed Results only: a Runner that could not sign would
		// take jobs and fail every one of them, so it refuses to take any.
		cfg, err := loadConfig(&opts)
		if err != nil {
			log.Error("runner configuration could not be loaded; taking no job", "error", err.Error())
			return ExitNoResult
		}
		if cfg.ResultSigning == nil {
			log.Error("claim mode requires resultSigning in the runner configuration; taking no job")
			return ExitNoResult
		}
		claim, err := exchange.Take(opts.ExchangeDir)
		if err != nil {
			log.Error("cannot take a job from the exchange directory", "error", err.Error())
			return ExitNoResult
		}
		if claim == nil {
			log.Info("no pending job in the exchange directory; nothing to do")
			return ExitSucceeded
		}
		name := opts.ExecutionName
		if name == "" {
			name, _ = opts.LookupEnv(EnvExecutionName)
		}
		if err := claim.MarkExecution(name); err != nil {
			// Without a valid execution name the Conductor can neither
			// observe nor stop this execution; the job is left claimed
			// with no result so the Conductor fails the run.
			log.Error("cannot record the execution name for the claimed job", "runId", claim.RunID, "error", err.Error())
			return ExitNoResult
		}
		log.Info("claimed job", "runId", claim.RunID, "execution", name)
		opts.JobPath, opts.ResultPath = claim.JobPath, claim.ResultPath
	}

	jobData, err := readBounded(opts.JobPath, v1alpha1.MaxSignedDocumentSize+1)
	if err != nil {
		log.Error("cannot read job spec", "error", err.Error())
		return ExitNoResult
	}
	// A signed envelope carries the JobSpec as its payload; the identity
	// is peeked from there so that a Result can name the run even when the
	// envelope fails verification.
	var envelope *v1alpha1.SignedJob
	identityData := jobData
	if v1alpha1.IsSignedJob(jobData) {
		sj, err := v1alpha1.DecodeSignedJob(bytes.NewReader(jobData))
		if err != nil {
			log.Error("signed job envelope rejected and no run identity could be recovered", "error", err.Error())
			return ExitNoResult
		}
		envelope = sj
		identityData = sj.PayloadBytes()
	}
	ids, idsOK := peekIdentity(identityData)
	if idsOK {
		log = log.With("runId", ids.RunID, "targetId", ids.TargetID)
	}

	// The result signer, if any, is loaded with the configuration below;
	// a Result produced before the configuration is known (or when it
	// cannot be loaded) is written bare.
	var resultSigner *ResultSigner
	finish := func(status v1alpha1.ResultStatus, out *outcome, f *failure) int {
		res := buildResult(ids, started, opts.Now().UTC(), status, out, f)
		if err := res.Validate(); err != nil {
			// The template produced something the contract rejects
			// (for example an error text that looked like a secret).
			// Fall back to the generic summary so a Result is always
			// produced.
			if f != nil {
				res.Error = &v1alpha1.ResultError{Code: f.code, Summary: genericSummary(f.code)}
			}
			if err := res.Validate(); err != nil {
				log.Error("result does not satisfy the contract", "error", err.Error())
				return ExitNoResult
			}
		}
		delivered, err := WriteSignedResult(res, resultSigner, opts.ResultPath, opts.Stdout)
		if err != nil {
			// The Result could not be written to the file. If it reached
			// stdout the run's outcome is still reported and the exit code
			// reflects it; only when nothing was delivered is there no
			// Result at all.
			log.Error("cannot write result file", "error", err.Error(), "deliveredOnStdout", delivered)
			if !delivered {
				return ExitNoResult
			}
		}
		if f != nil {
			log.Error("reconcile failed", "code", string(f.code), "summary", f.summary, "cause", causeText(f.err))
			return ExitFailed
		}
		log.Info("reconcile succeeded", "action", string(out.action), "fingerprintSha256", out.info.FingerprintSHA256, "expiresAt", out.info.NotAfter.Format(time.RFC3339), "storeObjectRef", out.objectRef)
		return ExitSucceeded
	}

	// The trusted configuration is needed before an envelope can be
	// verified; a bare JobSpec is decoded first and its configuration
	// failure reported afterwards, as before.
	cfg, cfgErr := loadConfig(&opts)
	if cfgErr == nil && cfg.ResultSigning != nil {
		signer, err := loadResultSigner(cfg.ResultSigning, opts.Now)
		if err != nil {
			// A Runner told to sign its Results must not report unsigned
			// ones: the run fails and, for lack of a key, the failure is
			// reported bare (the Conductor refuses it, which is the point).
			log.Error("result signing key could not be loaded", "error", err.Error())
			if !idsOK {
				return ExitNoResult
			}
			return finish(v1alpha1.StatusFailed, nil, fail(v1alpha1.ErrorCodeInternal, "result signing key could not be loaded", err))
		}
		resultSigner = signer
		log = log.With("resultKeyId", signer.KeyID())
	}

	var spec *v1alpha1.JobSpec
	if envelope != nil {
		if cfgErr != nil {
			if !idsOK {
				log.Error("runner configuration could not be loaded and no run identity could be recovered", "error", cfgErr.Error())
				return ExitNoResult
			}
			return finish(v1alpha1.StatusFailed, nil, fail(v1alpha1.ErrorCodeInternal, "runner configuration could not be loaded", cfgErr))
		}
		var f *failure
		spec, f = unwrapSignedJob(ctx, opts, cfg, envelope)
		if f != nil {
			if !idsOK {
				log.Error("signed job envelope rejected and no run identity could be recovered", "error", f.Error())
				return ExitNoResult
			}
			return finish(v1alpha1.StatusFailed, nil, f)
		}
		log.Info("signed job envelope verified")
	} else {
		if cfgErr == nil && cfg.JobSigning != nil {
			err := errors.New("this runner accepts signed job envelopes only")
			if !idsOK {
				log.Error("unsigned job spec rejected and no run identity could be recovered", "error", err.Error())
				return ExitNoResult
			}
			return finish(v1alpha1.StatusFailed, nil, fail(v1alpha1.ErrorCodeInvalidJobSpec, summarize("unsigned job spec rejected", err), err))
		}
		spec, err = v1alpha1.DecodeJobSpec(bytes.NewReader(jobData))
		if err != nil {
			f := fail(v1alpha1.ErrorCodeInvalidJobSpec, summarize("job spec rejected", err), err)
			if !idsOK {
				log.Error("job spec rejected and no run identity could be recovered", "error", err.Error())
				return ExitNoResult
			}
			return finish(v1alpha1.StatusFailed, nil, f)
		}
	}
	log = log.With("fqdn", spec.Target.FQDN)
	if cfgErr != nil {
		return finish(v1alpha1.StatusFailed, nil, fail(v1alpha1.ErrorCodeInternal, "runner configuration could not be loaded", cfgErr))
	}

	out, f := reconcile(ctx, opts, log, cfg, spec)
	if f != nil {
		return finish(v1alpha1.StatusFailed, nil, f)
	}
	return finish(v1alpha1.StatusSucceeded, out, nil)
}

// loadResultSigner reads the Runner's result-signing key.
func loadResultSigner(rs *config.ResultSigning, now func() time.Time) (*ResultSigner, error) {
	data, err := readBounded(rs.PrivateKeyFile, 16*1024)
	if err != nil {
		return nil, err
	}
	key, err := v1alpha1.ParseSigningPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rs.PrivateKeyFile, err)
	}
	return NewResultSigner(key, time.Duration(rs.ValiditySeconds)*time.Second, now)
}

// unwrapSignedJob verifies an envelope against the trusted keys and the
// clock, records its runId in the replay ledger, and returns the JobSpec
// it carries. Every failure is a rejection of the document, never a
// reason to fall back to the payload unverified.
func unwrapSignedJob(ctx context.Context, opts Options, cfg *config.Config, sj *v1alpha1.SignedJob) (*v1alpha1.JobSpec, *failure) {
	if cfg.JobSigning == nil {
		err := errors.New("this runner has no jobSigning keys configured")
		return nil, fail(v1alpha1.ErrorCodeInvalidJobSpec, summarize("signed job envelope rejected", err), err)
	}
	now := opts.Now().UTC()
	skew := time.Duration(cfg.JobSigning.ClockSkewSeconds) * time.Second
	spec, hdr, err := sj.Verify(cfg.JobSigning.Keys(), v1alpha1.VerifyOptions{Now: now, ClockSkew: skew})
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeInvalidJobSpec, summarize("signed job envelope rejected", err), err)
	}
	if err := recordJob(ctx, cfg.Lego.StateDir, spec.RunID, hdr.ExpiresAt, now, skew); err != nil {
		if errors.Is(err, ErrJobReplayed) {
			return nil, fail(v1alpha1.ErrorCodeInvalidJobSpec, summarize("signed job envelope rejected", err), err)
		}
		return nil, classifyCtx(ctx, fail(v1alpha1.ErrorCodeInternal, "replay ledger could not be updated", err))
	}
	return spec, nil
}

// reconcile performs steps 2-5 and returns either an outcome or a failure.
func reconcile(ctx context.Context, opts Options, log *slog.Logger, cfg *config.Config, spec *v1alpha1.JobSpec) (*outcome, *failure) {
	// Authorization against trusted configuration. This is the check that
	// bounds what any JobSpec, forged or not, can make this Runner do.
	req := policy.AuthorizationRequest{
		FQDN:         spec.Target.FQDN,
		ACMEBinding:  spec.ACME.Binding,
		DNSBinding:   spec.DNS.Binding,
		StoreBinding: spec.Store.Binding,
	}
	if err := cfg.Policy().Authorize(req); err != nil {
		return nil, fail(v1alpha1.ErrorCodePolicyViolation, summarize("runner authorization policy rejected the job", err), err)
	}
	acme, ok := cfg.ACMEBindings[spec.ACME.Binding]
	if !ok {
		return nil, fail(v1alpha1.ErrorCodeBindingNotFound, fmt.Sprintf("acme binding %q is not defined in runner configuration", spec.ACME.Binding), nil)
	}
	dns, ok := cfg.DNSBindings[spec.DNS.Binding]
	if !ok {
		return nil, fail(v1alpha1.ErrorCodeBindingNotFound, fmt.Sprintf("dns binding %q is not defined in runner configuration", spec.DNS.Binding), nil)
	}
	storeBinding, ok := cfg.StoreBindings[spec.Store.Binding]
	if !ok {
		return nil, fail(v1alpha1.ErrorCodeBindingNotFound, fmt.Sprintf("store binding %q is not defined in runner configuration", spec.Store.Binding), nil)
	}
	st, err := opts.Stores.Open(storeBinding)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeStoreFailure, "certificate store could not be opened", err)
	}
	object := st.ObjectName(spec.Target.FQDN)
	log = log.With("storeObjectRef", object, "storeType", st.Type())

	now := opts.Now().UTC()
	current, err := st.Current(ctx, object)
	switch {
	case errors.Is(err, store.ErrNotFound):
		current = nil
		log.Info("no certificate in store; issuing")
	case err != nil:
		return nil, classifyCtx(ctx, fail(v1alpha1.ErrorCodeStoreFailure, "certificate store read failed", err))
	default:
		renewBefore := time.Duration(spec.Policy.RenewBeforeDays) * 24 * time.Hour
		covers := containsFold(current.DNSNames, spec.Target.FQDN)
		valid := !current.NotBefore.After(now.Add(clockSkewTolerance))
		// A policy whose keyType changed takes effect at the target's next
		// run: a stored certificate with another key type is reissued.
		keyOK := current.KeyType == spec.Policy.KeyType
		if covers && valid && keyOK && current.NotAfter.After(now.Add(renewBefore)) {
			log.Info("certificate is current; nothing to do", "fingerprintSha256", current.FingerprintSHA256, "expiresAt", current.NotAfter.Format(time.RFC3339))
			return &outcome{action: v1alpha1.ActionNoop, info: current, objectRef: object, storeType: st.Type()}, nil
		}
		switch {
		case !covers:
			log.Warn("stored certificate does not cover the target; reissuing", "fingerprintSha256", current.FingerprintSHA256)
		case !valid:
			log.Warn("stored certificate is not yet valid; reissuing", "fingerprintSha256", current.FingerprintSHA256, "notBefore", current.NotBefore.Format(time.RFC3339))
		case !keyOK:
			log.Info("stored certificate key type differs from the policy; reissuing", "fingerprintSha256", current.FingerprintSHA256, "storedKeyType", string(current.KeyType), "keyType", string(spec.Policy.KeyType))
		default:
			log.Info("certificate is due for renewal", "fingerprintSha256", current.FingerprintSHA256, "expiresAt", current.NotAfter.Format(time.RFC3339))
		}
	}
	if ctx.Err() != nil {
		return nil, fail(v1alpha1.ErrorCodeCancelled, "run was cancelled before lego started", ctx.Err())
	}

	grace := opts.GracePeriod
	if grace <= 0 {
		grace = lego.DefaultGracePeriod
	}
	// A live run never outlasts the lego timeout plus the grace period
	// plus the surrounding store work; the sweep deadline adds a wide
	// margin on top of that (see staleMargin), so a directory past it is a
	// leftover of a killed process, never a live run.
	staleAfter := 2*time.Duration(cfg.Lego.TimeoutSeconds)*time.Second + grace + staleMargin
	work, cleanup, err := prepareWorkDir(cfg.Lego.WorkDir, spec.RunID, staleAfter)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeInternal, "work directory could not be prepared", err)
	}
	defer cleanup()
	if err := loadAccounts(ctx, cfg.Lego.StateDir, work); err != nil {
		return nil, classifyCtx(ctx, fail(v1alpha1.ErrorCodeInternal, "ACME account state could not be read", err))
	}

	inv, err := lego.Build(lego.Params{
		Binary:    cfg.Lego.Binary,
		WorkDir:   work,
		FQDN:      spec.Target.FQDN,
		KeyType:   spec.Policy.KeyType,
		ACME:      acme,
		DNS:       dns,
		LookupEnv: opts.LookupEnv,
	})
	if err != nil {
		if errors.Is(err, lego.ErrMissingEnv) && strings.Contains(err.Error(), "dns binding") {
			return nil, fail(v1alpha1.ErrorCodeDNSFailure, fmt.Sprintf("dns binding %q requires an environment variable that is not set", spec.DNS.Binding), err)
		}
		if errors.Is(err, lego.ErrMissingEnv) {
			return nil, fail(v1alpha1.ErrorCodeACMEFailure, fmt.Sprintf("acme binding %q requires EAB credentials that are not set", spec.ACME.Binding), err)
		}
		return nil, fail(v1alpha1.ErrorCodeInternal, "lego invocation could not be built", err)
	}
	log.Info("starting lego", "binary", cfg.Lego.Binary, "provider", dns.Provider, "directory", acme.DirectoryURL, "keyType", string(spec.Policy.KeyType))
	exec := &lego.Executor{
		Timeout:     time.Duration(cfg.Lego.TimeoutSeconds) * time.Second,
		Logger:      log,
		GracePeriod: opts.GracePeriod,
	}
	res, err := exec.Run(ctx, inv)
	// Whatever happened, keep the account state lego may have created or
	// updated, so the next run reuses the same ACME account. This runs even
	// after a cancellation (an account registered by the killed lego must
	// not be lost), but with its own bound so it cannot hang.
	persistCtx, cancelPersist := context.WithTimeout(context.WithoutCancel(ctx), persistTimeout)
	if perr := persistAccounts(persistCtx, work, cfg.Lego.StateDir); perr != nil {
		log.Warn("ACME account state could not be persisted", "error", perr.Error())
	}
	cancelPersist()
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeInternal, "lego could not be executed", err)
	}
	switch {
	case res.Cancelled:
		return nil, fail(v1alpha1.ErrorCodeCancelled, "run was cancelled by signal while lego was running", nil)
	case res.TimedOut:
		return nil, fail(v1alpha1.ErrorCodeTimeout, fmt.Sprintf("lego did not finish within %d seconds", cfg.Lego.TimeoutSeconds), nil)
	case res.ExitCode != 0:
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, fmt.Sprintf("lego exited with status %d", res.ExitCode), nil)
	}

	certPEM, keyPEM, issuerPEM, err := lego.ReadOutputs(work, spec.Target.FQDN)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "lego exited successfully but produced no usable certificate", err)
	}
	defer zero(keyPEM)
	leafPEM, chainPEM, err := store.SplitChain(certPEM)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "lego produced an unreadable certificate", err)
	}
	if len(chainPEM) == 0 {
		chainPEM = issuerPEM
	}
	leaf, err := store.ParseLeaf(leafPEM)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "lego produced an unreadable certificate", err)
	}
	if !store.Covers(leaf, spec.Target.FQDN) {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "issued certificate does not cover the target fqdn", nil)
	}
	if err := store.PrivateKeyMatches(leaf, keyPEM); err != nil {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "issued certificate and private key do not match", err)
	}
	if !leaf.NotAfter.After(now) {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "issued certificate is already expired", nil)
	}
	if leaf.NotBefore.After(now.Add(clockSkewTolerance)) {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "issued certificate is not yet valid", nil)
	}
	if len(leaf.DNSNames) != 1 {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "issued certificate does not contain exactly one subject alternative name", nil)
	}
	if err := store.KeyMatchesType(leaf, spec.Policy.KeyType); err != nil {
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, "issued certificate key does not match the requested key type", err)
	}
	info := store.InfoOf(leaf)
	if err := st.Put(ctx, object, store.Bundle{Certificate: leafPEM, Chain: chainPEM, PrivateKey: keyPEM}); err != nil {
		return nil, classifyCtx(ctx, fail(v1alpha1.ErrorCodeStoreFailure, "certificate store write failed", err))
	}
	action := v1alpha1.ActionIssued
	if current != nil {
		action = v1alpha1.ActionRenewed
		if current.FingerprintSHA256 == info.FingerprintSHA256 {
			action = v1alpha1.ActionNoop
		}
	}
	return &outcome{action: action, info: info, objectRef: object, storeType: st.Type(), legoOutcome: res}, nil
}

// loadConfig loads the trusted configuration and has the store registry
// validate every store binding against its provider, so that a binding
// of a type this binary does not provide, or with a configuration its
// provider refuses, is a configuration error and not a run-time surprise.
func loadConfig(opts *Options) (*config.Config, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	if opts.Stores == nil {
		return nil, fmt.Errorf("%w: no store registry", config.ErrInvalid)
	}
	if err := opts.Stores.Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// identity is the minimum needed to address a Result.
type identity struct {
	RunID    string `json:"runId"`
	TargetID string `json:"targetId"`
}

// peekIdentity leniently extracts runId and target.id so that a failed
// Result can be produced even for a JobSpec that fails strict validation.
// It succeeds only if both values are well-formed identifiers.
func peekIdentity(data []byte) (identity, bool) {
	var raw struct {
		RunID  string `json:"runId"`
		Target struct {
			ID string `json:"id"`
		} `json:"target"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return identity{}, false
	}
	probe := v1alpha1.Result{RunID: raw.RunID, TargetID: raw.Target.ID}
	if validateIdentifiers(&probe) != nil {
		return identity{}, false
	}
	return identity{RunID: raw.RunID, TargetID: raw.Target.ID}, true
}

// validateIdentifiers reuses the contract's identifier rules by validating
// a throwaway failed Result.
func validateIdentifiers(r *v1alpha1.Result) error {
	t := time.Unix(0, 0).UTC().Add(time.Second)
	probe := v1alpha1.Result{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileResult,
		RunID: r.RunID, TargetID: r.TargetID,
		Status: v1alpha1.StatusFailed, Action: v1alpha1.ActionFailed,
		StartedAt: t, FinishedAt: t,
		Error: &v1alpha1.ResultError{Code: v1alpha1.ErrorCodeInternal, Summary: "probe"},
	}
	return probe.Validate()
}

func buildResult(ids identity, started, finished time.Time, status v1alpha1.ResultStatus, out *outcome, f *failure) *v1alpha1.Result {
	res := &v1alpha1.Result{
		APIVersion: v1alpha1.APIVersion,
		Kind:       v1alpha1.KindCertificateReconcileResult,
		RunID:      ids.RunID,
		TargetID:   ids.TargetID,
		Status:     status,
		StartedAt:  started,
		FinishedAt: finished,
	}
	if !finished.After(started) {
		res.FinishedAt = started
	}
	if f != nil {
		res.Action = v1alpha1.ActionFailed
		res.Error = &v1alpha1.ResultError{Code: f.code, Summary: f.summary}
		return res
	}
	res.Action = out.action
	exp := out.info.NotAfter
	res.ExpiresAt = &exp
	res.FingerprintSha256 = out.info.FingerprintSHA256
	res.StoreObjectRef = out.objectRef
	return res
}

// summarize builds a one-line summary from a template prefix and an error
// whose text is known to derive from non-secret input (the JobSpec or the
// configuration). It is sanitized and bounded; if it still fails the
// contract, finish() replaces it with genericSummary.
func summarize(prefix string, err error) string {
	if err == nil {
		return prefix
	}
	text := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, err.Error())
	s := prefix + ": " + text
	if len(s) > 512 {
		s = s[:512]
		for len(s) > 0 && (s[len(s)-1]&0xC0) == 0x80 {
			s = s[:len(s)-1] // do not cut a UTF-8 sequence
		}
	}
	return s
}

func genericSummary(code v1alpha1.ErrorCode) string {
	switch code {
	case v1alpha1.ErrorCodeInvalidJobSpec:
		return "job spec rejected by strict validation"
	case v1alpha1.ErrorCodePolicyViolation:
		return "job rejected by runner authorization policy"
	default:
		return "reconcile failed; see runner log"
	}
}

func causeText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func containsFold(names []string, want string) bool {
	for _, n := range names {
		if strings.EqualFold(n, want) {
			return true
		}
	}
	return false
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func readBounded(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, int64(limit)))
}
