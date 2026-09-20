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
	"path/filepath"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/internal/runner/lego"
	"github.com/CITS-NUE/acme-conductor/internal/store"
	"github.com/CITS-NUE/acme-conductor/internal/store/filesystem"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

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

	jobData, err := readBounded(opts.JobPath, v1alpha1.MaxDocumentSize+1)
	if err != nil {
		log.Error("cannot read job spec", "error", err.Error())
		return ExitNoResult
	}
	ids, idsOK := peekIdentity(jobData)
	if idsOK {
		log = log.With("runId", ids.RunID, "targetId", ids.TargetID)
	}

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
		if err := WriteResult(res, opts.ResultPath, opts.Stdout); err != nil {
			log.Error("cannot write result", "error", err.Error())
			return ExitNoResult
		}
		if f != nil {
			log.Error("reconcile failed", "code", string(f.code), "summary", f.summary, "cause", causeText(f.err))
			return ExitFailed
		}
		log.Info("reconcile succeeded", "action", string(out.action), "fingerprintSha256", out.info.FingerprintSHA256, "expiresAt", out.info.NotAfter.Format(time.RFC3339), "storeObjectRef", out.objectRef)
		return ExitSucceeded
	}

	spec, err := v1alpha1.DecodeJobSpec(bytes.NewReader(jobData))
	if err != nil {
		f := fail(v1alpha1.ErrorCodeInvalidJobSpec, summarize("job spec rejected", err), err)
		if !idsOK {
			log.Error("job spec rejected and no run identity could be recovered", "error", err.Error())
			return ExitNoResult
		}
		return finish(v1alpha1.StatusFailed, nil, f)
	}
	log = log.With("fqdn", spec.Target.FQDN)

	out, f := reconcile(ctx, opts, log, spec)
	if f != nil {
		return finish(v1alpha1.StatusFailed, nil, f)
	}
	return finish(v1alpha1.StatusSucceeded, out, nil)
}

// reconcile performs steps 2-5 and returns either an outcome or a failure.
func reconcile(ctx context.Context, opts Options, log *slog.Logger, spec *v1alpha1.JobSpec) (*outcome, *failure) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeInternal, "runner configuration could not be loaded", err)
	}

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
	st, err := openStore(storeBinding)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeStoreFailure, "certificate store could not be opened", err)
	}
	object := store.ObjectName(spec.Target.FQDN)
	log = log.With("storeObjectRef", object, "storeType", st.Type())

	now := opts.Now().UTC()
	current, err := st.Current(ctx, object)
	switch {
	case errors.Is(err, store.ErrNotFound):
		current = nil
		log.Info("no certificate in store; issuing")
	case err != nil:
		return nil, fail(v1alpha1.ErrorCodeStoreFailure, "certificate store read failed", err)
	default:
		renewBefore := time.Duration(spec.Policy.RenewBeforeDays) * 24 * time.Hour
		covers := containsFold(current.DNSNames, spec.Target.FQDN)
		valid := !current.NotBefore.After(now.Add(clockSkewTolerance))
		if covers && valid && current.NotAfter.After(now.Add(renewBefore)) {
			log.Info("certificate is current; nothing to do", "fingerprintSha256", current.FingerprintSHA256, "expiresAt", current.NotAfter.Format(time.RFC3339))
			return &outcome{action: v1alpha1.ActionNoop, info: current, objectRef: object, storeType: st.Type()}, nil
		}
		switch {
		case !covers:
			log.Warn("stored certificate does not cover the target; reissuing", "fingerprintSha256", current.FingerprintSHA256)
		case !valid:
			log.Warn("stored certificate is not yet valid; reissuing", "fingerprintSha256", current.FingerprintSHA256, "notBefore", current.NotBefore.Format(time.RFC3339))
		default:
			log.Info("certificate is due for renewal", "fingerprintSha256", current.FingerprintSHA256, "expiresAt", current.NotAfter.Format(time.RFC3339))
		}
	}
	if ctx.Err() != nil {
		return nil, fail(v1alpha1.ErrorCodeCancelled, "run was cancelled before lego started", ctx.Err())
	}

	// A live run never outlasts twice the lego timeout; older per-run
	// directories are leftovers of a killed process.
	staleAfter := 2 * time.Duration(cfg.Lego.TimeoutSeconds) * time.Second
	work, cleanup, err := prepareWorkDir(cfg.Lego.WorkDir, spec.RunID, staleAfter)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeInternal, "work directory could not be prepared", err)
	}
	defer cleanup()
	if err := copyTree(filepath.Join(cfg.Lego.StateDir, lego.AccountsDir), filepath.Join(work, lego.AccountsDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fail(v1alpha1.ErrorCodeInternal, "ACME account state could not be read", err)
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
	// updated, so the next run reuses the same ACME account.
	if perr := persistAccounts(work, cfg.Lego.StateDir); perr != nil {
		log.Warn("ACME account state could not be persisted", "error", perr.Error())
	}
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
	info := store.InfoOf(leaf)
	if err := st.Put(ctx, object, store.Bundle{Certificate: leafPEM, Chain: chainPEM, PrivateKey: keyPEM}); err != nil {
		return nil, fail(v1alpha1.ErrorCodeStoreFailure, "certificate store write failed", err)
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

func openStore(b config.StoreBinding) (store.Store, error) {
	switch b.Type {
	case config.StoreTypeFilesystem:
		return filesystem.New(b.Directory)
	default:
		return nil, fmt.Errorf("unsupported store type %q", b.Type)
	}
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
