package runner

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/internal/runner/lego"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
	"github.com/CITS-NUE/acme-conductor/pkg/store"
)

// revokeEnv is what reconcile has resolved for the job before it hands a
// revocation over to revokeStored.
type revokeEnv struct {
	acme        config.ACMEBinding
	account     *v1alpha1.ACMEAccountRef
	accountRoot string
	store       store.Store
	object      string
}

// revokeStored carries out a revocation job (docs/adr/0029): it revokes
// the certificate in the store, which must be exactly the one the job
// names, through the ACME account that renews it. The store is left as it
// is. The job has passed the same authorization as a reconcile; the ACME
// binding must in addition allow revocation.
func revokeStored(ctx context.Context, opts Options, log *slog.Logger, cfg *config.Config, spec *v1alpha1.JobSpec, env revokeEnv) (*outcome, *failure) {
	rev := spec.Revocation
	log = log.With("operation", string(v1alpha1.OperationRevoke), "revocationReason", rev.Reason)
	if !env.acme.AllowRevocation {
		err := fmt.Errorf("acme binding %q does not set allowRevocation", spec.ACME.Binding)
		return nil, fail(v1alpha1.ErrorCodePolicyViolation, fmt.Sprintf("acme binding %q does not allow revocation on this runner", spec.ACME.Binding), err)
	}
	current, err := env.store.Current(ctx, env.object)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, fail(v1alpha1.ErrorCodeStoreFailure, "the store holds no certificate to revoke", err)
	case err != nil:
		return nil, classifyCtx(ctx, fail(v1alpha1.ErrorCodeStoreFailure, "certificate store read failed", err))
	}
	if current.FingerprintSHA256 != rev.FingerprintSha256 {
		// The store holds another certificate than the one the Conductor
		// asked to revoke (a later issuance, or a forged job): revoking it
		// would take down a certificate nobody asked about.
		log.Warn("stored certificate is not the one the job asks to revoke; nothing revoked", "fingerprintSha256", current.FingerprintSHA256, "requestedFingerprintSha256", rev.FingerprintSha256)
		return nil, fail(v1alpha1.ErrorCodeInvalidJobSpec, "the certificate in the store is not the one the job asks to revoke", nil)
	}
	if len(current.Certificate) == 0 {
		return nil, fail(v1alpha1.ErrorCodeStoreFailure, "the store did not return the certificate to revoke", nil)
	}
	if ctx.Err() != nil {
		return nil, fail(v1alpha1.ErrorCodeCancelled, "run was cancelled before lego started", ctx.Err())
	}

	grace := opts.GracePeriod
	if grace <= 0 {
		grace = lego.DefaultGracePeriod
	}
	staleAfter := 2*time.Duration(cfg.Lego.TimeoutSeconds)*time.Second + grace + staleMargin
	work, cleanup, err := prepareWorkDir(cfg.Lego.WorkDir, spec.RunID, staleAfter)
	if err != nil {
		return nil, fail(v1alpha1.ErrorCodeInternal, "work directory could not be prepared", err)
	}
	defer cleanup()
	if err := loadAccounts(ctx, env.accountRoot, work); err != nil {
		return nil, classifyCtx(ctx, fail(v1alpha1.ErrorCodeInternal, "ACME account state could not be read", err))
	}
	// The account must already be registered, as for a renewal: lego
	// would otherwise generate (and the persist below publish) a fresh
	// account key before finding that it is not. A generation is then used
	// without an EAB; the legacy account uses the binding's EAB, if any.
	if !accountRegistered(work) {
		if env.account == nil {
			return nil, fail(v1alpha1.ErrorCodeACMEFailure, fmt.Sprintf("acme binding %q has no registered account on this runner", spec.ACME.Binding), nil)
		}
		err := fmt.Errorf("acme account generation %d of binding %q has no registered account on this runner", env.account.Generation, spec.ACME.Binding)
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, fmt.Sprintf("acme account generation %d of binding %q is not provisioned on this runner", env.account.Generation, spec.ACME.Binding), err)
	}
	disableEAB := env.account != nil
	certPath, _, _ := lego.OutputFiles(work, spec.Target.FQDN)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, fail(v1alpha1.ErrorCodeInternal, "work directory could not be prepared", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: current.Certificate}), 0o600); err != nil {
		return nil, fail(v1alpha1.ErrorCodeInternal, "work directory could not be prepared", err)
	}

	inv, err := lego.BuildRevoke(lego.Params{
		Binary:     cfg.Lego.Binary,
		WorkDir:    work,
		FQDN:       spec.Target.FQDN,
		KeyType:    spec.Policy.KeyType,
		ACME:       env.acme,
		LookupEnv:  opts.LookupEnv,
		DisableEAB: disableEAB,
	}, rev.Reason)
	if err != nil {
		if errors.Is(err, lego.ErrMissingEnv) {
			return nil, fail(v1alpha1.ErrorCodeACMEFailure, fmt.Sprintf("acme binding %q requires EAB credentials that are not set", spec.ACME.Binding), err)
		}
		return nil, fail(v1alpha1.ErrorCodeInternal, "lego invocation could not be built", err)
	}
	log.Info("starting lego to revoke the stored certificate", "binary", cfg.Lego.Binary, "directory", env.acme.DirectoryURL, "fingerprintSha256", current.FingerprintSHA256)
	exec := &lego.Executor{
		Timeout:     time.Duration(cfg.Lego.TimeoutSeconds) * time.Second,
		Logger:      log,
		GracePeriod: opts.GracePeriod,
	}
	res, err := exec.Run(ctx, inv)
	// lego may have refreshed the account (registration recovery); keep it
	// exactly as a reconcile does.
	persistCtx, cancelPersist := context.WithTimeout(context.WithoutCancel(ctx), persistTimeout)
	if perr := persistAccounts(persistCtx, work, env.accountRoot); perr != nil {
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
	case res.ExitCode != 0 && res.Failure == lego.FailureAlreadyRevoked:
		log.Info("the CA reports the certificate as already revoked", "fingerprintSha256", current.FingerprintSHA256)
	case res.ExitCode != 0:
		return nil, fail(v1alpha1.ErrorCodeACMEFailure, fmt.Sprintf("lego could not revoke the certificate (exit status %d)", res.ExitCode), nil)
	default:
		log.Info("certificate revoked", "fingerprintSha256", current.FingerprintSHA256)
	}
	return &outcome{action: v1alpha1.ActionRevoked, info: current, objectRef: env.object, storeType: env.store.Type(), legoOutcome: res}, nil
}
