package scheduler

import (
	"context"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// issueScoped gives the fixture's target its own active account
// (generation 1) and a certificate, then disables it.
func issueScoped(t *testing.T, f *fixture) {
	t.Helper()
	requestScopedProvisioning(t, f, f.target.ID, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionIssued, 90)
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Scope: f.target.ID, Generation: 1, Status: v1alpha1.AccountProvisioningRegistered}
		return res, nil
	}
	f.cycle(t)
	f.target.Enabled = false
	if err := f.reg.UpdateTarget(context.Background(), f.target, f.target.Revision, nil); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) requestRevocation(t *testing.T) *registry.Run {
	t.Helper()
	r := &registry.Run{TargetID: f.target.ID, TargetRevision: f.target.Revision, RequestedBy: "operator",
		Operation: v1alpha1.OperationRevoke, RevocationReason: 5, RevocationFingerprint: strings.Repeat("0123456789abcdef", 4)}
	if err := f.reg.CreateRun(context.Background(), r, nil); err != nil {
		t.Fatal(err)
	}
	return r
}

// A revocation runs for a disabled target, through the target's active
// account and never with a pending provisioning (docs/adr/0029).
func TestRevocationRunsForDisabledTarget(t *testing.T) {
	f := setupScoped(t)
	issueScoped(t, f)
	// A pending request for generation 2 is not claimed by a revocation.
	requestScopedProvisioning(t, f, f.target.ID, 2)
	r := f.requestRevocation(t)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionRevoked, 60)
		res.FingerprintSha256 = spec.Revocation.FingerprintSha256
		return res, nil
	}
	before := len(f.fake.specs)
	if _, err := f.s.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.s.Drain(context.Background())
	if len(f.fake.specs) != before+1 {
		t.Fatalf("revocation not launched (%d specs)", len(f.fake.specs))
	}
	spec := f.fake.specs[len(f.fake.specs)-1]
	if spec.Operation != v1alpha1.OperationRevoke || spec.Revocation == nil || spec.Revocation.Reason != 5 || spec.Revocation.FingerprintSha256 != r.RevocationFingerprint {
		t.Fatalf("spec = %+v / %+v", spec.Operation, spec.Revocation)
	}
	if a := spec.ACME.Account; a == nil || a.Scope != f.target.ID || a.Generation != 1 || a.Provisioning != nil {
		t.Fatalf("spec.ACME.Account = %+v", spec.ACME.Account)
	}
	if got := f.lastRun(t); got.ID != r.ID || got.Status != registry.RunSucceeded || got.Action != v1alpha1.ActionRevoked {
		t.Fatalf("run = %+v", got)
	}
	list, _ := f.reg.ListACMEAccounts(context.Background(), f.policy.ACMEBinding, f.target.ID)
	for _, a := range list {
		if a.Generation == 2 && (a.RunID != "" || a.Status != registry.ACMEAccountProvisioning) {
			t.Fatalf("pending generation claimed by a revocation: %+v", a)
		}
	}
	// A revocation is never planned on its own.
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatalf("planned %d", planned)
	}
}

func TestRevocationCancelledWhenTargetEnabled(t *testing.T) {
	f := setupScoped(t)
	issueScoped(t, f)
	r := f.requestRevocation(t)
	// Enabled again before the revocation started: it must not reach
	// the Runner.
	f.target.Enabled = true
	if err := f.reg.UpdateTarget(context.Background(), f.target, f.target.Revision, nil); err != nil {
		t.Fatal(err)
	}
	before := len(f.fake.specs)
	if _, err := f.s.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.s.Drain(context.Background())
	if got := f.lastRun(t); got.ID != r.ID || got.Status != registry.RunCancelled || !strings.Contains(got.ErrorSummary, "enabled") || len(f.fake.specs) != before {
		t.Fatalf("run = %+v (specs %d)", got, len(f.fake.specs))
	}
}

func TestRevocationWithoutAccountFails(t *testing.T) {
	f := setupScoped(t)
	f.target.Enabled = false
	if err := f.reg.UpdateTarget(context.Background(), f.target, f.target.Revision, nil); err != nil {
		t.Fatal(err)
	}
	f.requestRevocation(t)
	if _, err := f.s.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.s.Drain(context.Background())
	if got := f.lastRun(t); got.Status != registry.RunFailed || got.ErrorCode != v1alpha1.ErrorCodeACMEFailure || !strings.Contains(got.ErrorSummary, "none to revoke with") {
		t.Fatalf("run = %+v", got)
	}
}
