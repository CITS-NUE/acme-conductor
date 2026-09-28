package scheduler

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

// setupScoped is setup with the fixture's binding keeping one account per
// target.
func setupScoped(t *testing.T) *fixture {
	t.Helper()
	f := setup(t, 1)
	f.s = New(Options{
		Registry: f.reg, Launchers: map[string]launcher.Launcher{"local": f.fake},
		Tick: 10 * time.Millisecond, MaxConcurrentRuns: 1,
		RetryBackoff: 5 * time.Minute, MaxRetryBackoff: 6 * time.Hour, Now: f.clock,
		ProvisioningBindings: []string{"fake-ca"}, TargetScopedBindings: []string{"fake-ca"},
	})
	return f
}

func requestScopedProvisioning(t *testing.T, f *fixture, scope string, generation int64) {
	t.Helper()
	runnerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := v1alpha1.SealScopedProvisioning(runnerPriv.PublicKey(), f.policy.ACMEBinding, scope, generation, v1alpha1.ProvisioningEAB{KID: "test-kid", HMAC: "dGVzdC1obWFj"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	a := &registry.ACMEAccount{Binding: f.policy.ACMEBinding, Scope: scope, Generation: generation, KeyID: sealed.KeyID, RequestedBy: "alice", RequestedByAuthority: "https://idp.example/v2.0"}
	if err := f.reg.RequestACMEAccountProvisioning(context.Background(), a, string(data), nil); err != nil {
		t.Fatalf("request provisioning: %v", err)
	}
}

func TestScopedAccountWithoutAccountFails(t *testing.T) {
	f := setupScoped(t)
	// Even with the binding's own account active, a target of a
	// target-scoped binding needs its own.
	requestProvisioning(t, f, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		t.Fatalf("runner started for a target without an account: %+v", spec.ACME)
		return nil, nil
	}
	f.cycle(t)
	run := f.lastRun(t)
	if run.Status != registry.RunFailed || run.ErrorCode != v1alpha1.ErrorCodeACMEFailure || !strings.Contains(run.ErrorSummary, "keeps one account per target") {
		t.Fatalf("run = %+v", run)
	}
	// The binding's own pending request was never claimed.
	list, _ := f.reg.ListACMEAccounts(context.Background(), f.policy.ACMEBinding, "")
	if len(list) != 1 || list[0].RunID != "" || list[0].Status != registry.ACMEAccountProvisioning {
		t.Fatalf("binding account = %+v", list)
	}
}

func TestScopedAccountClaimedActivatedAndReused(t *testing.T) {
	f := setupScoped(t)
	requestScopedProvisioning(t, f, f.target.ID, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionIssued, 90)
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Scope: f.target.ID, Generation: 1, Status: v1alpha1.AccountProvisioningRegistered}
		return res, nil
	}
	f.cycle(t)
	spec := f.fake.specs[0]
	if a := spec.ACME.Account; a == nil || a.Scope != f.target.ID || a.Generation != 1 || a.Provisioning == nil || a.Provisioning.Version != v1alpha1.ProvisioningVersionScoped {
		t.Fatalf("spec.ACME.Account = %+v", spec.ACME.Account)
	}
	if run := f.lastRun(t); run.Status != registry.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}
	if g, err := f.reg.ActiveACMEAccountGeneration(context.Background(), f.policy.ACMEBinding, f.target.ID); err != nil || g != 1 {
		t.Fatalf("target's active generation = %d, %v", g, err)
	}
	if g, _ := f.reg.ActiveACMEAccountGeneration(context.Background(), f.policy.ACMEBinding, ""); g != 0 {
		t.Fatalf("binding's own account activated: %d", g)
	}

	// The next run uses the target's active generation, without a payload.
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		return okResult(f.clock(), spec, v1alpha1.ActionRenewed, 90), nil
	}
	f.target.Owner = "other"
	if err := f.reg.UpdateTarget(context.Background(), f.target, f.target.Revision, nil); err != nil {
		t.Fatal(err)
	}
	f.cycle(t)
	spec = f.fake.specs[len(f.fake.specs)-1]
	if a := spec.ACME.Account; a == nil || a.Scope != f.target.ID || a.Generation != 1 || a.Provisioning != nil {
		t.Fatalf("second spec.ACME.Account = %+v", spec.ACME.Account)
	}
}

func TestScopedAccountResultForAnotherScopeBurnsGeneration(t *testing.T) {
	f := setupScoped(t)
	requestScopedProvisioning(t, f, f.target.ID, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionIssued, 90)
		// Right binding and generation, but reported unscoped.
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Generation: 1, Status: v1alpha1.AccountProvisioningRegistered}
		return res, nil
	}
	f.cycle(t)
	list, err := f.reg.ListACMEAccounts(context.Background(), f.policy.ACMEBinding, f.target.ID)
	if err != nil || len(list) != 1 || list[0].Status != registry.ACMEAccountFailed {
		t.Fatalf("target account = %+v, %v", list, err)
	}
}
