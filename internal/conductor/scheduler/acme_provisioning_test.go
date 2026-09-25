package scheduler

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"sync"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// requestProvisioning records a pending generation for f.policy.ACMEBinding
// (fixture setup uses "fake-ca"), with a well-formed (if not decryptable
// by anyone in this test) SealedProvisioning payload: the scheduler and
// spec.Validate() only check its shape, never its plaintext.
func requestProvisioning(t *testing.T, f *fixture, generation int64) {
	t.Helper()
	runnerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := v1alpha1.SealProvisioning(runnerPriv.PublicKey(), f.policy.ACMEBinding, generation, v1alpha1.ProvisioningEAB{KID: "test-kid", HMAC: "dGVzdC1obWFj"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	a := &registry.ACMEAccount{Binding: f.policy.ACMEBinding, Generation: generation, KeyID: sealed.KeyID, RequestedBy: "alice", RequestedByAuthority: "https://idp.example/v2.0"}
	if err := f.reg.RequestACMEAccountProvisioning(context.Background(), a, string(data), nil); err != nil {
		t.Fatalf("request provisioning: %v", err)
	}
}

func TestACMEProvisioningClaimedAndActivated(t *testing.T) {
	f := setup(t, 1)
	requestProvisioning(t, f, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionIssued, 90)
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Generation: 1, Status: v1alpha1.AccountProvisioningRegistered}
		return res, nil
	}
	planned, started := f.cycle(t)
	if planned != 1 || started != 1 {
		t.Fatalf("planned %d started %d", planned, started)
	}
	spec := f.fake.specs[0]
	if spec.ACME.Account == nil || spec.ACME.Account.Generation != 1 || spec.ACME.Account.Provisioning == nil {
		t.Fatalf("spec.ACME.Account = %+v", spec.ACME.Account)
	}
	run := f.lastRun(t)
	if run.Status != registry.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}
	active, err := f.reg.ActiveACMEAccountGeneration(context.Background(), f.policy.ACMEBinding)
	if err != nil || active != 1 {
		t.Fatalf("active generation = %d %v", active, err)
	}
	list, err := f.reg.ListACMEAccounts(context.Background(), f.policy.ACMEBinding)
	if err != nil || len(list) != 1 || list[0].Status != registry.ACMEAccountActive || list[0].RunID != "" {
		t.Fatalf("list = %+v %v", list, err)
	}
}

func TestACMEProvisioningNextRunUsesActiveGeneration(t *testing.T) {
	f := setup(t, 1)
	requestProvisioning(t, f, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionIssued, 1)
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Generation: 1, Status: v1alpha1.AccountProvisioningRegistered}
		return res, nil
	}
	f.cycle(t)
	// Force the target due again without a new provisioning request.
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		return okResult(f.clock(), spec, v1alpha1.ActionRenewed, 90), nil
	}
	f.target.Owner = "other"
	if err := f.reg.UpdateTarget(context.Background(), f.target, f.target.Revision, nil); err != nil {
		t.Fatal(err)
	}
	planned, started := f.cycle(t)
	if planned != 1 || started != 1 {
		t.Fatalf("planned %d started %d", planned, started)
	}
	spec := f.fake.specs[len(f.fake.specs)-1]
	if spec.ACME.Account == nil || spec.ACME.Account.Generation != 1 || spec.ACME.Account.Provisioning != nil {
		t.Fatalf("spec.ACME.Account = %+v", spec.ACME.Account)
	}
}

func TestACMEProvisioningFailedResultBurnsGeneration(t *testing.T) {
	f := setup(t, 1)
	requestProvisioning(t, f, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionIssued, 90)
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Generation: 1, Status: v1alpha1.AccountProvisioningFailed}
		return res, nil
	}
	f.cycle(t)
	list, err := f.reg.ListACMEAccounts(context.Background(), f.policy.ACMEBinding)
	if err != nil || len(list) != 1 || list[0].Status != registry.ACMEAccountFailed {
		t.Fatalf("list = %+v %v", list, err)
	}
	active, _ := f.reg.ActiveACMEAccountGeneration(context.Background(), f.policy.ACMEBinding)
	if active != 0 {
		t.Fatalf("active generation = %d", active)
	}
}

func TestACMEProvisioningNoResultCompletesFailed(t *testing.T) {
	f := setup(t, 1)
	requestProvisioning(t, f, 1)
	f.fake.respond = func(context.Context, *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		return nil, errNoResultTest{}
	}
	f.cycle(t)
	list, err := f.reg.ListACMEAccounts(context.Background(), f.policy.ACMEBinding)
	if err != nil || len(list) != 1 || list[0].Status != registry.ACMEAccountFailed || list[0].RunID != "" {
		t.Fatalf("list = %+v %v", list, err)
	}
}

// errNoResultTest is a plain error (not a *launcher.Error): the scheduler
// treats any Wait error as "no result", whatever its reason.
type errNoResultTest struct{}

func (errNoResultTest) Error() string { return "no result" }

func TestACMEProvisioningResultWithoutAccountProvisioningIsReleased(t *testing.T) {
	f := setup(t, 1)
	requestProvisioning(t, f, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		// A result that never carries AccountProvisioning: the Runner
		// never reached the provisioning step.
		return okResult(f.clock(), spec, v1alpha1.ActionIssued, 90), nil
	}
	f.cycle(t)
	list, err := f.reg.ListACMEAccounts(context.Background(), f.policy.ACMEBinding)
	if err != nil || len(list) != 1 || list[0].Status != registry.ACMEAccountProvisioning || list[0].RunID != "" {
		t.Fatalf("list = %+v %v", list, err)
	}
	// Still claimable: the generation was not burnt.
	claimed, _, err := f.reg.ClaimACMEAccountProvisioning(context.Background(), f.policy.ACMEBinding, "another-run")
	if err != nil || claimed == nil {
		t.Fatalf("reclaim: %+v %v", claimed, err)
	}
}

// TestACMEProvisioningOnlyOneRunCarriesPayload dispatches two runs sharing
// the same ACME binding concurrently; only one of them may claim (and
// carry) the pending provisioning payload.
func TestACMEProvisioningOnlyOneRunCarriesPayload(t *testing.T) {
	f := setup(t, 2)
	requestProvisioning(t, f, 1)
	target2 := &registry.Target{FQDN: "second.example.ac.jp", Enabled: true, Owner: "web", PolicyRef: f.policy.ID, ExecutionBinding: "local", DNSBinding: "fake-dns", StoreBinding: "filesystem-dev"}
	if err := f.reg.CreateTarget(context.Background(), target2, nil); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	carriers := 0
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		if spec.ACME.Account != nil && spec.ACME.Account.Provisioning != nil {
			mu.Lock()
			carriers++
			mu.Unlock()
		}
		res := okResult(f.clock(), spec, v1alpha1.ActionIssued, 90)
		if spec.ACME.Account != nil && spec.ACME.Account.Provisioning != nil {
			res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Generation: spec.ACME.Account.Generation, Status: v1alpha1.AccountProvisioningRegistered}
		}
		return res, nil
	}
	planned, started := f.cycle(t)
	if planned != 2 || started != 2 {
		t.Fatalf("planned %d started %d", planned, started)
	}
	if carriers != 1 {
		t.Fatalf("carriers = %d, want exactly 1", carriers)
	}
}

func TestACMEProvisioningMismatchedResultNeverActivates(t *testing.T) {
	f := setup(t, 1)
	requestProvisioning(t, f, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionIssued, 90)
		// "Registered", but for a generation this run was never sent.
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Generation: 2, Status: v1alpha1.AccountProvisioningRegistered}
		return res, nil
	}
	f.cycle(t)
	list, err := f.reg.ListACMEAccounts(context.Background(), f.policy.ACMEBinding)
	if err != nil || len(list) != 1 || list[0].Status != registry.ACMEAccountFailed || list[0].RunID != "" {
		t.Fatalf("list = %+v %v", list, err)
	}
	active, _ := f.reg.ActiveACMEAccountGeneration(context.Background(), f.policy.ACMEBinding)
	if active != 0 {
		t.Fatalf("active generation = %d", active)
	}
}
