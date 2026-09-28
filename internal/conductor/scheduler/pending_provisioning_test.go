package scheduler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// activateScoped gives the fixture target an active account (generation
// 1) of its own, as a completed provisioning would.
func activateScoped(t *testing.T, f *fixture) {
	t.Helper()
	ctx := context.Background()
	requestScopedProvisioning(t, f, f.target.ID, 1)
	if a, _, err := f.reg.ClaimACMEAccountProvisioning(ctx, f.policy.ACMEBinding, f.target.ID, "seed"); err != nil || a == nil {
		t.Fatalf("claim: %v %v", a, err)
	}
	if err := f.reg.CompleteACMEAccountProvisioning(ctx, f.policy.ACMEBinding, f.target.ID, 1, "seed", true, &registry.AuditEvent{Actor: "test", Action: registry.AuditACMEAccountActivated}); err != nil {
		t.Fatal(err)
	}
}

// runWhileInFlight plans and dispatches one run and, while its Runner is
// running (its job already built), calls during; then lets it succeed
// with a certificate far from its renewal window.
func runWhileInFlight(t *testing.T, f *fixture, during func()) {
	t.Helper()
	release := make(chan struct{})
	f.fake.started = make(chan struct{}, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		<-release
		return okResult(f.clock(), spec, v1alpha1.ActionIssued, 90), nil
	}
	ctx := context.Background()
	if n, err := f.s.Plan(ctx); err != nil || n != 1 {
		t.Fatalf("plan: %d %v", n, err)
	}
	if n, err := f.s.Dispatch(ctx); err != nil || n != 1 {
		t.Fatalf("dispatch: %d %v", n, err)
	}
	<-f.fake.started
	f.fake.started = nil
	during()
	close(release)
	f.s.Drain(ctx)
	if run := f.lastRun(t); run.Status != registry.RunSucceeded {
		t.Fatalf("in-flight run = %+v", run)
	}
}

// TestScopedProvisioningSubmittedDuringARunIsCarriedNext is the race of
// issue #59's review: an EAB submitted while the target's run is already
// running is not carried by that run, and after it the certificate is far
// from due; the scheduler must still start a run for the request.
func TestScopedProvisioningSubmittedDuringARunIsCarriedNext(t *testing.T) {
	f := setupScoped(t)
	activateScoped(t, f)
	runWhileInFlight(t, f, func() {
		requestScopedProvisioning(t, f, f.target.ID, 2)
		// While the run is active, nothing more is planned.
		if n, err := f.s.Plan(context.Background()); err != nil || n != 0 {
			t.Fatalf("plan during the run: %d %v", n, err)
		}
	})
	if spec := f.fake.specs[0]; spec.ACME.Account == nil || spec.ACME.Account.Provisioning != nil {
		t.Fatalf("the in-flight run carried %+v", spec.ACME.Account)
	}
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionRenewed, 90)
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Scope: f.target.ID, Generation: 2, Status: v1alpha1.AccountProvisioningRegistered}
		return res, nil
	}
	planned, started := f.cycle(t)
	if planned != 1 || started != 1 {
		t.Fatalf("planned %d started %d; want a run for the pending request", planned, started)
	}
	spec := f.fake.specs[len(f.fake.specs)-1]
	if a := spec.ACME.Account; a == nil || a.Generation != 2 || a.Provisioning == nil || a.Scope != f.target.ID {
		t.Fatalf("spec.ACME.Account = %+v", spec.ACME.Account)
	}
	if g, _ := f.reg.ActiveACMEAccountGeneration(context.Background(), f.policy.ACMEBinding, f.target.ID); g != 2 {
		t.Fatalf("active generation = %d, want 2", g)
	}
	// Nothing is pending any more: the certificate is current, so no run.
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatalf("planned %d after the request was carried", planned)
	}
}

func TestBindingProvisioningSubmittedDuringARunIsCarriedNext(t *testing.T) {
	f := setup(t, 1)
	runWhileInFlight(t, f, func() { requestProvisioning(t, f, 1) })
	if spec := f.fake.specs[0]; spec.ACME.Account != nil {
		t.Fatalf("the in-flight run carried %+v", spec.ACME.Account)
	}
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		res := okResult(f.clock(), spec, v1alpha1.ActionRenewed, 90)
		res.AccountProvisioning = &v1alpha1.AccountProvisioningResult{Binding: f.policy.ACMEBinding, Generation: 1, Status: v1alpha1.AccountProvisioningRegistered}
		return res, nil
	}
	planned, started := f.cycle(t)
	if planned != 1 || started != 1 {
		t.Fatalf("planned %d started %d; want a run for the pending request", planned, started)
	}
	if a := f.fake.specs[len(f.fake.specs)-1].ACME.Account; a == nil || a.Generation != 1 || a.Provisioning == nil {
		t.Fatalf("spec.ACME.Account = %+v", a)
	}
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatalf("planned %d after the request was carried", planned)
	}
}

func TestBindingProvisioningPicksOneTargetAndWaitsForAQueuedRun(t *testing.T) {
	f := setup(t, 2)
	ctx := context.Background()
	other := &registry.Target{FQDN: "other.example.ac.jp", Enabled: true, Owner: "web", PolicyRef: f.policy.ID, ExecutionBinding: "local", DNSBinding: "fake-dns", StoreBinding: "filesystem-dev"}
	if err := f.reg.CreateTarget(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	// Both targets reconciled, far from due; the fixture target's
	// certificate expires sooner.
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		days := 90
		if spec.Target.ID == f.target.ID {
			days = 80
		}
		return okResult(f.clock(), spec, v1alpha1.ActionIssued, days), nil
	}
	f.cycle(t)
	requestProvisioning(t, f, 1)
	// Exactly one run, for the target that expires sooner, and a second
	// plan while it is queued adds none.
	if n, err := f.s.Plan(ctx); err != nil || n != 1 {
		t.Fatalf("plan: %d %v", n, err)
	}
	if n, err := f.s.Plan(ctx); err != nil || n != 0 {
		t.Fatalf("second plan while queued: %d %v", n, err)
	}
	if run := f.lastRun(t); run.Status != registry.RunQueued || !strings.Contains(run.RequestedBy, "scheduler") {
		t.Fatalf("run = %+v", run)
	}
}

func TestPendingProvisioningKeepsBackoffOfLaterFailures(t *testing.T) {
	f := setupScoped(t)
	activateScoped(t, f)
	f.cycle(t) // reconciled, far from due
	requestScopedProvisioning(t, f, f.target.ID, 2)
	// The run for the request cannot reach a Runner: the request is
	// released and stays pending.
	f.fake.startErr = errors.New("launcher down")
	if planned, _ := f.cycle(t); planned != 1 {
		t.Fatalf("planned %d, want the provisioning run", planned)
	}
	if run := f.lastRun(t); run.Status != registry.RunFailed {
		t.Fatalf("run = %+v", run)
	}
	// That failure came after the request: its backoff holds.
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatalf("planned %d inside the backoff of a failure after the request", planned)
	}
	f.fake.startErr = nil
	f.advance(6 * time.Minute)
	if planned, _ := f.cycle(t); planned != 1 {
		t.Fatalf("planned %d after the backoff", planned)
	}
	if a := f.fake.specs[len(f.fake.specs)-1].ACME.Account; a == nil || a.Generation != 2 || a.Provisioning == nil {
		t.Fatalf("spec.ACME.Account = %+v", a)
	}
}
