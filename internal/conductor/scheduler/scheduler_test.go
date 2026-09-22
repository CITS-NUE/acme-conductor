package scheduler

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// fakeLauncher answers every Start with a scripted behaviour.
type fakeLauncher struct {
	mu       sync.Mutex
	startErr error
	// respond decides the outcome; it receives the run context so it can
	// block until cancelled.
	respond func(ctx context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error)
	specs   []*v1alpha1.JobSpec
	started chan struct{}
}

func (f *fakeLauncher) Type() string { return "fake" }

func (f *fakeLauncher) Start(ctx context.Context, spec *v1alpha1.JobSpec) (launcher.Execution, error) {
	f.mu.Lock()
	f.specs = append(f.specs, spec)
	f.mu.Unlock()
	if f.startErr != nil {
		return nil, f.startErr
	}
	if f.started != nil {
		f.started <- struct{}{}
	}
	return &fakeExec{ctx: ctx, spec: spec, respond: f.respond}, nil
}

type fakeExec struct {
	ctx     context.Context
	spec    *v1alpha1.JobSpec
	respond func(ctx context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error)
}

func (e *fakeExec) ID() string { return "fake:" + e.spec.RunID }
func (e *fakeExec) Wait() (*v1alpha1.Result, error) {
	return e.respond(e.ctx, e.spec)
}

func okResult(spec *v1alpha1.JobSpec, action v1alpha1.ResultAction, days int) *v1alpha1.Result {
	now := time.Now().UTC()
	exp := now.Add(time.Duration(days) * 24 * time.Hour)
	return &v1alpha1.Result{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileResult,
		RunID: spec.RunID, TargetID: spec.Target.ID, Status: v1alpha1.StatusSucceeded, Action: action,
		ExpiresAt: &exp, FingerprintSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		StoreObjectRef: "wiki.example.ac.jp-0123456789abcdef", StartedAt: now, FinishedAt: now.Add(time.Second),
	}
}

func failResult(spec *v1alpha1.JobSpec, code v1alpha1.ErrorCode, summary string) *v1alpha1.Result {
	now := time.Now().UTC()
	return &v1alpha1.Result{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileResult,
		RunID: spec.RunID, TargetID: spec.Target.ID, Status: v1alpha1.StatusFailed, Action: v1alpha1.ActionFailed,
		StartedAt: now, FinishedAt: now.Add(time.Second), Error: &v1alpha1.ResultError{Code: code, Summary: summary},
	}
}

type fixture struct {
	reg    *sqlite.DB
	fake   *fakeLauncher
	s      *Scheduler
	policy *registry.Policy
	target *registry.Target
	now    time.Time
	mu     sync.Mutex
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func setup(t *testing.T, maxRuns int) *fixture {
	t.Helper()
	reg, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	f := &fixture{reg: reg, fake: &fakeLauncher{}, now: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}
	f.fake.respond = func(ctx context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		return okResult(spec, v1alpha1.ActionIssued, 90), nil
	}
	f.s = New(Options{
		Registry: reg, Launchers: map[string]launcher.Launcher{"local": f.fake},
		Tick: 10 * time.Millisecond, MaxConcurrentRuns: maxRuns,
		RetryBackoff: 5 * time.Minute, MaxRetryBackoff: 6 * time.Hour, Now: f.clock,
	})
	ctx := context.Background()
	f.policy = &registry.Policy{AllowedDnsSuffixes: []string{"example.ac.jp"}, ACMEBinding: "fake-ca", RenewBeforeDays: 30, KeyType: v1alpha1.KeyTypeEC256, MaxSANs: 1, Enabled: true}
	if err := reg.CreatePolicy(ctx, f.policy, nil); err != nil {
		t.Fatal(err)
	}
	f.target = &registry.Target{FQDN: "wiki.example.ac.jp", Enabled: true, Owner: "web", PolicyRef: f.policy.ID, ExecutionBinding: "local", DNSBinding: "fake-dns", StoreBinding: "filesystem-dev"}
	if err := reg.CreateTarget(ctx, f.target, nil); err != nil {
		t.Fatal(err)
	}
	return f
}

// cycle plans, dispatches and waits for the started executions.
func (f *fixture) cycle(t *testing.T) (planned, started int) {
	t.Helper()
	ctx := context.Background()
	planned, err := f.s.Plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	started, err = f.s.Dispatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.s.Drain(ctx)
	return planned, started
}

func (f *fixture) lastRun(t *testing.T) *registry.Run {
	t.Helper()
	sum, err := f.reg.RunSummary(context.Background(), f.target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.LastRun == nil {
		t.Fatal("no run")
	}
	return sum.LastRun
}

func (f *fixture) auditActions(t *testing.T, runID string) []registry.AuditAction {
	t.Helper()
	events, err := f.reg.ListAudit(context.Background(), registry.ListAuditOptions{RunID: runID})
	if err != nil {
		t.Fatal(err)
	}
	var out []registry.AuditAction
	for i := len(events) - 1; i >= 0; i-- {
		out = append(out, events[i].Action)
	}
	return out
}

func TestPlanAndExecuteSuccess(t *testing.T) {
	f := setup(t, 2)
	planned, started := f.cycle(t)
	if planned != 1 || started != 1 {
		t.Fatalf("planned %d started %d", planned, started)
	}
	run := f.lastRun(t)
	if run.Status != registry.RunSucceeded || run.Action != v1alpha1.ActionIssued || run.ExpiresAt == nil || run.StartedAt == nil || run.FinishedAt == nil || run.ExternalExecutionID != "fake:"+run.ID || run.RequestedBy != Actor || run.TargetRevision != 1 {
		t.Fatalf("run = %+v", run)
	}
	got := f.auditActions(t, run.ID)
	want := []registry.AuditAction{registry.AuditRunRequested, registry.AuditRunStarted, registry.AuditRunSucceeded}
	if len(got) != len(want) {
		t.Fatalf("audit = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit = %v, want %v", got, want)
		}
	}
	// The JobSpec carried a policy snapshot and the run/target identity.
	spec := f.fake.specs[0]
	if spec.RunID != run.ID || spec.Target.ID != f.target.ID || spec.Target.Revision != 1 || spec.ACME.Binding != "fake-ca" || spec.DNS.Binding != "fake-dns" || spec.Store.Binding != "filesystem-dev" || spec.Policy.RenewBeforeDays != 30 {
		t.Fatalf("spec = %+v", spec)
	}
	// Not due again: the certificate is current.
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatalf("planned %d after success", planned)
	}
	// Due again once inside the renewal window.
	f.advance(61 * 24 * time.Hour)
	if planned, _ := f.cycle(t); planned != 1 {
		t.Fatalf("planned %d inside renewal window", planned)
	}
	if f.s.InFlight() != 0 {
		t.Fatalf("inflight = %d", f.s.InFlight())
	}
}

func TestRevisionChangeMakesTargetDueAndStaleRunIsCancelled(t *testing.T) {
	f := setup(t, 1)
	f.cycle(t)
	ctx := context.Background()
	// A revision bump makes the target due again.
	f.target.Owner = "other"
	if err := f.reg.UpdateTarget(ctx, f.target, 1, nil); err != nil {
		t.Fatal(err)
	}
	planned, err := f.s.Plan(ctx)
	if err != nil || planned != 1 {
		t.Fatalf("planned %d, %v", planned, err)
	}
	// The target moves on again before the run starts: the queued run is
	// stale and must be cancelled, never executed.
	f.target.Owner = "another"
	if err := f.reg.UpdateTarget(ctx, f.target, 2, nil); err != nil {
		t.Fatal(err)
	}
	before := len(f.fake.specs)
	if _, err := f.s.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	f.s.Drain(ctx)
	run := f.lastRun(t)
	if run.Status != registry.RunCancelled || run.ErrorCode != v1alpha1.ErrorCodeCancelled || run.TargetRevision != 2 {
		t.Fatalf("stale run = %+v", run)
	}
	if len(f.fake.specs) != before {
		t.Fatal("a stale run reached the launcher")
	}
	// A disabled target is cancelled at start as well.
	f.target.Enabled = false
	if err := f.reg.UpdateTarget(ctx, f.target, 3, nil); err != nil {
		t.Fatal(err)
	}
	r := &registry.Run{TargetID: f.target.ID, TargetRevision: 4, RequestedBy: "operator"}
	if err := f.reg.CreateRun(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	f.s.Drain(ctx)
	if got := f.lastRun(t); got.ID != r.ID || got.Status != registry.RunCancelled || len(f.fake.specs) != before {
		t.Fatalf("disabled target run = %+v (specs %d)", got, len(f.fake.specs))
	}
	// Disabled targets are never planned.
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatalf("planned %d for a disabled target", planned)
	}
}

func TestPolicyRejectionAtExecution(t *testing.T) {
	f := setup(t, 1)
	ctx := context.Background()
	// The policy no longer covers the target by the time the run starts.
	f.policy.AllowedDnsSuffixes = []string{"example.org"}
	if err := f.reg.UpdatePolicy(ctx, f.policy, nil); err != nil {
		t.Fatal(err)
	}
	f.cycle(t)
	run := f.lastRun(t)
	if run.Status != registry.RunFailed || run.ErrorCode != v1alpha1.ErrorCodePolicyViolation || len(f.fake.specs) != 0 {
		t.Fatalf("run = %+v", run)
	}
	events, err := f.reg.ListAudit(ctx, registry.ListAuditOptions{RunID: run.ID})
	if err != nil {
		t.Fatal(err)
	}
	var rejected bool
	for _, e := range events {
		if e.Action == registry.AuditPolicyRejected && e.PolicyID == f.policy.ID {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("no policy.rejected event: %+v", events)
	}
	// A disabled policy holds the target back entirely.
	f.policy.AllowedDnsSuffixes = []string{"example.ac.jp"}
	f.policy.Enabled = false
	if err := f.reg.UpdatePolicy(ctx, f.policy, nil); err != nil {
		t.Fatal(err)
	}
	f.advance(24 * time.Hour)
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatalf("planned %d under a disabled policy", planned)
	}
}

func TestLauncherFailuresAreClassified(t *testing.T) {
	cases := []struct {
		name    string
		start   error
		respond func(ctx context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error)
		status  registry.RunStatus
		code    v1alpha1.ErrorCode
		summary string
	}{
		{name: "start", start: &launcher.Error{Reason: launcher.ReasonStart, Err: errors.New("boom")}, status: registry.RunFailed, code: v1alpha1.ErrorCodeInternal, summary: "runner could not be started"},
		{name: "noresult", respond: func(context.Context, *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
			return nil, &launcher.Error{Reason: launcher.ReasonNoResult, Err: errors.New("exit 2 secret-stderr")}
		}, status: registry.RunFailed, code: v1alpha1.ErrorCodeInternal, summary: "runner ended without reporting a result"},
		{name: "timeout", respond: func(context.Context, *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
			return nil, &launcher.Error{Reason: launcher.ReasonTimeout}
		}, status: registry.RunFailed, code: v1alpha1.ErrorCodeTimeout, summary: "runner did not report a result before the launcher timeout"},
		{name: "mismatch", respond: func(context.Context, *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
			return nil, &launcher.Error{Reason: launcher.ReasonMismatch}
		}, status: registry.RunFailed, code: v1alpha1.ErrorCodeInternal, summary: "runner reported a result for another run"},
		{name: "cancelled-noresult", respond: func(context.Context, *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
			return nil, &launcher.Error{Reason: launcher.ReasonCancelled}
		}, status: registry.RunCancelled, code: v1alpha1.ErrorCodeCancelled, summary: "run was cancelled before the runner reported a result"},
		{name: "result-failed", respond: func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
			return failResult(spec, v1alpha1.ErrorCodeDNSFailure, "TXT record propagation timed out"), nil
		}, status: registry.RunFailed, code: v1alpha1.ErrorCodeDNSFailure, summary: "TXT record propagation timed out"},
		{name: "result-cancelled", respond: func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
			return failResult(spec, v1alpha1.ErrorCodeCancelled, "run was cancelled by signal while lego was running"), nil
		}, status: registry.RunCancelled, code: v1alpha1.ErrorCodeCancelled, summary: "run was cancelled by signal while lego was running"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, 1)
			f.fake.startErr = tc.start
			if tc.respond != nil {
				f.fake.respond = tc.respond
			}
			f.cycle(t)
			run := f.lastRun(t)
			if run.Status != tc.status || run.ErrorCode != tc.code || run.ErrorSummary != tc.summary || run.Action != v1alpha1.ActionFailed {
				t.Fatalf("run = %+v", run)
			}
		})
	}
}

func TestMissingExecutionBinding(t *testing.T) {
	f := setup(t, 1)
	f.s.launchers = map[string]launcher.Launcher{}
	f.cycle(t)
	run := f.lastRun(t)
	if run.Status != registry.RunFailed || run.ErrorCode != v1alpha1.ErrorCodeBindingNotFound {
		t.Fatalf("run = %+v", run)
	}
}

func TestBackoffAfterFailures(t *testing.T) {
	f := setup(t, 1)
	f.fake.respond = func(_ context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		return failResult(spec, v1alpha1.ErrorCodeACMEFailure, "lego exited with status 1"), nil
	}
	if planned, _ := f.cycle(t); planned != 1 {
		t.Fatal("first attempt not planned")
	}
	// Within the backoff nothing is planned; after it, one retry.
	f.advance(4 * time.Minute)
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatalf("planned %d inside first backoff", planned)
	}
	f.advance(2 * time.Minute)
	if planned, _ := f.cycle(t); planned != 1 {
		t.Fatal("retry not planned after backoff")
	}
	// Second failure doubles the wait.
	f.advance(6 * time.Minute)
	if planned, _ := f.cycle(t); planned != 0 {
		t.Fatal("planned inside doubled backoff")
	}
	f.advance(5 * time.Minute)
	if planned, _ := f.cycle(t); planned != 1 {
		t.Fatal("retry not planned after doubled backoff")
	}
	sum, _ := f.reg.RunSummary(context.Background(), f.target.ID)
	if sum.ConsecutiveFailures != 3 {
		t.Fatalf("consecutive failures = %d", sum.ConsecutiveFailures)
	}
}

func TestDueTable(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	tgt := &registry.Target{Enabled: true, Revision: 2}
	pol := &registry.Policy{Enabled: true, RenewBeforeDays: 30}
	exp := func(days int) *time.Time { t := now.Add(time.Duration(days) * 24 * time.Hour); return &t }
	fin := now.Add(-time.Minute)
	cases := []struct {
		name string
		sum  registry.TargetRunSummary
		due  bool
	}{
		{"never", registry.TargetRunSummary{}, true},
		{"current", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 2, ExpiresAt: exp(60)}, LastSucceeded: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 2, ExpiresAt: exp(60)}}, false},
		{"window", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 2, ExpiresAt: exp(29)}, LastSucceeded: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 2, ExpiresAt: exp(29)}}, true},
		{"revision", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 1, ExpiresAt: exp(60)}, LastSucceeded: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 1, ExpiresAt: exp(60)}}, true},
		{"no-expiry", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 2}, LastSucceeded: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 2}}, true},
		{"active", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunRunning}}, false},
		{"failed-recent", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunFailed, FinishedAt: &fin}, ConsecutiveFailures: 1}, false},
		{"cancelled-recent", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunCancelled, FinishedAt: &fin}, ConsecutiveFailures: 1}, false},
		{"failed-old-current-cert", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunFailed, RequestedAt: now.Add(-time.Hour)}, LastSucceeded: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 2, ExpiresAt: exp(60)}, ConsecutiveFailures: 1}, false},
		{"failed-old-window", registry.TargetRunSummary{LastRun: &registry.Run{Status: registry.RunFailed, RequestedAt: now.Add(-time.Hour)}, LastSucceeded: &registry.Run{Status: registry.RunSucceeded, TargetRevision: 2, ExpiresAt: exp(10)}, ConsecutiveFailures: 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			due, why := Due(tgt, pol, &tc.sum, now, 5*time.Minute, time.Hour)
			if due != tc.due {
				t.Fatalf("Due = %v (%s), want %v", due, why, tc.due)
			}
		})
	}
	disabled := *tgt
	disabled.Enabled = false
	if due, _ := Due(&disabled, pol, &registry.TargetRunSummary{}, now, time.Minute, time.Hour); due {
		t.Fatal("disabled target is due")
	}
	for n, want := range map[int]time.Duration{0: time.Minute, 1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 10: time.Hour, 100: time.Hour} {
		if got := Backoff(n, time.Minute, time.Hour); got != want {
			t.Fatalf("Backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestConcurrencyLimitAndCancel(t *testing.T) {
	f := setup(t, 1)
	ctx := context.Background()
	other := &registry.Target{FQDN: "www.example.ac.jp", Enabled: true, Owner: "web", PolicyRef: f.policy.ID, ExecutionBinding: "local", DNSBinding: "fake-dns", StoreBinding: "filesystem-dev"}
	if err := f.reg.CreateTarget(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	f.fake.started = make(chan struct{}, 4)
	f.fake.respond = func(ctx context.Context, spec *v1alpha1.JobSpec) (*v1alpha1.Result, error) {
		<-ctx.Done()
		return failResult(spec, v1alpha1.ErrorCodeCancelled, "run was cancelled by signal while lego was running"), nil
	}
	if planned, err := f.s.Plan(ctx); err != nil || planned != 2 {
		t.Fatalf("planned %d, %v", planned, err)
	}
	if started, err := f.s.Dispatch(ctx); err != nil || started != 1 {
		t.Fatalf("started %d, %v (limit 1)", started, err)
	}
	<-f.fake.started
	if f.s.InFlight() != 1 {
		t.Fatalf("inflight = %d", f.s.InFlight())
	}
	active, _ := f.reg.ListActiveRuns(ctx)
	var running, queued *registry.Run
	for _, r := range active {
		switch r.Status {
		case registry.RunRunning:
			running = r
		case registry.RunQueued:
			queued = r
		}
	}
	if running == nil || queued == nil {
		t.Fatalf("active = %+v", active)
	}
	if f.s.Cancel("NOPE") {
		t.Fatal("Cancel of unknown run reported true")
	}
	if !f.s.Cancel(running.ID) {
		t.Fatal("Cancel of running run reported false")
	}
	// The second run is dispatched once capacity frees.
	deadline := time.Now().Add(5 * time.Second)
	for f.s.InFlight() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if started, err := f.s.Dispatch(ctx); err != nil || started != 1 {
		t.Fatalf("second dispatch started %d, %v", started, err)
	}
	<-f.fake.started
	// Drain with an expired context cancels what is left.
	dctx, cancel := context.WithCancel(ctx)
	cancel()
	f.s.Drain(dctx)
	got, _ := f.reg.GetRun(ctx, running.ID)
	if got.Status != registry.RunCancelled {
		t.Fatalf("cancelled run = %+v", got)
	}
	got, _ = f.reg.GetRun(ctx, queued.ID)
	if got.Status != registry.RunCancelled {
		t.Fatalf("drained run = %+v", got)
	}
	// After Drain the scheduler dispatches nothing more.
	r := &registry.Run{TargetID: f.target.ID, TargetRevision: 1, RequestedBy: "operator"}
	if err := f.reg.CreateRun(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	if started, _ := f.s.Dispatch(ctx); started != 0 {
		t.Fatal("dispatched after drain")
	}
}

func TestRecoverMarksInFlightRunsFailed(t *testing.T) {
	f := setup(t, 1)
	ctx := context.Background()
	other := &registry.Target{FQDN: "www.example.ac.jp", Enabled: true, Owner: "web", PolicyRef: f.policy.ID, ExecutionBinding: "local", DNSBinding: "fake-dns", StoreBinding: "filesystem-dev"}
	if err := f.reg.CreateTarget(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	third := &registry.Target{FQDN: "mail.example.ac.jp", Enabled: true, Owner: "web", PolicyRef: f.policy.ID, ExecutionBinding: "local", DNSBinding: "fake-dns", StoreBinding: "filesystem-dev"}
	if err := f.reg.CreateTarget(ctx, third, nil); err != nil {
		t.Fatal(err)
	}
	// Create and claim one run at a time: ids created within the same
	// millisecond do not order deterministically.
	starting := &registry.Run{TargetID: f.target.ID, TargetRevision: 1, RequestedBy: "x"}
	if err := f.reg.CreateRun(ctx, starting, nil); err != nil {
		t.Fatal(err)
	}
	c1, err := f.reg.ClaimQueuedRun(ctx)
	if err != nil || c1.ID != starting.ID {
		t.Fatalf("claim 1: %v %v", c1, err)
	}
	running := &registry.Run{TargetID: other.ID, TargetRevision: 1, RequestedBy: "x"}
	if err := f.reg.CreateRun(ctx, running, nil); err != nil {
		t.Fatal(err)
	}
	c2, err := f.reg.ClaimQueuedRun(ctx)
	if err != nil || c2.ID != running.ID {
		t.Fatalf("claim 2: %v %v", c2, err)
	}
	c2.Status = registry.RunRunning
	if err := f.reg.UpdateRun(ctx, c2, registry.RunStarting, nil); err != nil {
		t.Fatal(err)
	}
	queued := &registry.Run{TargetID: third.ID, TargetRevision: 1, RequestedBy: "x"}
	if err := f.reg.CreateRun(ctx, queued, nil); err != nil {
		t.Fatal(err)
	}
	n, err := f.s.Recover(ctx)
	if err != nil || n != 2 {
		t.Fatalf("Recover = %d, %v", n, err)
	}
	for _, id := range []string{c1.ID, c2.ID} {
		r, _ := f.reg.GetRun(ctx, id)
		if r.Status != registry.RunFailed || r.ErrorCode != v1alpha1.ErrorCodeInternal || r.FinishedAt == nil {
			t.Fatalf("recovered run = %+v", r)
		}
	}
	q, _ := f.reg.GetRun(ctx, queued.ID)
	if q.Status != registry.RunQueued {
		t.Fatalf("queued run = %+v", q)
	}
	// The queued run is still dispatched normally afterwards.
	if started, err := f.s.Dispatch(ctx); err != nil || started != 1 {
		t.Fatalf("dispatch after recover = %d, %v", started, err)
	}
	f.s.Drain(ctx)
}

func TestRunLoopWakes(t *testing.T) {
	f := setup(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.s.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sum, _ := f.reg.RunSummary(ctx, f.target.ID)
		if sum.LastSucceeded != nil {
			break
		}
		f.s.Wake()
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	f.s.Drain(context.Background())
	if run := f.lastRun(t); run.Status != registry.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}
}

func TestSanitize(t *testing.T) {
	long := make([]byte, 700)
	for i := range long {
		long[i] = 'a'
	}
	if got := sanitize("a\nb\x00c d"); got != "a bcd" {
		t.Fatalf("sanitize = %q", got)
	}
	if got := sanitize(string(long)); len(got) != registry.MaxAuditDetailLength {
		t.Fatalf("len = %d", len(got))
	}
}
