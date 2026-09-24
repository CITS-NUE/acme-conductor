// Package scheduler decides when a Target is due, records a Run for it,
// and drives that Run through a Launcher to completion.
//
// Mutual exclusion per target is enforced by the registry (at most one
// queued, starting or running run per target, a schema-level invariant),
// so neither a scheduler tick, an operator request nor a restart can start
// a second Runner for a target that already has one in flight. Before a
// queued run is started the target is re-read: if it was disabled or its
// revision moved on since the run was requested, the run is cancelled
// instead of started, so a stale request is never actioned
// (docs/threat-model.md, T7).
//
// Bookkeeping is tracked by what the registry actually holds, not by what
// the scheduler intended: every status transition is attempted against the
// last status known to be recorded, a conflict re-reads the registry, and
// a transient failure is retried for a bounded window so a Runner's outcome
// is not lost to one failed write. A run whose outcome still could not be
// recorded is closed by the sweep at the next loop iteration (and by
// Recover at the next start), so the target's exclusion slot is freed and
// the next run can be registered.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

// Actor is the audit actor and requestedBy value of automatic runs, and
// Authority its namespace: the scheduler is its own authority, distinct
// from any identity provider and from localhost-dev.
const (
	Actor     = "scheduler"
	Authority = "scheduler"
)

// Options configure a Scheduler.
type Options struct {
	Registry registry.Registry
	// Launchers maps an execution binding name to its launcher.
	Launchers         map[string]launcher.Launcher
	Tick              time.Duration
	MaxConcurrentRuns int
	RetryBackoff      time.Duration
	MaxRetryBackoff   time.Duration
	Logger            *slog.Logger
	Now               func() time.Time
	// RecordRetry is the initial wait between attempts to record a status
	// transition that failed with a transient registry error (doubled per
	// attempt, capped at ten times the initial); RecordWindow bounds the
	// total time spent retrying one transition. Zero selects the defaults
	// (DefaultRecordRetry, DefaultRecordWindow).
	RecordRetry  time.Duration
	RecordWindow time.Duration
}

// Defaults for Options.RecordRetry and Options.RecordWindow.
const (
	DefaultRecordRetry  = 250 * time.Millisecond
	DefaultRecordWindow = 2 * time.Minute
)

// Scheduler runs the planning/dispatch loop.
type Scheduler struct {
	reg       registry.Registry
	launchers map[string]launcher.Launcher
	tick      time.Duration
	maxRuns   int
	backoff   time.Duration
	maxBack   time.Duration
	log       *slog.Logger
	now       func() time.Time

	recordRetry  time.Duration
	recordWindow time.Duration

	wake chan struct{}

	// runsCtx bounds every execution; Drain cancels it when its own
	// deadline passes so in-flight Runners are asked to stop.
	runsCtx    context.Context
	cancelRuns context.CancelFunc

	mu       sync.Mutex
	inflight map[string]context.CancelFunc
	wg       sync.WaitGroup
}

// New creates a Scheduler.
func New(o Options) *Scheduler {
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Tick <= 0 {
		o.Tick = time.Minute
	}
	if o.MaxConcurrentRuns <= 0 {
		o.MaxConcurrentRuns = 1
	}
	if o.RetryBackoff <= 0 {
		o.RetryBackoff = 5 * time.Minute
	}
	if o.MaxRetryBackoff < o.RetryBackoff {
		o.MaxRetryBackoff = o.RetryBackoff
	}
	if o.RecordRetry <= 0 {
		o.RecordRetry = DefaultRecordRetry
	}
	if o.RecordWindow <= 0 {
		o.RecordWindow = DefaultRecordWindow
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		reg: o.Registry, launchers: o.Launchers, tick: o.Tick, maxRuns: o.MaxConcurrentRuns,
		backoff: o.RetryBackoff, maxBack: o.MaxRetryBackoff, log: o.Logger, now: o.Now,
		recordRetry: o.RecordRetry, recordWindow: o.RecordWindow,
		wake: make(chan struct{}, 1), runsCtx: ctx, cancelRuns: cancel, inflight: map[string]context.CancelFunc{},
	}
}

// Wake asks the loop to plan and dispatch now rather than at the next
// tick (an operator just requested a run).
func (s *Scheduler) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run executes the loop until ctx is done. It does not wait for in-flight
// executions; call Drain for that.
//
// Each iteration plans, dispatches and then sweeps. The sweep runs in this
// goroutine only, after Dispatch has registered every run it claimed, so
// it can never mistake a freshly claimed run for a stranded one.
func (s *Scheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()
	for {
		if _, err := s.Plan(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("scheduler planning failed", "error", err.Error())
		}
		if _, err := s.Dispatch(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("scheduler dispatch failed", "error", err.Error())
		}
		if _, err := s.sweep(ctx, strandedSummary, "run marked failed by the scheduler: "); err != nil && ctx.Err() == nil {
			s.log.Error("scheduler sweep failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-s.wake:
		}
	}
}

// Drain waits for in-flight executions to finish. When ctx is done before
// that, every execution is cancelled and Drain waits for the launchers to
// return (bounded by their termination grace period).
func (s *Scheduler) Drain(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.log.Warn("cancelling in-flight runs", "inflight", s.InFlight())
		s.cancelRuns()
		<-done
	}
}

// InFlight reports the number of executions in progress.
func (s *Scheduler) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inflight)
}

// Cancel asks the execution of runID to stop. It reports whether the run
// was in flight; a queued run is cancelled through the registry instead.
func (s *Scheduler) Cancel(runID string) bool {
	s.mu.Lock()
	cancel, ok := s.inflight[runID]
	s.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// maxConflictRereads bounds how many times one record call re-reads the
// registry to resolve a status conflict before giving up.
const maxConflictRereads = 2

// Summaries recorded on runs whose outcome this process does not know.
const (
	recoveredSummary = "conductor stopped while the run was in flight; outcome unknown"
	strandedSummary  = "run outcome could not be recorded while the runner ran; outcome unknown"
)

// Recover marks every run left in starting or running by a previous
// process as failed: their outcome is unknown to this process. Queued runs
// are left for Dispatch. It returns the number of runs marked. It is meant
// to be called once, before Run, by the process that owns the registry.
func (s *Scheduler) Recover(ctx context.Context) (int, error) {
	return s.sweep(ctx, recoveredSummary, "run marked failed at startup: ")
}

// sweep marks every starting or running run that this process is not
// executing as failed with summary. Such a run exists when a previous
// process stopped mid-flight (Recover) or when an execution exhausted its
// attempts to record the outcome; either way the outcome is unknown, and
// leaving the run active would hold the target's exclusion slot forever.
// Runs that another writer closed between the listing and the update are
// skipped (ErrConflict): the registry's expected-status guard, not the
// listing, decides.
func (s *Scheduler) sweep(ctx context.Context, summary, detailPrefix string) (int, error) {
	active, err := s.reg.ListActiveRuns(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range active {
		if r.Status == registry.RunQueued {
			continue
		}
		s.mu.Lock()
		_, executing := s.inflight[r.ID]
		s.mu.Unlock()
		if executing {
			continue
		}
		now := s.now().UTC()
		prev := r.Status
		r.Status = registry.RunFailed
		r.FinishedAt = &now
		r.Action = v1alpha1.ActionFailed
		r.ErrorCode = v1alpha1.ErrorCodeInternal
		r.ErrorSummary = summary
		ev := &registry.AuditEvent{Actor: Actor, ActorAuthority: Authority, Action: registry.AuditRunFailed, Detail: detailPrefix + summary}
		err := s.reg.UpdateRun(ctx, r, prev, ev)
		if errors.Is(err, registry.ErrConflict) {
			continue
		}
		if err != nil {
			return n, err
		}
		s.log.Warn("stranded run marked failed", "runId", r.ID, "targetId", r.TargetID, "previousStatus", string(prev), "summary", summary)
		n++
	}
	return n, nil
}

// Plan records a queued run for every enabled target that is due and has
// no active run. It returns the number of runs created.
func (s *Scheduler) Plan(ctx context.Context) (int, error) {
	enabled := true
	targets, err := s.reg.ListTargets(ctx, registry.ListTargetsOptions{Enabled: &enabled})
	if err != nil {
		return 0, err
	}
	created := 0
	policies := map[string]*registry.Policy{}
	for _, t := range targets {
		if ctx.Err() != nil {
			return created, ctx.Err()
		}
		p, ok := policies[t.PolicyRef]
		if !ok {
			p, err = s.reg.GetPolicy(ctx, t.PolicyRef)
			if err != nil {
				s.log.Error("target policy could not be loaded", "targetId", t.ID, "policyId", t.PolicyRef, "error", err.Error())
				continue
			}
			policies[t.PolicyRef] = p
		}
		if !p.Enabled {
			continue
		}
		sum, err := s.reg.RunSummary(ctx, t.ID)
		if err != nil {
			return created, err
		}
		if sum.LastRun != nil && sum.LastRun.Status.Active() {
			continue
		}
		due, why := Due(t, p, sum, s.now(), s.backoff, s.maxBack)
		if !due {
			continue
		}
		run := &registry.Run{TargetID: t.ID, TargetRevision: t.Revision, RequestedBy: Actor, RequestedByAuthority: Authority}
		ev := &registry.AuditEvent{Actor: Actor, ActorAuthority: Authority, Action: registry.AuditRunRequested, Detail: "run requested by scheduler: " + why}
		err = s.reg.CreateRun(ctx, run, ev)
		switch {
		case errors.Is(err, registry.ErrRunActive):
			continue
		case err != nil:
			return created, err
		}
		s.log.Info("run queued", "runId", run.ID, "targetId", t.ID, "fqdn", t.FQDN, "reason", why)
		created++
	}
	return created, nil
}

// Due decides whether target t under policy p is due for a run at now.
// The second value explains the decision for logs and audit.
func Due(t *registry.Target, p *registry.Policy, sum *registry.TargetRunSummary, now time.Time, backoff, maxBackoff time.Duration) (bool, string) {
	if !t.Enabled || !p.Enabled {
		return false, "target or policy disabled"
	}
	if sum.LastRun != nil && sum.LastRun.Status.Active() {
		return false, "a run is active"
	}
	// A failed or cancelled last run holds the target back for a while.
	if last := sum.LastRun; last != nil && (last.Status == registry.RunFailed || last.Status == registry.RunCancelled) {
		wait := Backoff(sum.ConsecutiveFailures, backoff, maxBackoff)
		ref := last.RequestedAt
		if last.FinishedAt != nil {
			ref = *last.FinishedAt
		}
		if next := ref.Add(wait); now.Before(next) {
			return false, fmt.Sprintf("retry backoff until %s after %d consecutive failures", next.UTC().Format(time.RFC3339), sum.ConsecutiveFailures)
		}
		if sum.LastSucceeded == nil {
			return true, "retry after failure; never reconciled successfully"
		}
	}
	ok := sum.LastSucceeded
	if ok == nil {
		return true, "never reconciled"
	}
	if ok.TargetRevision != t.Revision {
		return true, fmt.Sprintf("target revision %d differs from last successful run (revision %d)", t.Revision, ok.TargetRevision)
	}
	if ok.ExpiresAt == nil {
		return true, "last successful run recorded no expiry"
	}
	renewAt := ok.ExpiresAt.Add(-time.Duration(p.RenewBeforeDays) * 24 * time.Hour)
	if !now.Before(renewAt) {
		return true, fmt.Sprintf("certificate expires at %s, within renewBeforeDays", ok.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return false, fmt.Sprintf("certificate current until %s", ok.ExpiresAt.UTC().Format(time.RFC3339))
}

// Backoff returns the wait after n consecutive failures: base doubled per
// failure beyond the first, capped at max.
func Backoff(n int, base, max time.Duration) time.Duration {
	if n < 1 {
		n = 1
	}
	wait := base
	for i := 1; i < n; i++ {
		if wait >= max/2 {
			return max
		}
		wait *= 2
	}
	if wait > max {
		return max
	}
	return wait
}

// Dispatch claims queued runs while capacity allows and executes each in
// its own goroutine. It returns the number of runs started.
func (s *Scheduler) Dispatch(ctx context.Context) (int, error) {
	started := 0
	for {
		if ctx.Err() != nil || s.runsCtx.Err() != nil {
			return started, nil
		}
		if s.InFlight() >= s.maxRuns {
			return started, nil
		}
		run, err := s.reg.ClaimQueuedRun(ctx)
		if errors.Is(err, registry.ErrNotFound) {
			return started, nil
		}
		if err != nil {
			return started, err
		}
		runCtx, cancel := context.WithCancel(s.runsCtx)
		s.mu.Lock()
		s.inflight[run.ID] = cancel
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				cancel()
				s.mu.Lock()
				delete(s.inflight, run.ID)
				s.mu.Unlock()
			}()
			s.execute(runCtx, run)
		}()
		started++
	}
}

// execute drives one claimed (starting) run to a terminal status. Registry
// calls use a context that outlives runCtx, so a cancelled run is still
// recorded.
func (s *Scheduler) execute(runCtx context.Context, run *registry.Run) {
	ctx := context.WithoutCancel(runCtx)
	log := s.log.With("runId", run.ID, "targetId", run.TargetID)
	// recorded is the status the registry is known to hold for this run.
	// Every transition is attempted against it, never against the status
	// the scheduler meant to record.
	recorded := registry.RunStarting

	finish := func(status registry.RunStatus, action registry.AuditAction, detail string) {
		now := s.now().UTC()
		run.Status = status
		run.FinishedAt = &now
		ev := &registry.AuditEvent{Actor: Actor, ActorAuthority: Authority, Action: action, Detail: detail}
		if err := s.record(ctx, log, run, &recorded, ev, s.recordWindow); err != nil {
			log.Error("run outcome could not be recorded; the sweep will close the run with an unknown outcome", "status", string(status), "error", err.Error())
			return
		}
		switch status {
		case registry.RunSucceeded:
			log.Info("run succeeded", "action", string(run.Action), "storeObjectRef", run.StoreObjectRef, "fingerprintSha256", run.FingerprintSha256)
		default:
			log.Warn("run "+string(status), "code", string(run.ErrorCode), "summary", run.ErrorSummary)
		}
	}
	failed := func(code v1alpha1.ErrorCode, summary string) {
		run.Action = v1alpha1.ActionFailed
		run.ErrorCode = code
		run.ErrorSummary = summary
		finish(registry.RunFailed, registry.AuditRunFailed, "run failed: "+string(code)+": "+summary)
	}
	cancelled := func(summary string) {
		run.Action = v1alpha1.ActionFailed
		run.ErrorCode = v1alpha1.ErrorCodeCancelled
		run.ErrorSummary = summary
		finish(registry.RunCancelled, registry.AuditRunCancelled, "run cancelled: "+summary)
	}

	target, err := s.reg.GetTarget(ctx, run.TargetID)
	if err != nil {
		failed(v1alpha1.ErrorCodeInternal, "target could not be loaded")
		return
	}
	log = log.With("fqdn", target.FQDN)
	switch {
	case !target.Enabled:
		cancelled("target was disabled before the run started")
		return
	case target.Revision != run.TargetRevision:
		cancelled(fmt.Sprintf("target revision changed from %d to %d before the run started", run.TargetRevision, target.Revision))
		return
	}
	policy, err := s.reg.GetPolicy(ctx, target.PolicyRef)
	if err != nil {
		failed(v1alpha1.ErrorCodeInternal, "target policy could not be loaded")
		return
	}
	if !policy.Enabled {
		cancelled("policy was disabled before the run started")
		return
	}
	spec := BuildJobSpec(run, target, policy)
	if err := spec.Validate(); err != nil {
		summary := sanitize("job spec rejected: " + err.Error())
		rej := &registry.AuditEvent{Actor: Actor, ActorAuthority: Authority, Action: registry.AuditPolicyRejected, TargetID: target.ID, RunID: run.ID, PolicyID: policy.ID, Detail: summary}
		if aerr := s.reg.AppendAudit(ctx, rej); aerr != nil {
			log.Error("policy rejection could not be audited", "error", aerr.Error())
		}
		failed(v1alpha1.ErrorCodePolicyViolation, summary)
		return
	}
	l, ok := s.launchers[target.ExecutionBinding]
	if !ok {
		failed(v1alpha1.ErrorCodeBindingNotFound, fmt.Sprintf("execution binding %q is not configured", target.ExecutionBinding))
		return
	}
	if runCtx.Err() != nil {
		cancelled("run was cancelled before the runner started")
		return
	}
	exec, err := l.Start(runCtx, spec)
	if err != nil {
		if launcher.ReasonOf(err) == launcher.ReasonCancelled {
			log.Warn("run cancelled before the runner started", "launcher", l.Type(), "error", err.Error())
			cancelled("run was cancelled before the runner started")
			return
		}
		log.Error("runner could not be started", "launcher", l.Type(), "error", err.Error())
		failed(v1alpha1.ErrorCodeInternal, "runner could not be started")
		return
	}
	now := s.now().UTC()
	run.Status = registry.RunRunning
	run.StartedAt = &now
	run.ExternalExecutionID = exec.ID()
	started := &registry.AuditEvent{Actor: Actor, ActorAuthority: Authority, Action: registry.AuditRunStarted, Detail: "runner started via " + l.Type() + " (" + exec.ID() + ")"}
	// The Runner is already executing, so the start is recorded without
	// retrying (a wait here would only delay collecting the outcome). If
	// it fails, recorded stays starting: the outcome below is then
	// recorded against starting, after one more attempt at the start.
	if err := s.record(ctx, log, run, &recorded, started, 0); err != nil {
		log.Error("run start could not be recorded; the outcome will be recorded against the last known status", "error", err.Error())
	}
	res, err := exec.Wait()
	if recorded == registry.RunStarting {
		// One more attempt now that the Runner has finished, so the
		// audit trail carries run.started when the registry is back.
		run.Status = registry.RunRunning
		if rerr := s.record(ctx, log, run, &recorded, started, 0); rerr != nil {
			log.Warn("run start still could not be recorded", "error", rerr.Error())
		}
	}
	if err != nil {
		log.Error("runner produced no result", "launcher", l.Type(), "error", err.Error())
		switch launcher.ReasonOf(err) {
		case launcher.ReasonTimeout:
			failed(v1alpha1.ErrorCodeTimeout, "runner did not report a result before the launcher timeout")
		case launcher.ReasonCancelled:
			cancelled("run was cancelled before the runner reported a result")
		case launcher.ReasonMismatch:
			failed(v1alpha1.ErrorCodeInternal, "runner reported a result for another run")
		default:
			failed(v1alpha1.ErrorCodeInternal, "runner ended without reporting a result")
		}
		return
	}
	// The Result has passed the contract's own validation (the launcher
	// decodes it strictly), so its fields are safe to record as-is.
	run.Action = res.Action
	run.ExpiresAt = res.ExpiresAt
	run.FingerprintSha256 = res.FingerprintSha256
	run.StoreObjectRef = res.StoreObjectRef
	if res.Status == v1alpha1.StatusSucceeded {
		run.ErrorCode = ""
		run.ErrorSummary = ""
		finish(registry.RunSucceeded, registry.AuditRunSucceeded, "run succeeded: "+string(res.Action))
		return
	}
	run.ErrorCode = res.Error.Code
	run.ErrorSummary = res.Error.Summary
	if res.Error.Code == v1alpha1.ErrorCodeCancelled {
		finish(registry.RunCancelled, registry.AuditRunCancelled, "run cancelled: "+res.Error.Summary)
		return
	}
	finish(registry.RunFailed, registry.AuditRunFailed, "run failed: "+string(res.Error.Code)+": "+res.Error.Summary)
}

// record writes run (whose Status is the status to reach) to the registry
// against *recorded, the status the registry is known to hold, and sets
// *recorded on success.
//
// ErrConflict means the registry holds another status than expected (a
// write that reported failure after committing, for example): the run is
// re-read and, if it is still active, the transition is retried against
// the actual status; a run already terminal is left alone. ErrNotFound is
// final. Any other error is retried with backoff until window has passed
// or the scheduler is being drained (s.runsCtx), then returned. With a
// zero window a single attempt is made, but a conflict is still resolved.
// Re-reading is itself bounded (maxConflictRereads): only this process
// writes an active run, so one re-read converges; a bound keeps a future
// second writer from turning the loop into a spin.
func (s *Scheduler) record(ctx context.Context, log *slog.Logger, run *registry.Run, recorded *registry.RunStatus, ev *registry.AuditEvent, window time.Duration) error {
	want := run.Status
	deadline := time.Now().Add(window)
	wait := s.recordRetry
	rereads := 0
	for attempt := 1; ; attempt++ {
		run.Status = want
		err := s.reg.UpdateRun(ctx, run, *recorded, ev)
		if err == nil {
			*recorded = want
			return nil
		}
		switch {
		case errors.Is(err, registry.ErrNotFound):
			return err
		case errors.Is(err, registry.ErrConflict):
			actual, gerr := s.reg.GetRun(ctx, run.ID)
			if gerr == nil {
				if actual.Status == want {
					// The transition had already committed (a write that
					// reported failure after committing); recording it
					// again would duplicate its audit event.
					*recorded = want
					return nil
				}
				if !actual.Status.Active() {
					*recorded = actual.Status
					return fmt.Errorf("run is already %s: %w", actual.Status, err)
				}
				if actual.Status != *recorded && rereads < maxConflictRereads {
					rereads++
					log.Warn("registry holds another status than recorded; retrying against it", "recorded", string(*recorded), "actual", string(actual.Status))
					*recorded = actual.Status
					continue
				}
			}
		}
		if window <= 0 || !time.Now().Before(deadline) || s.runsCtx.Err() != nil {
			return err
		}
		log.Warn("status transition could not be recorded; retrying", "status", string(want), "attempt", attempt, "error", err.Error())
		select {
		case <-s.runsCtx.Done():
			return err
		case <-time.After(wait):
		}
		if wait < 10*s.recordRetry {
			wait *= 2
		}
	}
}

// BuildJobSpec produces the JobSpec for run against the current target and
// policy. The policy is copied by value (a snapshot), so the run can be
// audited from the document alone.
func BuildJobSpec(run *registry.Run, t *registry.Target, p *registry.Policy) *v1alpha1.JobSpec {
	return &v1alpha1.JobSpec{
		APIVersion: v1alpha1.APIVersion,
		Kind:       v1alpha1.KindCertificateReconcileJob,
		RunID:      run.ID,
		Target:     v1alpha1.TargetRef{ID: t.ID, FQDN: t.FQDN, Revision: t.Revision},
		Policy: v1alpha1.PolicySpec{
			AllowedDnsSuffixes: append([]string(nil), p.AllowedDnsSuffixes...),
			AllowWildcard:      p.AllowWildcard,
			RenewBeforeDays:    p.RenewBeforeDays,
			KeyType:            p.KeyType,
		},
		ACME:  v1alpha1.ACMERef{Binding: p.ACMEBinding},
		DNS:   v1alpha1.DNSRef{Binding: t.DNSBinding},
		Store: v1alpha1.StoreRef{Binding: t.StoreBinding},
	}
}

// sanitize bounds and cleans a summary built from validated values.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
	if len(s) > registry.MaxAuditDetailLength {
		s = s[:registry.MaxAuditDetailLength]
		for len(s) > 0 && (s[len(s)-1]&0xC0) == 0x80 {
			s = s[:len(s)-1]
		}
	}
	return s
}
