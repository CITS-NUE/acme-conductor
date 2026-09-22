package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

func open(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "conductor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newPolicy() *registry.Policy {
	return &registry.Policy{
		AllowedDnsSuffixes: []string{"example.ac.jp"},
		ACMEBinding:        "letsencrypt-staging",
		RenewBeforeDays:    30,
		KeyType:            v1alpha1.KeyTypeEC256,
		MaxSANs:            1,
		Enabled:            true,
	}
}

func newTarget(policyID, fqdn string) *registry.Target {
	return &registry.Target{
		FQDN: fqdn, Enabled: true, Owner: "web-team", PolicyRef: policyID,
		ExecutionBinding: "local", DNSBinding: "azure-dns-staging", StoreBinding: "filesystem-dev",
	}
}

func seed(t *testing.T, db *DB) (*registry.Policy, *registry.Target) {
	t.Helper()
	ctx := context.Background()
	p := newPolicy()
	if err := db.CreatePolicy(ctx, p, &registry.AuditEvent{Actor: "test", Action: registry.AuditPolicyCreated, Detail: "policy created"}); err != nil {
		t.Fatal(err)
	}
	tg := newTarget(p.ID, "wiki.example.ac.jp")
	if err := db.CreateTarget(ctx, tg, &registry.AuditEvent{Actor: "test", Action: registry.AuditTargetCreated, Detail: "target created"}); err != nil {
		t.Fatal(err)
	}
	return p, tg
}

func TestOpenMigratesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := db.Version(context.Background())
	if err != nil || v != SchemaVersion {
		t.Fatalf("version = %d, %v; want %d", v, err, SchemaVersion)
	}
	if err := db.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	db.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %o, want 0600", info.Mode().Perm())
	}
	// Reopen is idempotent.
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// A newer schema is refused.
	if _, err := db.db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, SchemaVersion+1, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(path); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Open newer schema: %v, want ErrSchemaTooNew", err)
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.db")
	link := filepath.Join(dir, "link.db")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Open(link); err == nil {
		t.Fatal("Open through a symlink succeeded")
	}
}

func TestPolicyCRUD(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	p := newPolicy()
	if err := db.CreatePolicy(ctx, p, nil); err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || p.CreatedAt.IsZero() {
		t.Fatalf("policy not populated: %+v", p)
	}
	got, err := db.GetPolicy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ACMEBinding != "letsencrypt-staging" || got.KeyType != v1alpha1.KeyTypeEC256 || len(got.AllowedDnsSuffixes) != 1 || !got.Enabled {
		t.Fatalf("GetPolicy = %+v", got)
	}
	got.AllowedDnsSuffixes = []string{"example.ac.jp", "example.org"}
	got.Enabled = false
	if err := db.UpdatePolicy(ctx, got, &registry.AuditEvent{Actor: "test", Action: registry.AuditPolicyUpdated, Detail: "updated"}); err != nil {
		t.Fatal(err)
	}
	again, err := db.GetPolicy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.AllowedDnsSuffixes) != 2 || again.Enabled || !again.UpdatedAt.After(again.CreatedAt) && !again.UpdatedAt.Equal(again.CreatedAt) {
		t.Fatalf("after update: %+v", again)
	}
	list, err := db.ListPolicies(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPolicies = %v, %v", list, err)
	}
	if _, err := db.GetPolicy(ctx, "NOPE"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("GetPolicy missing: %v", err)
	}
	if err := db.UpdatePolicy(ctx, &registry.Policy{ID: "NOPE"}, nil); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("UpdatePolicy missing: %v", err)
	}
	if err := db.CreatePolicy(ctx, &registry.Policy{ID: p.ID}, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("CreatePolicy duplicate id: %v", err)
	}
	events, err := db.ListAudit(ctx, registry.ListAuditOptions{PolicyID: p.ID})
	if err != nil || len(events) != 1 || events[0].Action != registry.AuditPolicyUpdated {
		t.Fatalf("ListAudit = %v, %v", events, err)
	}
}

func TestTargetCreateUniqueAndOptimisticLocking(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	p, tg := seed(t, db)
	if tg.Revision != 1 {
		t.Fatalf("revision = %d, want 1", tg.Revision)
	}
	dup := newTarget(p.ID, "wiki.example.ac.jp")
	if err := db.CreateTarget(ctx, dup, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("duplicate fqdn: %v", err)
	}
	orphan := newTarget("MISSING", "other.example.ac.jp")
	if err := db.CreateTarget(ctx, orphan, nil); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("missing policy: %v", err)
	}
	// Update at the right revision bumps it.
	tg.Owner = "other-team"
	if err := db.UpdateTarget(ctx, tg, 1, &registry.AuditEvent{Actor: "test", Action: registry.AuditTargetUpdated, Detail: "owner"}); err != nil {
		t.Fatal(err)
	}
	if tg.Revision != 2 {
		t.Fatalf("revision after update = %d", tg.Revision)
	}
	// A stale revision is refused.
	tg.Owner = "stale"
	if err := db.UpdateTarget(ctx, tg, 1, nil); !errors.Is(err, registry.ErrStaleRevision) {
		t.Fatalf("stale update: %v", err)
	}
	got, err := db.GetTarget(ctx, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != "other-team" || got.Revision != 2 {
		t.Fatalf("after stale update: %+v", got)
	}
	// FQDN is immutable through UpdateTarget.
	got.FQDN = "changed.example.ac.jp"
	if err := db.UpdateTarget(ctx, got, 2, nil); err != nil {
		t.Fatal(err)
	}
	again, _ := db.GetTarget(ctx, tg.ID)
	if again.FQDN != "wiki.example.ac.jp" {
		t.Fatalf("fqdn changed to %q", again.FQDN)
	}
	if err := db.UpdateTarget(ctx, &registry.Target{ID: "NOPE", PolicyRef: p.ID}, 1, nil); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	again.PolicyRef = "MISSING"
	if err := db.UpdateTarget(ctx, again, again.Revision, nil); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("update to missing policy: %v", err)
	}
	// List filters.
	f := false
	list, err := db.ListTargets(ctx, registry.ListTargetsOptions{Enabled: &f})
	if err != nil || len(list) != 0 {
		t.Fatalf("ListTargets disabled = %v, %v", list, err)
	}
	list, err = db.ListTargets(ctx, registry.ListTargetsOptions{PolicyRef: p.ID})
	if err != nil || len(list) != 1 {
		t.Fatalf("ListTargets by policy = %v, %v", list, err)
	}
}

func TestRunLifecycleAndExclusion(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	_, tg := seed(t, db)
	r := &registry.Run{TargetID: tg.ID, TargetRevision: tg.Revision, RequestedBy: "test"}
	if err := db.CreateRun(ctx, r, &registry.AuditEvent{Actor: "test", Action: registry.AuditRunRequested, Detail: "requested"}); err != nil {
		t.Fatal(err)
	}
	if r.Status != registry.RunQueued || r.ID == "" {
		t.Fatalf("run = %+v", r)
	}
	// A second active run for the same target is refused at the schema level.
	r2 := &registry.Run{TargetID: tg.ID, TargetRevision: tg.Revision, RequestedBy: "test"}
	if err := db.CreateRun(ctx, r2, nil); !errors.Is(err, registry.ErrRunActive) {
		t.Fatalf("second run: %v", err)
	}
	if err := db.CreateRun(ctx, &registry.Run{TargetID: "MISSING", TargetRevision: 1, RequestedBy: "t"}, nil); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("run for missing target: %v", err)
	}
	// Claim moves it to starting.
	now := time.Now()
	claimed, err := db.ClaimQueuedRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != r.ID || claimed.Status != registry.RunStarting {
		t.Fatalf("claimed = %+v", claimed)
	}
	if _, err := db.ClaimQueuedRun(ctx); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("second claim: %v", err)
	}
	// Still active: still excluded.
	if err := db.CreateRun(ctx, r2, nil); !errors.Is(err, registry.ErrRunActive) {
		t.Fatalf("run while starting: %v", err)
	}
	// Update with the wrong expected status is a conflict.
	claimed.Status = registry.RunRunning
	started := now.UTC()
	claimed.StartedAt = &started
	claimed.ExternalExecutionID = "pid:123"
	if err := db.UpdateRun(ctx, claimed, registry.RunQueued, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("wrong expected status: %v", err)
	}
	if err := db.UpdateRun(ctx, claimed, registry.RunStarting, &registry.AuditEvent{Actor: "scheduler", Action: registry.AuditRunStarted, Detail: "started"}); err != nil {
		t.Fatal(err)
	}
	finished := started.Add(time.Minute)
	expires := started.Add(90 * 24 * time.Hour)
	claimed.Status = registry.RunSucceeded
	claimed.FinishedAt = &finished
	claimed.Action = v1alpha1.ActionIssued
	claimed.ExpiresAt = &expires
	claimed.FingerprintSha256 = "ab"
	claimed.StoreObjectRef = "wiki.example.ac.jp-0123456789abcdef"
	if err := db.UpdateRun(ctx, claimed, registry.RunRunning, &registry.AuditEvent{Actor: "scheduler", Action: registry.AuditRunSucceeded, Detail: "ok"}); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetRun(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != registry.RunSucceeded || got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) || got.StartedAt == nil || got.FinishedAt == nil || got.ExternalExecutionID != "pid:123" {
		t.Fatalf("GetRun = %+v", got)
	}
	// Terminal: a new run may be created.
	if err := db.CreateRun(ctx, r2, nil); err != nil {
		t.Fatalf("run after completion: %v", err)
	}
	active, err := db.ListActiveRuns(ctx)
	if err != nil || len(active) != 1 || active[0].ID != r2.ID {
		t.Fatalf("ListActiveRuns = %v, %v", active, err)
	}
	// Summary.
	s, err := db.RunSummary(ctx, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.LastRun.ID != r2.ID || s.LastSucceeded.ID != r.ID || s.ConsecutiveFailures != 0 {
		t.Fatalf("summary = last %s ok %s failures %d", s.LastRun.ID, s.LastSucceeded.ID, s.ConsecutiveFailures)
	}
	// Fail r2, then two more failures: consecutive failures count since the success.
	fail := func(run *registry.Run) {
		t.Helper()
		c, err := db.ClaimQueuedRun(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c.Status = registry.RunFailed
		fin := time.Now().UTC()
		c.FinishedAt = &fin
		c.Action = v1alpha1.ActionFailed
		c.ErrorCode = v1alpha1.ErrorCodeACMEFailure
		c.ErrorSummary = "lego exited with status 1"
		if err := db.UpdateRun(ctx, c, registry.RunStarting, nil); err != nil {
			t.Fatal(err)
		}
	}
	fail(r2)
	r3 := &registry.Run{TargetID: tg.ID, TargetRevision: 1, RequestedBy: "scheduler"}
	if err := db.CreateRun(ctx, r3, nil); err != nil {
		t.Fatal(err)
	}
	fail(r3)
	s, err = db.RunSummary(ctx, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.ConsecutiveFailures != 2 || s.LastRun.ID != r3.ID || s.LastSucceeded.ID != r.ID {
		t.Fatalf("summary after failures = %+v", s)
	}
	// Lists: newest first, filters, pagination.
	runs, err := db.ListRuns(ctx, registry.ListRunsOptions{TargetID: tg.ID})
	if err != nil || len(runs) != 3 || runs[0].ID != r3.ID {
		t.Fatalf("ListRuns = %v, %v", runs, err)
	}
	runs, err = db.ListRuns(ctx, registry.ListRunsOptions{Statuses: []registry.RunStatus{registry.RunFailed}, Limit: 1})
	if err != nil || len(runs) != 1 || runs[0].ID != r3.ID {
		t.Fatalf("ListRuns failed limit 1 = %v, %v", runs, err)
	}
	runs, err = db.ListRuns(ctx, registry.ListRunsOptions{Before: r3.ID})
	if err != nil || len(runs) != 2 || runs[0].ID != r2.ID {
		t.Fatalf("ListRuns before = %v, %v", runs, err)
	}
	if _, err := db.GetRun(ctx, "NOPE"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("GetRun missing: %v", err)
	}
	if err := db.UpdateRun(ctx, &registry.Run{ID: "NOPE", Status: registry.RunFailed}, registry.RunRunning, nil); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("UpdateRun missing: %v", err)
	}
	if err := db.UpdateRun(ctx, &registry.Run{ID: r.ID, Status: "bogus"}, registry.RunRunning, nil); err == nil {
		t.Fatal("UpdateRun accepted an invalid status")
	}
	// An empty summary for a target with no runs.
	other := newTarget(tg.PolicyRef, "other.example.ac.jp")
	if err := db.CreateTarget(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	s, err = db.RunSummary(ctx, other.ID)
	if err != nil || s.LastRun != nil || s.LastSucceeded != nil || s.ConsecutiveFailures != 0 {
		t.Fatalf("empty summary = %+v, %v", s, err)
	}
}

func TestConcurrentCreateRunAdmitsExactlyOne(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	_, tg := seed(t, db)
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, active := 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.CreateRun(ctx, &registry.Run{TargetID: tg.ID, TargetRevision: 1, RequestedBy: "race"}, &registry.AuditEvent{Actor: "race", Action: registry.AuditRunRequested, Detail: "x"})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, registry.ErrRunActive):
				active++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || active != n-1 {
		t.Fatalf("ok = %d, active = %d", ok, active)
	}
	events, err := db.ListAudit(ctx, registry.ListAuditOptions{TargetID: tg.ID})
	if err != nil {
		t.Fatal(err)
	}
	// The target.created event plus exactly one run.requested: a refused
	// run leaves no audit trace because its transaction rolled back.
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want 2", len(events))
	}
}

func TestAuditIsAppendOnlyAndNothingIsDeletable(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	p, tg := seed(t, db)
	r := &registry.Run{TargetID: tg.ID, TargetRevision: 1, RequestedBy: "t"}
	if err := db.CreateRun(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE audit_events SET detail = 'tampered'`,
		`DELETE FROM audit_events`,
		`DELETE FROM targets`,
		`DELETE FROM runs`,
		`DELETE FROM policies`,
	} {
		if _, err := db.db.ExecContext(ctx, stmt); err == nil {
			t.Fatalf("%q succeeded; the schema must refuse it", stmt)
		}
	}
	events, err := db.ListAudit(ctx, registry.ListAuditOptions{})
	if err != nil || len(events) != 2 {
		t.Fatalf("ListAudit = %v, %v", events, err)
	}
	if events[0].Action != registry.AuditTargetCreated || events[0].TargetID != tg.ID || events[1].PolicyID != p.ID {
		t.Fatalf("events = %+v %+v", events[0], events[1])
	}
	// Pagination and a long detail being bounded.
	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'x'
	}
	ev := &registry.AuditEvent{Actor: "t", Action: registry.AuditRunFailed, RunID: r.ID, Detail: string(long)}
	if err := db.AppendAudit(ctx, ev); err != nil {
		t.Fatal(err)
	}
	got, err := db.ListAudit(ctx, registry.ListAuditOptions{RunID: r.ID, Limit: 1})
	if err != nil || len(got) != 1 || len(got[0].Detail) != registry.MaxAuditDetailLength {
		t.Fatalf("bounded detail: %v, %v", got, err)
	}
	page, err := db.ListAudit(ctx, registry.ListAuditOptions{Before: got[0].ID, Limit: 1})
	if err != nil || len(page) != 1 || page[0].ID >= got[0].ID {
		t.Fatalf("page = %v, %v", page, err)
	}
}
