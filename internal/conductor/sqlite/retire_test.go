package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

func disable(t *testing.T, db *DB, id string) {
	t.Helper()
	tg, err := db.GetTarget(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	tg.Enabled = false
	if err := db.UpdateTarget(context.Background(), tg, tg.Revision, nil); err != nil {
		t.Fatal(err)
	}
}

func retireEv() *registry.AuditEvent {
	return &registry.AuditEvent{Actor: "op", ActorAuthority: "https://idp.example/v2.0", Action: registry.AuditTargetRetired, Detail: "target retired"}
}

func TestRetireTarget(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	p, _ := seed(t, db)
	tg := newTarget(p.ID, "portal.example.ac.jp")
	tg.AdditionalNames = []string{"www.example.ac.jp"}
	if err := db.CreateTarget(ctx, tg, nil); err != nil {
		t.Fatal(err)
	}

	// Preconditions: not found, enabled, active run.
	if _, err := db.RetireTarget(ctx, "nope", "op", "a", retireEv()); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
	if _, err := db.RetireTarget(ctx, tg.ID, "op", "a", retireEv()); !errors.Is(err, registry.ErrTargetEnabled) {
		t.Fatalf("enabled target: %v", err)
	}
	disable(t, db, tg.ID)
	run := &registry.Run{TargetID: tg.ID, TargetRevision: 2, RequestedBy: "op"}
	if err := db.CreateRun(ctx, run, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RetireTarget(ctx, tg.ID, "op", "a", retireEv()); !errors.Is(err, registry.ErrRunActive) {
		t.Fatalf("active run: %v", err)
	}
	// A refused retirement changes nothing.
	if got, _ := db.GetTarget(ctx, tg.ID); got.Retired() || got.Revision != 2 {
		t.Fatalf("target after refusal: %+v", got)
	}
	run.Status = registry.RunSucceeded
	if err := db.UpdateRun(ctx, run, registry.RunQueued, nil); err != nil {
		t.Fatal(err)
	}

	// A pending request for the target's own account, and one of another.
	mk := func(scope string) {
		a := newACMEAccount("upki", 1)
		a.Scope = scope
		if err := db.RequestACMEAccountProvisioning(ctx, a, `{"c":"x"}`, nil); err != nil {
			t.Fatal(err)
		}
	}
	mk(tg.ID)
	mk("other-target")

	got, err := db.RetireTarget(ctx, tg.ID, "op", "https://idp.example/v2.0", retireEv())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Retired() || got.RetiredBy != "op" || got.RetiredByAuthority != "https://idp.example/v2.0" || got.Revision != 3 || got.Enabled {
		t.Fatalf("retired target = %+v", got)
	}
	if _, err := db.RetireTarget(ctx, tg.ID, "op", "a", retireEv()); !errors.Is(err, registry.ErrRetired) {
		t.Fatalf("retire twice: %v", err)
	}

	// Nothing is deleted: row, run and audit history stay; the account
	// request is cancelled, not deleted, and only for this target.
	if again, err := db.GetTarget(ctx, tg.ID); err != nil || !again.Retired() {
		t.Fatalf("GetTarget = %+v, %v", again, err)
	}
	if runs, _ := db.ListRuns(ctx, registry.ListRunsOptions{TargetID: tg.ID}); len(runs) != 1 {
		t.Fatalf("runs = %d", len(runs))
	}
	accts, _ := db.ListACMEAccounts(ctx, "upki", tg.ID)
	if len(accts) != 1 || accts[0].Status != registry.ACMEAccountCancelled {
		t.Fatalf("own account requests = %+v", accts)
	}
	var sealed sql.NullString
	if err := db.db.QueryRow(`SELECT sealed_payload FROM acme_accounts WHERE scope = ?`, tg.ID).Scan(&sealed); err != nil || sealed.Valid {
		t.Fatalf("sealed payload kept: %v %v", sealed, err)
	}
	if other, _ := db.ListACMEAccounts(ctx, "upki", "other-target"); len(other) != 1 || other[0].Status != registry.ACMEAccountProvisioning {
		t.Fatalf("another target's request = %+v", other)
	}
	events, _ := db.ListAudit(ctx, registry.ListAuditOptions{TargetID: tg.ID})
	var actions []registry.AuditAction
	for _, e := range events {
		actions = append(actions, e.Action)
	}
	if !slices.Contains(actions, registry.AuditTargetRetired) || !slices.Contains(actions, registry.AuditACMEAccountProvisioningCancelled) {
		t.Fatalf("audit actions = %v", actions)
	}

	// Listing hides it unless asked; the policy's list too.
	list, _ := db.ListTargets(ctx, registry.ListTargetsOptions{})
	for _, x := range list {
		if x.ID == tg.ID {
			t.Fatal("retired target in the default list")
		}
	}
	all, _ := db.ListTargets(ctx, registry.ListTargetsOptions{IncludeRetired: true})
	if len(all) != len(list)+1 {
		t.Fatalf("include retired: %d vs %d", len(all), len(list))
	}

	// Nothing about it can change or run any more.
	got.Owner = "x"
	if err := db.UpdateTarget(ctx, got, got.Revision, nil); !errors.Is(err, registry.ErrRetired) {
		t.Fatalf("UpdateTarget = %v", err)
	}
	if err := db.CreateRun(ctx, &registry.Run{TargetID: tg.ID, TargetRevision: got.Revision, RequestedBy: "op"}, nil); !errors.Is(err, registry.ErrRetired) {
		t.Fatalf("CreateRun = %v", err)
	}
	a := newACMEAccount("upki", 2)
	a.Scope = tg.ID
	if err := db.RequestACMEAccountProvisioning(ctx, a, `{}`, nil); !errors.Is(err, registry.ErrRetired) {
		t.Fatalf("provisioning request = %v", err)
	}
	for _, stmt := range []string{
		`UPDATE targets SET enabled = 1 WHERE id = '` + tg.ID + `'`,
		`UPDATE targets SET retired_at = NULL WHERE id = '` + tg.ID + `'`,
		`DELETE FROM targets`,
	} {
		if _, err := db.db.ExecContext(ctx, stmt); err == nil {
			t.Fatalf("%q succeeded; the schema must refuse it", stmt)
		}
	}

	// Its names are free again, the FQDN and the additional one.
	for _, names := range [][]string{{"portal.example.ac.jp"}, {"www.example.ac.jp"}} {
		n := newTarget(p.ID, "x-"+names[0])
		if names[0] == "portal.example.ac.jp" {
			n = newTarget(p.ID, names[0])
		} else {
			n.AdditionalNames = names
		}
		if err := db.CreateTarget(ctx, n, nil); err != nil {
			t.Fatalf("re-register %v: %v", names, err)
		}
	}
	// Still one target per name among those in service.
	if err := db.CreateTarget(ctx, newTarget(p.ID, "portal.example.ac.jp"), nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("duplicate in-service fqdn: %v", err)
	}
	// A second retirement of the same FQDN is fine: retired rows may repeat.
	again, _ := db.ListTargets(ctx, registry.ListTargetsOptions{})
	var reborn *registry.Target
	for _, x := range again {
		if x.FQDN == "portal.example.ac.jp" {
			reborn = x
		}
	}
	disable(t, db, reborn.ID)
	if _, err := db.RetireTarget(ctx, reborn.ID, "op", "a", retireEv()); err != nil {
		t.Fatalf("retire the re-registered target: %v", err)
	}
	var n int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM targets WHERE fqdn = 'portal.example.ac.jp' AND retired_at IS NOT NULL`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("retired rows with the fqdn = %d, %v", n, err)
	}
}

// TestMigrationV6RebuildsTargets opens a database written at schema
// version 5, with foreign keys enforced as Open does, and checks that the
// rebuild of targets keeps every row and every reference, keeps the
// uniqueness of names among targets in service, and lets a retired
// target's names be registered again.
func TestMigrationV6RebuildsTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	stmts := []string{`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`}
	for i := 0; i < 5; i++ {
		stmts = append(stmts, migrations[i], `INSERT INTO schema_migrations (version, applied_at) VALUES (`+string(rune('1'+i))+`, '2026-09-01T00:00:00Z')`)
	}
	const ts = `'2026-09-01T00:00:00Z'`
	stmts = append(stmts,
		`INSERT INTO policies (id, allowed_dns_suffixes, allow_wildcard, acme_binding, renew_before_days, key_type, max_sans, enabled, created_at, updated_at)
		   VALUES ('P1', '["example.ac.jp"]', 0, 'upki', 30, 'ec256', 4, 1, `+ts+`, `+ts+`)`,
		`INSERT INTO targets (id, fqdn, enabled, owner, policy_id, execution_binding, dns_binding, store_binding, created_at, updated_at, revision, additional_names)
		   VALUES ('T1', 'portal.example.ac.jp', 1, 'web', 'P1', 'local', 'dns', 'store', `+ts+`, `+ts+`, 3, '["www.example.ac.jp","cms.example.ac.jp"]'),
		          ('T2', 'wiki.example.ac.jp', 0, 'web', 'P1', 'local', 'dns', 'store', `+ts+`, `+ts+`, 1, '[]')`,
		`INSERT INTO target_names (name, target_id) VALUES ('portal.example.ac.jp','T1'),('www.example.ac.jp','T1'),('cms.example.ac.jp','T1'),('wiki.example.ac.jp','T2')`,
		`INSERT INTO runs (id, target_id, target_revision, status, requested_by, requested_at) VALUES ('R1', 'T1', 3, 'succeeded', 'op', `+ts+`), ('R2', 'T1', 3, 'running', 'op', `+ts+`)`,
		`INSERT INTO audit_events (id, time, actor, actor_authority, action, target_id, run_id, policy_id, detail) VALUES ('E1', `+ts+`, 'op', 'a', 'run.requested', 'T1', 'R1', '', 'x')`,
		`INSERT INTO acme_accounts (binding, scope, generation, status, key_id, sealed_payload, run_id, requested_by, requested_by_authority, created_at, updated_at) VALUES ('upki', 'T1', 1, 'provisioning', 'k', '{}', NULL, 'op', 'a', `+ts+`, `+ts+`)`,
	)
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("v5 setup: %v\n%s", err, s)
		}
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open v5 database: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if v, _ := db.Version(ctx); v != SchemaVersion || v < 6 {
		t.Fatalf("version = %d", v)
	}
	// Foreign keys are enforced again on the connection.
	var fk int
	if err := db.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d, %v", fk, err)
	}
	rows, err := db.db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Fatal("foreign_key_check reports violations after the migration")
	}
	rows.Close()
	// The references of runs and target_names still name targets, and
	// the old table is gone.
	for _, tbl := range []string{"runs", "target_names"} {
		var ddl string
		if err := db.db.QueryRow(`SELECT sql FROM sqlite_master WHERE name = ?`, tbl).Scan(&ddl); err != nil || !strings.Contains(ddl, "REFERENCES targets(id)") {
			t.Fatalf("%s ddl = %q, %v", tbl, ddl, err)
		}
	}
	var n int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'targets_v6%' AND type = 'table'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("leftover table: %d %v", n, err)
	}
	// The FK still bites in both directions.
	if _, err := db.db.Exec(`INSERT INTO runs (id, target_id, target_revision, status, requested_by, requested_at) VALUES ('R9', 'nope', 1, 'failed', 'op', '2026-09-01T00:00:00Z')`); err == nil {
		t.Fatal("a run of an unknown target was accepted")
	}

	// Every row survived, unchanged.
	t1, err := db.GetTarget(ctx, "T1")
	if err != nil || t1.FQDN != "portal.example.ac.jp" || t1.Revision != 3 || !t1.Enabled || t1.Retired() ||
		!slices.Equal(t1.AdditionalNames, []string{"www.example.ac.jp", "cms.example.ac.jp"}) {
		t.Fatalf("T1 = %+v, %v", t1, err)
	}
	if t2, err := db.GetTarget(ctx, "T2"); err != nil || t2.Enabled {
		t.Fatalf("T2 = %+v, %v", t2, err)
	}
	for table, want := range map[string]int{"targets": 2, "target_names": 4, "runs": 2, "audit_events": 1, "acme_accounts": 1, "policies": 1} {
		var got int
		if err := db.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&got); err != nil || got != want {
			t.Fatalf("%s rows = %d, %v; want %d", table, got, err, want)
		}
	}
	if runs, err := db.ListRuns(ctx, registry.ListRunsOptions{TargetID: "T1"}); err != nil || len(runs) != 2 {
		t.Fatalf("runs of T1 = %d, %v", len(runs), err)
	}
	if active, _ := db.ListActiveRuns(ctx); len(active) != 1 || active[0].ID != "R2" {
		t.Fatalf("active runs = %+v", active)
	}

	// The old behaviour holds for targets in service: a name is one
	// target's, the one-active-run index still works, deletes are refused.
	if err := db.CreateTarget(ctx, newTarget("P1", "portal.example.ac.jp"), nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("duplicate fqdn: %v", err)
	}
	dup := newTarget("P1", "new.example.ac.jp")
	dup.AdditionalNames = []string{"cms.example.ac.jp"}
	if err := db.CreateTarget(ctx, dup, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("duplicate additional name: %v", err)
	}
	if err := db.CreateRun(ctx, &registry.Run{TargetID: "T1", TargetRevision: 3, RequestedBy: "op"}, nil); !errors.Is(err, registry.ErrRunActive) {
		t.Fatalf("second active run: %v", err)
	}
	if _, err := db.db.Exec(`DELETE FROM targets`); err == nil {
		t.Fatal("DELETE FROM targets succeeded after the migration")
	}

	// T1 (running) cannot be retired; T2 can, and its name is reusable.
	if _, err := db.RetireTarget(ctx, "T1", "op", "a", retireEv()); !errors.Is(err, registry.ErrTargetEnabled) {
		t.Fatalf("retire T1: %v", err)
	}
	if _, err := db.RetireTarget(ctx, "T2", "op", "a", retireEv()); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateTarget(ctx, newTarget("P1", "wiki.example.ac.jp"), nil); err != nil {
		t.Fatalf("a retired target's name was not released: %v", err)
	}
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("targets = %d, %v", n, err)
	}
}
