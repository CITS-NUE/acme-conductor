package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

func TestScopedACMEAccountsAreIndependent(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	const binding = "upki"
	scoped := func(scope string, gen int64) *registry.ACMEAccount {
		a := newACMEAccount(binding, gen)
		a.Scope = scope
		return a
	}
	// The binding's own account and two targets' accounts each start at
	// generation 1 and may each have a pending request at once.
	for _, a := range []*registry.ACMEAccount{newACMEAccount(binding, 1), scoped("T1", 1), scoped("T2", 1)} {
		if err := db.RequestACMEAccountProvisioning(ctx, a, `{"ciphertext":"`+a.Scope+`"}`, nil); err != nil {
			t.Fatalf("request %q: %v", a.Scope, err)
		}
	}
	if err := db.RequestACMEAccountProvisioning(ctx, scoped("T1", 2), `{}`, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("second pending request of T1: %v", err)
	}
	// A claim for T1 takes T1's payload and nothing else.
	claimed, sealed, err := db.ClaimACMEAccountProvisioning(ctx, binding, "T1", "run-1")
	if err != nil || claimed == nil || claimed.Scope != "T1" || sealed != `{"ciphertext":"T1"}` {
		t.Fatalf("claim T1 = %+v %q %v", claimed, sealed, err)
	}
	if err := db.CompleteACMEAccountProvisioning(ctx, binding, "T1", 1, "run-1", true, &registry.AuditEvent{Actor: "scheduler", Action: registry.AuditACMEAccountActivated}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		scope string
		want  int64
	}{{"T1", 1}, {"T2", 0}, {"", 0}} {
		if got, err := db.ActiveACMEAccountGeneration(ctx, binding, c.scope); err != nil || got != c.want {
			t.Fatalf("active %q = %d, %v; want %d", c.scope, got, err, c.want)
		}
	}
	// Completing T1 again under another scope's name is refused.
	if err := db.CompleteACMEAccountProvisioning(ctx, binding, "T2", 1, "run-1", true, &registry.AuditEvent{Actor: "scheduler"}); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("complete T2 with T1's run: %v", err)
	}
	// Cancel is per scope too.
	if err := db.CancelACMEAccountProvisioning(ctx, binding, "T2", 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.CancelACMEAccountProvisioning(ctx, binding, "T3", 1, nil); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("cancel of an account with no generation: %v", err)
	}

	own, err := db.ListACMEAccounts(ctx, binding, "")
	if err != nil || len(own) != 1 || own[0].Scope != "" {
		t.Fatalf("binding's own accounts = %+v, %v", own, err)
	}
	list, err := db.ListScopedACMEAccounts(ctx, binding)
	if err != nil || len(list) != 2 || list[0].Scope != "T1" || list[0].Status != registry.ACMEAccountActive || list[1].Scope != "T2" || list[1].Status != registry.ACMEAccountCancelled {
		t.Fatalf("scoped accounts = %+v, %v", list, err)
	}
}

// TestMigrationV5KeepsBindingAccounts opens a database written at schema
// version 4 with a pending and an active generation and checks that they
// survive the rebuild of acme_accounts as the binding's own account, that
// the table still refuses deletes, and that the one-pending rule still
// holds per account.
func TestMigrationV5KeepsBindingAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := append([]string{}, migrations[:4]...)
	stmts = append(stmts,
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (1, 'x'), (2, 'x'), (3, 'x'), (4, 'x')`,
		`INSERT INTO acme_accounts (binding, generation, status, key_id, sealed_payload, run_id, requested_by, requested_by_authority, created_at, updated_at, activated_at)
		   VALUES ('upki', 1, 'active', '0123456789abcdef', NULL, NULL, 'alice', 'idp', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z'),
		          ('upki', 2, 'provisioning', '0123456789abcdef', '{"ciphertext":"two"}', NULL, 'alice', 'idp', '2026-09-02T00:00:00Z', '2026-09-02T00:00:00Z', NULL)`,
	)
	for _, stmt := range stmts {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("v4 setup: %v\n%s", err, stmt)
		}
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open v4 database: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	list, err := db.ListACMEAccounts(ctx, "upki", "")
	if err != nil || len(list) != 2 || list[0].Generation != 2 || list[0].Status != registry.ACMEAccountProvisioning || list[1].Status != registry.ACMEAccountActive {
		t.Fatalf("accounts after migration = %+v, %v", list, err)
	}
	if _, sealed, err := db.ClaimACMEAccountProvisioning(ctx, "upki", "", "run-1"); err != nil || sealed != `{"ciphertext":"two"}` {
		t.Fatalf("pending payload after migration = %q, %v", sealed, err)
	}
	if err := db.RequestACMEAccountProvisioning(ctx, newACMEAccount("upki", 3), `{}`, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("one-pending rule after migration: %v", err)
	}
	if _, err := db.db.ExecContext(ctx, `DELETE FROM acme_accounts`); err == nil {
		t.Fatal("acme_accounts accepted a delete after migration")
	}
}
