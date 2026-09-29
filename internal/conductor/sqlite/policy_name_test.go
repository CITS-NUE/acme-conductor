package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

func TestPolicyNameUnique(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	a, b, c := newPolicy(), newPolicy(), newPolicy()
	a.Name = "UPKI 本番"
	if err := db.CreatePolicy(ctx, a, nil); err != nil {
		t.Fatal(err)
	}
	// Names are compared case-insensitively (Unicode too).
	b.Name = "upki 本番"
	if err := db.CreatePolicy(ctx, b, nil); !errors.Is(err, registry.ErrPolicyNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	b.Name = "Émile"
	if err := db.CreatePolicy(ctx, b, nil); err != nil {
		t.Fatal(err)
	}
	c.Name = "éMILE"
	if err := db.CreatePolicy(ctx, c, nil); !errors.Is(err, registry.ErrPolicyNameTaken) {
		t.Fatalf("unicode duplicate: %v", err)
	}
	// Any number of unnamed policies; a policy may keep its own name.
	c.Name = ""
	d := newPolicy()
	if err := db.CreatePolicy(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePolicy(ctx, d, nil); err != nil {
		t.Fatal(err)
	}
	a.Name = "UPKI 本番"
	a.Enabled = false
	if err := db.UpdatePolicy(ctx, a, nil); err != nil {
		t.Fatalf("update keeping own name: %v", err)
	}
	d.Name = "UPKI 本番"
	if err := db.UpdatePolicy(ctx, d, nil); !errors.Is(err, registry.ErrPolicyNameTaken) {
		t.Fatalf("rename to a taken name: %v", err)
	}
	got, _ := db.GetPolicy(ctx, a.ID)
	if got.Name != "UPKI 本番" || got.Enabled {
		t.Fatalf("policy = %+v", got)
	}
}

// TestMigrationV7AddsPolicyName migrates a version 6 database holding
// policies: the rows survive and their name is ”.
func TestMigrationV7AddsPolicyName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	stmts := []string{`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`}
	for i := 0; i < 6; i++ {
		stmts = append(stmts, migrations[i], `INSERT INTO schema_migrations (version, applied_at) VALUES (`+string(rune('1'+i))+`, '2026-09-01T00:00:00Z')`)
	}
	const ts = `'2026-09-01T00:00:00Z'`
	stmts = append(stmts,
		`INSERT INTO policies (id, allowed_dns_suffixes, allow_wildcard, acme_binding, renew_before_days, key_type, max_sans, enabled, created_at, updated_at)
		   VALUES ('P1', '["example.ac.jp"]', 0, 'upki', 30, 'ec256', 4, 1, `+ts+`, `+ts+`), ('P2', '["example.org"]', 1, 'upki', 20, 'ec384', 1, 0, `+ts+`, `+ts+`)`,
		`INSERT INTO targets (id, fqdn, enabled, owner, policy_id, execution_binding, dns_binding, store_binding, created_at, updated_at, revision)
		   VALUES ('T1', 'portal.example.ac.jp', 1, 'web', 'P1', 'local', 'dns', 'store', `+ts+`, `+ts+`, 1)`,
	)
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("v6 setup: %v\n%s", err, s)
		}
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open v6 database: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if v, _ := db.Version(ctx); v != SchemaVersion || v < 7 {
		t.Fatalf("version = %d", v)
	}
	list, err := db.ListPolicies(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("policies = %v, %v", list, err)
	}
	for _, p := range list {
		if p.Name != "" {
			t.Fatalf("policy %s name = %q, want ''", p.ID, p.Name)
		}
	}
	if list[1].AllowWildcard != true || list[1].Enabled {
		t.Fatalf("row not kept: %+v", list[1])
	}
	if _, err := db.GetTarget(ctx, "T1"); err != nil {
		t.Fatal(err)
	}
	// Unnamed policies coexist; the first name is accepted.
	list[0].Name = "本番"
	if err := db.UpdatePolicy(ctx, list[0], nil); err != nil {
		t.Fatal(err)
	}
}
