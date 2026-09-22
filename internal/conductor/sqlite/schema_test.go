package sqlite

import (
	"context"
	"regexp"
	"testing"
)

// forbiddenColumnRe lists column names the Conductor's schema must never
// have: the Conductor stores no private key, certificate body, PFX, or
// cloud credential (docs/architecture.md, invariants).
var forbiddenColumnRe = regexp.MustCompile(`(?i)(private|secret|password|passphrase|token|credential|pem|pfx|hmac|eab|cert(ificate)?_?(body|data|blob|pem))`)

// TestSchemaHasNoSecretBearingColumns walks every table and column of a
// freshly migrated database.
func TestSchemaHasNoSecretBearingColumns(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	rows, err := db.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if len(tables) < 5 {
		t.Fatalf("unexpectedly few tables: %v", tables)
	}
	seen := map[string]bool{}
	for _, table := range tables {
		cols, err := db.db.QueryContext(ctx, `SELECT name, type FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		for cols.Next() {
			var name, typ string
			if err := cols.Scan(&name, &typ); err != nil {
				t.Fatal(err)
			}
			seen[table] = true
			if forbiddenColumnRe.MatchString(name) {
				t.Errorf("table %s has a secret-bearing column %q", table, name)
			}
			if typ == "BLOB" {
				t.Errorf("table %s column %q is a BLOB; the Conductor stores no opaque blobs", table, name)
			}
		}
		cols.Close()
	}
	for _, want := range []string{"policies", "targets", "runs", "audit_events", "schema_migrations"} {
		if !seen[want] {
			t.Errorf("expected table %s is missing", want)
		}
	}
}
