package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

func TestTargetAdditionalNames(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	p, wiki := seed(t, db)

	portal := newTarget(p.ID, "portal.example.ac.jp")
	portal.AdditionalNames = []string{"www.example.ac.jp", "cms.example.ac.jp"}
	if err := db.CreateTarget(ctx, portal, nil); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetTarget(ctx, portal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.AdditionalNames, portal.AdditionalNames) {
		t.Fatalf("additional names = %v, want %v (in order)", got.AdditionalNames, portal.AdditionalNames)
	}
	if again, _ := db.GetTarget(ctx, wiki.ID); again.AdditionalNames != nil {
		t.Fatalf("single-name target reads back additional names %v", again.AdditionalNames)
	}

	// No name belongs to two targets, whichever side it is on.
	for _, tc := range []struct {
		name string
		mk   func() *registry.Target
	}{
		{"fqdn is another target's additional name", func() *registry.Target { return newTarget(p.ID, "www.example.ac.jp") }},
		{"additional name is another target's fqdn", func() *registry.Target {
			tg := newTarget(p.ID, "new.example.ac.jp")
			tg.AdditionalNames = []string{"wiki.example.ac.jp"}
			return tg
		}},
		{"additional name is another target's additional name", func() *registry.Target {
			tg := newTarget(p.ID, "new.example.ac.jp")
			tg.AdditionalNames = []string{"cms.example.ac.jp"}
			return tg
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg := tc.mk()
			if err := db.CreateTarget(ctx, tg, nil); !errors.Is(err, registry.ErrConflict) {
				t.Fatalf("CreateTarget = %v, want ErrConflict", err)
			}
			// Nothing of the refused target remains.
			if _, err := db.GetTarget(ctx, tg.ID); !errors.Is(err, registry.ErrNotFound) {
				t.Fatalf("refused target was stored: %v", err)
			}
		})
	}

	// Updating replaces the additional names and frees the dropped ones.
	got.AdditionalNames = []string{"cms.example.ac.jp", "blog.example.ac.jp"}
	if err := db.UpdateTarget(ctx, got, got.Revision, nil); err != nil {
		t.Fatal(err)
	}
	www := newTarget(p.ID, "www.example.ac.jp")
	if err := db.CreateTarget(ctx, www, nil); err != nil {
		t.Fatalf("a dropped name is not free again: %v", err)
	}
	// An update that takes another target's name is refused as a whole.
	wikiNow, _ := db.GetTarget(ctx, wiki.ID)
	wikiNow.Owner = "changed"
	wikiNow.AdditionalNames = []string{"blog.example.ac.jp"}
	if err := db.UpdateTarget(ctx, wikiNow, wikiNow.Revision, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("UpdateTarget = %v, want ErrConflict", err)
	}
	if after, _ := db.GetTarget(ctx, wiki.ID); after.Owner == "changed" || after.Revision != wikiNow.Revision {
		t.Fatalf("refused update was applied: %+v", after)
	}
	// Removing every additional name makes it a single-name target again.
	cur, _ := db.GetTarget(ctx, portal.ID)
	cur.AdditionalNames = nil
	if err := db.UpdateTarget(ctx, cur, cur.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if after, _ := db.GetTarget(ctx, portal.ID); after.AdditionalNames != nil || after.FQDN != "portal.example.ac.jp" {
		t.Fatalf("after clearing: %+v", after)
	}
	blog := newTarget(p.ID, "blog.example.ac.jp")
	if err := db.CreateTarget(ctx, blog, nil); err != nil {
		t.Fatalf("a cleared name is not free again: %v", err)
	}
	// The FQDN itself stays claimed through every update.
	if err := db.CreateTarget(ctx, newTarget(p.ID, "portal.example.ac.jp"), nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("fqdn of an updated target: %v, want ErrConflict", err)
	}
}

// TestMigrationV4ClaimsExistingFQDNs opens a database written at schema
// version 3 and checks that every existing target's FQDN is claimed, so a
// new target cannot take it as an additional name.
func TestMigrationV4ClaimsExistingFQDNs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := append([]string{}, migrations[:3]...)
	stmts = append(stmts,
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (1, '2026-09-01T00:00:00Z'), (2, '2026-09-01T00:00:00Z'), (3, '2026-09-01T00:00:00Z')`,
		`INSERT INTO policies (id, allowed_dns_suffixes, allow_wildcard, acme_binding, renew_before_days, key_type, max_sans, enabled, created_at, updated_at)
		   VALUES ('01JPOLICY0000000000000000A', '["example.ac.jp"]', 0, 'fake-ca', 30, 'ec256', 1, 1, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`,
		`INSERT INTO targets (id, fqdn, enabled, owner, policy_id, execution_binding, dns_binding, store_binding, created_at, updated_at, revision)
		   VALUES ('01JTARGET0000000000000000A', 'wiki.example.ac.jp', 1, 'web', '01JPOLICY0000000000000000A', 'local', 'fake-dns', 'filesystem-dev', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', 1)`,
	)
	for _, stmt := range stmts {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("v3 setup: %v\n%s", err, stmt)
		}
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open v3 database: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	legacy, err := db.GetTarget(ctx, "01JTARGET0000000000000000A")
	if err != nil || legacy.AdditionalNames != nil || legacy.Revision != 1 {
		t.Fatalf("legacy target = %+v, %v", legacy, err)
	}
	tg := newTarget("01JPOLICY0000000000000000A", "portal.example.ac.jp")
	tg.AdditionalNames = []string{"wiki.example.ac.jp"}
	if err := db.CreateTarget(ctx, tg, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("CreateTarget taking a pre-migration FQDN = %v, want ErrConflict", err)
	}
}
