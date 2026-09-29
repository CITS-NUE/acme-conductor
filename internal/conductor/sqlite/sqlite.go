// Package sqlite implements registry.Registry on a local SQLite database
// (modernc.org/sqlite, pure Go, no cgo).
//
// Design points:
//
//   - One connection. database/sql is limited to a single open connection,
//     so every statement and transaction is serialized in process order;
//     SQLite's own busy handling never comes into play and there is no
//     lock-upgrade deadlock. The MVP's write volume (a scheduler tick, an
//     operator API) does not need more, and a multi-replica Conductor is an
//     explicit non-goal.
//   - Versioned, explicit migrations, applied at Open and recorded in
//     schema_migrations. A database written by a newer schema is refused.
//   - The schema itself enforces the model's invariants where it can: at
//     most one active run per target (partial unique index), no deletion of
//     targets, runs or audit events and no update of audit events
//     (triggers), no column that could ever hold a secret.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"

	sqlite3 "modernc.org/sqlite"
)

// DB is the SQLite-backed registry.
type DB struct {
	db *sql.DB
}

var _ registry.Registry = (*DB)(nil)

// ErrSchemaTooNew reports a database written by a newer Conductor.
var ErrSchemaTooNew = errors.New("database schema is newer than this binary supports")

// Open opens (creating if needed) the database at path and applies pending
// migrations. The file is created with mode 0600 and a symbolic link at
// path is refused.
func Open(path string) (*DB, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open database file: %w", err)
	}
	f.Close()
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	d := &DB{db: db}
	if err := d.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// Ping checks that the database answers.
func (d *DB) Ping(ctx context.Context) error {
	var one int
	if err := d.db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

// migrations are applied in order; each runs in one transaction. Never
// edit a shipped entry: append a new one.
var migrations = []string{
	// 1: initial schema.
	`
CREATE TABLE policies (
  id                   TEXT PRIMARY KEY,
  allowed_dns_suffixes TEXT    NOT NULL,
  allow_wildcard       INTEGER NOT NULL,
  acme_binding         TEXT    NOT NULL,
  renew_before_days    INTEGER NOT NULL,
  key_type             TEXT    NOT NULL,
  max_sans             INTEGER NOT NULL,
  enabled              INTEGER NOT NULL,
  created_at           TEXT    NOT NULL,
  updated_at           TEXT    NOT NULL
);
CREATE TABLE targets (
  id                TEXT PRIMARY KEY,
  fqdn              TEXT    NOT NULL UNIQUE,
  enabled           INTEGER NOT NULL,
  owner             TEXT    NOT NULL,
  policy_id         TEXT    NOT NULL REFERENCES policies(id),
  execution_binding TEXT    NOT NULL,
  dns_binding       TEXT    NOT NULL,
  store_binding     TEXT    NOT NULL,
  created_at        TEXT    NOT NULL,
  updated_at        TEXT    NOT NULL,
  revision          INTEGER NOT NULL
);
CREATE INDEX targets_policy ON targets(policy_id);
CREATE TABLE runs (
  id                    TEXT PRIMARY KEY,
  target_id             TEXT    NOT NULL REFERENCES targets(id),
  target_revision       INTEGER NOT NULL,
  status                TEXT    NOT NULL,
  requested_by          TEXT    NOT NULL,
  requested_at          TEXT    NOT NULL,
  started_at            TEXT,
  finished_at           TEXT,
  action                TEXT    NOT NULL DEFAULT '',
  expires_at            TEXT,
  fingerprint_sha256    TEXT    NOT NULL DEFAULT '',
  store_object_ref      TEXT    NOT NULL DEFAULT '',
  error_code            TEXT    NOT NULL DEFAULT '',
  error_summary         TEXT    NOT NULL DEFAULT '',
  external_execution_id TEXT    NOT NULL DEFAULT ''
);
-- At most one active run per target (docs/threat-model.md, T7).
CREATE UNIQUE INDEX runs_one_active_per_target ON runs(target_id)
  WHERE status IN ('queued', 'starting', 'running');
CREATE INDEX runs_target_id ON runs(target_id, id);
CREATE INDEX runs_status ON runs(status, id);
CREATE TABLE audit_events (
  id        TEXT PRIMARY KEY,
  time      TEXT NOT NULL,
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  target_id TEXT NOT NULL DEFAULT '',
  run_id    TEXT NOT NULL DEFAULT '',
  policy_id TEXT NOT NULL DEFAULT '',
  detail    TEXT NOT NULL
);
CREATE INDEX audit_events_target ON audit_events(target_id, id);
CREATE INDEX audit_events_run ON audit_events(run_id, id);
-- Append-only audit log and no purge (docs/adr/0008).
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER targets_no_delete BEFORE DELETE ON targets
  BEGIN SELECT RAISE(ABORT, 'targets cannot be deleted'); END;
CREATE TRIGGER runs_no_delete BEFORE DELETE ON runs
  BEGIN SELECT RAISE(ABORT, 'runs cannot be deleted'); END;
CREATE TRIGGER policies_no_delete BEFORE DELETE ON policies
  BEGIN SELECT RAISE(ABORT, 'policies cannot be deleted'); END;
`,
	// 2: authority-qualified principals (docs/adr/0018). Rows written
	// before this version keep '' — they are not rewritten (audit_events
	// is append-only) and '' is documented as "recorded before the
	// authority was known".
	`
ALTER TABLE audit_events ADD COLUMN actor_authority TEXT NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN requested_by_authority TEXT NOT NULL DEFAULT '';
`,
	// 3: encrypted EAB provisioning and ACME account generations (issue
	// #42, docs/adr/0022). sealed_payload and run_id are cleared once a
	// generation reaches a terminal or attached-outcome state; at most
	// one pending (provisioning) and one active generation per binding.
	`
CREATE TABLE acme_accounts (
  binding                 TEXT    NOT NULL,
  generation              INTEGER NOT NULL CHECK (generation >= 1),
  status                  TEXT    NOT NULL CHECK (status IN ('provisioning','active','retired','failed','cancelled')),
  key_id                  TEXT    NOT NULL,
  sealed_payload          TEXT,
  run_id                  TEXT,
  requested_by            TEXT    NOT NULL,
  requested_by_authority  TEXT    NOT NULL,
  created_at              TEXT    NOT NULL,
  updated_at              TEXT    NOT NULL,
  activated_at            TEXT,
  PRIMARY KEY (binding, generation)
);
CREATE UNIQUE INDEX acme_accounts_one_pending ON acme_accounts(binding) WHERE status = 'provisioning';
CREATE UNIQUE INDEX acme_accounts_one_active  ON acme_accounts(binding) WHERE status = 'active';
CREATE INDEX acme_accounts_run ON acme_accounts(run_id) WHERE run_id IS NOT NULL;
CREATE TRIGGER acme_accounts_no_delete BEFORE DELETE ON acme_accounts
  BEGIN SELECT RAISE(ABORT, 'acme_accounts cannot be deleted'); END;
`,
	// 4: multi-name (SAN) certificates (issue #56, docs/adr/0024).
	// targets.additional_names is the JSON list read back with the target;
	// target_names holds every name of every target (the FQDN and each
	// additional name) once, so that no name can belong to two targets.
	// Rows for a target's additional names are replaced when they change;
	// the change itself is recorded in the audit log.
	`
ALTER TABLE targets ADD COLUMN additional_names TEXT NOT NULL DEFAULT '[]';
CREATE TABLE target_names (
  name      TEXT NOT NULL PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id)
);
CREATE INDEX target_names_target ON target_names(target_id);
INSERT INTO target_names (name, target_id) SELECT fqdn, id FROM targets;
`,
	// 5: ACME accounts scoped to one target (issue #57, docs/adr/0024).
	// scope is '' for a binding's own account (every row before this
	// version) and a target id for an account of that target; the key,
	// the one-pending and the one-active rules become per (binding,
	// scope). SQLite cannot change a primary key in place, so the table is
	// rebuilt: rows are copied as they are, then the old table is dropped
	// (DROP TABLE does not fire the no-delete trigger, which is recreated
	// on the new table).
	`
CREATE TABLE acme_accounts_v5 (
  binding                 TEXT    NOT NULL,
  scope                   TEXT    NOT NULL DEFAULT '',
  generation              INTEGER NOT NULL CHECK (generation >= 1),
  status                  TEXT    NOT NULL CHECK (status IN ('provisioning','active','retired','failed','cancelled')),
  key_id                  TEXT    NOT NULL,
  sealed_payload          TEXT,
  run_id                  TEXT,
  requested_by            TEXT    NOT NULL,
  requested_by_authority  TEXT    NOT NULL,
  created_at              TEXT    NOT NULL,
  updated_at              TEXT    NOT NULL,
  activated_at            TEXT,
  PRIMARY KEY (binding, scope, generation)
);
INSERT INTO acme_accounts_v5 (binding, scope, generation, status, key_id, sealed_payload, run_id, requested_by, requested_by_authority, created_at, updated_at, activated_at)
  SELECT binding, '', generation, status, key_id, sealed_payload, run_id, requested_by, requested_by_authority, created_at, updated_at, activated_at FROM acme_accounts;
DROP TABLE acme_accounts;
ALTER TABLE acme_accounts_v5 RENAME TO acme_accounts;
CREATE UNIQUE INDEX acme_accounts_one_pending ON acme_accounts(binding, scope) WHERE status = 'provisioning';
CREATE UNIQUE INDEX acme_accounts_one_active  ON acme_accounts(binding, scope) WHERE status = 'active';
CREATE INDEX acme_accounts_run ON acme_accounts(run_id) WHERE run_id IS NOT NULL;
CREATE TRIGGER acme_accounts_no_delete BEFORE DELETE ON acme_accounts
  BEGIN SELECT RAISE(ABORT, 'acme_accounts cannot be deleted'); END;
`,
	// 6: retire targets (docs/adr/0026). A retired target keeps its row
	// and history but is out of service for good and gives up its names:
	// retired_at (NULL while in service), retired_by and its authority.
	// targets.fqdn was NOT NULL UNIQUE, which would keep a retired
	// target's FQDN from ever being registered again, and an inline
	// UNIQUE cannot be dropped, so the table is rebuilt (SQLite's "Making
	// Other Kinds Of Table Schema Changes" procedure; see
	// foreignKeysOffMigrations: runs and target_names reference targets,
	// and this migration must run with foreign keys off): fqdn becomes
	// unique only among targets that are not retired. target_names keeps
	// only the names of targets in service (a retire deletes the rows;
	// the table has no delete trigger). A retired target's row cannot
	// change any more (trigger), so retirement is irreversible in the
	// schema itself.
	`
CREATE TABLE targets_v6 (
  id                   TEXT PRIMARY KEY,
  fqdn                 TEXT    NOT NULL,
  enabled              INTEGER NOT NULL,
  owner                TEXT    NOT NULL,
  policy_id            TEXT    NOT NULL REFERENCES policies(id),
  execution_binding    TEXT    NOT NULL,
  dns_binding          TEXT    NOT NULL,
  store_binding        TEXT    NOT NULL,
  created_at           TEXT    NOT NULL,
  updated_at           TEXT    NOT NULL,
  revision             INTEGER NOT NULL,
  additional_names     TEXT    NOT NULL DEFAULT '[]',
  retired_at           TEXT,
  retired_by           TEXT    NOT NULL DEFAULT '',
  retired_by_authority TEXT    NOT NULL DEFAULT ''
);
INSERT INTO targets_v6 (id, fqdn, enabled, owner, policy_id, execution_binding, dns_binding, store_binding, created_at, updated_at, revision, additional_names)
  SELECT id, fqdn, enabled, owner, policy_id, execution_binding, dns_binding, store_binding, created_at, updated_at, revision, additional_names FROM targets;
DROP TABLE targets;
ALTER TABLE targets_v6 RENAME TO targets;
CREATE INDEX targets_policy ON targets(policy_id);
CREATE UNIQUE INDEX targets_fqdn_in_service ON targets(fqdn) WHERE retired_at IS NULL;
CREATE TRIGGER targets_no_delete BEFORE DELETE ON targets
  BEGIN SELECT RAISE(ABORT, 'targets cannot be deleted'); END;
CREATE TRIGGER targets_retired_is_final BEFORE UPDATE ON targets WHEN OLD.retired_at IS NOT NULL
  BEGIN SELECT RAISE(ABORT, 'a retired target cannot be changed'); END;
`,
	// 7: optional policy display name. '' means none; a non-empty name is
	// unique (ASCII case-insensitively here; the registry also compares
	// with Unicode case folding before writing).
	`
ALTER TABLE policies ADD COLUMN name TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX policies_name ON policies(name COLLATE NOCASE) WHERE name <> '';
`,
}

// foreignKeysOffMigrations are the migrations that rebuild a table other
// tables reference. SQLite's procedure for that is: foreign keys off
// (PRAGMA foreign_keys is a no-op inside a transaction, so it is set on the
// connection before the transaction begins), create the new table, copy,
// DROP the old one, RENAME the new one to the old name, recreate indexes and
// triggers, PRAGMA foreign_key_check, commit, foreign keys back on. With
// foreign keys on, the implicit DELETE FROM of DROP TABLE would fail on the
// rows that still refer to the table. (RENAME of the new table does not touch the
// references to the old name in runs and target_names: they name "targets",
// and only references to the renamed table, "targets_v6", are rewritten.)
var foreignKeysOffMigrations = map[int]bool{6: true}

// SchemaVersion is the schema version this binary expects.
var SchemaVersion = len(migrations)

func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	var current int
	if err := d.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > SchemaVersion {
		return fmt.Errorf("%w: database is at version %d, binary supports %d", ErrSchemaTooNew, current, SchemaVersion)
	}
	for v := current + 1; v <= SchemaVersion; v++ {
		var err error
		if foreignKeysOffMigrations[v] {
			err = d.applyWithoutForeignKeys(ctx, v)
		} else {
			err = d.tx(ctx, func(tx *sql.Tx) error { return applyMigration(ctx, tx, v) })
		}
		if err != nil {
			return fmt.Errorf("apply migration %d: %w", v, err)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, tx *sql.Tx, v int) error {
	if _, err := tx.ExecContext(ctx, migrations[v-1]); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, v, fmtTime(time.Now()))
	return err
}

// applyWithoutForeignKeys applies migration v on one pinned connection with
// foreign keys switched off, then checks them before the commit: any row
// the migration left dangling rolls the whole migration back. Foreign keys
// are switched back on whatever happens.
func (d *DB) applyWithoutForeignKeys(ctx context.Context, v int) (err error) {
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("pin connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("switch foreign keys off: %w", err)
	}
	defer func() {
		if _, ferr := conn.ExecContext(ctx, `PRAGMA foreign_keys = ON`); ferr != nil && err == nil {
			err = fmt.Errorf("switch foreign keys on: %w", ferr)
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := applyMigration(ctx, tx, v); err != nil {
		_ = tx.Rollback()
		return err
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("foreign key check: %w", err)
	}
	var violations []string
	for rows.Next() {
		var table, parent string
		var rowid sql.NullInt64
		var fkid int
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			rows.Close()
			_ = tx.Rollback()
			return fmt.Errorf("foreign key check: %w", err)
		}
		violations = append(violations, fmt.Sprintf("%s -> %s (rowid %d)", table, parent, rowid.Int64))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("foreign key check: %w", err)
	}
	if len(violations) > 0 {
		_ = tx.Rollback()
		return fmt.Errorf("foreign key check failed after the migration: %s", strings.Join(violations, "; "))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// Version returns the applied schema version.
func (d *DB) Version(ctx context.Context) (int, error) {
	var v int
	err := d.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

func (d *DB) tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// ---- encoding helpers -------------------------------------------------

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("corrupt timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

func fmtOptTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: fmtTime(*t), Valid: true}
}

func parseOptTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid {
		return nil, nil
	}
	t, err := parseTime(s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// sqliteCode extracts the extended result code of a modernc.org/sqlite
// error, or 0.
func sqliteCode(err error) int {
	var e *sqlite3.Error
	if errors.As(err, &e) {
		return e.Code()
	}
	return 0
}

// SQLite extended result codes used to classify constraint failures.
const (
	codeConstraintForeignKey = 787
	codeConstraintPrimaryKey = 1555
	codeConstraintUnique     = 2067
)

func isUnique(err error) bool {
	c := sqliteCode(err)
	return c == codeConstraintUnique || c == codeConstraintPrimaryKey
}

func isForeignKey(err error) bool { return sqliteCode(err) == codeConstraintForeignKey }

// ---- audit ------------------------------------------------------------

func insertAudit(ctx context.Context, tx *sql.Tx, ev *registry.AuditEvent) error {
	if ev == nil {
		return nil
	}
	if ev.ID == "" {
		ev.ID = registry.NewID()
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if len(ev.Detail) > registry.MaxAuditDetailLength {
		ev.Detail = ev.Detail[:registry.MaxAuditDetailLength]
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id, time, actor, actor_authority, action, target_id, run_id, policy_id, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, fmtTime(ev.Time), ev.Actor, ev.ActorAuthority, string(ev.Action), ev.TargetID, ev.RunID, ev.PolicyID, ev.Detail)
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

// AppendAudit records an event on its own.
func (d *DB) AppendAudit(ctx context.Context, ev *registry.AuditEvent) error {
	return d.tx(ctx, func(tx *sql.Tx) error { return insertAudit(ctx, tx, ev) })
}

// ListAudit returns events newest first.
func (d *DB) ListAudit(ctx context.Context, opts registry.ListAuditOptions) ([]*registry.AuditEvent, error) {
	q := `SELECT id, time, actor, actor_authority, action, target_id, run_id, policy_id, detail FROM audit_events WHERE 1=1`
	var args []any
	if opts.TargetID != "" {
		q += ` AND target_id = ?`
		args = append(args, opts.TargetID)
	}
	if opts.RunID != "" {
		q += ` AND run_id = ?`
		args = append(args, opts.RunID)
	}
	if opts.PolicyID != "" {
		q += ` AND policy_id = ?`
		args = append(args, opts.PolicyID)
	}
	if opts.Before != "" {
		q += ` AND id < ?`
		args = append(args, opts.Before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit(opts.Limit))
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	var out []*registry.AuditEvent
	for rows.Next() {
		var ev registry.AuditEvent
		var ts, action string
		if err := rows.Scan(&ev.ID, &ts, &ev.Actor, &ev.ActorAuthority, &action, &ev.TargetID, &ev.RunID, &ev.PolicyID, &ev.Detail); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if ev.Time, err = parseTime(ts); err != nil {
			return nil, err
		}
		ev.Action = registry.AuditAction(action)
		out = append(out, &ev)
	}
	return out, rows.Err()
}

func limit(n int) int {
	if n <= 0 {
		return registry.DefaultListLimit
	}
	if n > registry.MaxListLimit {
		return registry.MaxListLimit
	}
	return n
}

// ---- policies ---------------------------------------------------------

const policyCols = `id, name, allowed_dns_suffixes, allow_wildcard, acme_binding, renew_before_days, key_type, max_sans, enabled, created_at, updated_at`

func scanPolicy(sc interface{ Scan(...any) error }) (*registry.Policy, error) {
	var p registry.Policy
	var suffixes, keyType, created, updated string
	var wildcard, enabled int
	if err := sc.Scan(&p.ID, &p.Name, &suffixes, &wildcard, &p.ACMEBinding, &p.RenewBeforeDays, &keyType, &p.MaxSANs, &enabled, &created, &updated); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(suffixes), &p.AllowedDnsSuffixes); err != nil {
		return nil, fmt.Errorf("corrupt policy %s suffix list: %w", p.ID, err)
	}
	p.AllowWildcard = wildcard != 0
	p.Enabled = enabled != 0
	p.KeyType = v1alpha1.KeyType(keyType)
	var err error
	if p.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if p.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	return &p, nil
}

// checkPolicyName returns ErrPolicyNameTaken if a policy other than id
// already has name (Unicode case-folded). An empty name is never taken.
func checkPolicyName(ctx context.Context, tx *sql.Tx, id, name string) error {
	if name == "" {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT name FROM policies WHERE name <> '' AND id <> ?`, id)
	if err != nil {
		return fmt.Errorf("check policy name: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var other string
		if err := rows.Scan(&other); err != nil {
			return err
		}
		if strings.EqualFold(other, name) {
			return fmt.Errorf("%w: %q", registry.ErrPolicyNameTaken, name)
		}
	}
	return rows.Err()
}

// CreatePolicy inserts p. ID, CreatedAt and UpdatedAt are assigned when
// empty.
func (d *DB) CreatePolicy(ctx context.Context, p *registry.Policy, ev *registry.AuditEvent) error {
	if p.ID == "" {
		p.ID = registry.NewID()
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = p.CreatedAt
	suffixes, err := json.Marshal(p.AllowedDnsSuffixes)
	if err != nil {
		return err
	}
	if ev != nil {
		ev.PolicyID = p.ID
	}
	return d.tx(ctx, func(tx *sql.Tx) error {
		if err := checkPolicyName(ctx, tx, p.ID, p.Name); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO policies (`+policyCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.ID, p.Name, string(suffixes), boolInt(p.AllowWildcard), p.ACMEBinding, p.RenewBeforeDays, string(p.KeyType), p.MaxSANs, boolInt(p.Enabled), fmtTime(p.CreatedAt), fmtTime(p.UpdatedAt))
		if err != nil {
			if isUnique(err) && strings.Contains(err.Error(), "policies.name") {
				return fmt.Errorf("%w: %q", registry.ErrPolicyNameTaken, p.Name)
			}
			if isUnique(err) {
				return fmt.Errorf("%w: policy %s exists", registry.ErrConflict, p.ID)
			}
			return fmt.Errorf("insert policy: %w", err)
		}
		return insertAudit(ctx, tx, ev)
	})
}

// GetPolicy returns the policy with id.
func (d *DB) GetPolicy(ctx context.Context, id string) (*registry.Policy, error) {
	p, err := scanPolicy(d.db.QueryRowContext(ctx, `SELECT `+policyCols+` FROM policies WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: policy %s", registry.ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	return p, nil
}

// ListPolicies returns every policy, oldest first.
func (d *DB) ListPolicies(ctx context.Context) ([]*registry.Policy, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+policyCols+` FROM policies ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()
	var out []*registry.Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePolicy replaces the mutable fields of p.
func (d *DB) UpdatePolicy(ctx context.Context, p *registry.Policy, ev *registry.AuditEvent) error {
	suffixes, err := json.Marshal(p.AllowedDnsSuffixes)
	if err != nil {
		return err
	}
	p.UpdatedAt = time.Now().UTC()
	if ev != nil {
		ev.PolicyID = p.ID
	}
	return d.tx(ctx, func(tx *sql.Tx) error {
		if err := checkPolicyName(ctx, tx, p.ID, p.Name); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE policies SET name = ?, allowed_dns_suffixes = ?, allow_wildcard = ?, acme_binding = ?, renew_before_days = ?, key_type = ?, max_sans = ?, enabled = ?, updated_at = ? WHERE id = ?`,
			p.Name, string(suffixes), boolInt(p.AllowWildcard), p.ACMEBinding, p.RenewBeforeDays, string(p.KeyType), p.MaxSANs, boolInt(p.Enabled), fmtTime(p.UpdatedAt), p.ID)
		if err != nil {
			if isUnique(err) && strings.Contains(err.Error(), "policies.name") {
				return fmt.Errorf("%w: %q", registry.ErrPolicyNameTaken, p.Name)
			}
			return fmt.Errorf("update policy: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: policy %s", registry.ErrNotFound, p.ID)
		}
		return insertAudit(ctx, tx, ev)
	})
}

// ---- targets ----------------------------------------------------------

const targetCols = `id, fqdn, enabled, owner, policy_id, execution_binding, dns_binding, store_binding, created_at, updated_at, revision, additional_names, retired_at, retired_by, retired_by_authority`

func scanTarget(sc interface{ Scan(...any) error }) (*registry.Target, error) {
	var t registry.Target
	var enabled int
	var created, updated, additional string
	var retired sql.NullString
	if err := sc.Scan(&t.ID, &t.FQDN, &enabled, &t.Owner, &t.PolicyRef, &t.ExecutionBinding, &t.DNSBinding, &t.StoreBinding, &created, &updated, &t.Revision, &additional, &retired, &t.RetiredBy, &t.RetiredByAuthority); err != nil {
		return nil, err
	}
	t.Enabled = enabled != 0
	if err := json.Unmarshal([]byte(additional), &t.AdditionalNames); err != nil {
		return nil, fmt.Errorf("corrupt additional names of target %s: %w", t.ID, err)
	}
	if len(t.AdditionalNames) == 0 {
		t.AdditionalNames = nil
	}
	var err error
	if t.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if t.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	if t.RetiredAt, err = parseOptTime(retired); err != nil {
		return nil, err
	}
	return &t, nil
}

// additionalNamesJSON encodes a target's additional names for the
// additional_names column; none is "[]".
func additionalNamesJSON(names []string) (string, error) {
	if names == nil {
		names = []string{}
	}
	data, err := json.Marshal(names)
	return string(data), err
}

// claimNames records names as belonging to targetID; names it already
// has are kept. ErrConflict names each name another target already has,
// and that target's FQDN.
func claimNames(ctx context.Context, tx *sql.Tx, targetID string, names []string) error {
	var taken, free []string
	for _, n := range names {
		var ownerID, ownerFQDN string
		err := tx.QueryRowContext(ctx, `SELECT n.target_id, t.fqdn FROM target_names n JOIN targets t ON t.id = n.target_id WHERE n.name = ?`, n).Scan(&ownerID, &ownerFQDN)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			free = append(free, n)
		case err != nil:
			return fmt.Errorf("check target names: %w", err)
		case ownerID != targetID:
			taken = append(taken, fmt.Sprintf("%q (target %s)", n, ownerFQDN))
		}
	}
	if len(taken) > 0 {
		return fmt.Errorf("%w: already a name of another target: %s", registry.ErrConflict, strings.Join(taken, ", "))
	}
	for _, n := range free {
		if _, err := tx.ExecContext(ctx, `INSERT INTO target_names (name, target_id) VALUES (?, ?)`, n, targetID); err != nil {
			if isUnique(err) {
				return fmt.Errorf("%w: %q is already a name of another target", registry.ErrConflict, n)
			}
			return fmt.Errorf("insert target name: %w", err)
		}
	}
	return nil
}

// CreateTarget inserts t at revision 1. ID and timestamps are assigned
// when empty. ErrConflict if the FQDN or an additional name is already a
// name of a target; ErrNotFound if the policy does not exist.
func (d *DB) CreateTarget(ctx context.Context, t *registry.Target, ev *registry.AuditEvent) error {
	additional, err := additionalNamesJSON(t.AdditionalNames)
	if err != nil {
		return err
	}
	if t.ID == "" {
		t.ID = registry.NewID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	t.UpdatedAt = t.CreatedAt
	t.Revision = 1
	if ev != nil {
		ev.TargetID = t.ID
	}
	return d.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO targets (id, fqdn, enabled, owner, policy_id, execution_binding, dns_binding, store_binding, created_at, updated_at, revision, additional_names) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			t.ID, t.FQDN, boolInt(t.Enabled), t.Owner, t.PolicyRef, t.ExecutionBinding, t.DNSBinding, t.StoreBinding, fmtTime(t.CreatedAt), fmtTime(t.UpdatedAt), t.Revision, additional)
		if err != nil {
			switch {
			case isUnique(err):
				return fmt.Errorf("%w: a target for fqdn %q already exists", registry.ErrConflict, t.FQDN)
			case isForeignKey(err):
				return fmt.Errorf("%w: policy %s", registry.ErrNotFound, t.PolicyRef)
			}
			return fmt.Errorf("insert target: %w", err)
		}
		if err := claimNames(ctx, tx, t.ID, append([]string{t.FQDN}, t.AdditionalNames...)); err != nil {
			return err
		}
		return insertAudit(ctx, tx, ev)
	})
}

// GetTarget returns the target with id.
func (d *DB) GetTarget(ctx context.Context, id string) (*registry.Target, error) {
	t, err := scanTarget(d.db.QueryRowContext(ctx, `SELECT `+targetCols+` FROM targets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: target %s", registry.ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get target: %w", err)
	}
	return t, nil
}

// ListTargets returns targets oldest first.
func (d *DB) ListTargets(ctx context.Context, opts registry.ListTargetsOptions) ([]*registry.Target, error) {
	q := `SELECT ` + targetCols + ` FROM targets WHERE 1=1`
	var args []any
	if !opts.IncludeRetired {
		q += ` AND retired_at IS NULL`
	}
	if opts.Enabled != nil {
		q += ` AND enabled = ?`
		args = append(args, boolInt(*opts.Enabled))
	}
	if opts.PolicyRef != "" {
		q += ` AND policy_id = ?`
		args = append(args, opts.PolicyRef)
	}
	q += ` ORDER BY id`
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer rows.Close()
	var out []*registry.Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpdateTarget applies t's mutable fields if the stored revision equals
// expectedRevision, bumping the revision.
func (d *DB) UpdateTarget(ctx context.Context, t *registry.Target, expectedRevision int64, ev *registry.AuditEvent) error {
	additional, err := additionalNamesJSON(t.AdditionalNames)
	if err != nil {
		return err
	}
	t.UpdatedAt = time.Now().UTC()
	if ev != nil {
		ev.TargetID = t.ID
	}
	return d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE targets SET enabled = ?, owner = ?, policy_id = ?, execution_binding = ?, dns_binding = ?, store_binding = ?, additional_names = ?, updated_at = ?, revision = revision + 1 WHERE id = ? AND revision = ? AND retired_at IS NULL`,
			boolInt(t.Enabled), t.Owner, t.PolicyRef, t.ExecutionBinding, t.DNSBinding, t.StoreBinding, additional, fmtTime(t.UpdatedAt), t.ID, expectedRevision)
		if err != nil {
			if isForeignKey(err) {
				return fmt.Errorf("%w: policy %s", registry.ErrNotFound, t.PolicyRef)
			}
			return fmt.Errorf("update target: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var retired sql.NullString
			err := tx.QueryRowContext(ctx, `SELECT retired_at FROM targets WHERE id = ?`, t.ID).Scan(&retired)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: target %s", registry.ErrNotFound, t.ID)
			}
			if err != nil {
				return fmt.Errorf("update target: %w", err)
			}
			if retired.Valid {
				return fmt.Errorf("%w: target %s", registry.ErrRetired, t.ID)
			}
			return fmt.Errorf("%w: target %s is not at revision %d", registry.ErrStaleRevision, t.ID, expectedRevision)
		}
		// The FQDN is immutable, so only the additional names' rows change:
		// drop this target's rows other than its FQDN, then claim the
		// current names (the FQDN's row is kept as is).
		var fqdn string
		if err := tx.QueryRowContext(ctx, `SELECT fqdn FROM targets WHERE id = ?`, t.ID).Scan(&fqdn); err != nil {
			return fmt.Errorf("update target: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM target_names WHERE target_id = ? AND name <> ?`, t.ID, fqdn); err != nil {
			return fmt.Errorf("update target names: %w", err)
		}
		if err := claimNames(ctx, tx, t.ID, append([]string{fqdn}, t.AdditionalNames...)); err != nil {
			return err
		}
		t.Revision = expectedRevision + 1
		return insertAudit(ctx, tx, ev)
	})
}

// RetireTarget implements registry.Registry (docs/adr/0026). Every check
// and every change is in one transaction: a run cannot be requested between
// the check for an active run and the retirement, and a failure leaves
// nothing half done.
func (d *DB) RetireTarget(ctx context.Context, id, by, authority string, ev *registry.AuditEvent) (*registry.Target, error) {
	now := time.Now().UTC()
	if ev != nil {
		ev.TargetID = id
	}
	err := d.tx(ctx, func(tx *sql.Tx) error {
		var enabled int
		var retired sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT enabled, retired_at FROM targets WHERE id = ?`, id).Scan(&enabled, &retired)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: target %s", registry.ErrNotFound, id)
		}
		if err != nil {
			return fmt.Errorf("retire target: %w", err)
		}
		switch {
		case retired.Valid:
			return fmt.Errorf("%w: target %s", registry.ErrRetired, id)
		case enabled != 0:
			return fmt.Errorf("%w: target %s must be disabled before it is retired", registry.ErrTargetEnabled, id)
		}
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE target_id = ? AND status IN ('queued', 'starting', 'running')`, id).Scan(&active); err != nil {
			return fmt.Errorf("retire target: %w", err)
		}
		if active > 0 {
			return fmt.Errorf("%w: target %s", registry.ErrRunActive, id)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE targets SET retired_at = ?, retired_by = ?, retired_by_authority = ?, updated_at = ?, revision = revision + 1 WHERE id = ?`,
			fmtTime(now), by, authority, fmtTime(now), id); err != nil {
			return fmt.Errorf("retire target: %w", err)
		}
		// Release every name (the FQDN's row included).
		if _, err := tx.ExecContext(ctx, `DELETE FROM target_names WHERE target_id = ?`, id); err != nil {
			return fmt.Errorf("release target names: %w", err)
		}
		// A pending request for the target's own ACME account can no
		// longer be carried by any run: withdraw it (rows are kept).
		rows, err := tx.QueryContext(ctx, `SELECT binding, generation FROM acme_accounts WHERE scope = ? AND status = ? ORDER BY binding, generation`, id, string(registry.ACMEAccountProvisioning))
		if err != nil {
			return fmt.Errorf("find pending acme account requests: %w", err)
		}
		type pending struct {
			binding    string
			generation int64
		}
		var cancel []pending
		for rows.Next() {
			var p pending
			if err := rows.Scan(&p.binding, &p.generation); err != nil {
				rows.Close()
				return err
			}
			cancel = append(cancel, p)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, p := range cancel {
			if _, err := tx.ExecContext(ctx, `UPDATE acme_accounts SET status = ?, sealed_payload = NULL, run_id = NULL, updated_at = ? WHERE binding = ? AND scope = ? AND generation = ? AND status = ?`,
				string(registry.ACMEAccountCancelled), fmtTime(now), p.binding, id, p.generation, string(registry.ACMEAccountProvisioning)); err != nil {
				return fmt.Errorf("cancel acme account request: %w", err)
			}
			cev := &registry.AuditEvent{
				Actor: by, ActorAuthority: authority, Action: registry.AuditACMEAccountProvisioningCancelled, TargetID: id,
				Detail: fmt.Sprintf("acme account provisioning cancelled: %s generation=%d (target retired)", accountDetail(p.binding, id), p.generation),
			}
			if err := insertAudit(ctx, tx, cev); err != nil {
				return err
			}
		}
		return insertAudit(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return d.GetTarget(ctx, id)
}

// ---- runs -------------------------------------------------------------

const runCols = `id, target_id, target_revision, status, requested_by, requested_by_authority, requested_at, started_at, finished_at, action, expires_at, fingerprint_sha256, store_object_ref, error_code, error_summary, external_execution_id`

func scanRun(sc interface{ Scan(...any) error }) (*registry.Run, error) {
	var r registry.Run
	var status, requested, action, code string
	var started, finished, expires sql.NullString
	if err := sc.Scan(&r.ID, &r.TargetID, &r.TargetRevision, &status, &r.RequestedBy, &r.RequestedByAuthority, &requested, &started, &finished, &action, &expires, &r.FingerprintSha256, &r.StoreObjectRef, &code, &r.ErrorSummary, &r.ExternalExecutionID); err != nil {
		return nil, err
	}
	r.Status = registry.RunStatus(status)
	r.Action = v1alpha1.ResultAction(action)
	r.ErrorCode = v1alpha1.ErrorCode(code)
	var err error
	if r.RequestedAt, err = parseTime(requested); err != nil {
		return nil, err
	}
	if r.StartedAt, err = parseOptTime(started); err != nil {
		return nil, err
	}
	if r.FinishedAt, err = parseOptTime(finished); err != nil {
		return nil, err
	}
	if r.ExpiresAt, err = parseOptTime(expires); err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateRun inserts r as queued.
func (d *DB) CreateRun(ctx context.Context, r *registry.Run, ev *registry.AuditEvent) error {
	if r.ID == "" {
		r.ID = registry.NewID()
	}
	if r.RequestedAt.IsZero() {
		r.RequestedAt = time.Now().UTC()
	}
	r.Status = registry.RunQueued
	if ev != nil {
		ev.RunID = r.ID
		ev.TargetID = r.TargetID
	}
	return d.tx(ctx, func(tx *sql.Tx) error {
		var retired sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT retired_at FROM targets WHERE id = ?`, r.TargetID).Scan(&retired); err == nil && retired.Valid {
			return fmt.Errorf("%w: target %s", registry.ErrRetired, r.TargetID)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO runs (id, target_id, target_revision, status, requested_by, requested_by_authority, requested_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			r.ID, r.TargetID, r.TargetRevision, string(r.Status), r.RequestedBy, r.RequestedByAuthority, fmtTime(r.RequestedAt))
		if err != nil {
			switch {
			case isUnique(err):
				return fmt.Errorf("%w: target %s", registry.ErrRunActive, r.TargetID)
			case isForeignKey(err):
				return fmt.Errorf("%w: target %s", registry.ErrNotFound, r.TargetID)
			}
			return fmt.Errorf("insert run: %w", err)
		}
		return insertAudit(ctx, tx, ev)
	})
}

// GetRun returns the run with id.
func (d *DB) GetRun(ctx context.Context, id string) (*registry.Run, error) {
	r, err := scanRun(d.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: run %s", registry.ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get run: %w", err)
	}
	return r, nil
}

func (d *DB) queryRuns(ctx context.Context, q string, args ...any) ([]*registry.Run, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()
	var out []*registry.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRuns returns runs newest first.
func (d *DB) ListRuns(ctx context.Context, opts registry.ListRunsOptions) ([]*registry.Run, error) {
	q := `SELECT ` + runCols + ` FROM runs WHERE 1=1`
	var args []any
	if opts.TargetID != "" {
		q += ` AND target_id = ?`
		args = append(args, opts.TargetID)
	}
	if len(opts.Statuses) > 0 {
		q += ` AND status IN (` + strings.TrimSuffix(strings.Repeat("?,", len(opts.Statuses)), ",") + `)`
		for _, s := range opts.Statuses {
			args = append(args, string(s))
		}
	}
	if opts.Before != "" {
		q += ` AND id < ?`
		args = append(args, opts.Before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit(opts.Limit))
	return d.queryRuns(ctx, q, args...)
}

// ListActiveRuns returns every non-terminal run, oldest first.
func (d *DB) ListActiveRuns(ctx context.Context) ([]*registry.Run, error) {
	return d.queryRuns(ctx, `SELECT `+runCols+` FROM runs WHERE status IN ('queued', 'starting', 'running') ORDER BY id`)
}

// ClaimQueuedRun moves the oldest queued run to starting.
func (d *DB) ClaimQueuedRun(ctx context.Context) (*registry.Run, error) {
	var claimed *registry.Run
	err := d.tx(ctx, func(tx *sql.Tx) error {
		r, err := scanRun(tx.QueryRowContext(ctx, `UPDATE runs SET status = ? WHERE id = (SELECT id FROM runs WHERE status = ? ORDER BY id LIMIT 1) RETURNING `+runCols, string(registry.RunStarting), string(registry.RunQueued)))
		if errors.Is(err, sql.ErrNoRows) {
			return registry.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("claim run: %w", err)
		}
		claimed = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

// UpdateRun replaces the mutable fields of r if its status is
// expectedStatus.
func (d *DB) UpdateRun(ctx context.Context, r *registry.Run, expectedStatus registry.RunStatus, ev *registry.AuditEvent) error {
	if !r.Status.Valid() {
		return fmt.Errorf("invalid run status %q", r.Status)
	}
	if ev != nil {
		ev.RunID = r.ID
		ev.TargetID = r.TargetID
	}
	return d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE runs SET status = ?, started_at = ?, finished_at = ?, action = ?, expires_at = ?, fingerprint_sha256 = ?, store_object_ref = ?, error_code = ?, error_summary = ?, external_execution_id = ? WHERE id = ? AND status = ?`,
			string(r.Status), fmtOptTime(r.StartedAt), fmtOptTime(r.FinishedAt), string(r.Action), fmtOptTime(r.ExpiresAt), r.FingerprintSha256, r.StoreObjectRef, string(r.ErrorCode), r.ErrorSummary, r.ExternalExecutionID, r.ID, string(expectedStatus))
		if err != nil {
			return fmt.Errorf("update run: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var status string
			err := tx.QueryRowContext(ctx, `SELECT status FROM runs WHERE id = ?`, r.ID).Scan(&status)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: run %s", registry.ErrNotFound, r.ID)
			}
			if err != nil {
				return fmt.Errorf("update run: %w", err)
			}
			return fmt.Errorf("%w: run %s is %s, not %s", registry.ErrConflict, r.ID, status, expectedStatus)
		}
		return insertAudit(ctx, tx, ev)
	})
}

// RunSummary computes the scheduling view of a target.
func (d *DB) RunSummary(ctx context.Context, targetID string) (*registry.TargetRunSummary, error) {
	var s registry.TargetRunSummary
	last, err := d.queryRuns(ctx, `SELECT `+runCols+` FROM runs WHERE target_id = ? ORDER BY id DESC LIMIT 1`, targetID)
	if err != nil {
		return nil, err
	}
	if len(last) == 1 {
		s.LastRun = last[0]
	}
	ok, err := d.queryRuns(ctx, `SELECT `+runCols+` FROM runs WHERE target_id = ? AND status = ? ORDER BY id DESC LIMIT 1`, targetID, string(registry.RunSucceeded))
	if err != nil {
		return nil, err
	}
	since := ""
	if len(ok) == 1 {
		s.LastSucceeded = ok[0]
		since = ok[0].ID
	}
	err = d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE target_id = ? AND id > ? AND status IN (?, ?)`, targetID, since, string(registry.RunFailed), string(registry.RunCancelled)).Scan(&s.ConsecutiveFailures)
	if err != nil {
		return nil, fmt.Errorf("count failures: %w", err)
	}
	return &s, nil
}

// ---- acme accounts (issue #42) ----------------------------------------

// schedulerActor and schedulerAuthority are used for the audit event this
// package writes itself, when the scheduler-driven operation's signature
// carries no *registry.AuditEvent (Claim). They mirror the values the
// scheduler package uses for its own run audit events (package scheduler
// cannot be imported here: it imports registry, which sqlite implements).
const (
	schedulerActor     = "scheduler"
	schedulerAuthority = "scheduler"
)

const acmeAccountCols = `binding, scope, generation, status, key_id, run_id, requested_by, requested_by_authority, created_at, updated_at, activated_at`

func scanACMEAccount(sc interface{ Scan(...any) error }) (*registry.ACMEAccount, error) {
	var a registry.ACMEAccount
	var status string
	var runID, activated sql.NullString
	var created, updated string
	if err := sc.Scan(&a.Binding, &a.Scope, &a.Generation, &status, &a.KeyID, &runID, &a.RequestedBy, &a.RequestedByAuthority, &created, &updated, &activated); err != nil {
		return nil, err
	}
	a.Status = registry.ACMEAccountStatus(status)
	a.RunID = runID.String
	var err error
	if a.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if a.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	if a.ActivatedAt, err = parseOptTime(activated); err != nil {
		return nil, err
	}
	return &a, nil
}

// ListACMEAccounts implements registry.Registry.
func (d *DB) ListACMEAccounts(ctx context.Context, binding, scope string) ([]*registry.ACMEAccount, error) {
	return d.queryACMEAccounts(ctx, `SELECT `+acmeAccountCols+` FROM acme_accounts WHERE binding = ? AND scope = ? ORDER BY generation DESC`, binding, scope)
}

// ListScopedACMEAccounts implements registry.Registry.
func (d *DB) ListScopedACMEAccounts(ctx context.Context, binding string) ([]*registry.ACMEAccount, error) {
	return d.queryACMEAccounts(ctx, `SELECT `+acmeAccountCols+` FROM acme_accounts WHERE binding = ? AND scope <> '' ORDER BY scope, generation DESC`, binding)
}

func (d *DB) queryACMEAccounts(ctx context.Context, q string, args ...any) ([]*registry.ACMEAccount, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list acme accounts: %w", err)
	}
	defer rows.Close()
	var out []*registry.ACMEAccount
	for rows.Next() {
		a, err := scanACMEAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan acme account: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RequestACMEAccountProvisioning implements registry.Registry.
func (d *DB) RequestACMEAccountProvisioning(ctx context.Context, a *registry.ACMEAccount, sealedJSON string, ev *registry.AuditEvent) error {
	now := time.Now().UTC()
	a.Status = registry.ACMEAccountProvisioning
	a.RunID = ""
	a.CreatedAt = now
	a.UpdatedAt = now
	a.ActivatedAt = nil
	return d.tx(ctx, func(tx *sql.Tx) error {
		if a.Scope != "" {
			var retired sql.NullString
			if err := tx.QueryRowContext(ctx, `SELECT retired_at FROM targets WHERE id = ?`, a.Scope).Scan(&retired); err == nil && retired.Valid {
				return fmt.Errorf("%w: target %s", registry.ErrRetired, a.Scope)
			}
		}
		var maxGen sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT MAX(generation) FROM acme_accounts WHERE binding = ? AND scope = ?`, a.Binding, a.Scope).Scan(&maxGen); err != nil {
			return fmt.Errorf("read max generation: %w", err)
		}
		want := int64(1)
		if maxGen.Valid {
			want = maxGen.Int64 + 1
		}
		if a.Generation != want {
			return fmt.Errorf("%w: %s next generation is %d, not %d", registry.ErrConflict, accountName(a.Binding, a.Scope), want, a.Generation)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO acme_accounts (binding, scope, generation, status, key_id, sealed_payload, run_id, requested_by, requested_by_authority, created_at, updated_at, activated_at)
			VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, NULL)`,
			a.Binding, a.Scope, a.Generation, string(a.Status), a.KeyID, sealedJSON, a.RequestedBy, a.RequestedByAuthority, fmtTime(a.CreatedAt), fmtTime(a.UpdatedAt))
		if err != nil {
			if isUnique(err) {
				return fmt.Errorf("%w: %s already has a pending provisioning request", registry.ErrConflict, accountName(a.Binding, a.Scope))
			}
			return fmt.Errorf("insert acme account: %w", err)
		}
		return insertAudit(ctx, tx, ev)
	})
}

// ClaimACMEAccountProvisioning implements registry.Registry.
func (d *DB) ClaimACMEAccountProvisioning(ctx context.Context, binding, scope string, runID string) (*registry.ACMEAccount, string, error) {
	var claimed *registry.ACMEAccount
	var sealedJSON string
	err := d.tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+acmeAccountCols+`, sealed_payload FROM acme_accounts
			WHERE binding = ? AND scope = ? AND status = ? AND run_id IS NULL ORDER BY generation LIMIT 1`,
			binding, scope, string(registry.ACMEAccountProvisioning))
		var status string
		var runIDCol, activated, sealed sql.NullString
		var created, updated string
		var a registry.ACMEAccount
		err := row.Scan(&a.Binding, &a.Scope, &a.Generation, &status, &a.KeyID, &runIDCol, &a.RequestedBy, &a.RequestedByAuthority, &created, &updated, &activated, &sealed)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("claim acme account: %w", err)
		}
		a.Status = registry.ACMEAccountStatus(status)
		if a.CreatedAt, err = parseTime(created); err != nil {
			return err
		}
		if a.UpdatedAt, err = parseTime(updated); err != nil {
			return err
		}
		if a.ActivatedAt, err = parseOptTime(activated); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE acme_accounts SET run_id = ?, updated_at = ? WHERE binding = ? AND scope = ? AND generation = ? AND status = ? AND run_id IS NULL`,
			runID, fmtTime(time.Now().UTC()), a.Binding, a.Scope, a.Generation, string(registry.ACMEAccountProvisioning))
		if err != nil {
			return fmt.Errorf("attach acme account: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Lost the race to another claim (cannot happen with this
			// package's single connection, but stay correct anyway).
			return nil
		}
		a.RunID = runID
		claimed = &a
		sealedJSON = sealed.String
		ev := &registry.AuditEvent{
			Actor: schedulerActor, ActorAuthority: schedulerAuthority, Action: registry.AuditACMEAccountProvisioningAttached, RunID: runID,
			Detail: fmt.Sprintf("acme account provisioning attached: %s generation=%d keyId=%s runId=%s", accountDetail(a.Binding, a.Scope), a.Generation, a.KeyID, runID),
		}
		return insertAudit(ctx, tx, ev)
	})
	if err != nil {
		return nil, "", err
	}
	if claimed == nil {
		return nil, "", nil
	}
	return claimed, sealedJSON, nil
}

// ReleaseACMEAccountProvisioning implements registry.Registry.
func (d *DB) ReleaseACMEAccountProvisioning(ctx context.Context, binding, scope string, generation int64, runID string) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE acme_accounts SET run_id = NULL, updated_at = ? WHERE binding = ? AND scope = ? AND generation = ? AND run_id = ? AND status = ?`,
			fmtTime(time.Now().UTC()), binding, scope, generation, runID, string(registry.ACMEAccountProvisioning))
		if err != nil {
			return fmt.Errorf("release acme account: %w", err)
		}
		return nil
	})
}

// CompleteACMEAccountProvisioning implements registry.Registry.
func (d *DB) CompleteACMEAccountProvisioning(ctx context.Context, binding, scope string, generation int64, runID string, registered bool, ev *registry.AuditEvent) error {
	now := time.Now().UTC()
	return d.tx(ctx, func(tx *sql.Tx) error {
		if registered {
			// Retire whatever generation of this account is currently
			// active before activating the new one: the partial unique
			// index allows at most one active row at a time, so the old
			// one must be gone before the new one can be set.
			retireRows, err := tx.QueryContext(ctx, `SELECT generation FROM acme_accounts WHERE binding = ? AND scope = ? AND status = ? AND generation != ?`, binding, scope, string(registry.ACMEAccountActive), generation)
			if err != nil {
				return fmt.Errorf("find previous active acme account: %w", err)
			}
			var previous []int64
			for retireRows.Next() {
				var g int64
				if err := retireRows.Scan(&g); err != nil {
					retireRows.Close()
					return err
				}
				previous = append(previous, g)
			}
			if err := retireRows.Err(); err != nil {
				return err
			}
			retireRows.Close()
			for _, g := range previous {
				if _, err := tx.ExecContext(ctx, `UPDATE acme_accounts SET status = ?, updated_at = ? WHERE binding = ? AND scope = ? AND generation = ?`, string(registry.ACMEAccountRetired), fmtTime(now), binding, scope, g); err != nil {
					return fmt.Errorf("retire previous acme account: %w", err)
				}
				rev := &registry.AuditEvent{
					Actor: ev.Actor, ActorAuthority: ev.ActorAuthority, Action: registry.AuditACMEAccountRetired, RunID: ev.RunID,
					Detail: fmt.Sprintf("acme account retired: %s generation=%d (superseded by generation=%d)", accountDetail(binding, scope), g, generation),
				}
				if err := insertAudit(ctx, tx, rev); err != nil {
					return err
				}
			}
		}
		var q string
		var args []any
		if registered {
			q = `UPDATE acme_accounts SET status = ?, sealed_payload = NULL, run_id = NULL, updated_at = ?, activated_at = ? WHERE binding = ? AND scope = ? AND generation = ? AND run_id = ? AND status = ?`
			args = []any{string(registry.ACMEAccountActive), fmtTime(now), fmtTime(now), binding, scope, generation, runID, string(registry.ACMEAccountProvisioning)}
		} else {
			q = `UPDATE acme_accounts SET status = ?, sealed_payload = NULL, run_id = NULL, updated_at = ? WHERE binding = ? AND scope = ? AND generation = ? AND run_id = ? AND status = ?`
			args = []any{string(registry.ACMEAccountFailed), fmtTime(now), binding, scope, generation, runID, string(registry.ACMEAccountProvisioning)}
		}
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("complete acme account: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: %s generation %d is not attached to run %s under status provisioning", registry.ErrConflict, accountName(binding, scope), generation, runID)
		}
		return insertAudit(ctx, tx, ev)
	})
}

// CancelACMEAccountProvisioning implements registry.Registry.
func (d *DB) CancelACMEAccountProvisioning(ctx context.Context, binding, scope string, generation int64, ev *registry.AuditEvent) error {
	now := time.Now().UTC()
	return d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE acme_accounts SET status = ?, sealed_payload = NULL, updated_at = ? WHERE binding = ? AND scope = ? AND generation = ? AND status = ? AND run_id IS NULL`,
			string(registry.ACMEAccountCancelled), fmtTime(now), binding, scope, generation, string(registry.ACMEAccountProvisioning))
		if err != nil {
			return fmt.Errorf("cancel acme account: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var exists int
			_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM acme_accounts WHERE binding = ? AND scope = ? AND generation = ?`, binding, scope, generation).Scan(&exists)
			if exists == 0 {
				return fmt.Errorf("%w: %s generation %d", registry.ErrNotFound, accountName(binding, scope), generation)
			}
			return fmt.Errorf("%w: %s generation %d is not an unattached pending request", registry.ErrConflict, accountName(binding, scope), generation)
		}
		return insertAudit(ctx, tx, ev)
	})
}

// ActiveACMEAccountGeneration implements registry.Registry.
func (d *DB) ActiveACMEAccountGeneration(ctx context.Context, binding, scope string) (int64, error) {
	var g int64
	err := d.db.QueryRowContext(ctx, `SELECT generation FROM acme_accounts WHERE binding = ? AND scope = ? AND status = ?`, binding, scope, string(registry.ACMEAccountActive)).Scan(&g)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("active acme account generation: %w", err)
	}
	return g, nil
}

// accountName names an account in an error: "acme binding "b"" or
// "acme binding "b" target t".
func accountName(binding, scope string) string {
	if scope == "" {
		return fmt.Sprintf("acme binding %q", binding)
	}
	return fmt.Sprintf("acme binding %q target %s", binding, scope)
}

// accountDetail names an account in an audit detail: "binding=b" or
// "binding=b scope=t".
func accountDetail(binding, scope string) string {
	if scope == "" {
		return "binding=" + binding
	}
	return "binding=" + binding + " scope=" + scope
}
