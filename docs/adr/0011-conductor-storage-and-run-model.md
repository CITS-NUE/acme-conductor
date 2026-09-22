# 0011: Conductor storage and run model

- Status: Accepted
- Date: 2026-09-22

## Context

Phase 2 gives `acme-conductor` its first real state: the `Target`,
`CertificatePolicy`, `Run` and `AuditEvent` registries described in
[`docs/architecture.md`](../architecture.md#domain-model), a scheduler that
decides when a target is due, and a launcher that starts a Runner job. It
needs answers to several coupled questions:

- Where does that state live, and how is it kept consistent with the
  audit log that is supposed to describe it?
- How is double execution for one target prevented (threat model T7), and
  how is a run that was requested against an older version of a target
  kept from being actioned once the target has moved on?
- How does a Runner job actually get started in this phase, and what does
  the Conductor do about runs that were in flight when it stopped?
- What can the Conductor know about an issued certificate without ever
  reading the Certificate Store?

## Decision

- **SQLite, one file, one connection, explicit migrations.** The registry
  is a SQLite database (`modernc.org/sqlite`, pure Go, so the binaries stay
  `CGO_ENABLED=0` and distroless-static) behind the
  `registry.Registry` interface (`internal/conductor/registry`). Only
  `internal/conductor/sqlite` knows SQL. `database/sql` is limited to a
  single open connection, so every statement is serialized in process
  order and there are no lock-upgrade deadlocks to reason about; the MVP's
  write volume does not need more and a multi-replica Conductor is a
  non-goal. Migrations are a numbered list applied at open and recorded in
  `schema_migrations`; a database at a newer version than the binary is
  refused rather than downgraded. The file is created `0600` and a
  symbolic link at its path is refused. Identifiers are ULIDs, monotonic
  within one process, so every "newest first" listing and the "oldest
  queued run" claim order by id alone.
- **The schema enforces the model's invariants.** At most one active
  (`queued`/`starting`/`running`) run per target is a partial unique index,
  so a scheduler tick, an operator request and a restart cannot race a
  second Runner into existence for the same target whatever the code
  above the registry does. Audit events cannot be updated or deleted, and
  targets, runs and policies cannot be deleted — triggers abort those
  statements (see [ADR 0008](0008-no-purge-in-mvp.md)). No column can hold
  a secret (see [ADR 0005](0005-conductor-never-touches-secrets.md)).
- **Audit in the same transaction as the change.** Every mutating registry
  method takes the `AuditEvent` describing it and appends it in the same
  transaction, so the audit log can never describe a change that was
  rolled back or miss one that committed.
- **Optimistic locking on `Target.revision`.** Every update names the
  revision it was made against and fails with `stale_revision` otherwise;
  every successful update increments the revision. A run records the
  revision it was requested for, the `JobSpec` carries it, and before a
  queued run is started the target is re-read: a disabled target or a
  changed revision cancels the run instead of starting it. An operator
  request may also name the revision it acts on.
- **Run lifecycle.** `queued` (requested by the scheduler or an operator)
  → `starting` (claimed by the scheduler; target and policy re-checked,
  `JobSpec` built and validated) → `running` (a Runner execution exists;
  its platform id is recorded) → `succeeded` / `failed` / `cancelled`.
  The terminal state and every certificate-related field come from the
  Runner's `Result` only; the Conductor never derives them from anything
  else. A `Result` whose error code is `Cancelled` ends the run as
  `cancelled`; any other failure ends it as `failed`. When a launcher
  cannot produce a `Result` at all the run fails with a Conductor-owned
  summary (`Internal`, `Timeout` or `Cancelled` by cause); nothing the
  Runner printed is ever copied into a run record.
- **Due decision.** A target is due when it has never succeeded, when its
  revision differs from the one its last successful run was made for,
  when the last successful run reported no expiry, or when
  `expiresAt - renewBeforeDays` has passed. After a failed or cancelled
  run the target is held back for `retryBackoffSeconds`, doubled per
  consecutive failure up to `maxRetryBackoffSeconds`. The Runner remains
  the authority on whether anything needs to be issued (it asks the
  Store); a due run that finds the certificate current is a cheap `noop`.
- **Local-process launcher.** Phase 2 ships one `Launcher`: it writes the
  `JobSpec` into a private per-run directory, executes
  `acme-runner reconcile --job … --result … --config …` in its own process
  group with an explicit, from-scratch environment, reads the `Result`
  back with the strict contract decoder, checks that it names the run and
  target it was started for, and removes the directory. On cancellation
  the Runner receives `SIGTERM` (and normally reports `Cancelled`),
  `SIGKILL` after a grace period. It is a development shape: the only way
  a DNS credential can reach the Runner through it is `passthroughEnv`,
  which means the Conductor's own environment carries that credential.
- **One process owns a registry.** `serve` takes an exclusive advisory
  lock on `<database.path>.lock` before it opens the database, recovers
  anything or binds a port, and exits (code 2) without touching state
  when another process holds it. SQLite itself would let two processes
  share the file; what must be exclusive is the scheduler's view of which
  runs are in flight, since a second process would otherwise mark the
  first one's runs failed at its own startup and both would plan and
  dispatch against the same targets. The lock is `flock`-based like the
  Runner's (`internal/fslock`), so a crashed owner leaves nothing stale.
- **Recording follows the registry, not the scheduler's intent.** Each
  transition is written against the status the registry is known to hold
  (`expectedStatus`) and carries its audit event in the same transaction.
  A failed `starting → running` write while the Runner is already running
  is not fatal to the run: the outcome is later recorded against
  `starting`, after one more attempt to record the start. Terminal writes
  that fail transiently are retried with backoff for a bounded window;
  `ErrConflict` is resolved by re-reading the run and retrying against its
  actual status (a transition found already committed is not recorded
  twice). A run whose outcome still cannot be recorded is closed by the
  loop's sweep — every `starting`/`running` run the process is not
  executing becomes `failed`/"outcome unknown" — which is the same
  operation startup recovery performs, so a stranded run never holds a
  target's exclusion slot until the next restart.
- **Shutdown and recovery.** On shutdown the API stops, planning stops,
  and in-flight runs are given `server.shutdownGraceSeconds` to finish
  before they are cancelled. Runs still `starting` or `running` when a
  process starts (a crash, a hard kill, an expired grace) are marked
  `failed` with `Internal` "outcome unknown" and audited; they are never
  resumed, because the Conductor cannot know whether the Runner finished.
- **Policy changes apply at the next run.** Policies are not versioned;
  an update must keep every existing target valid, and its values are
  read when a target's next run is planned (`renewBeforeDays`) and
  executed (`keyType`, `acmeBinding`, copied into the `JobSpec`
  snapshot). The Runner reissues a current certificate whose key type
  differs from the requested one, so a `keyType` change rotates a target
  at its next run (manual or renewal). An `acmeBinding` change only
  selects the CA for the next order; forcing reissue of current
  certificates on a CA change is deferred until a phase needs it.
- **What the Conductor knows about a certificate** is exactly the last
  successful `Result` for the target: expiry, fingerprint and logical
  store object name. It never opens the Store.

## Alternatives considered

- **PostgreSQL or another server database.** Explicitly out of scope
  (docs/architecture.md, non-goals); SQLite keeps the MVP a single
  process with a single file to back up.
- **An in-process mutex for per-target exclusion instead of a schema
  constraint.** Rejected: it would hold only for one process and would
  not survive a restart with runs left in the database; the partial unique
  index holds regardless of which code path creates a run.
- **Resuming in-flight runs after a restart** by re-reading a `Result`
  file the Runner may have written. Rejected for the MVP: the Runner may
  still be running when the Conductor restarts, and marking it either way
  without knowing is a guess. Failing closed with an explicit "outcome
  unknown" and letting the next due check schedule a fresh run keeps the
  record honest; the on-disk stores tolerate the overlap (Phase 1 locks).
- **Letting the Conductor read the Store to learn expiry.** Rejected by
  [ADR 0005](0005-conductor-never-touches-secrets.md): the Conductor has
  no Store credential.

## Consequences

- Double issuance for one target from within one Conductor is prevented
  by construction. What remains (threat model T7) is a Runner orphaned by
  a hard kill of the Conductor still finishing while a later run for the
  same target starts; the Store and account state tolerate that, the
  duplicate ACME order does not go away.
- The database file is the whole state of the control plane: backup and
  restore are a file copy taken while the process is stopped (or a
  `sqlite3 .backup`), and rollback of a Phase 2 deployment is "stop,
  restore the file, start the previous binary" — a newer schema version is
  refused by an older binary, never silently downgraded.
- Every future schema change is a new numbered migration; shipped entries
  are never edited.
