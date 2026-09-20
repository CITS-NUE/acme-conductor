# 0008: No purge in the MVP

- Status: Accepted
- Date: 2026-09-20

## Context

Over a `Target`'s lifetime, an operator will eventually want to stop
managing a certificate for it. There are two different operations that
could be meant by that: stopping future issuance/renewal while keeping the
`Target`'s history, or permanently erasing the `Target` and everything
recorded about it (its `Run` history, its `AuditEvent`s). Conflating these
two — for example, implementing "disable" so that it also deletes audit
history, or expecting "disable" to delete a certificate that is still in
active use elsewhere — is a documented threat in its own right (see
[`docs/threat-model.md`](../threat-model.md), T11: disable vs. purge
confusion), and permanent deletion of audit data is a much bigger decision
than pausing management of a name.

## Decision

The MVP implements **disable only**. `Target.enabled = false` stops future
issuance and renewal for that target; it does not delete the `Target`
row, its `Run` history, or its `AuditEvent`s. There is no purge operation
of any kind in the MVP — no API endpoint, no scheduled job, no admin
tooling deletes a `Target`, a `Run`, or an `AuditEvent`.

If and when a purge operation is added, it must be:

- **a separate operation** from disable, requiring its own explicit
  action, never a side effect or an automatic consequence of disabling a
  target;
- **audited**, recording who purged what and when, in the same append-only
  audit log that records everything else; and
- scoped deliberately (what exactly is deleted — the `Target` row, its
  `Run` history, both? — and what, if anything, about a certificate
  already issued into the Certificate Store) rather than an unqualified
  "delete everything for this target."

## Consequences

- Operators can stop managing a name without any risk of losing the audit
  trail for it — "why was this certificate issued, who requested it, did
  it ever fail" remains answerable indefinitely for every `Target` that
  has ever existed.
- There is currently no way to actually remove a `Target`'s data from the
  system at all, even for legitimate reasons (e.g. GDPR-style data
  minimization requests, or simple database hygiene) — this is an accepted
  limitation of the MVP, deferred rather than solved, and tracked as a
  non-goal in [`docs/architecture.md`](../architecture.md#non-goals) until
  a future ADR designs purge properly.
- Any future work that touches deletion of a `Target`, `Run`, or
  `AuditEvent` should be read as implicitly requiring a new ADR, since it
  changes a decision recorded here.
