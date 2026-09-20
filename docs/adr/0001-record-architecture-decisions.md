# 0001: Record architecture decisions

- Status: Accepted
- Date: 2026-09-20

## Context

ACME Conductor makes a number of decisions early — before most of the code
exists — that are expensive to reverse later: the binary split, how ACME is
performed, what the control-plane/data-plane contract looks like, and how
secrets and identities are separated. Without a record, later contributors
(and later versions of the same contributors) will not know *why* these
choices were made, and will be tempted to relitigate or silently violate
them.

## Decision

We record architecturally significant decisions as Architecture Decision
Records (ADRs) under `docs/adr/`, using a lightweight
[MADR](https://adr.github.io/madr/)-like format: **Status**, **Context**,
**Decision**, **Consequences**. Each ADR is numbered sequentially and dated.
`docs/adr/README.md` indexes them.

An ADR is superseded, not edited in place, when a later decision changes
it: the old ADR's Status is updated to note what supersedes it, and a new
ADR is added.

## Consequences

- Every non-trivial architectural choice gets a short, durable, dated
  record instead of living only in a pull request description or a
  person's memory.
- Reviewers can point to an ADR number instead of re-explaining a
  constraint (e.g. "see ADR 0005" instead of re-arguing why the Conductor
  has no DNS credential).
- This adds a small amount of process overhead: a change that reverses an
  earlier ADR needs a new ADR, not just a code diff.
