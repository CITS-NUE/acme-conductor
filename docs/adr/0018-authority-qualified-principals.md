# 0018: Audit principals are qualified by their authority

- Status: Accepted
- Date: 2026-09-24

## Context

Phase 5 ([ADR 0016](0016-oidc-bearer-auth-and-gui.md)) records a stable
claim of the caller's token as the audit actor and as `requestedBy`:
`sub` by default, `oid` for Microsoft Entra ID. That value is stable, but
it is unique only within the provider that asserted it. Two issuers can
each assert the same subject string; an Entra ID `oid` is scoped to its
tenant; `sub` is often pairwise per client. One Conductor trusts one
issuer at a time, so this is not an authorization problem today. It is a
record-keeping problem the moment a deployment changes tenant or
provider, restores an old registry under a new configuration, or
compares records from two deployments: the actor string alone no longer
says who acted. `localhost-dev` and the scheduler write actors too, and
they are not OIDC subjects at all.

## Decision

- **A principal is `(authority, name)`, and both are recorded.**
  `api.Principal` carries `Authority` next to `Name`; every audit event
  stores `actorAuthority` next to `actor`, every run
  `requestedByAuthority` next to `requestedBy`. The authority is the
  namespace within which the name is unique: the OIDC issuer URL
  (`server.auth.oidc.issuer`, which for Entra ID contains the tenant),
  the fixed string `localhost-dev` for that mode, and the fixed string
  `scheduler` for automatic runs. The term is *authority* rather than
  *issuer* because two of the three are not issuers; it is the thing
  that vouches for the name.
- **Structured, not concatenated.** The authority is its own column and
  its own JSON field, not a prefix folded into the actor string. A
  concatenation would need an escaping rule, would break every existing
  consumer of `actor`, and would make "same subject, different
  authority" a string-parsing question.
- **Additive API.** `actorAuthority` and `requestedByAuthority` are new
  fields; `actor` and `requestedBy` keep their meaning and shape. The
  GUI shows the authority next to the actor in the audit log and on the
  run page.
- **Legacy rows stay empty.** Schema version 2 adds the two columns with
  default `''`. Rows written under version 1 are not backfilled: the
  audit log is append-only by trigger, and inventing an authority for a
  row that was recorded without one would be a fabrication. `''` means
  "recorded before the Conductor stored the authority"; an operator who
  needs to attribute such rows knows which issuer the deployment used
  then. New rows always carry the authority.
- **Rollback is the schema rule that already exists.** A binary older
  than schema version 2 refuses to open a version-2 database; restore
  the backup taken before the upgrade, as `docs/conductor.md` says.

## Consequences

- Audit and run attribution is self-contained: a record names its
  principal unambiguously after `server.auth.oidc.issuer` changes, and
  two deployments' records can be compared. Tests cover two issuers
  asserting the same subject and show the recorded actors differ in the
  authority.
- The threat model's T14 attribution argument now rests on the pair.
- Filtering the audit log by authority is not offered; there is one
  authority per deployment at a time, and the column exists to keep old
  records honest, not to partition current ones.
