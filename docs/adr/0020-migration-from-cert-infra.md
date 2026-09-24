# 0020: Migration from cert-infra — list import, shadow comparison, target-source flag

- Status: Accepted
- Date: 2026-09-24

## Context

The hosts ACME Conductor is meant to take over are renewed today by the
`cert-infra` deployment: a Bicep-defined Container Apps Job that runs
`lego` for a fixed list of names, the `targetDomains` parameter of
`infra/main.bicepparam`, and imports the results into Key Vault. That
list is the only thing the two systems share; the ACME account, the
certificates and their Key Vault names are each system's own. The
migration has to move the list into the Conductor's registry without a
flag day, let both systems be looked at side by side before the
Conductor issues anything, and be reversible by an operator who has
found a reason to go back. The `cert-infra` repository is a reference
and a source, not something this project changes.

## Decision

- **The list is the only input, and it carries names only.** A source
  is a `.bicepparam` file (read by a purpose-built reader that accepts
  the `param <name> = [ … ]` statement, comments and string literals,
  and refuses anything it would have to evaluate), a strictly decoded
  `TargetList` JSON document, or an inline list in the configuration.
  Every other property of an imported target — policy, execution, DNS
  and store bindings, owner — comes from `migration.profile` in the
  administrator's configuration. A host list can never choose a binding
  (principle 6), and the names it contributes are normalized and checked
  by the same code as the API and against the profile's policy.
- **Comparison before import, and import creates only.** A report sorts
  every name into `added`, `changed`, `missing`, `unchanged` or
  `rejected`. Import creates the `added` targets and nothing else: no
  update of a `changed` one, no deletion of a `missing` one
  ([ADR 0008](0008-no-purge-in-mvp.md)), nothing at all when any name is
  `rejected`. It is a dry run unless asked otherwise, idempotent, and
  each created target is a `target.imported` audit event naming the
  caller and the list.
- **A feature flag says who issues.** `migration.targetSource` is
  `registry` (the default and the end state: the scheduler plans and
  starts runs), `shadow` (it does not, and the configured list is
  compared with the registry at an interval, every change of outcome an
  audit event) or `iac` (it does not, full stop). Under `shadow` and
  `iac` the scheduler's plan and dispatch are inert and a run request is
  refused, so nothing the migration does issues a certificate or
  touches a DNS record or a cloud resource until the operator sets
  `registry`. The flag is configuration, read at start, never settable
  through the API; a rollback is the flag set back. `iac` and `shadow`
  stay supported for at least one minor release after the migration is
  declared complete.
- **The tooling lives in the Conductor.** The API gains
  `GET /migration`, `GET|POST /migration/diff` and
  `POST /migration/import`; a `migrate` command reads a source locally
  and drives them, so the operator's checkout of `cert-infra` is enough.
  The shadow comparison runs inside `serve` against the configured
  source. No second binary, no direct access to the database from the
  command line: the API's authentication, roles and audit apply to the
  migration as to everything else.

## Consequences

- The registry can be filled and reviewed while `cert-infra` keeps
  renewing, and the Conductor's first issuance is an explicit operator
  step. The two may overlap after the switch: separate ACME accounts and
  separate Key Vault object names make that safe, at the cost of one
  extra issuance per host against the CA's rate limits, and re-pointing
  consumers to the new objects is an operator step outside this
  repository.
- Shadow mode compares lists, not certificates: a host the old job
  stopped renewing is not noticed by it. That is a known limit, recorded
  in the threat model (T16).
- The Bicep reader is deliberately small; a `targetDomains` that ever
  needs evaluation is exported to a `TargetList` first, by hand or with
  `acme-conductor migrate list --output json`.
- A queued run that predates the flag stays queued under `iac`/`shadow`
  and starts when the flag returns to `registry`, unless cancelled. The
  flag pauses planning and dispatch; it does not rewrite history.
- The fixture the tests read mirrors the shape of `cert-infra`'s
  parameter file with example names; the reader is also run against the
  real file by hand before a release that touches it.

## See also

- [`docs/migration.md`](../migration.md)
- [`docs/conductor.md`](../conductor.md#migration)
- [`docs/threat-model.md`](../threat-model.md), T16
