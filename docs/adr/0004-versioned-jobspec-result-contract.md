# 0004: Versioned JobSpec/Result contract

- Status: Accepted
- Date: 2026-09-20

## Context

The Conductor and the Runner are deliberately separate processes,
deployed and even scaled independently, with the only sanctioned
communication between them being one document produced by the Conductor
(`JobSpec`) and one document produced by the Runner (`Result`). This
boundary is also the system's main security control: it is where "API
input can never specify commands, images, resource IDs, credentials or
provider configuration" (see
[`docs/architecture.md`](../architecture.md#security-principles)) has to be
enforced. It therefore needs to be a contract in the fullest sense — typed,
versioned, and strictly validated on both sides — not an informally-agreed
JSON shape.

## Decision

- The contract lives in `pkg/api/v1alpha1` as Go types (`types.go`)
  carrying an explicit `apiVersion`
  (`acme-conductor.cits-nue.github.io/v1alpha1`) and `kind`
  (`CertificateReconcileJob` / `CertificateReconcileResult`) on every
  document.
- Documents are **strictly decoded**: unknown fields, duplicate JSON object
  keys, and trailing data are all rejected, and any document over 64 KiB is
  rejected before decoding is even attempted (`decode.go`).
- A `JobSpec` carries only opaque identifiers, a normalized FQDN, a policy
  snapshot, and **logical binding names** (`ACMERef`, `DNSRef`, `StoreRef`)
  — never a command, an image, an environment variable, a credential, or a
  cloud resource ID. Bindings are resolved to real configuration only on
  the Runner side, from Runner-side administrator configuration.
- A `Result` carries a fixed, append-only `ErrorCode` enum plus a
  length-bounded, secret-scanned `error.summary` — never a raw error,
  stack trace, command line, or environment dump.
- The Go validation in `pkg/api/v1alpha1` is authoritative. JSON Schemas
  under `schemas/v1alpha1/` mirror it for external tooling and human
  reference, and a test (`pkg/api/v1alpha1/schema_test.go` and its
  `testdata/` fixtures) keeps the two from drifting apart; `schemas/README.md`
  documents exactly which rules are Go-only because they are not
  expressible in JSON Schema (label-boundary suffix matching, cross-field
  rules, exact post-normalization duplicate detection, and so on).
- **Compatibility policy** (from `schemas/README.md`, restated here because
  it is part of this decision): `v1alpha1` is pre-release and may change
  incompatibly until Phase 1 ships. From Phase 1 onward, changes within a
  version must be additive only (new optional fields, new enum values);
  anything that would reject a previously valid document requires a new
  `apiVersion`/`kind` pair and a new schema file (e.g. `v1alpha2`), never an
  in-place edit of a shipped schema.

## Consequences

- A `JobSpec` or `Result` is either fully valid per this contract or
  rejected outright; there is no partial or best-effort acceptance path
  that a caller could exploit to smuggle in unsupported fields.
- Strict decoding closes the classic "two parsers disagree on a duplicate
  key" class of validation bypass, since the contract is checked once, in
  one place, before either side acts on it.
- Every wire-visible change to the contract must go through
  `pkg/api/v1alpha1`, its tests, and (once Phase 1 ships) the additive-only
  compatibility rule — this is intentionally more process than editing a
  loosely-typed JSON blob, in exchange for the contract being a reliable
  security boundary.
- Keeping the JSON Schema in sync with Go by test, rather than generating
  one from the other, means both have to be hand-maintained together; the
  sync test is what keeps that from silently drifting.
