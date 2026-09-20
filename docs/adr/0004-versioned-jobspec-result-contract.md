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
  keys, and trailing data are all rejected, any document over 64 KiB is
  rejected before decoding is even attempted, and nesting deeper than
  8 levels is rejected in linear time (`decode.go`).
- A `JobSpec` carries only opaque identifiers, a normalized FQDN, a policy
  snapshot, and **logical binding names** (`ACMERef`, `DNSRef`, `StoreRef`)
  — never a command, an image, an environment variable, a credential, or a
  cloud resource ID. Bindings are resolved to real configuration only on
  the Runner side, from Runner-side administrator configuration.
- A `Result` carries a fixed, append-only `ErrorCode` enum plus a
  length-bounded `error.summary` checked against a defense-in-depth
  secret-marker heuristic (not a secret detector — see "Validation vs
  authorization" below) — never a raw error, stack trace, command line, or
  environment dump.
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

### Validation vs authorization

The contract deliberately separates two things, and this ADR states the
split explicitly because it is easy to conflate them:

- **`JobSpec.Validate`** (`pkg/api/v1alpha1/validate.go`) checks
  **structure, normalization, and self-consistency**: constants and
  syntax, ranges, that `target.fqdn` and the `policy` snapshot's suffixes
  are already in canonical form, and that `target.fqdn` is consistent with
  the `policy` snapshot embedded in the same document. Every value it
  compares comes from the document itself, so a party that can produce or
  alter the whole document — including a compromised Conductor — can
  change `target.fqdn` and the `policy` snapshot together, or swap a
  binding name for another well-formed, registered one, and still pass
  `Validate`. This method is never called authorization, in code comments
  or here.
- **Authorization** is `policy.RunnerAuthorizationPolicy.Authorize`
  (`internal/policy/authorize.go`), evaluated by the Runner against
  configuration it trusts, not against anything carried in the `JobSpec`.
  Its five fields: `AllowedDnsSuffixes`, `AllowWildcard`,
  `AllowedACMEBindings`, `AllowedDNSBindings`, `AllowedStoreBindings`.
  Every list is deny-by-default. Phase 0 ships the type and the decision
  function with tests; loading the configuration and wiring `Authorize`
  into the Runner's execution path is Phase 1 work.
- **Signing's scope.** A future signed/authenticated `JobSpec` envelope
  (Phase 4) protects the document against tampering in transit between
  production and consumption. It does not address a compromised Conductor
  that legitimately produces a self-consistent but wrongful `JobSpec` —
  only the Runner-side `RunnerAuthorizationPolicy` bounds that case,
  because it never trusts anything from the document itself.
- **`storeObjectRef`** is a strict logical name
  (`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`, at most 128
  characters — covering Azure Key Vault certificate names, 1..127
  characters — with `..` rejected), never a URL, URI, path, or query
  string.
- **`error.summary`** is bounded in length and printable-character class,
  and checked against a defense-in-depth secret-marker heuristic
  (`secretMarkers`, case-insensitive where the marker's meaning does not
  depend on case) — not a secret detector. The control that actually keeps
  raw external output out of a `Result` is a Runner responsibility (Phase
  1): the Runner never copies a raw external command/SDK error, stdout, or
  stderr into `error.summary`; summaries come only from Runner-owned safe
  templates, and `error.code` is the primary machine-readable signal for
  API consumers.

See `docs/threat-model.md` (T1, T2, T5, "Assurance levels") and
`docs/architecture.md` ("Validation vs. authorization") for the full
reasoning.

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
