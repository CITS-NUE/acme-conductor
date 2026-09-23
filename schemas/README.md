# ACME Conductor JSON Schemas

This directory holds JSON Schema (draft 2020-12) documents that describe the
wire contract defined in Go by `pkg/api/v1alpha1`: the `JobSpec`
(`jobspec.schema.json`), the `Result` (`result.schema.json`) and, since
Phase 4, the signed job envelope (`signedjob.schema.json`), whose
`payload` is a base64url-encoded `JobSpec` document.

## Version policy

- `v1alpha1` is a pre-release contract version: it may change **incompatibly**
  (fields renamed or removed, validation tightened or loosened, new required
  fields) at any time until Phase 1 ships and the contract reaches `v1`.
- Once Phase 1 ships, changes within a version (e.g. further `v1alpha1`
  revisions, and every version from `v1` onward) must be **additive only**:
  new optional fields and new enum values are fine; removing or renaming a
  field, or narrowing an existing constraint in a way that rejects previously
  valid documents, requires a new version.
- A breaking change always means a new `kind`/`apiVersion` pair and a new
  schema file (e.g. `v1alpha2`), never an in-place edit of a shipped schema.

## Go validation is authoritative

These schemas are a **best-effort, human- and tool-readable approximation**
of the rules enforced by `pkg/api/v1alpha1/validate.go` and
`internal/policy/fqdn.go`. The Go code is the source of truth and is
strictly stricter than the schema. In particular, the following are checked
only by Go, not by JSON Schema:

- FQDN normalization (a value must already be in canonical form).
- Label-boundary suffix matching (`evil-example.ac.jp` is not under
  `example.ac.jp`, even though it matches the suffix as a raw string).
- Rejection of an all-numeric top-level label and of `xn--` (IDNA) labels.
- The cross-field rule that a wildcard FQDN requires `policy.allowWildcard`.
- Exact (post-normalization) duplicate detection in
  `policy.allowedDnsSuffixes` (JSON Schema's `uniqueItems` only catches
  duplicates that are already byte-identical strings).
- The `finishedAt >= startedAt` ordering rule on `Result`.
- Rejection of the zero `time.Time` value for `expiresAt`.
- Rejection of non-printable characters (control characters, Unicode
  line/paragraph separators, bidi/format characters) and known secret
  markers (PEM headers, bearer tokens, `password=`, `sig=`, etc.) in
  free-text fields such as `error.summary`. Header- and key=value-shaped
  markers (`bearer `, `basic `, `authorization:`, `password=`, `sig=`, and
  similar) are matched case-insensitively; token-prefix markers whose case
  is part of the format (`eyJ`, `AKIA`, `ghp_`, ...) are matched exactly.
  This marker check is a best-effort, defense-in-depth heuristic, not a
  secret detector: it cannot recognize an arbitrary secret or an unknown
  format, and it does not by itself make a free-text field safe to fill
  with raw external output. The real control is that a Runner never copies
  raw external output into a Result at all; `error.summary` must come from
  Runner-owned templates.
- Everything inside the signed envelope's `protected` header (the fixed
  `alg`, the `kid` format, the validity window, the nonce), the
  signature itself, and the decoding of `payload` as a `JobSpec`: the
  schema sees `protected`, `payload` and `signature` as opaque base64url
  strings (`TestSignedJobFixtures`, with its own `schema-accepts.txt`).
- Strict decoding: unknown fields, duplicate JSON object keys and trailing
  data after the document are always rejected by
  `pkg/api/v1alpha1/decode.go`, regardless of what a particular JSON Schema
  validator implementation enforces for `additionalProperties` or malformed
  JSON.

A document that fails the JSON Schema is never expected to be accepted by
Go. The converse is not guaranteed: some invalid documents are rejected by
Go but accepted by the schema, because the rule above is not expressible in
JSON Schema. Never treat "passes the schema" as "valid" on its own.

## The sync test

`pkg/api/v1alpha1/schema_test.go` keeps the schemas and the Go code from
drifting apart:

- Every fixture under `pkg/api/v1alpha1/testdata/jobspec/valid/` and
  `testdata/result/valid/` must pass both the JSON Schema and
  `v1alpha1.DecodeJobSpec` / `v1alpha1.DecodeResult`.
- Every fixture under `.../invalid/` must be rejected by Go decoding, and
  must also be rejected by the JSON Schema **unless** it is listed in the
  matching `schema-accepts.txt` allowlist next to it. That allowlist
  documents, file by file, exactly which Go-only semantic rule (from the
  list above) makes the fixture invalid even though the schema alone would
  accept it. The test fails if an allowlisted fixture is *not* actually
  accepted by the schema (a stale allowlist entry).
- `TestSchemaInvariants` walks all three schema documents and asserts every
  `object` node sets `additionalProperties: false`, that no property name
  looks like it could carry a secret, a command, an image reference or a
  cloud resource identifier, and that `apiVersion`/`kind` are pinned with
  `const`.
- A further test asserts the schema's `keyType` and `error.code` enums are
  exactly the sets in `v1alpha1.KeyTypes` and `v1alpha1.ErrorCodes`.

Run it with:

```sh
go test ./pkg/api/v1alpha1/...
```
