# Architecture

## Overview

ACME Conductor is a cloud-agnostic certificate-management control plane. It
is **not** a new ACME client. All ACME protocol work is delegated to the
existing, widely used [go-acme/lego](https://github.com/go-acme/lego) CLI, a
version-pinned official binary invoked as a subprocess by the Runner via an
argument vector (`argv`), never through a shell string.

The system is split into two binaries with a hard boundary between them:

- **`acme-conductor`** is the control plane: a long-running service that
  owns the FQDN registry (`Target`), certificate policy, an append-only
  audit log, the run registry, a scheduler, and a `Job Launcher` interface
  that starts Runner executions on whatever execution platform is
  configured. It never touches ACME, DNS or certificate material directly.
- **`acme-runner`** is the data plane: a one-shot OCI job. It strictly
  validates the `JobSpec` it receives, authorizes the request against its
  own trusted, Runner-side policy (`policy.RunnerAuthorizationPolicy`,
  Phase 1), invokes `lego` exactly once, normalizes
  the result, writes the certificate directly into an external
  **Certificate Store** (filesystem for local development, Azure Key Vault
  since Phase 3), and exits. It runs no server and no
  scheduler of its own.

This split exists so that the two halves can be deployed with different,
minimal identities: the Conductor coordinates but is never trusted with
secrets, and the Runner is trusted with secrets only for the single run it
was launched for.

## Diagram

```
 Web UI / REST API
        |
        v
 +---------------------------------------------------------------+
 |                        acme-conductor                          |
 |  Target Registry | CertificatePolicy | Audit Log (append-only) |
 |  Run Registry     | Scheduler         | Job Launcher interface |
 +---------------------------------------------------------------+
        |
        | versioned JobSpec (CertificateReconcileJob, v1alpha1)
        v
 +---------------------------------------------------------------+
 |                          acme-runner                           |
 |  JobSpec validation (strict) | lego invocation (argv, once)    |
 |  Result normalization        | Certificate Store adapter       |
 +---------------------------------------------------------------+
        |                                   |
        v                                   v
   DNS provider                     Certificate Store
   (lego built-in)                  (filesystem / Key Vault / ...)
```

The Conductor never talks to the DNS provider or the Certificate Store
directly; it only ever produces a `JobSpec` and later consumes a `Result`.
Both cross the Conductor/Runner boundary as the only two documents the two
binaries ever exchange, and both are defined by the versioned contract in
`pkg/api/v1alpha1` (see [JobSpec/Result contract](#jobspecresult-contract)
below).

## Components and responsibilities

### acme-conductor (control plane)

- **Target Registry** — the authoritative list of FQDNs under management
  (see [domain model](#domain-model)). Owns uniqueness and normalization of
  FQDNs.
- **CertificatePolicy** — the rules a `Target` is issued under: allowed DNS
  suffixes, whether wildcards are permitted, renewal window, key type.
- **Audit Log** — an append-only record of administrative and run events
  (target create/update/disable, job start, failure, policy rejection).
  Nothing is ever deleted from it in the MVP.
- **Run Registry** — the history and current state of every reconcile
  attempt (`Run`), independent of where or how it executed.
- **Scheduler** — decides when a `Target` is due for issuance or renewal and
  produces a `JobSpec` for it.
- **Job Launcher interface** — an abstraction over "start a Runner
  execution somewhere" (the contract is `pkg/launcher`; the
  implementations are `internal/conductor/launcher/localprocess`, a local
  process since Phase 2, and `internal/conductor/launcher/acajob`, an
  Azure Container Apps Job since Phase 4). Cloud-specific launcher code
  lives behind this interface, never in Conductor core.
- **API and GUI** — the REST API (`internal/conductor/api`) is the only
  boundary that accepts free-form input; since Phase 5 it authenticates
  callers with OIDC bearer tokens as named principals with an admin or
  viewer role (`internal/conductor/oidc`, [ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md))
  and serves a minimal static GUI (`internal/conductor/ui`) over the
  same API. The development mode `localhost-dev` remains for one host.

### acme-runner (data plane)

- **JobSpec validation and authorization** — strict decoding (see
  [contract](#jobspecresult-contract)) plus full semantic validation
  (`JobSpec.Validate`, a self-consistency check of the document itself),
  followed by authorization against the Runner's own trusted
  `policy.RunnerAuthorizationPolicy` (Phase 1) — see
  [Validation vs. authorization](#validation-vs-authorization) below.
- **lego invocation** — a single subprocess call to the pinned `lego`
  binary with an explicit argument vector built from the validated
  `JobSpec`. No shell is ever invoked to build or run this command.
- **Result normalization** — turns whatever `lego` produced into a
  `Result` document: a stable error taxonomy, a certificate fingerprint,
  an expiry timestamp, and a logical store reference. No certificate body,
  key material or credential ever appears in a `Result`.
- **Certificate Store adapter** — writes the private key and certificate
  directly into the configured store (filesystem since Phase 1, Azure Key
  Vault since Phase 3) and then destroys the local copy. This is the
  only place in the whole system that ever holds a private key, and only
  for the duration of one run.

### DNS provider

Resolved through `lego`'s built-in DNS provider support via a `DnsBinding`.
The Runner holds only the credential or workload identity for the single
provider its binding names, scoped to the challenge zone.

### Certificate Store

An external system that durably holds issued certificates and their private
keys (filesystem for dev, Azure Key Vault for deployments — see
[ADR 0013](adr/0013-azure-key-vault-store-adapter.md)), addressed
through a `StoreBinding`. The Conductor never reads from it. A store
adapter writes a bundle and reads back a certificate's public part for
the renewal decision; no adapter reads a private key back out of its
store.

## Control plane vs data plane

| | Control plane (`acme-conductor`) | Data plane (`acme-runner`) |
|---|---|---|
| Lifetime | long-running service | one-shot job, exits after one run |
| Holds private keys / certs | never | briefly, in a temporary area, during one run |
| Holds DNS / Key Vault / cloud credentials | never | yes, via workload identity, scoped to the binding it was launched with |
| Talks to ACME/DNS/Store | never directly | yes, exclusively |
| Failure mode if down | already-scheduled Runner jobs still run to completion | a failed run is retried by the next Conductor scheduling pass |
| Network exposure | Web UI / REST API (admin-facing) | none (batch job, no HTTP server, no cron) |

A Conductor outage must never prevent an already-launched Runner job from
completing: the Runner does not call back into the Conductor to do its
work, it only reports a `Result` once finished. With the Phase 2
local-process launcher the Runner is a child of the Conductor, so a
graceful stop waits for it (up to `server.shutdownGraceSeconds`) and then
cancels it; a run whose outcome the Conductor missed is recorded as
failed with "outcome unknown" at the next start, never guessed (see
[ADR 0011](adr/0011-conductor-storage-and-run-model.md)).

## Domain model

Implemented in Phase 2 (`internal/conductor/registry` defines the model
and the `Registry` interface, `internal/conductor/sqlite` persists it —
see [ADR 0011](adr/0011-conductor-storage-and-run-model.md) and
[`docs/conductor.md`](conductor.md)); documented here so the contract in
Phase 0 and the storage design agree.

- **`Target`** — `{id, fqdn (normalized ASCII, unique), enabled, owner,
  policyRef, executionBinding, dnsBinding, storeBinding, createdAt,
  updatedAt, revision}`. One `Target` is one FQDN (MVP: one certificate per
  FQDN, no SAN). `revision` is an optimistic-locking counter that also
  appears in every `JobSpec` produced for that target, so a `Result` can
  always be matched back to the exact target state it was produced for.
- **`CertificatePolicy`** — `{id, allowedDnsSuffixes, allowWildcard,
  acmeBinding, renewBeforeDays, keyType, maxSANs, enabled}`. `maxSANs` is
  fixed at 1 in the MVP domain model even though it is represented, because
  the JobSpec contract for v1alpha1 has no SAN list at all (see
  [non-goals](#non-goals)).
- **Bindings** — `ExecutionBinding`, `DnsBinding`, `StoreBinding`,
  `AcmeBinding`: administrator-registered logical names loaded from startup
  configuration. See [binding model](#binding-model).
- **`Run`** — `{id, targetId, targetRevision, status
  (queued|starting|running|succeeded|failed|cancelled), requestedBy,
  requestedAt, startedAt, finishedAt, action, expiresAt, fingerprint,
  errorCode, errorSummary, externalExecutionId}`. One `Run` corresponds to
  one `JobSpec`/`Result` pair once it completes.
- **`AuditEvent`** — append-only; recorded for target create/update/disable,
  job start, job failure, and policy rejection. There is no purge operation
  in the MVP (see
  [ADR 0008](adr/0008-no-purge-in-mvp.md)); disabling a target is not the
  same as deleting its history.

## Binding model

API input can never specify commands, container images, cloud resource IDs,
credentials or provider configuration directly. It can only name a logical
binding that an administrator registered ahead of time:

- **`ExecutionBinding`** — where and how a Runner job actually runs (a
  local process, later an Azure Container Apps Job).
- **`DnsBinding`** — which DNS provider and zone the ACME DNS-01 challenge
  is written to.
- **`StoreBinding`** — which Certificate Store a result is written to.
- **`AcmeBinding`** — which ACME directory, account and (optional) External
  Account Binding the Runner authenticates as.

In the MVP, all four binding types are loaded from Runner/Conductor startup
configuration; there is no admin API to create or modify them at runtime.
The Conductor's configuration (`internal/conductor/config`) defines
`ExecutionBinding`s and lists the ACME/DNS/Store binding **names** a policy
or target may select — names only; what a name resolves to is Runner
configuration, and the Conductor never sees it.
A `JobSpec` carries only the binding's name (a short DNS-label-like string,
see `pkg/api/v1alpha1/validate.go`'s `bindingNameRe`); the Runner resolves
that name to the actual directory URL, credential, or workload identity
from its own configuration. This is what keeps arbitrary infrastructure
values out of API input entirely, and is why the Conductor can be given no
DNS write and no Certificate Store read permission at all: it never needs
to know what a binding actually resolves to.

## JobSpec/Result contract

Defined in `pkg/api/v1alpha1` (`types.go`, `validate.go`, `decode.go`) and
mirrored as JSON Schema under `schemas/v1alpha1/` (kept in sync with the Go
validation by tests; the Go code is always authoritative — see
`schemas/README.md`). Schema API version:
`acme-conductor.cits-nue.github.io/v1alpha1`.

### `CertificateReconcileJob` (`JobSpec`)

Produced by the Conductor, consumed exactly once by a Runner.

```json
{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "CertificateReconcileJob",
  "runId": "01JABCDEFGHJKMNPQRSTVWXYZ0",
  "target": {
    "id": "01JABCDEFGHJKMNPQRSTVWXYZ1",
    "fqdn": "www.example.ac.jp",
    "revision": 3
  },
  "policy": {
    "allowedDnsSuffixes": ["example.ac.jp"],
    "allowWildcard": false,
    "renewBeforeDays": 30,
    "keyType": "ec256"
  },
  "acme": { "binding": "letsencrypt-prod" },
  "dns": { "binding": "azure-dns-example" },
  "store": { "binding": "fs-dev" }
}
```

`policy` is a **snapshot**, not a reference: it is the policy the Conductor
applied when it created the job, copied by value so that a run can be fully
audited from the `JobSpec` alone without calling back to the Conductor. It
is untrusted input to the Runner, exactly like every other field in the
document — see
[Validation vs. authorization](#validation-vs-authorization) below.

Forbidden in a `JobSpec`, by construction of the schema (there is simply no
field for these, and strict decoding rejects any attempt to add one): a
shell command, an executable path, arbitrary environment variables, a
container image reference, a client secret / access key / private key, an
arbitrary cloud resource ID, or an arbitrary output path. Only opaque
identifiers, a normalized FQDN, policy values, and logical binding names
ever appear.

### Validation vs. authorization

`pkg/api/v1alpha1/validate.go` and `internal/policy` deliberately separate
two different questions, and the docs (and code comments) never use the
word "authorize" for the first one:

- **Validation** — what `JobSpec.Validate` does. It checks that a document
  is well-formed and **internally self-consistent**: constants and syntax,
  ranges, that `target.fqdn` and every entry of `policy.allowedDnsSuffixes`
  are already in canonical form, and that `target.fqdn` lies under one of
  the suffixes in the `policy` snapshot **embedded in the same document**,
  on a label boundary, with wildcard use only when that same snapshot
  allows it. Every value this check compares comes from the document
  itself. Whoever can produce or alter a `JobSpec` — including a
  compromised Conductor — can change `target.fqdn` and the `policy`
  snapshot together and still pass this check, or point a binding name at
  a different, equally well-formed, registered binding. Passing `Validate`
  means "this document is coherent," never "this issuance is permitted."
  See `TestJobSpecValidateIsSelfConsistencyNotAuthorization` in
  `pkg/api/v1alpha1/validate_test.go`.
- **Authorization** — what the Runner must do, with its own trusted
  configuration, before acting on a validated document. This is
  `policy.RunnerAuthorizationPolicy` and its `Authorize` method
  (`internal/policy/authorize.go`): a deny-by-default decision evaluated
  against configuration loaded on the execution platform, never against
  the `JobSpec`'s own `policy` snapshot. Its fields are:
  - `AllowedDnsSuffixes` — the DNS suffixes this Runner may issue for.
  - `AllowWildcard` — whether wildcard names under those suffixes are
    permitted.
  - `AllowedACMEBindings`, `AllowedDNSBindings`, `AllowedStoreBindings` —
    allow-lists of the logical binding names this Runner may select; a
    binding name that is well-formed but not listed is rejected even if
    the Runner has configuration for it. Because a `JobSpec`'s binding
    names are only selectors into this Runner-side configuration, a
    document whose binding names have been swapped for other registered
    names is not caught by `Validate` and is caught here instead.

  `Authorize` requires an already-normalized FQDN (it does not normalize on
  the caller's behalf) and matches suffixes on the same label-boundary
  rule as validation. Phase 0 defined the policy type and the decision
  function, with tests; as of Phase 1, the Runner loads its trusted
  configuration (`internal/runner/config`) and wires
  `RunnerAuthorizationPolicy` from it (`Config.Policy()`) before it acts on
  any `JobSpec` — see [`docs/runner.md`](runner.md#execution-flow) for the
  exact sequence and `docs/threat-model.md` (T1/T2/T5 and
  "Assurance levels") for what this does and does not close.
- **Signing's scope.** Since Phase 4 a `JobSpec` can travel inside a
  `SignedCertificateReconcileJob` envelope (`pkg/api/v1alpha1/signedjob.go`,
  [ADR 0015](adr/0015-signed-job-envelope.md)): the JWS construction with
  Ed25519 over the exact JobSpec bytes, a strict protected header with
  `kid`, `issuedAt`, `expiresAt` and `nonce`, verified by the Runner
  against public keys in its trusted configuration and backed by a
  replay ledger in its state directory. It protects the document against
  tampering in transit and bounds replay; it does not by itself address a
  compromised Conductor that legitimately produces (and signs) a bad
  `JobSpec`. Only the Runner-side trusted authorization policy above
  bounds that case, and it runs on the unwrapped document exactly as
  before.

### `CertificateReconcileResult` (`Result`)

Produced by exactly one Runner execution, consumed by the Conductor.

Success:

```json
{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "CertificateReconcileResult",
  "runId": "01JABCDEFGHJKMNPQRSTVWXYZ0",
  "targetId": "01JABCDEFGHJKMNPQRSTVWXYZ1",
  "status": "succeeded",
  "action": "issued",
  "expiresAt": "2026-12-19T00:00:00Z",
  "fingerprintSha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "storeObjectRef": "www-example-ac-jp",
  "startedAt": "2026-09-20T00:00:00Z",
  "finishedAt": "2026-09-20T00:02:11Z",
  "error": null
}
```

Failure:

```json
{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "CertificateReconcileResult",
  "runId": "01JABCDEFGHJKMNPQRSTVWXYZ0",
  "targetId": "01JABCDEFGHJKMNPQRSTVWXYZ1",
  "status": "failed",
  "action": "failed",
  "startedAt": "2026-09-20T00:00:00Z",
  "finishedAt": "2026-09-20T00:01:04Z",
  "error": {
    "code": "DnsFailure",
    "summary": "TXT record propagation timed out"
  }
}
```

`storeObjectRef` is a **strict logical name**
(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`, at most 128 characters
— sized to cover Azure Key Vault certificate names, 1..127 characters — and
`..` rejected). None of `/ \ : ? # @ % & =` or whitespace can appear, so it
is never a URL, a URI, a path, or a query string, with or without
credentials, by construction of the pattern, not just by convention.

`error.summary` is a short, bounded, printable-only string additionally
checked against the secret-marker heuristic described in
`pkg/api/v1alpha1/validate.go` (`secretMarkers`) — markers whose meaning
does not depend on case (`bearer `, `basic `, `authorization:`,
`password=`, `secret=`, `token=`, `sig=`, `key=`, and similar) are matched
case-insensitively. That check is defense-in-depth, not a secret detector:
it cannot recognize an arbitrary secret or an unknown format. The rule that
actually keeps a `Result` free of raw external output is a Runner
responsibility (Phase 1): the Runner never copies a raw external
command/SDK error, stdout, or stderr into a `Result`; `error.summary` is
generated only from Runner-owned safe templates, and full external details
go to redacted internal logs only. `error.code` — one of a fixed,
append-only set (`InvalidJobSpec`, `PolicyViolation`, `BindingNotFound`,
`AcmeFailure`, `DnsFailure`, `StoreFailure`, `Timeout`, `Cancelled`,
`Internal`) — is the primary machine-readable signal for API consumers;
`error.summary` is for humans and is never meant to be parsed.

### Decoding rules

Both documents are decoded **strictly**: unknown fields, duplicate JSON
object keys, and trailing data after the document are all rejected, any
document over 64 KiB is rejected outright, and nesting deeper than 8 levels
is rejected before the walker spends CPU on it (`pkg/api/v1alpha1/decode.go`).
Duplicate-key rejection matters because `encoding/json` silently keeps the
last value for a repeated key, which is a classic validation-bypass vector
if left unchecked.

## FQDN normalization rules

Implemented in `internal/policy/fqdn.go` and applied identically by the
Conductor and the Runner (`JobSpec.Validate()` re-runs `policy.Evaluate`).
`v1alpha1` is ASCII-only:

- Surrounding whitespace is trimmed.
- Exactly one trailing dot (absolute name) is removed.
- ASCII letters are lower-cased.
- Non-ASCII input is rejected (`ErrNonASCII`) — internationalized domain
  names are not supported yet; see
  [ADR 0006](adr/0006-ascii-only-fqdn-in-v1alpha1.md).
- Labels must be 1–63 octets, contain only ASCII letters, digits and
  hyphens, and must not start or end with a hyphen. Underscore labels are
  rejected outright: they are not valid host names and a certificate for
  one is never wanted.
- A label starting with `xn--` is rejected in `v1alpha1` (`ErrIDNALabel`),
  even though it is syntactically a valid ASCII label — see ADR 0006.
- At least two labels are required, and the total length must not exceed
  253 octets.
- The top-level (right-most) label must not be all-digits.
- A wildcard (`*`) is accepted only as the entire left-most label
  (`*.example.ac.jp`, never `foo*.example.ac.jp` or `*foo.example.ac.jp`),
  and only when the remaining base name still has at least two labels
  itself (`*.ac.jp` alone is rejected: a wildcard for an entire TLD is
  never valid).

Allowed DNS suffixes in a `CertificatePolicy` go through the same
normalization (`NormalizeSuffix`), plus a check that a suffix itself never
contains a wildcard.

### Label-boundary suffix matching

A `Target`'s FQDN is checked against a policy's allowed suffixes by
**whole label**, never by raw string suffix. `evil-example.ac.jp` is
**not** under the allowed suffix `example.ac.jp`, even though it ends with
the characters `example.ac.jp`: the match requires either an exact match or
a preceding `.` so the boundary falls exactly on a label separator
(`example.ac.jp` or `*.example.ac.jp` matches; `evil-example.ac.jp` does
not, because there is no `.` immediately before `example.ac.jp` in that
name). For a wildcard target, the base name — the part after `*.` — is what
gets matched against the suffix list.

## Repository layout

```
cmd/
  acme-conductor/   control-plane binary (serve, Phase 2)
  acme-runner/      data-plane binary (reconcile, Phase 1)
internal/
  conductor/            Conductor wiring: config, registry, scheduler, launchers, API (Phase 2)
  conductor/api/        REST API handlers, the localhost-dev authenticator, role enforcement, GUI routes
  conductor/oidc/       OIDC bearer-token authenticator: discovery, key set cache, JWS verification (Phase 5)
  conductor/oidc/oidctest/ in-process OpenID provider for tests; not compiled into shipped binaries
  conductor/ui/         the embedded GUI: index.html, app.js, app.css (Phase 5)
  conductor/config/     Conductor configuration loading and validation
  conductor/launcher/localprocess/ the local-process launcher (development and tests)
  conductor/launcher/acajob/ Azure Container Apps Job launcher (Phase 4) — the Conductor's only Azure SDK import
  conductor/registry/   domain model (Target, CertificatePolicy, Run, AuditEvent) and Registry interface
  conductor/scheduler/  due decision, per-target exclusion, run execution
  conductor/sqlite/     SQLite implementation of Registry, with migrations
  conductor/fakerunner/ test double for acme-runner used by Conductor tests; not compiled into shipped binaries
  fslock/           advisory file locks shared by the Runner's on-disk stores
  policy/           FQDN normalization and suffix-matching (internal/policy/fqdn.go)
  runner/           Runner reconcile loop, work-dir/state-dir handling, Result writer (Phase 1)
  runner/config/    Runner configuration loading and validation (Phase 1)
  runner/lego/      lego argv/env construction, subprocess execution, output redaction (Phase 1)
  runner/fakelego/  test double for lego used by Runner tests; not compiled into shipped binaries
  store/            Certificate Store implementations; the contract itself is pkg/store
  store/filesystem/ filesystem-backed Certificate Store (dev/test only, Phase 1)
  store/keyvault/   Azure Key Vault Certificate Store (Phase 3) — the Runner's only Azure SDK import
  version/          build metadata injected via -ldflags
pkg/api/v1alpha1/   the versioned JobSpec/Result contract and the signed job envelope (types, validation, strict decoding)
pkg/store/          the Certificate Store contract (Store, Bundle, Info) and the certificate helpers every store shares
pkg/launcher/       the Job Launcher contract (Launcher, Execution, Error/Reason), job signing and result verification
                    — pkg/ is what a provider adapter in another module imports (pkg/contracts_test.go keeps it so)
schemas/v1alpha1/   JSON Schema mirror of the Go contract, kept in sync by tests
deploy/examples/    example Conductor and Runner configurations and a JobSpec document
deploy/azure/       Bicep for the Container Apps deployment: environment, identities, custom roles, Runner Job, Conductor app (Phase 4)
docs/               this document, the threat model, the Conductor and Runner guides, and ADRs
Dockerfile.conductor  distroless, non-root image for acme-conductor
Dockerfile.runner     distroless, non-root image for acme-runner
Makefile            build / verify / image targets
.github/workflows/   CI (format, vet, build, test, race, govulncheck, container smoke test) and the release workflow (GHCR images with SBOM and provenance, Phase 5)
```

`pkg/` holds code meant to be importable by both binaries and, eventually,
by external tooling that speaks the JobSpec/Result contract; `internal/`
holds code private to this module.

## Technology choices

- **Go**, using the standard `net/http` (method-and-pattern `ServeMux`)
  for the REST API — no web framework (Phase 2).
- **SQLite** (`modernc.org/sqlite`, pure Go, so `CGO_ENABLED=0` still
  holds) behind a `Registry` interface with versioned, explicit
  migrations for the Conductor's state (Target, CertificatePolicy, Run,
  AuditEvent) — see [ADR 0011](adr/0011-conductor-storage-and-run-model.md).
  PostgreSQL and multi-replica Conductor are explicitly out of scope for
  now (see [non-goals](#non-goals)).
- **No SPA framework, no build step** for the GUI (Phase 5): three
  static files embedded in the binary, DOM rendering, a strict
  Content-Security-Policy, and OIDC authorization code + PKCE in the
  browser as a public client. The API's token verification is written in
  the repository on the standard library's `crypto/rsa` and
  `crypto/ecdsa` rather than taken from a JWT library, so that what is
  accepted is exactly what the threat model lists
  ([ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)).
- **Runner image**: multi-stage build, pinned official `lego` binary
  fetched and checksum-verified (Phase 1), distroless static base image.
- **GHCR** (`ghcr.io/cits-nue/acme-conductor`,
  `ghcr.io/cits-nue/acme-runner`) is the canonical container registry;
  a version tag publishes both images for `linux/amd64` and
  `linux/arm64` with an SBOM and SLSA provenance attached, from
  digest-pinned base images ([ADR 0017](adr/0017-release-pipeline.md)).
- **Configuration**: non-secret configuration via environment variables or
  a config file; secrets are never part of Conductor configuration at all,
  by design (the Conductor holds no DNS, Key Vault, or long-lived cloud
  credential — see [security principles](#security-principles)).
- Cloud SDKs (Azure, later AWS/GCP if ever added) live only inside launcher
  and store adapter implementations, never in Conductor core.

## Security principles

These hold across every phase and are traced to concrete mitigations in
[`docs/threat-model.md`](threat-model.md):

1. The Conductor never stores, retrieves or distributes certificate private
   keys.
2. The Conductor holds no DNS credential, Key Vault credential, or
   long-lived cloud credential of any kind.
3. The Runner authenticates to cloud services using the execution
   platform's workload identity (Azure Managed Identity, AWS IAM Role, GCP
   Service Account) — never a static secret baked into configuration.
4. Private keys are generated in the Runner's temporary area, stored
   directly into the Certificate Store, and then destroyed; they never
   transit through the Conductor.
5. Conductor identity and Runner identity are kept separate. The Conductor
   is granted no DNS write permission and no Certificate Store read
   permission.
6. API input can never specify commands, container images, resource IDs,
   credentials, or provider configuration — only the logical names of
   administrator-registered bindings (see
   [binding model](#binding-model)).
7. FQDN policy is validated by the Conductor when it accepts a `Target`/
   `CertificatePolicy`; the Runner does not trust that the Conductor
   already did the check. The Runner both **validates** the `JobSpec`
   document it receives (self-consistency; see
   [Validation vs. authorization](#validation-vs-authorization)) and
   **authorizes** it against its own trusted, Runner-side policy — the
   validation step is not itself authorization.
8. Production ACME certificate authorities are never called from automated
   tests.

## Observability & logging rules

- Structured JSON logs, always in UTC.
- Every log line for a run carries `runId` and `targetId`.
- Logs never carry credentials, private keys, or the ACME External Account
  Binding (EAB) HMAC — see the threat model's secret-leakage entry.
- `/healthz` and `/readyz` exist since Phase 2 (`readyz` pings the
  registry); a Prometheus `/metrics` endpoint follows in a later phase.

## Roadmap

**Phases 0 to 5** are implemented today. Phases are strictly
sequential; a given pull request implements one phase's scope and no more
(see [`CONTRIBUTING.md`](../CONTRIBUTING.md)).

| Phase | Scope |
|---|---|
| 0 | Bootstrap: module layout, JobSpec/Result contract, CI. |
| 1 | **Implemented.** Runner + filesystem Certificate Store, with a pinned `lego` CLI. See [`docs/runner.md`](runner.md), [ADR 0009](adr/0009-runner-execution-model.md) and [ADR 0010](adr/0010-pinned-lego-binary.md). |
| 2 | **Implemented.** Conductor MVP: SQLite registry, REST API, local process launcher, localhost-only dev auth. See [`docs/conductor.md`](conductor.md), [ADR 0011](adr/0011-conductor-storage-and-run-model.md) and [ADR 0012](adr/0012-localhost-only-dev-auth.md). |
| 3 | **Implemented.** Azure Key Vault store adapter, authenticated with the platform's managed identity (or the SDK's `DefaultAzureCredential` chain for development). See [`docs/runner.md`](runner.md#certificate-store-azure-key-vault) and [ADR 0013](adr/0013-azure-key-vault-store-adapter.md). |
| 4 | **Implemented.** Azure Container Apps Job launcher (the Runner as a scheduled Job under its own managed identity that takes the jobs the Conductor offers on a shared volume; the Conductor cannot start executions), provisioned via Bicep with disjoint identities and least-privilege custom roles; signed, expiring job envelope with a Runner-side replay ledger, and Runner-signed Results. See [`docs/conductor.md`](conductor.md#execution-binding-azure-container-apps-job), [`deploy/azure/README.md`](../deploy/azure/README.md), [ADR 0014](adr/0014-azure-container-apps-job-launcher.md) and [ADR 0015](adr/0015-signed-job-envelope.md). |
| 5 | **Implemented.** OIDC bearer-token authentication with named principals and admin/viewer roles, a TLS listener or an explicit behind-ingress statement, a minimal static GUI with PKCE sign-in, and a release workflow that publishes both images to GHCR with an SBOM and provenance from digest-pinned bases. The Container Apps deployment gains an HTTPS ingress and loses the admin sidecar. See [`docs/conductor.md`](conductor.md#authentication), [ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md) and [ADR 0017](adr/0017-release-pipeline.md). |
| 6 | Migration tooling from the existing cert-infra repository (import/diff/shadow mode, feature-flag switch). |

## Non-goals

Explicitly out of scope until a future phase or ADR says otherwise:

- Re-implementing the ACME protocol or DNS provider integrations (`lego`
  already does this).
- Custom cryptography.
- A private-key distribution API of any kind.
- A Kubernetes operator or CRDs.
- Multi-replica / highly-available Conductor.
- PostgreSQL (SQLite is the store for the foreseeable future).
- AWS or GCP providers (the binding model anticipates them; nothing is
  implemented yet).
- Delivering certificates to Arc-managed hosts.
- Automatic purge of any kind (see
  [ADR 0008](adr/0008-no-purge-in-mvp.md)).
- Arbitrary scripts or post-issuance hooks.
- User-supplied container images.
- Dynamic plugin download.

## See also

- [Threat model](threat-model.md)
- [Architecture Decision Records](adr/README.md)
