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
  validates the `JobSpec` it receives, re-validates FQDN policy
  independently of the Conductor, invokes `lego` exactly once, normalizes
  the result, writes the certificate directly into an external
  **Certificate Store** (filesystem for local development; Azure Key Vault
  and others in later phases), and exits. It runs no server and no
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
  execution somewhere" (a local process in Phase 2, an Azure Container Apps
  Job from Phase 4). Cloud-specific launcher code lives behind this
  interface, never in Conductor core.

### acme-runner (data plane)

- **JobSpec validation** — strict decoding (see
  [contract](#jobspecresult-contract)) plus full semantic validation,
  including an independent FQDN policy re-check.
- **lego invocation** — a single subprocess call to the pinned `lego`
  binary with an explicit argument vector built from the validated
  `JobSpec`. No shell is ever invoked to build or run this command.
- **Result normalization** — turns whatever `lego` produced into a
  `Result` document: a stable error taxonomy, a certificate fingerprint,
  an expiry timestamp, and a logical store reference. No certificate body,
  key material or credential ever appears in a `Result`.
- **Certificate Store adapter** — writes the private key and certificate
  directly into the configured store (filesystem in Phase 1, Azure Key
  Vault in Phase 3, ...) and then destroys the local copy. This is the
  only place in the whole system that ever holds a private key, and only
  for the duration of one run.

### DNS provider

Resolved through `lego`'s built-in DNS provider support via a `DnsBinding`.
The Runner holds only the credential or workload identity for the single
provider its binding names, scoped to the challenge zone.

### Certificate Store

An external system that durably holds issued certificates and their private
keys (filesystem for dev, Azure Key Vault and others later), addressed
through a `StoreBinding`. The Conductor never reads from it.

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
work, it only reports a `Result` once finished.

## Domain model

Implemented from Phase 2 onward; documented here so the contract in Phase 0
and the storage design in Phase 2 agree from the start.

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

`policy` is a **snapshot**, not a reference: it is the exact policy the
Runner must re-validate against, copied by value, so that a Runner can be
fully audited from the `JobSpec` alone without calling back to the
Conductor.

Forbidden in a `JobSpec`, by construction of the schema (there is simply no
field for these, and strict decoding rejects any attempt to add one): a
shell command, an executable path, arbitrary environment variables, a
container image reference, a client secret / access key / private key, an
arbitrary cloud resource ID, or an arbitrary output path. Only opaque
identifiers, a normalized FQDN, policy values, and logical binding names
ever appear.

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

`storeObjectRef` is a logical, versionless reference to the stored object
(for example a Key Vault certificate name) — never a URL with credentials,
a file system path outside the store, or the object itself. `error.summary`
is a short, machine-checked, secret-free string: `validate.go` rejects PEM
headers, bearer tokens, `AKIA`/`ghp_`/`github_pat_` prefixes, JWT-shaped
base64 (`eyJ`), and any control characters, so a `Result` can never carry a
command line, an environment dump, or a credential fragment. `error.code`
is one of a fixed, append-only set (`InvalidJobSpec`, `PolicyViolation`,
`BindingNotFound`, `AcmeFailure`, `DnsFailure`, `StoreFailure`, `Timeout`,
`Cancelled`, `Internal`).

### Decoding rules

Both documents are decoded **strictly**: unknown fields, duplicate JSON
object keys, and trailing data after the document are all rejected, and any
document over 64 KiB is rejected outright (`pkg/api/v1alpha1/decode.go`).
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
  acme-conductor/   control-plane binary (main.go, --version/--help only in Phase 0)
  acme-runner/      data-plane binary (main.go, --version/--help only in Phase 0)
internal/
  policy/           FQDN normalization and suffix-matching (internal/policy/fqdn.go)
  version/          build metadata injected via -ldflags
pkg/api/v1alpha1/   the versioned JobSpec/Result contract (types, validation, strict decoding)
schemas/v1alpha1/   JSON Schema mirror of the Go contract, kept in sync by tests
docs/               this document, the threat model, and ADRs
Dockerfile.conductor  distroless, non-root image for acme-conductor
Dockerfile.runner     distroless, non-root image for acme-runner
Makefile            build / verify / image targets
.github/workflows/   CI (format, vet, build, test, race, govulncheck, container smoke test)
```

`pkg/` holds code meant to be importable by both binaries and, eventually,
by external tooling that speaks the JobSpec/Result contract; `internal/`
holds code private to this module.

## Technology choices

- **Go**, using the standard `net/http` or a small router when the REST API
  lands in Phase 2 — no large web framework.
- **SQLite** behind a `Registry` interface with versioned, explicit
  migrations for the Conductor's state (Target, CertificatePolicy, Run,
  AuditEvent). PostgreSQL and multi-replica Conductor are explicitly out of
  scope for now (see [non-goals](#non-goals)).
- **No SPA framework** before Phase 5; the initial UI is deliberately
  minimal.
- **Runner image**: multi-stage build, pinned official `lego` binary
  fetched and checksum-verified (Phase 1), distroless static base image.
- **GHCR** (`ghcr.io/cits-nue/acme-conductor`,
  `ghcr.io/cits-nue/acme-runner`) is the canonical container registry.
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
7. FQDN policy is validated by the Conductor **and independently
   re-validated by the Runner**; the Runner never trusts that the Conductor
   already did the check.
8. Production ACME certificate authorities are never called from automated
   tests.

## Observability & logging rules

- Structured JSON logs, always in UTC.
- Every log line for a run carries `runId` and `targetId`.
- Logs never carry credentials, private keys, or the ACME External Account
  Binding (EAB) HMAC — see the threat model's secret-leakage entry.
- `/healthz` and `/readyz` are added as the Conductor gains real state to
  report on; a Prometheus `/metrics` endpoint follows. None of these exist
  yet in Phase 0.

## Roadmap

Only **Phase 0** is implemented today. Phases are strictly sequential; a
given pull request implements one phase's scope and no more (see
[`CONTRIBUTING.md`](../CONTRIBUTING.md)).

| Phase | Scope |
|---|---|
| 0 | Bootstrap: module layout, JobSpec/Result contract, CI. |
| 1 | Runner + filesystem Certificate Store, with a pinned `lego` CLI. |
| 2 | Conductor MVP: SQLite registry, REST API, local process launcher, localhost-only dev auth. |
| 3 | Azure Key Vault store adapter, authenticated via `DefaultAzureCredential`. |
| 4 | Azure Container Apps Job launcher, provisioned via Bicep. |
| 5 | OIDC auth, a minimal GUI, GHCR releases with SBOM and provenance. |
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
