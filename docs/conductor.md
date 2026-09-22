# Conductor operator guide

This is the operator-facing reference for `acme-conductor`, the control
plane described in [`docs/architecture.md`](architecture.md). It covers
the command line, the configuration file, the REST API, how a `Target`
becomes a `Run` and how a `Run` is driven to completion, the
`localhost-dev` authentication mode, the on-disk state and how to back it
up, and what the Phase 2 Conductor does and does not guarantee.

Phase 2 ships the Conductor MVP: a SQLite-backed registry of targets,
policies, runs and audit events, a REST API, a scheduler, and a
local-process launcher that runs `acme-runner` (see
[`docs/runner.md`](runner.md)) as a child process. It is a
**single-host, single-user development and test deployment**: the API is
reachable from the local host only and authenticates nothing finer than
"a process on this host" (see [Authentication](#authentication)).

## Overview

`acme-conductor serve` runs, in one process:

- the **REST API** on a loopback address (`/api/v1alpha1/...`, plus
  `/healthz` and `/readyz`);
- the **registries** — `Target`, `CertificatePolicy`, `Run` and the
  append-only `AuditEvent` log — in one SQLite file;
- the **scheduler**, which every `tickSeconds` (and whenever the API
  changes something) records a queued `Run` for every enabled target that
  is due, and starts queued runs through a launcher up to
  `maxConcurrentRuns` at a time;
- one **launcher** per configured execution binding — in Phase 2 only
  `local-process`, which runs `acme-runner reconcile` as a child.

The Conductor never talks to an ACME CA, a DNS provider or a Certificate
Store. It produces a `JobSpec` and consumes a `Result`; everything it
knows about a certificate (expiry, fingerprint, logical store name) is
what the last successful `Result` said.

## Command line

```
acme-conductor serve [--config FILE] [--log-level LEVEL]
acme-conductor --version
acme-conductor --help
```

- `--config FILE` — path to the configuration document. Defaults to
  `$ACME_CONDUCTOR_CONFIG` if set, otherwise
  `/etc/acme-conductor/config.json`.
- `--log-level LEVEL` — `debug`, `info` (default), `warn` or `error`.
  At `debug` the Runner's own log lines (already redacted by the Runner)
  are relayed into the Conductor log.

`serve` runs until it receives `SIGTERM` or `SIGINT`. It then stops
accepting API requests, stops planning new runs, waits up to
`server.shutdownGraceSeconds` for in-flight runs, cancels whatever is
still running (the Runner then reports `Cancelled`), and exits. A second
signal kills the process outright; see [Shutdown and recovery](#shutdown-and-recovery).

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Stopped cleanly after a signal. |
| `1` | The configuration was rejected, or a launcher could not be built from it, or the bound address was not loopback. |
| `2` | A fatal runtime error: the registry could not be opened or migrated, in-flight runs could not be recovered, the listener could not be bound, or the HTTP server failed. |

## Configuration reference

The configuration is a strictly decoded JSON document (unknown fields,
duplicate keys, trailing data and over-deep nesting rejected; 256 KiB cap)
that contains **no secret**. The Conductor knows ACME, DNS and Store
bindings **by name only**; what a name resolves to is Runner configuration
(`docs/runner.md`). See
[`deploy/examples/conductor-config.example.json`](../deploy/examples/conductor-config.example.json)
for a complete example whose binding names match the Runner example.

Top level:

| Field | Type | Notes |
|---|---|---|
| `apiVersion` | string | Must equal `acme-conductor.cits-nue.github.io/v1alpha1`. |
| `kind` | string | Must equal `ConductorConfig`. |
| `server` | object | Listener, authentication, shutdown — see below. |
| `database` | object | `{ "path": "..." }` — clean, absolute path of the SQLite file (created `0600` if missing; a symbolic link is refused). Its directory must exist and be writable; SQLite also creates `<path>-wal` and `<path>-shm` next to it. |
| `scheduler` | object | Pacing — see below. |
| `executionBindings` | map | At least one. Keys are binding names (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, ≤63 chars). |
| `acmeBindings` | []string | Non-empty, distinct binding names a policy may select. |
| `dnsBindings` | []string | Non-empty, distinct binding names a target may select. |
| `storeBindings` | []string | Non-empty, distinct binding names a target may select. |

### `server`

| Field | Type | Default | Notes |
|---|---|---|---|
| `listen` | string | `127.0.0.1:8080` | `host:port`. With `auth.mode: localhost-dev` the host must be `localhost` or a loopback IP literal (`127.0.0.1`, `[::1]`); any other name or address is rejected, and a name is never resolved. Port `0` picks a free port (tests). |
| `auth.mode` | string | `localhost-dev` | The only mode in Phase 2. See [Authentication](#authentication). |
| `shutdownGraceSeconds` | int | `900` | How long in-flight runs may continue after a stop signal before they are cancelled. `1`–`86400`. |

### `scheduler`

| Field | Type | Default | Notes |
|---|---|---|---|
| `tickSeconds` | int | `60` | How often due targets are examined and queued runs dispatched. API changes also wake the scheduler immediately. `1`–`86400`. |
| `maxConcurrentRuns` | int | `2` | Runner executions in flight at once, across all execution bindings. `1`–`64`. |
| `retryBackoffSeconds` | int | `300` | Wait before retrying a target after a failed or cancelled run. |
| `maxRetryBackoffSeconds` | int | `21600` | The backoff doubles per consecutive failure up to this cap (≥ `retryBackoffSeconds`, ≤ 7 days). |

### `executionBindings.<name>`

| Field | Type | Notes |
|---|---|---|
| `type` | string | Only `local-process` in Phase 2. |
| `localProcess` | object | Required for `local-process` — see below. |

### `executionBindings.<name>.localProcess`

| Field | Type | Default | Notes |
|---|---|---|---|
| `runnerBinary` | string | — (required) | Clean, absolute path of the `acme-runner` executable. |
| `runnerConfig` | string | — (required) | Clean, absolute path of the **Runner's** configuration, passed as `--config`. The Conductor never reads it. |
| `workDir` | string | — (required) | Clean, absolute path; parent of the per-run directory (`run-<runId>/`, mode `0700`) that holds `job.json` and `result.json` while a run is in flight. It never holds certificate material — the Runner has its own `workDir`/`stateDir`. Created if missing. |
| `timeoutSeconds` | int | `1200` | Bounds one Runner execution as seen by the Conductor. Set it above the Runner's `lego.timeoutSeconds` so the Runner's own, more precise `Timeout` result wins. `1`–`86400`. |
| `passthroughEnv` | []string | `[]` | Names of environment variables of the **Conductor process** forwarded to the Runner child unchanged (`^[A-Z][A-Z0-9_]{0,63}$`; `PATH`, `HOME`, `TMPDIR` and `LD_*` are reserved). Everything else is withheld: the child gets only `HOME`/`TMPDIR` (its run directory), a fixed `PATH`, and these. A listed variable that is not set is logged as a warning and omitted — the Runner then fails the run closed itself (`DnsFailure`/`AcmeFailure` naming the binding). See the security note below. |

**Security note on `passthroughEnv`.** This is the only way a DNS
credential or an EAB secret can reach a Runner started by the local
launcher, and it means the Conductor process's environment carries that
credential — the opposite of security principle 2 ("the Conductor holds
no DNS credential"). That is acceptable on a single-user development host
and nowhere else; the Azure Container Apps Job launcher (Phase 4) hands
the Runner a workload identity instead and needs no passthrough at all.
The threat model records this as T10's Phase 2 residual.

## REST API

All resource endpoints live under `/api/v1alpha1`. Requests and responses
are JSON (`Content-Type: application/json`); every request body is decoded
strictly (unknown fields, duplicate keys, trailing data, nesting deeper
than 8 levels all rejected) and capped at 64 KiB. Responses carry
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

Identifiers (`id`, `policyRef`, `targetId`, `runId`, `before`) are ULIDs
generated by the Conductor (monotonic within one process, so they sort in
creation order); a path or query identifier that is not
`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` is answered `404`/`400` without
touching the registry.

### Errors

```json
{ "error": { "code": "stale_revision", "message": "target 01J… is at revision 3, not 2", "details": { } } }
```

| HTTP | `code` | When |
|---|---|---|
| 400 | `invalid_request` | Malformed body, failed field validation, unknown field, unregistered binding name, invalid FQDN/suffix, bad query parameter. |
| 400 | `policy_violation` | The target's FQDN is not allowed by the policy it names (label-boundary suffix match, wildcard rule). Audited as `policy.rejected`. |
| 403 | `forbidden` | Refused by the authentication mode (see [Authentication](#authentication)). |
| 404 | `not_found` | No such policy, target, run, or endpoint. |
| 409 | `conflict` | A second target for the same FQDN; a policy edit that would no longer cover an existing target; cancelling a run that is not cancellable. |
| 409 | `stale_revision` | The `revision` in the request is not the target's current revision. |
| 409 | `run_active` | A run is already queued/starting/running for the target (`details.activeRunId`, `details.status`). |
| 409 | `target_disabled` | A run was requested for a disabled target. |
| 413 | `too_large` | Body over 64 KiB. |
| 415 | `unsupported_media_type` | Body without `Content-Type: application/json`. |
| 500 | `internal` | Registry or other internal failure; details are in the log only. |

### Endpoints

| Method and path | Purpose |
|---|---|
| `GET /healthz` | Liveness: `{"status":"ok"}`. Unauthenticated. |
| `GET /readyz` | Readiness: pings the registry; `503` `{"status":"unavailable"}` on failure. Unauthenticated. |
| `GET /api/v1alpha1/bindings` | The registered binding names: `{"execution":[…],"acme":[…],"dns":[…],"store":[…]}`. |
| `GET /api/v1alpha1/policies` | `{"items":[Policy…]}`, oldest first. |
| `POST /api/v1alpha1/policies` | Create a policy → `201` Policy, `Location`. |
| `GET /api/v1alpha1/policies/{id}` | One policy. |
| `PUT /api/v1alpha1/policies/{id}` | Replace a policy → `200`. Refused (`409`) if any target under it would no longer satisfy it. |
| `GET /api/v1alpha1/targets[?enabled=&policyRef=]` | `{"items":[Target…]}`, oldest first. |
| `POST /api/v1alpha1/targets` | Create a target → `201` Target, `Location`. Wakes the scheduler. |
| `GET /api/v1alpha1/targets/{id}` | One target, with its certificate and last-run summary. |
| `PUT /api/v1alpha1/targets/{id}` | Update mutable fields at a given `revision` → `200`. Wakes the scheduler. |
| `POST /api/v1alpha1/targets/{id}/enable` | Set `enabled: true` → `200` Target (revision bumps if it changed). |
| `POST /api/v1alpha1/targets/{id}/disable` | Set `enabled: false` → `200` Target. Deletes nothing; does not stop an in-flight run. |
| `GET /api/v1alpha1/targets/{id}/runs[?status=&limit=&before=]` | The target's runs, newest first. |
| `POST /api/v1alpha1/targets/{id}/runs` | Request a run now → `202` Run, `Location`. Optional body `{"revision": N}`. |
| `GET /api/v1alpha1/runs[?targetId=&status=&limit=&before=]` | Runs, newest first. `status` is a comma-separated list. |
| `GET /api/v1alpha1/runs/{id}` | One run. |
| `POST /api/v1alpha1/runs/{id}/cancel` | Cancel: a queued run is cancelled at once (`200`); a starting/running one is asked to stop (`202`, outcome recorded when the Runner reports). |
| `GET /api/v1alpha1/audit[?targetId=&runId=&policyId=&limit=&before=]` | Audit events, newest first. |

Lists that page (`runs`, `audit`) take `limit` (`1`–`1000`, default
`100`) and `before=<id>` (return items whose id sorts before it; ids sort
by creation time).

### Policy

Request body (`POST`, `PUT`):

```json
{
  "allowedDnsSuffixes": ["example.ac.jp"],
  "allowWildcard": false,
  "acmeBinding": "letsencrypt-staging",
  "renewBeforeDays": 30,
  "keyType": "ec256",
  "maxSANs": 1,
  "enabled": true
}
```

- `allowedDnsSuffixes` — 1–64 entries, each normalized on input
  (`internal/policy.NormalizeSuffix`: trimmed, lower-cased, trailing dot
  removed; no wildcard; ASCII only, no `xn--`); duplicates after
  normalization are rejected.
- `acmeBinding` — must be listed in the configuration's `acmeBindings`.
- `renewBeforeDays` — `1`–`365`. `keyType` — `ec256`, `ec384`, `rsa2048`,
  `rsa3072`, `rsa4096`.
- `maxSANs` — optional, must be `1` (one certificate per FQDN).
- `enabled` — optional; defaults to `true` on create and to the current
  value on update. A disabled policy holds every target under it back
  from scheduling.

Response adds `id`, `createdAt`, `updatedAt`.

### Target

Create:

```json
{
  "fqdn": "wiki.example.ac.jp",
  "owner": "web-team",
  "policyRef": "01JPOLICY…",
  "executionBinding": "local",
  "dnsBinding": "azure-dns-staging",
  "storeBinding": "filesystem-dev",
  "enabled": true
}
```

- `fqdn` — normalized on input (`internal/policy.NormalizeFQDN`) and
  unique; it must satisfy the named policy (label-boundary suffix match,
  wildcard only if the policy allows it) or the request is refused with
  `policy_violation` and audited. The FQDN is **immutable** afterwards: a
  target is one FQDN.
- `owner` — 1–128 bytes of printable UTF-8; free text for humans.
- `policyRef` — an existing policy id. The three binding names must be
  listed in the configuration.

Update (`PUT`): `{"revision": N, …}` with any of `owner`, `policyRef`,
`executionBinding`, `dnsBinding`, `storeBinding`, `enabled`; omitted
fields keep their value; `revision` must be the current one
(`stale_revision` otherwise) and is incremented on success.

Response:

```json
{
  "id": "01JTARGET…", "fqdn": "wiki.example.ac.jp", "enabled": true, "owner": "web-team",
  "policyRef": "01JPOLICY…", "executionBinding": "local", "dnsBinding": "azure-dns-staging",
  "storeBinding": "filesystem-dev", "createdAt": "…", "updatedAt": "…", "revision": 1,
  "certificate": {
    "expiresAt": "2026-12-21T…", "fingerprintSha256": "…", "storeObjectRef": "wiki.example.ac.jp-…",
    "lastSucceededAt": "…", "lastSucceededRunId": "01JRUN…"
  },
  "lastRun": { "id": "01JRUN…", "status": "succeeded", "requestedAt": "…", "finishedAt": "…" }
}
```

`certificate` is `null` until a run has succeeded; it is exactly what the
last successful `Result` reported, never anything read from the Store.
`lastRun` is `null` until a run exists; it carries `errorCode` when the
run failed.

### Run

```json
{
  "id": "01JRUN…", "targetId": "01JTARGET…", "targetRevision": 1,
  "status": "succeeded", "requestedBy": "scheduler",
  "requestedAt": "…", "startedAt": "…", "finishedAt": "…",
  "action": "issued", "expiresAt": "…", "fingerprintSha256": "…", "storeObjectRef": "…",
  "error": null, "externalExecutionId": "local-process:12345"
}
```

`status` is one of `queued`, `starting`, `running`, `succeeded`,
`failed`, `cancelled`. `action`, `expiresAt`, `fingerprintSha256`,
`storeObjectRef` and `error` mirror the Runner's `Result`
([contract](architecture.md#certificatereconcileresult-result)); `error`
is `{ "code", "summary" }` on failure or cancellation. `requestedBy` is
`scheduler` or the API principal (`localhost-dev`).

### Audit event

```json
{ "id": "01JEVENT…", "time": "…", "actor": "localhost-dev", "action": "target.created",
  "targetId": "01JTARGET…", "runId": "", "policyId": "", "detail": "target created: fqdn=… policy=… …" }
```

Actions: `policy.created`, `policy.updated`, `policy.rejected`,
`target.created`, `target.updated`, `target.enabled`, `target.disabled`,
`run.requested`, `run.started`, `run.succeeded`, `run.failed`,
`run.cancelled`. `detail` is a short sentence built by the Conductor from
validated values (at most 512 bytes); it never contains Runner output.
Events are written in the same transaction as the change they describe
and can be neither updated nor deleted.

### Example session

```sh
C=http://127.0.0.1:8080/api/v1alpha1
P=$(curl -s -H 'Content-Type: application/json' -d '{"allowedDnsSuffixes":["example.ac.jp"],"acmeBinding":"letsencrypt-staging","renewBeforeDays":30,"keyType":"ec256"}' $C/policies | jq -r .id)
T=$(curl -s -H 'Content-Type: application/json' -d "{\"fqdn\":\"wiki.example.ac.jp\",\"owner\":\"web-team\",\"policyRef\":\"$P\",\"executionBinding\":\"local\",\"dnsBinding\":\"azure-dns-staging\",\"storeBinding\":\"filesystem-dev\"}" $C/targets | jq -r .id)
curl -s $C/targets/$T | jq .lastRun          # the scheduler queues a run at once
curl -s -X POST $C/targets/$T/runs             # or request one explicitly (409 while one is active)
curl -s "$C/audit?targetId=$T" | jq '.items[].action'
```

## Run lifecycle and scheduling

```
 scheduler tick / API request
        |
        v
    queued ──(claimed by scheduler)──> starting ──(runner started)──> running ──(Result)──> succeeded
        |                                 |                               |                  failed
        |                                 | target disabled / revision    |                  cancelled
        |                                 | changed / policy disabled     |
        └── cancel via API ──> cancelled  └──────────> cancelled          └── cancel ──> cancelled
```

1. **Due check** (every tick and on every wake). For each enabled target
   whose policy is enabled and that has no active run, a run is queued if
   the target has never succeeded, its revision differs from the one its
   last successful run was made for, the last successful run recorded no
   expiry, or `expiresAt - renewBeforeDays` has passed. After a failed or
   cancelled run the target waits `retryBackoffSeconds`, doubled per
   consecutive failure up to `maxRetryBackoffSeconds`. The reason is
   recorded in the `run.requested` audit event.
2. **Exclusion.** At most one run per target may be queued, starting or
   running; the registry enforces it as a schema constraint, so a tick, an
   operator and a restart cannot race a second Runner into existence. A
   second API request answers `409 run_active` naming the active run.
3. **Claim and re-check.** Up to `maxConcurrentRuns` queued runs are
   claimed (`starting`). Each re-reads its target and policy: a disabled
   target or policy, or a target whose revision moved on since the run was
   requested, ends the run as `cancelled` without starting a Runner. Then
   the `JobSpec` is built (policy copied by value as a snapshot) and
   validated with the contract's own `Validate`; a rejection ends the run
   as `failed`/`PolicyViolation` and is audited as `policy.rejected`.
4. **Launch.** The execution binding's launcher starts the Runner; the run
   becomes `running` with the platform's execution id recorded.
5. **Result.** The Runner's `Result` (strictly decoded, checked to name
   this run and target) sets the terminal status and every certificate
   field. `Cancelled` → `cancelled`; any other error → `failed`. If the
   launcher obtains no `Result` at all, the run fails with a
   Conductor-owned summary: `Timeout` (launcher timeout), `Cancelled`
   (stopped before reporting), or `Internal` (no/unusable/mismatched
   result, could not start). Nothing the Runner printed is copied into a
   run record.

The Runner stays the authority on whether a certificate must actually be
issued or renewed (it asks the Store, see [ADR 0009](adr/0009-runner-execution-model.md)):
a run the Conductor considered due that finds the certificate current
ends as `succeeded`/`noop` without contacting the CA.

### Shutdown and recovery

On `SIGTERM`/`SIGINT`: the listener closes, planning stops, in-flight runs
continue for up to `server.shutdownGraceSeconds`, then are cancelled (the
Runner receives `SIGTERM` and normally reports `Cancelled`, `SIGKILL`
follows after 10 s). A second signal kills the Conductor immediately and
leaves any Runner child running on its own.

At start, runs still `starting` or `running` in the registry are marked
`failed` with `Internal` — "conductor stopped while the run was in flight;
outcome unknown" — and audited; queued runs are dispatched normally. The
Conductor never resumes a run, because it cannot know whether the Runner
finished. A Runner orphaned by a hard kill may still complete its work in
the Store; the next due check then schedules a fresh run, which finds the
certificate current (`noop`) or renews.

## Authentication

Phase 2 has one mode, `localhost-dev` ([ADR 0012](adr/0012-localhost-only-dev-auth.md)).
A request to anything under `/api/` is accepted only if **all** hold:

- the listener is bound to a loopback address (enforced by configuration
  and re-checked at start);
- the TCP peer is a loopback address;
- the `Host` header names `localhost` or a loopback IP, on the listener's
  port if a port is given (defeats DNS rebinding);
- an `Origin` header, if present, is `http://<loopback host>[:port]` for
  that same port (`null` and foreign origins are refused);
- `Sec-Fetch-Site`, if present, is `same-origin` or `none`;
- a request with a body carries `Content-Type: application/json`.

Every accepted caller is the principal `localhost-dev`; that name is what
the audit log records. **Any local user who can open a loopback
connection is an administrator** in this mode. Do not expose it beyond a
single-user development or test host, and do not publish a container
running it to a network; OIDC with named principals is Phase 5.

## Directories and container usage

| Path | Purpose |
|---|---|
| `/usr/local/bin/acme-conductor` | The Conductor binary (image entrypoint). |
| `/etc/acme-conductor/config.json` | The configuration, mounted **read-only**. |
| `/var/lib/acme-conductor/` | Writable, **persistent**: `conductor.db` (plus `-wal`/`-shm`) and `runs/` (per-run `job.json`/`result.json`, no certificate material). |

The Conductor image (`Dockerfile.conductor`) contains **no** `acme-runner`
and no `lego`. The `local-process` launcher therefore only works where
both binaries are on the same host — a development checkout, or a custom
image that adds the Runner. In a container the image supports
`--read-only` as long as `/var/lib/acme-conductor` is a writable mount;
publish the port to the host's loopback only (`-p 127.0.0.1:8080:8080`)
and remember that the process inside the container sees the peer as the
container's loopback only when the client is inside the same network
namespace (`docker exec`, or `--network host`) — with a published port the
peer is the bridge gateway, not loopback, and every request is refused,
which is the intended fail-closed outcome for this phase.

### Backup, restore, rollback

The whole control-plane state is `database.path`. Back it up with the
process stopped (copy the file; the `-wal` file is folded in on the next
open) or online with `sqlite3 conductor.db ".backup out.db"`. Restore by
stopping the process and putting the file back. A newer binary migrates
the schema forward at start (versions are recorded in
`schema_migrations`); an older binary refuses a database written by a
newer schema, so rolling back a deployment means restoring the matching
backup as well. Runs that were in flight at backup time are recovered as
`failed`/"outcome unknown" on the next start.

## Logging

Structured JSON on stderr, always UTC. Every line about a run carries
`runId` and `targetId` (and `fqdn` once known). At `debug`, the Runner
child's stderr — its own structured log, already redacted by the Runner —
is relayed line by line (bounded to 8 KiB per line, non-printable
characters replaced). The Conductor never logs a request body, a binding's
resolved configuration (it has none), or anything from the Runner's
`Result` beyond the fields the contract defines.

## Security boundaries

- The Conductor holds no private key, no certificate body, no DNS or Store
  credential and no cloud credential; its database has no column for any
  of them and no endpoint returns one ([ADR 0005](adr/0005-conductor-never-touches-secrets.md)).
  The one exception a deployment can create for itself is `passthroughEnv`
  on the local launcher (see the security note above).
- API input can only name administrator-registered bindings; there is no
  field for a command, image, path, environment variable, resource id or
  credential, and unknown fields are rejected, so none can be smuggled in.
- FQDNs and suffixes are normalized and checked on a label boundary before
  they are stored; a target that does not satisfy its policy is refused
  and audited, and a policy cannot be edited so that an existing target
  stops satisfying it. The Runner re-validates the `JobSpec` and
  authorizes it against its own trusted configuration regardless
  ([architecture](architecture.md#validation-vs-authorization)).
- Per-target exclusion, optimistic locking on `revision`, and the
  re-check before start keep a stale or duplicate request from being
  actioned (threat model T7).
- The audit log is append-only and written atomically with each change;
  targets, runs and policies cannot be deleted ([ADR 0008](adr/0008-no-purge-in-mvp.md)).
- The Runner child gets an explicit environment (only `passthroughEnv`
  from the Conductor's), runs in its own process group under a timeout,
  and its `Result` is decoded with the strict contract decoder and
  checked to name the run it was started for. Its stderr reaches only the
  debug log, never a record.

## Limitations in Phase 2

- **Development authentication only.** `localhost-dev` authenticates a
  host, not a person. No roles, no named principals, no remote access.
- **One execution shape, one host.** The `local-process` launcher needs
  `acme-runner` (and its `lego`) on the same host, and a credential the
  Runner needs must be in the Conductor's environment
  (`passthroughEnv`). The Azure Container Apps Job launcher with workload
  identity is Phase 4.
- **A hard kill can orphan a Runner.** Recovery marks such runs
  `failed`/"outcome unknown"; the Runner may still finish, and the next
  due run then races it (the Store and account state tolerate that; the
  duplicate ACME order is not prevented).
- **Single process, single connection.** The registry serializes every
  statement; that is fine for hundreds of targets and one operator, not
  for a busy multi-tenant API. Multi-replica is a non-goal.
- **No `JobSpec` signing or replay check** (Phase 4); the local launcher
  hands the document to the Runner over a private directory, but nothing
  authenticates it end to end.
- **No metrics endpoint yet**; `/healthz` and `/readyz` exist, Prometheus
  `/metrics` does not.
- The Runner's `renewBeforeDays`/`keyType` cost levers are still not
  bounded on the Runner side (threat model, residual risks).
