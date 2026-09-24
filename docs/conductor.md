# Conductor operator guide

This is the operator-facing reference for `acme-conductor`, the control
plane described in [`docs/architecture.md`](architecture.md). It covers
the command line, the configuration file, the REST API and the GUI, how
a `Target` becomes a `Run` and how a `Run` is driven to completion, the
two authentication modes, the on-disk state and how to back it up, and
what the Conductor does and does not guarantee today.

Phase 2 shipped the Conductor MVP: a SQLite-backed registry of targets,
policies, runs and audit events, a REST API, a scheduler, and a
local-process launcher that runs `acme-runner` (see
[`docs/runner.md`](runner.md)) as a child process — a **single-host,
single-user development and test deployment**. Phase 4 adds a second
launcher, `azure-container-apps-job`, which starts one execution of a
separately provisioned Azure Container Apps Job per run (the Runner then
holds its own managed identity and no credential ever passes through the
Conductor), and **job signing**: every launcher can hand the Runner a
signed, expiring envelope instead of a bare `JobSpec`, and the Container
Apps launcher always does. Phase 5 adds the production authentication
mode, `oidc` — bearer tokens from an OpenID Connect provider, named
principals, an admin and a viewer role, a TLS listener or a platform
ingress in front of it — and a minimal **GUI** served by the Conductor
itself (see [Authentication](#authentication) and [GUI](#gui)). The
`localhost-dev` mode remains for a single development host. Phase 6
adds the **migration tooling**: a `migrate` command and API that read
the host list of an existing infrastructure definition, compare it with
the registry and import what is missing, and a `migration.targetSource`
flag that keeps the Conductor from issuing anything until the switch
(see [`docs/migration.md`](migration.md) and [`migration`](#migration)).

## Overview

`acme-conductor serve` runs, in one process:

- the **REST API** (`/api/v1alpha1/...`, plus `/healthz` and `/readyz`)
  and the **GUI** (`/ui/`), on a loopback address in `localhost-dev`
  mode or wherever the configuration says in `oidc` mode;
- the **registries** — `Target`, `CertificatePolicy`, `Run` and the
  append-only `AuditEvent` log — in one SQLite file;
- the **scheduler**, which every `tickSeconds` (and whenever the API
  changes something) records a queued `Run` for every enabled target that
  is due, and starts queued runs through a launcher up to
  `maxConcurrentRuns` at a time;
- one **launcher** per configured execution binding — `local-process`,
  which runs `acme-runner reconcile` as a child, or
  `azure-container-apps-job`, which hands a job to the next scheduled
  execution of a Container Apps Job (see [Execution binding: Azure Container Apps Job](#execution-binding-azure-container-apps-job)).

The Conductor never talks to an ACME CA, a DNS provider or a Certificate
Store. It produces a `JobSpec` and consumes a `Result`; everything it
knows about a certificate (expiry, fingerprint, logical store name) is
what the last successful `Result` said.

## Command line

```
acme-conductor serve [--config FILE] [--log-level LEVEL]
acme-conductor keygen --private FILE --public FILE
acme-conductor migrate (list|diff|import) [flags]
acme-conductor --version
acme-conductor --help
```

`migrate` reads a host list from a Bicep parameter file or a TargetList
document, compares it with a running Conductor's registry over the API
and imports the names the registry lacks (a dry run unless `--apply` is
given). It is documented in [`docs/migration.md`](migration.md#command-line).

`keygen` generates the Ed25519 key pair for [job signing](#jobsigning):
the private key is written to `--private` (created `0600`; an existing
file is never overwritten), the public key to `--public` as PEM, and the
key id plus the one-line form of the public key are printed for pasting
into the Runner's `jobSigning.publicKeys`. It needs no configuration and
touches nothing else.

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
| `1` | The configuration was rejected, a launcher could not be built from it, the bound address was not loopback in `localhost-dev` mode, or the TLS certificate could not be loaded. |
| `2` | A fatal runtime error: another Conductor process owns the database (see [Shutdown and recovery](#shutdown-and-recovery)), the registry could not be opened or migrated, in-flight runs could not be recovered, the listener could not be bound, or the HTTP server failed. |

## Configuration reference

The configuration is a strictly decoded JSON document (unknown fields,
duplicate keys, trailing data and over-deep nesting rejected; 256 KiB cap)
that contains **no secret**. The Conductor knows ACME, DNS and Store
bindings **by name only**; what a name resolves to is Runner configuration
(`docs/runner.md`). See
[`deploy/examples/conductor-config.example.json`](../deploy/examples/conductor-config.example.json)
for a complete example whose binding names match the Runner example, and
[`deploy/examples/conductor-config.aca.example.json`](../deploy/examples/conductor-config.aca.example.json)
for the Container Apps shape (`oidc` behind the platform's ingress), and
[`deploy/examples/conductor-config.oidc.example.json`](../deploy/examples/conductor-config.oidc.example.json)
for a self-hosted `oidc` deployment with the Conductor's own TLS listener.

Top level:

| Field | Type | Notes |
|---|---|---|
| `apiVersion` | string | Must equal `acme-conductor.cits-nue.github.io/v1alpha1`. |
| `kind` | string | Must equal `ConductorConfig`. |
| `server` | object | Listener, authentication, shutdown — see below. |
| `database` | object | `{ "path": "..." }` — clean, absolute path of the SQLite file (created `0600` if missing; a symbolic link is refused). Its directory must exist and be writable; SQLite also creates `<path>-wal` and `<path>-shm` next to it, and `serve` holds its ownership lock at `<path>.lock` (see [Shutdown and recovery](#shutdown-and-recovery)). |
| `scheduler` | object | Pacing — see below. |
| `executionBindings` | map | At least one. Keys are binding names (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, ≤63 chars). |
| `acmeBindings` | []string | Non-empty, distinct binding names a policy may select. |
| `dnsBindings` | []string | Non-empty, distinct binding names a target may select. |
| `storeBindings` | []string | Non-empty, distinct binding names a target may select. |
| `jobSigning` | object | Optional; required when an `azure-container-apps-job` binding exists. See below. |
| `migration` | object | Optional. The migration from an infrastructure-defined host list: the `targetSource` flag, the list and the import profile. See [`migration`](#migration). Absent means `targetSource: registry` and no list. |

### `server`

| Field | Type | Default | Notes |
|---|---|---|---|
| `listen` | string | `127.0.0.1:8080` | `host:port`. With `auth.mode: localhost-dev` the host must be `localhost` or a loopback IP literal (`127.0.0.1`, `[::1]`); any other name or address is rejected, and a name is never resolved. With `oidc` any host is allowed, but a non-loopback one needs `tls` or `behindTlsProxy`. Port `0` picks a free port (tests). |
| `auth.mode` | string | `localhost-dev` | `localhost-dev` (one development host) or `oidc` (production). See [Authentication](#authentication). |
| `auth.oidc` | object | — | Required for, and only allowed with, `oidc` — see below. |
| `tls` | object | — | `oidc` only. `{ "certFile": "...", "keyFile": "..." }`, clean absolute paths of a PEM certificate chain and private key: the listener then speaks HTTPS (TLS 1.2+). Both files are read once at start. Mutually exclusive with `behindTlsProxy`. |
| `behindTlsProxy` | bool | `false` | `oidc` only. States that a platform ingress or reverse proxy terminates TLS in front of this port and is the only route to it, so a non-loopback plaintext listener is acceptable. Never set it because it is convenient: a bearer token in the clear is a stolen session. |
| `shutdownGraceSeconds` | int | `900` | How long in-flight runs may continue after a stop signal before they are cancelled. `1`–`86400`. |

### `server.auth.oidc`

| Field | Type | Default | Notes |
|---|---|---|---|
| `issuer` | string | — (required) | The provider's issuer URL, `https://…` (plain `http://` only to a loopback host, for tests); no user information, query or fragment. Its discovery document is read from `<issuer>/.well-known/openid-configuration` and must name the same issuer; every token's `iss` must equal it exactly. Entra ID v2: `https://login.microsoftonline.com/<tenant-id>/v2.0`. |
| `audience` | string | — (required) | The value every token's `aud` must contain, as the provider writes it. Entra ID v2 access tokens carry the API app registration's **Application (client) ID** (a GUID) as `aud`, never its application ID URI, whatever scope was requested. Verification only; nothing is derived from it. Printable ASCII without whitespace, ≤256 bytes. |
| `clientId` | string | — | The public client the GUI signs in as (Entra ID: a single-page-application registration with redirect URI `https://<host>/ui/`). Without it the GUI cannot sign in; the API still accepts tokens obtained elsewhere. |
| `scopes` | []string | — (required with `clientId`) | What the GUI requests at sign-in; not derived from `audience`, since the scope a client requests and the audience the provider writes are different identifiers. Entra ID: `openid`, `profile` and `<application ID URI>/.default`, e.g. `api://<api-client-id>/.default`. ≤16 distinct values; only with `clientId`. |
| `principalClaim` | string | `sub` | The claim whose value is recorded as the audit actor and `requestedBy`: a **stable identifier** of the subject, not a display name (`preferred_username`, `email` and `name` change when a user is renamed). Entra ID: set `oid` (`sub` is pairwise per client there). It must be a string of printable characters, ≤256 bytes. |
| `rolesClaim` | string | `roles` | The claim (a string or an array of strings) whose values are matched against `roles`. |
| `roles.admin` | []string | — (required, non-empty) | Values that grant the **admin** role: every endpoint. |
| `roles.viewer` | []string | — | Values that grant the **viewer** role: `GET` only. A value may appear in one list only; a token carrying values from both is an admin. |
| `clockSkewSeconds` | int | `60` | Tolerance applied to `exp`, `nbf` and `iat`. `1`–`300`. |
| `keyCacheSeconds` | int | `3600` | How long the discovery document and signing keys are reused before they are fetched again. An unknown key id triggers an earlier refresh, at most once a minute. `60`–`86400`. |

The Conductor holds **no client secret**: it verifies tokens with the
provider's published keys and performs no sign-in of its own
([ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)).

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
| `type` | string | The launcher type name (`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`). The Conductor binary decides which types it provides: the official binary provides `local-process` and `azure-container-apps-job`. A type this binary does not provide is refused at start, before anything else happens. |
| `config` | object | The configuration of that type, decoded strictly by the type's provider (unknown fields are refused, duplicate keys are refused, nothing else is accepted). Its content is opaque to the generic configuration: adding a launcher type adds nothing here. Whether a type needs `jobSigning`/`resultSigning` is also the provider's rule, checked when the launcher is built. |

```json
"executionBindings": {
  "local": {
    "type": "local-process",
    "config": { "runnerBinary": "/usr/local/bin/acme-runner", "runnerConfig": "/etc/acme-runner/config.json", "workDir": "/var/lib/acme-conductor/runs" }
  }
}
```

### `type: local-process` — `config`

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
and nowhere else; the Azure Container Apps Job launcher runs the Runner
under its own managed identity and has no passthrough at all. The threat
model records this as T10's local-launcher residual.

### Execution binding: Azure Container Apps Job

`type: azure-container-apps-job` hands each run to an **existing**,
**scheduled** Container Apps Job — the Runner image with its own managed
identity, its configuration, its state volume, an exchange volume and a
fixed command `reconcile --exchange /exchange`, all provisioned in
infrastructure ([`deploy/azure`](../deploy/azure/README.md),
[ADR 0014](adr/0014-azure-container-apps-job-launcher.md)). The Conductor
never creates, changes or **starts** the Job: the platform's start
operation accepts an execution template that can replace the image,
command and environment of the Job's containers, so an identity allowed
to start the Job could run any image under the Runner's identity. The
Conductor's identity is not allowed to. For a run it:

1. offers the signed job on the exchange volume (a file share both
   containers mount): it writes `<exchangeDir>/staging/run-<runId>/job.json`
   and moves the directory to `<exchangeDir>/pending/` in one rename;
2. waits for the next execution the platform's schedule starts (every
   minute in the Bicep) to take the job — the Runner moves the directory
   to `<exchangeDir>/claimed/` (exactly one execution wins) and records
   its execution name there — and confirms with the platform that the
   recorded name is an execution of this Job (a name the platform
   consistently does not know, on every attempt, ends the run; a
   platform that cannot be asked, or a 404 that does not persist, does
   not — after a few attempts the execution is watched unconfirmed,
   because a Runner holds the job). If none takes it within `claimTimeoutSeconds`
   the offer is withdrawn (by the same rename, so a late taker cannot
   race it) and the run fails; a cancelled run is withdrawn the same way
   and ends `cancelled`;
3. polls the execution's status every `pollIntervalSeconds` until it is
   terminal (`Succeeded`, `Failed`, `Stopped`, `Degraded`). Whenever
   polling ends without a terminal status — the run was cancelled,
   `timeoutSeconds` passed, or the status could not be read any more —
   the execution is stopped through the platform *before* the run
   directory is removed, then given a bounded grace to end;
4. reads `result.json` (waiting up to `resultGraceSeconds` for the share
   to show it), which must be a `SignedCertificateReconcileResult`
   verifying against `resultSigning.publicKeys` (see below), checks it
   names this run and target and that its status agrees with the
   platform's verdict (`Succeeded` with a failed `Result`, or `Failed`
   with a succeeded one, is a mismatch → `Internal`), and removes the run
   directory — only once the execution has been seen to end; an
   execution whose status stayed unreadable and whose stop could not be
   confirmed keeps its directory (a Runner may still be writing there),
   logged as "run directory kept" for an operator to remove.

The run's `externalExecutionId` is `azure-container-apps-job:<execution
name>`. The Conductor's identity needs, on the Job resource only, the
three actions the Bicep grants (`jobs/execution/read`,
`jobs/executions/read`, `jobs/stop/execution/action`) — it cannot start
or change the Job and holds no DNS, Key Vault or storage data
permission. A run therefore starts up to one schedule interval plus the
platform's start latency after it is queued, and at most one run starts
per schedule tick (each execution runs one replica and takes one job).

| Field | Type | Default | Notes |
|---|---|---|---|
| `subscriptionId` | string | — (required) | GUID of the subscription holding the Job. |
| `resourceGroup` | string | — (required) | Resource group of the Job. |
| `jobName` | string | — (required) | Name of the Container Apps Job (2–32 lower-case letters, digits and hyphens, no `--`). |
| `cloud` | string | `public` | `public`, `china` or `government`: selects the Resource Manager endpoint and identity authority. |
| `credential` | string | `default` | How the Conductor authenticates to Resource Manager: `managed-identity` (the platform's identity — use this in production) or `default` (the SDK's `DefaultAzureCredential` chain, for a Conductor run on a developer host with the exchange share mounted). |
| `managedIdentityClientId` | string | — | `managed-identity` only: the client ID of a user-assigned identity; omitted means system-assigned. |
| `exchangeDir` | string | — (required) | Clean, absolute path where the exchange volume is mounted in the **Conductor's** filesystem (`/mnt/exchange` in the Bicep). Created if missing. The Runner is told its own mount path by its fixed arguments in infrastructure. |
| `claimTimeoutSeconds` | int | `300` | How long to wait for a scheduled execution to take an offered job before withdrawing it. Must not exceed `jobSigning.validitySeconds` (a job taken after its expiry is refused by the Runner). `1`–`86400`. |
| `timeoutSeconds` | int | `1200` | Bounds one execution, from the moment it took the job, as seen by the Conductor; after it the execution is stopped. Set it above the Job's `replicaTimeout`, which is above the Runner's `lego.timeoutSeconds`. `1`–`86400`. |
| `pollIntervalSeconds` | int | `10` | How often the exchange directory and the execution's status are read. `1`–`300`. |
| `resultGraceSeconds` | int | `30` | How long to wait for `result.json` after the execution ended (file shares propagate writes with a delay). `0`–`600`. |

A configuration with an `azure-container-apps-job` binding and no
`jobSigning` or no `resultSigning` is rejected: the exchange volume is
not a transport the Conductor owns, so every job on it is signed and
every Result on it must be. See
[`deploy/examples/conductor-config.aca.example.json`](../deploy/examples/conductor-config.aca.example.json).

### `migration`

The migration from an existing infrastructure-defined host list
([`docs/migration.md`](migration.md)). The whole section is optional;
its parts are:

| Field | Type | Default | Notes |
|---|---|---|---|
| `targetSource` | string | `registry` | Who issues. `registry`: the scheduler plans and starts runs for the registry's targets. `shadow`: it does not, and the configured list is compared with the registry every `compareIntervalSeconds`. `iac`: it does not, full stop. Under `shadow` and `iac`, `POST /targets/{id}/runs` answers `409 issuance_disabled`; the registry stays editable. |
| `source` | object | — | Where the list is read from: exactly one of `bicepParamFile` (a clean absolute path; with `parameter`, default `targetDomains`), `jsonFile` (a TargetList document, clean absolute path) or `fqdns` (the list inline, at most 10000 names). Required under `shadow`; otherwise it is the default list of `GET /migration/diff` and of an import without `fqdns`. Needs `profile`. |
| `profile` | object | — | What every imported target is made of besides its FQDN: `policyRef` (an identifier; the policy must exist when the profile is used), `executionBinding`, `dnsBinding` and `storeBinding` (each a binding this configuration registers) and `owner` (printable, at most 128 bytes). Required with `source`, and for any diff or import at all. |
| `compareIntervalSeconds` | int | `300` | How often the shadow comparison runs. `10`–`86400`. |

The list contributes FQDNs and nothing else; the profile, and so the
administrator, decides everything a target needs beyond its name.

### `jobSigning`

| Field | Type | Default | Notes |
|---|---|---|---|
| `privateKeyFile` | string | — (required) | Clean, absolute path of the PEM `PRIVATE KEY` (PKCS #8, Ed25519) file from `acme-conductor keygen`. Read once at start; an unreadable or wrong-type key is a configuration error (exit 1). |
| `validitySeconds` | int | `900` | How long a signed job stays acceptable after it is issued; it only needs to cover the platform's start latency, because the Runner checks it before doing anything. `1`–`86400`. |

With `jobSigning` present, **every** launcher hands the Runner a
`SignedCertificateReconcileJob` ([ADR 0015](adr/0015-signed-job-envelope.md)):
the exact `JobSpec` bytes, base64url, under a strict header with the key
id, `issuedAt`, `expiresAt` and a random nonce, signed with Ed25519. The
Runner must then list the matching public key under its own
`jobSigning.publicKeys` ([`docs/runner.md`](runner.md#jobsigning)) and
refuses bare JobSpecs. Without `jobSigning` the local launcher hands over
a bare `JobSpec` as in Phase 2. The private key is the only secret the
Conductor ever reads; it is the Conductor's identity towards Runners, not
a DNS, Store or cloud credential. To rotate it, add the new public key to
the Runners first, then switch `privateKeyFile`, then remove the old
public key. The key id appears in the `job signing enabled` log line at
start.

### `resultSigning`

| Field | Type | Default | Notes |
|---|---|---|---|
| `publicKeys` | []string | — (required) | 1–8 Runner result-signing public keys (Ed25519), each either a PEM `PUBLIC KEY` block or the standard base64 of its DER SubjectPublicKeyInfo — the one-line `publicKey:` that `acme-runner keygen` prints. Several keys let a Runner key rotate. Duplicates are rejected. |
| `clockSkewSeconds` | int | `300` | How far a signed Result's `issuedAt` may lie in the future of this Conductor's clock before it is refused. Expiry has no tolerance. `1`–`3600`. |

With `resultSigning` present, **every** launcher accepts only a
`SignedCertificateReconcileResult` ([ADR 0015](adr/0015-signed-job-envelope.md))
whose signature verifies against one of these keys and whose payload is
a valid `Result`; a bare `Result` is then "no result" and the run ends
`Internal`. The Runner must then be configured with the matching private
key under its `resultSigning.privateKeyFile`
([`docs/runner.md`](runner.md#resultsigning)). Without `resultSigning`
a signed Result is refused the same way, so signing is decided once, by
configuration, never by the document. The Container Apps launcher
requires it; the local launcher over a private directory may run either
way. The Conductor holds public keys only.

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
| 401 | `unauthenticated` | `oidc` mode: no bearer token, or one that does not verify (signature, issuer, audience, expiry, unknown key). Carries `WWW-Authenticate: Bearer realm="acme-conductor"`. |
| 403 | `forbidden` | `localhost-dev`: refused by the mode's rules. `oidc`: the token verified but carries no role this API grants, or a viewer called anything but `GET`. |
| 404 | `not_found` | No such policy, target, run, or endpoint. |
| 409 | `conflict` | A second target for the same FQDN; a policy edit that would no longer cover an existing target; cancelling a run that is not cancellable. |
| 409 | `stale_revision` | The `revision` in the request is not the target's current revision. |
| 409 | `run_active` | A run is already queued/starting/running for the target (`details.activeRunId`, `details.status`). |
| 409 | `target_disabled` | A run was requested for a disabled target. |
| 409 | `issuance_disabled` | A run was requested while `migration.targetSource` is `shadow` or `iac` ([`docs/migration.md`](migration.md)). |
| 409 | `migration_unconfigured` | A migration diff or import was requested but no `migration.profile` is configured, or the policy it names does not exist. |
| 409 | `source_unreadable` | The configured `migration.source` could not be read (file missing, malformed, a name that is not a host name). |
| 413 | `too_large` | Body over 64 KiB. |
| 415 | `unsupported_media_type` | Body without `Content-Type: application/json`. |
| 500 | `internal` | Registry or other internal failure; details are in the log only. |

### Endpoints

| Method and path | Purpose |
|---|---|
| `GET /healthz` | Liveness: `{"status":"ok"}`. Unauthenticated. |
| `GET /readyz` | Readiness: pings the registry; `503` `{"status":"unavailable"}` on failure. Unauthenticated. |
| `GET /` | Redirects to `/ui/`. |
| `GET /ui/`, `/ui/app.js`, `/ui/app.css` | The GUI's three static files. Unauthenticated (they contain no data). |
| `GET /ui/config` | How the GUI signs in: `{"auth":{"mode":"oidc","issuer":…,"clientId":…,"scopes":[…],"authorizationEndpoint":…,"tokenEndpoint":…}}` or `{"auth":{"mode":"localhost-dev"}}`. Unauthenticated; `503` while the provider's discovery document is unavailable. |
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
| `GET /api/v1alpha1/migration` | The migration state: `targetSource`, `issuanceEnabled`, the configured source and profile, and under `shadow` the latest comparison. |
| `GET /api/v1alpha1/migration/diff` | Compare the configured list with the registry → report. |
| `POST /api/v1alpha1/migration/diff` | Compare `{"fqdns": […]}` with the registry → report. |
| `POST /api/v1alpha1/migration/import` | Import a list: `{"fqdns": […], "dryRun": true}`, both optional (`dryRun` defaults to `true`; without `fqdns`, the configured list) → import result. Creates targets only for names the registry lacks, never updates or deletes. Wakes the scheduler when it created something. See [`docs/migration.md`](migration.md#api). |

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

**When a policy change takes effect.** A policy is not versioned and
targets do not carry a policy revision; an update is accepted only if
every existing target under the policy still satisfies it (`409
conflict` naming the offending targets otherwise), and the new values are read at each
target's **next run**. A run is next due when the certificate enters its
`renewBeforeDays` window, when the target itself changes (its revision
moves), or when an operator requests one (`POST /targets/{id}/runs`).
Updating a policy does not by itself queue runs or bump target revisions.
What each field does at that next run:

- `keyType` — the Runner compares the stored certificate's key type with
  the requested one and reissues on a mismatch, even if the certificate
  is otherwise current; so after a `keyType` change, a manual run on each
  target rotates it now, and the renewal window rotates it later
  otherwise.
- `renewBeforeDays` — read by the scheduler at every due check, so a
  larger window can make targets due at the next tick.
- `acmeBinding` — selects the CA for the next ACME order only; a current
  certificate from the previous CA is not reissued on account of the
  change alone, so a target moves to the new CA at its next renewal (or
  at a manual run that finds something else to reissue). Phase 2 does
  not force reissue on a binding change ([ADR 0011](adr/0011-conductor-storage-and-run-model.md)).
- `allowedDnsSuffixes`, `allowWildcard` — enforced on the update itself
  against existing targets and on every later target create/update; the
  Runner re-validates the snapshot it receives.

The `JobSpec` handed to the Runner carries the policy values as a snapshot,
so the audit trail of a run always shows the values it was executed with.

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
  "status": "succeeded", "requestedBy": "scheduler", "requestedByAuthority": "scheduler",
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
`scheduler` or the API principal (`localhost-dev`, or in `oidc` mode the
value of `principalClaim`, an identifier such as an Entra ID `oid`), and
`requestedByAuthority` is the namespace that value is unique in:
`scheduler`, `localhost-dev`, or the OIDC issuer URL
(`server.auth.oidc.issuer` at the time of the run). The pair is the
durable identity ([ADR 0018](adr/0018-authority-qualified-principals.md));
`requestedByAuthority` is `""` on runs recorded before the Conductor
stored it (schema version 1).

### Audit event

```json
{ "id": "01JEVENT…", "time": "…", "actor": "localhost-dev", "actorAuthority": "localhost-dev",
  "action": "target.created", "targetId": "01JTARGET…", "runId": "", "policyId": "",
  "detail": "target created: fqdn=… policy=… …" }
```

`actor` and `actorAuthority` identify who acted the same way
`requestedBy` and `requestedByAuthority` do on a run: the actor value is
unique only within its authority (an OIDC issuer URL, `localhost-dev` or
`scheduler`), so the pair, not the actor alone, names a principal across
a change of identity provider. `actorAuthority` is `""` on events
recorded before the Conductor stored it; such rows are never rewritten
(the audit log is append-only).

Actions: `policy.created`, `policy.updated`, `policy.rejected`,
`target.created`, `target.updated`, `target.enabled`, `target.disabled`,
`target.imported` (a target created by a migration import, with the list
it came from), `run.requested`, `run.started`, `run.succeeded`,
`run.failed`, `run.cancelled`, `migration.compared` (a shadow comparison
whose outcome differs from the previous one; actor and authority are
both `migration`, the Conductor's own comparison loop, the way `scheduler`
is its own authority). `detail` is a short sentence built by the
Conductor from validated values (at most 512 bytes); it never contains
Runner output.
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
4. **Launch.** The `JobSpec` is serialized — as a signed envelope when
   `jobSigning` is configured — and the execution binding's launcher
   starts the Runner (a child process, or a Container Apps Job
   execution); the run becomes `running` with the platform's execution
   id recorded.
5. **Result.** The Runner's `Result` (strictly decoded, checked to name
   this run and target) sets the terminal status and every certificate
   field. `Cancelled` → `cancelled`; any other error → `failed`. If the
   launcher obtains no `Result` at all, the run fails with a
   Conductor-owned summary: `Timeout` (launcher timeout), `Cancelled`
   (stopped before reporting), or `Internal` (no/unusable/mismatched
   result, could not start). Nothing the Runner printed is copied into a
   run record.
6. **Recording.** Every status transition is written against the status
   the registry is known to hold, not the one the scheduler intended, and
   each write carries its audit event in the same transaction. If the
   `starting → running` write fails while the Runner is already executing,
   the scheduler keeps waiting for the Runner and records the outcome
   against `starting` (after one more attempt to record the start, so the
   trail carries `run.started` whenever the registry is back). A terminal
   write that fails transiently is retried with backoff for up to two
   minutes; a conflict (the registry holds another status than expected,
   for example after a write that committed but reported an error) is
   resolved by re-reading the run and retrying against its actual status,
   never by recording a transition twice. Should the outcome still not be
   recorded, the run is left `running` by its execution and closed at the
   next loop iteration by the **sweep**, which marks every `starting` or
   `running` run this process is not executing as `failed`/`Internal`
   "run outcome could not be recorded while the runner ran; outcome
   unknown", so the target's exclusion slot is freed and its next run can
   be registered. The sweep runs in the loop goroutine only, after
   dispatch has registered what it claimed, so it never mistakes a run
   claimed a moment ago for a stranded one.

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

**Exactly one Conductor per database.** Before it opens the registry,
recovers anything or binds its port, `serve` takes an exclusive advisory
lock (`flock`) on `<database.path>.lock`. If another process holds it,
`serve` logs "another conductor process owns this database; refusing to
start" and exits with code `2` without having changed any state — in
particular without marking the owner's in-flight runs failed. The lock is
released when the process exits (also on a crash: the kernel drops it with
the descriptor), so a restart owns the database again. The database path
must be on a local filesystem for the lock to be meaningful (`flock`
semantics on network filesystems vary; the same caveat as for the
Runner's `internal/fslock`). A second instance on another port with the
same `database.path` is therefore refused, not merely a port clash.

At start, runs still `starting` or `running` in the registry are marked
`failed` with `Internal` — "conductor stopped while the run was in flight;
outcome unknown" — and audited; queued runs are dispatched normally. The
Conductor never resumes a run, because it cannot know whether the Runner
finished. A Runner orphaned by a hard kill may still complete its work in
the Store; the next due check then schedules a fresh run, which finds the
certificate current (`noop`) or renews.

## Authentication

Two modes, selected by `server.auth.mode`. Both authenticate every
request under `/api/`; `/healthz`, `/readyz` and the GUI's static files
need no credential, and every handler under `/api/` runs only behind the
same middleware, so no endpoint can be added that bypasses it.

### `oidc` (production)

The Conductor is an OpenID Connect **resource server**
([ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)): it accepts an
`Authorization: Bearer <access token>` header — never a cookie or a
query parameter — and a token is accepted only if **all** hold:

- it is a compact JWS signed with `RS256`, `PS256` or `ES256` (`none` and
  HMAC are refused), names a key id, uses no critical extension, and its
  signature verifies against that key in the set the provider publishes
  at its discovery document's `jwks_uri` (RSA ≥ 2048 bits or P-256);
- `iss` equals `server.auth.oidc.issuer`, and `aud` contains
  `server.auth.oidc.audience`;
- `exp` is present and not passed (within `clockSkewSeconds`); `nbf` and
  `iat`, if present, are not in the future;
- its header and payload decode strictly (a duplicated claim is refused);
- `principalClaim` is a printable string, which becomes the caller's
  identity in the audit log and in `requestedBy`;
- `rolesClaim` carries a value in `roles.admin` (→ **admin**, every
  endpoint) or `roles.viewer` (→ **viewer**, `GET` only). A token with
  neither verified but is refused with `403`.

Failures answer `401` with a `WWW-Authenticate: Bearer` challenge, or
`403` when the caller was identified but is not permitted. Error texts
say why (expired, wrong audience, unknown key) and never echo the token.
The log records every refusal with the method, path and reason.

The provider's discovery document and keys are read once at start
(a provider that is unreachable then is a warning; tokens are refused
until it answers, and scheduled renewals are unaffected) and again every
`keyCacheSeconds`, or sooner when a token names a key id the cached set
does not hold (at most once a minute). A refresh that fails keeps the
previous keys.

**Transport.** A bearer token is a session; it must not travel in the
clear. With a non-loopback `server.listen` the configuration insists on
`server.tls` (the Conductor's own certificate and key; TLS 1.2+) or on
`server.behindTlsProxy: true` — an explicit statement that a platform
ingress or reverse proxy terminates TLS and is the only route to the
port. The Container Apps deployment uses the latter with the
environment's peer-traffic encryption
([`deploy/azure/README.md`](../deploy/azure/README.md)).

**Obtaining a token.** The GUI does it in the browser (see [GUI](#gui)).
From a terminal, ask the provider for a token for the API's scope; with
Microsoft Entra ID, an API app registration whose client ID (the
`audience`) is `1111…` and whose application ID URI is the default
`api://1111…`:

```sh
token="$(az account get-access-token --scope api://11111111-1111-1111-1111-111111111111/.default --query accessToken -o tsv)"
curl -s -H "Authorization: Bearer $token" https://conductor.example.ac.jp/api/v1alpha1/targets
```

The provider-side setup (an API app registration with app roles, a
public client for the GUI) is described with the Azure deployment; any
provider that publishes a discovery document and signs tokens with one
of the three algorithms works the same way, with `principalClaim` and
`rolesClaim` set to what it issues.

### `localhost-dev` (one development host)

The Phase 2 mode ([ADR 0012](adr/0012-localhost-only-dev-auth.md)).
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

Every accepted caller is the principal `localhost-dev` with the admin
role; that name is what the audit log records. **Any local user who can
open a loopback connection is an administrator** in this mode. Do not
expose it beyond a single-user development or test host, and do not
publish a container running it to a network; that is what `oidc` is
for.

## GUI

`/ui/` is a minimal interface over the same API: targets (list, create,
edit, enable/disable, request a run), policies (list, create, edit),
runs (list with a status filter, detail, cancel) and the audit log. It
is three static files embedded in the binary — one page, one script,
one stylesheet — with no framework and no build step; everything it
shows is rendered through DOM methods, never as markup built from data,
and it calls the API on its own origin only.

In `oidc` mode the page signs the operator in as a **public client**
(`server.auth.oidc.clientId`) with the authorization code flow and PKCE:
it reads `/ui/config`, sends the browser to the provider's
`authorization_endpoint`, exchanges the returned code at the
`token_endpoint` with the code verifier, and keeps the access token in
the tab's session storage (gone when the tab closes, never in a URL or a
cookie). The token is sent as a bearer header, so the API needs no
cookie and no CSRF token; a `401` sends the operator back to sign-in. A
viewer sees everything and gets `403` on any change. The page is served
with a Content-Security-Policy that allows its own script and
stylesheet, connections to its own origin and to the provider's token
endpoint origin, and nothing else (`default-src 'none'`, no inline
script, `frame-ancestors 'none'`), plus `X-Frame-Options: DENY` and
`Referrer-Policy: no-referrer`. In `localhost-dev` mode the same page
works without sign-in, because it is a same-origin caller on loopback.

The GUI shows only what the API returns: never a private key, a
certificate body or a credential, because the Conductor has none.

## Directories and container usage

| Path | Purpose |
|---|---|
| `/usr/local/bin/acme-conductor` | The Conductor binary (image entrypoint). |
| `/etc/acme-conductor/config.json` | The configuration, mounted **read-only**. |
| `/etc/acme-conductor/job-signing.pem` | The job-signing private key (when `jobSigning` is configured), mounted **read-only** for this container only. |
| `/etc/acme-conductor/tls.crt`, `tls.key` | The listener's certificate and key when `server.tls` is configured (a convention; the paths are what the configuration names), mounted **read-only**. |
| `/var/lib/acme-conductor/` | Writable, **persistent**: `conductor.db` (plus `-wal`/`-shm`) and `runs/` (per-run `job.json`/`result.json`, no certificate material). |
| `/mnt/exchange` | With the Container Apps launcher: the exchange share, holding per-run `job.json`/`result.json` while an execution is in flight. |

The Conductor image (`Dockerfile.conductor`) contains **no** `acme-runner`
and no `lego`. The `local-process` launcher therefore only works where
both binaries are on the same host — a development checkout, or a custom
image that adds the Runner. In a container the image supports
`--read-only` as long as `/var/lib/acme-conductor` is a writable mount.
In `localhost-dev` mode publish the port to the host's loopback only
(`-p 127.0.0.1:8080:8080`) and remember that the process inside the
container sees the peer as the container's loopback only when the client
is inside the same network namespace (`docker exec`, or `--network
host`) — with a published port the peer is the bridge gateway, not
loopback, and every request is refused, which is the intended
fail-closed outcome for that mode. In `oidc` mode listen on
`0.0.0.0:<port>` with `server.tls` (mount the certificate and key
read-only) or behind an ingress that terminates TLS
(`server.behindTlsProxy: true`); the peer address does not matter.

Released images are published to `ghcr.io/cits-nue/acme-conductor` and
`ghcr.io/cits-nue/acme-runner` on a version tag whose commit is on
`main` (the workflow refuses any other), for `linux/amd64` and
`linux/arm64`, with an SBOM and provenance attached
([ADR 0017](adr/0017-release-pipeline.md)); verify one with
`gh attestation verify oci://ghcr.io/cits-nue/acme-conductor:<version> --owner CITS-NUE`
and pin its digest.

### Backup, restore, rollback

The whole control-plane state is `database.path`. Back it up with the
process stopped (copy the file; the `-wal` file is folded in on the next
open) or online with `sqlite3 conductor.db ".backup out.db"`. Restore by
stopping the process and putting the file back. A newer binary migrates
the schema forward at start (versions are recorded in
`schema_migrations`; version 2 added the `actorAuthority` and
`requestedByAuthority` columns, leaving existing rows empty); an older
binary refuses a database written by a
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
- In `oidc` mode every caller is a named principal with a role, decided
  from a token the provider signed and checked in one middleware for
  every endpoint; the Conductor holds no client secret, refuses `none`
  and HMAC algorithms, and never lets a bearer token onto a non-loopback
  plaintext listener unless the configuration states that TLS is
  terminated in front of it. The GUI is static, same-origin, DOM-rendered
  and served under a strict Content-Security-Policy.
- FQDNs and suffixes are normalized and checked on a label boundary before
  they are stored; a target that does not satisfy its policy is refused
  and audited, and a policy cannot be edited so that an existing target
  stops satisfying it. The Runner re-validates the `JobSpec` and
  authorizes it against its own trusted configuration regardless
  ([architecture](architecture.md#validation-vs-authorization)).
- Per-target exclusion, optimistic locking on `revision`, and the
  re-check before start keep a stale or duplicate request from being
  actioned (threat model T7); the database ownership lock keeps a second
  Conductor process from planning against the same registry or marking
  the owner's runs failed.
- The audit log is append-only and written atomically with each change;
  targets, runs and policies cannot be deleted ([ADR 0008](adr/0008-no-purge-in-mvp.md)).
- The Runner child gets an explicit environment (only `passthroughEnv`
  from the Conductor's), runs in its own process group under a timeout,
  and its `Result` is decoded with the strict contract decoder and
  checked to name the run it was started for. Its stderr reaches only the
  debug log, never a record.
- With `jobSigning`, what leaves the Conductor is a signed, expiring
  envelope; a Runner detects a job altered on the way (a changed FQDN, a
  swapped binding, an extended expiry) and refuses to execute the same
  run twice. Signing authenticates the Conductor; it does not widen what
  a Runner may do, which its own trusted policy still decides.
- With the Container Apps launcher the Conductor's identity can start,
  observe and stop executions of one Job and nothing else; it cannot
  change what the Runner is, and the Runner's DNS and Key Vault access is
  its own managed identity, provisioned in Bicep with least-privilege
  custom roles. Platform errors reach the log as fixed wording (status
  and error code), never as response bodies.

## Limitations

- **The provider is trusted within the audience.** Whoever the provider
  issues an admin-role token to, for this audience, is an administrator;
  role assignment is provider-side administration this project cannot
  audit. A stolen access token is usable until it expires (the Conductor
  performs no revocation or introspection check); short provider
  lifetimes and TLS everywhere bound that. Two roles only, no
  per-target or per-policy permissions.
- **`localhost-dev` authenticates a host, not a person**, and is for one
  development host only.
- **The GUI is minimal.** Lists and forms over the API, no dashboards,
  no bulk operations, no state of its own; it needs `clientId` and a
  public-client registration at the provider to sign in.
- **The local launcher is one host.** It needs `acme-runner` (and its
  `lego`) on the same host, and a credential the Runner needs must be in
  the Conductor's environment (`passthroughEnv`). The Container Apps
  launcher has neither constraint.
- **The Container Apps launcher is verified against a fake platform.**
  Its tests exercise the whole exchange against an in-process fake of
  the Jobs API; the Bicep compiles and lints. The platform's
  execution-template override inheriting volume mounts, the custom role
  action names, SQLite and `flock` on an SMB share, and the Result
  propagation delay are documented expectations until a first real
  deployment confirms them ([`deploy/azure/README.md`](../deploy/azure/README.md)).
- **A hard kill can orphan a Runner.** Recovery marks such runs
  `failed`/"outcome unknown"; the Runner may still finish, and the next
  due run then races it (the Store and account state tolerate that; the
  duplicate ACME order is not prevented).
- **Single process, single connection.** The registry serializes every
  statement; that is fine for hundreds of targets and one operator, not
  for a busy multi-tenant API. Multi-replica is a non-goal, and the
  ownership lock makes a second process on the same database a startup
  error rather than a supported shape.
- **The migration moves names, not certificates or accounts.** An
  imported target is issued afresh under the Conductor's own object
  name once `targetSource` is `registry`; consumers are re-pointed by
  the operator, and the shadow comparison compares lists, not the
  certificates in the store ([`docs/migration.md`](migration.md)).
- **Policy changes are not versioned or pushed.** A policy update applies
  at each target's next run (see [Policy](#policy)); an `acmeBinding`
  change does not force reissue of current certificates, and there is no
  policy revision on runs, only the snapshot in each `JobSpec`.
- **Signing is optional for the local launcher.** Without `jobSigning`
  it hands a bare `JobSpec` over a private per-run directory, which
  nothing authenticates end to end; that is acceptable on one host only.
- **No metrics endpoint yet**; `/healthz` and `/readyz` exist, Prometheus
  `/metrics` does not.
- The Runner's `renewBeforeDays`/`keyType` cost levers are still not
  bounded on the Runner side (threat model, residual risks).
