# Deploying to Azure Container Apps (Phase 4)

`main.bicep` provisions a complete ACME Conductor deployment on Azure
Container Apps: the Conductor as a single-replica Container App, the
Runner as a *scheduled* Container Apps Job whose executions take the
jobs the Conductor offers (the Conductor cannot start executions: the
start operation could replace the Runner's image), two managed
identities with disjoint grants, and the storage the two signed exchange
documents travel over. It is the reviewable,
versioned form of the IAM the threat model requires
([`docs/threat-model.md`](../../docs/threat-model.md), T10): every grant
is a custom role with the smallest set of actions, assigned at the
narrowest scope.

Read [`docs/conductor.md`](../../docs/conductor.md#execution-binding-azure-container-apps-job)
for how the launcher works and
[`docs/adr/0014-azure-container-apps-job-launcher.md`](../../docs/adr/0014-azure-container-apps-job-launcher.md)
for why it is shaped this way. **What this template has not been
verified against is listed at the end; read that before relying on it.**

## What gets deployed

| Resource | Purpose |
|---|---|
| `<prefix>-log` (Log Analytics) | Container logs of both binaries. The Runner's own log is redacted before it is written; the Conductor's carries no secret. |
| `<prefix>-cae` (Container Apps environment) | Hosts the app and the job. Consumption plan, no VNet integration. |
| `<prefix><hash>` (storage account) | Three Azure Files shares, mounted into the environment: `conductor-state` (the SQLite registry, mounted with `nobrl`), `runner-state` (ACME account state, `/state`), `exchange` (signed jobs in, results out). |
| `<prefix>-id-conductor` (user-assigned identity) | The Conductor's identity. Granted the **Conductor Job Execution Observer** custom role (read, list and stop executions; no start) on the Runner Job only. |
| `<prefix>-id-runner` (user-assigned identity) | The Runner's identity. Granted the **Runner DNS TXT Writer** custom role on the challenge zone and the **Runner Key Vault Certificate Writer** custom role on the vault. |
| `<prefix>-runner` (Container Apps Job) | The Runner image with the Runner configuration and its result-signing private key mounted under `/etc/acme-runner/`, `/exchange`, `/state`, and an ephemeral `/work`. Schedule trigger (`runnerCronExpression`, every minute), one replica per execution (`parallelism: 1`: the launcher's contract is one run per execution), no retries, fixed command `reconcile --exchange /exchange`. |
| `<prefix>-conductor` (Container App) | The Conductor image with its configuration and the job-signing private key mounted under `/etc/acme-conductor/`, `/var/lib/acme-conductor` and `/mnt/exchange`. One replica, no ingress, optional admin sidecar. |
| Three custom role definitions (subscription scope) | See `modules/roles.bicep`. |

The Conductor's identity holds **no** DNS, Key Vault or storage data
permission. The Runner's identity holds **no** permission on the Job,
the app or the storage account. Neither identity can read the storage
account key: the environment mounts the shares with it, and the key
never enters either container.

## Prerequisites

- A resource group for this deployment, a DNS zone the Runner may write
  TXT records in, and a Key Vault with the **RBAC** permission model
  (`enableRbacAuthorization: true`). Both may live in other resource
  groups but **must be in the same subscription** as the deployment: the
  custom roles are defined with that subscription as their only
  assignable scope, and a role cannot be assigned outside its assignable
  scopes. The deployer needs the right to create role assignments there
  (Owner or User Access Administrator), and to create role definitions
  at subscription scope. Cross-subscription placement is a later
  extension (role definitions per subscription), not a parameter.
- `namePrefix` of 3–20 lower-case letters, digits and hyphens. The
  storage account is named from its first 11 characters without hyphens
  plus a 13-character unique suffix, so any accepted prefix yields a
  valid 24-character-bounded name.
- Container images for both binaries, pinned by digest. Phase 4 has no
  release workflow; build them with `make images` and push them to a
  registry the environment can pull from (GHCR public images need no
  registry credential).
- Two signing key pairs, one per direction of the exchange share:

  ```sh
  acme-conductor keygen --private job-signing.pem --public job-signing.pub
  acme-runner keygen --private result-signing.pem --public result-signing.pub
  ```

  Each command prints `keyId:` and `publicKey:` (the one-line form of the
  public key). The private key files go in as secure parameters
  (`jobSigningPrivateKeyPem`, mounted for the Conductor;
  `resultSigningPrivateKeyPem`, mounted for the Runner); the public keys
  go to the other side (`jobSigningPublicKey` into the Runner
  configuration, `resultSigningPublicKey` into the Conductor's).

## Deploy

1. Write the Runner configuration
   ([`deploy/examples/runner-config.aca.example.json`](../examples/runner-config.aca.example.json)
   is a starting point). Keep `lego.stateDir` at `/state` and
   `lego.workDir` at `/work`, and make every DNS binding authenticate
   with the managed identity (see below). `jobSigning.publicKeys` is
   **added by the template** from the `jobSigningPublicKey` parameter,
   so the Runner cannot be deployed without the key it needs.
2. Copy `main.bicepparam`, fill in images, binding names, zone, vault
   and the public key.
3. Deploy:

   ```sh
   export ACME_JOB_SIGNING_PRIVATE_KEY_PEM="$(cat job-signing.pem)"
   az deployment group create --resource-group rg-acme \
     --template-file main.bicep --parameters main.bicepparam
   ```

The `conductorConfig` output shows the Conductor configuration the
template derived (subscription, resource group, job name, the
Conductor identity's client ID, the exchange paths); it is what the
Conductor runs with.

### The Runner's identity inside the Job

The Runner authenticates to Key Vault with its user-assigned identity:
the template sets `managedIdentityClientId` on every `azure-keyvault`
store binding with `credential: managed-identity` to the identity's
client ID (a managed-identity credential that names no client ID asks
the platform for a system-assigned identity, which this Job does not
have), and sets `AZURE_CLIENT_ID` in the Job's environment for `lego`. `lego`'s `azuredns`
provider uses the same identity when the DNS binding says
`AZURE_AUTH_METHOD=msi`. Container Apps exposes the identity through the
`IDENTITY_ENDPOINT` and `IDENTITY_HEADER` variables of the container,
and the Runner builds `lego`'s environment from scratch, so the binding
must forward exactly those names:

```json
"passthroughEnv": ["AZURE_CLIENT_ID", "IDENTITY_ENDPOINT", "IDENTITY_HEADER"]
```

No credential value appears anywhere; `IDENTITY_HEADER` is a
per-container token for the local identity endpoint and is redacted from
the Runner's log like any other passthrough value.

## Operating the deployment

**The API is reachable from inside the Conductor replica only.** The
Conductor listens on `127.0.0.1:8080` with `localhost-dev`
authentication ([ADR 0012](../../docs/adr/0012-localhost-only-dev-auth.md)):
the app has no ingress, and a request from anywhere but the replica's
own loopback is refused. Until Phase 5 adds OIDC, administration goes
through the optional sidecar (`adminSidecarImage`): a second container in
the same replica shares the loopback interface, so

```sh
az containerapp exec --name acme-conductor --resource-group rg-acme --container admin --command sh
curl -s -H 'Content-Type: application/json' \
  -d '{"allowedDnsSuffixes":["example.ac.jp"],"acmeBinding":"letsencrypt-staging","renewBeforeDays":30,"keyType":"ec256"}' \
  http://127.0.0.1:8080/api/v1alpha1/policies
```

is an administrator session. Who may run `az containerapp exec` on the
app is decided by Azure RBAC on the Container App; that is the access
control of the API in this phase. The audit log records every such
caller as `localhost-dev`. Pin the sidecar image by digest and give it
nothing but a shell and `curl`; it needs no identity and no mounts.
Without a sidecar the deployment runs (scheduled renewals continue) but
cannot be administered.

**Backup.** The registry is `conductor.db` on the `conductor-state`
share; snapshot the share or copy the file while the app is scaled to
zero. The `runner-state` share holds the ACME account key (not
certificate keys); back it up too. The `exchange` share holds nothing
durable.

**Rollback.** `az deployment group create` with the previous template
and parameters, or set the previous image digests. A newer Conductor
schema is not read by an older binary; restore the matching
`conductor.db` as well ([`docs/conductor.md`](../../docs/conductor.md#backup-restore-rollback)).

**Rotating a signing key.** Add the new public key on the verifying
side first (`jobSigning.publicKeys` in the Runner configuration, or
`resultSigningPublicKey` for the Conductor — both lists take several
keys), deploy, then switch the signer to the new private key, then
remove the old public key.

**Latency, throughput and idle executions.** A run starts when the next
scheduled execution takes it: up to `runnerCronExpression`'s interval (a
minute) plus the platform's start latency. Each execution runs one
replica and takes one job, so at most one run starts per tick; runs
overlap only insofar as executions of successive ticks overlap
(expected, not observed — see below). While nothing is pending, every
tick still runs one execution that finds no job and exits at once; that
is the price of not holding `jobs/start/action`, and an event-driven
trigger is the noted follow-up if it matters.

**Stale run directories.** When an execution could not be seen to end —
its status unreadable and the stop not confirmed — the Conductor keeps
`claimed/run-<runId>/` on the `exchange` share (a Runner may still be
writing there) and logs "run directory kept". Remove such directories by
hand once the execution has ended (`az containerapp job execution list`).

## Not verified by this repository

This template compiles (`bicep build`, `bicep lint`) and its configuration
documents load with the same validators the binaries use
(`internal/conductor/config`, `internal/runner/config`). It has **not**
been deployed to a subscription by the project, so the following are
documented from the platform's reference documentation, not observed:

- **Schedule semantics.** An execution with one replica is expected to
  start every minute and to overlap with a still-running execution of an
  earlier tick; a platform that skips a tick instead only delays runs
  (`claimTimeoutSeconds` bounds the wait, and the run then fails and is
  retried by the scheduler). `CONTAINER_APP_JOB_EXECUTION_NAME` is
  documented as set in every execution's containers; the Runner refuses
  to work without it.
- **Rename atomicity on Azure Files (SMB).** Taking and withdrawing a
  job are directory renames, which are atomic on a local filesystem and
  expected to be on an SMB share (the server performs them); if two
  executions could both succeed, both would run the same job and the
  Runner's replay ledger would refuse the second. Not observed.
- **Role action names.** `Microsoft.App/jobs/execution/read`,
  `Microsoft.App/jobs/executions/read`,
  `Microsoft.App/jobs/stop/execution/action` (the singular forms are
  what the get-execution and stop-execution operations require),
  `Microsoft.KeyVault/vaults/certificates/import/action` and the DNS
  TXT actions are taken from the provider operation lists; a wrong name
  fails the deployment (role definitions are validated), not silently.
- **SQLite and `flock` on Azure Files (SMB).** The registry share is
  mounted with `nobrl` so SQLite's byte-range locks do not fail on SMB;
  with one process that is safe, but the ownership lock the Conductor
  takes (`<db>.lock`) is then only as reliable as `flock` is on that
  mount. The app is pinned to one replica in single-revision mode; a
  revision update can still overlap two replicas for a moment, and the
  second is expected to refuse to start if the lock holds and to start
  anyway if it does not. NFS Azure Files (a VNet-integrated environment)
  is the more robust choice and is a one-line change (`NfsAzureFile`
  storage type).
- **Result propagation delay.** The Conductor waits
  `resultGraceSeconds` (30 s) for `result.json` to appear on the share
  after the execution ends; SMB caching may need tuning of that value.
- **Managed identity for `lego`.** `AZURE_AUTH_METHOD=msi` with a
  user-assigned identity selected by `AZURE_CLIENT_ID`, through the
  Container Apps identity endpoint (`IDENTITY_ENDPOINT`/`IDENTITY_HEADER`),
  is what the `azuredns` provider's SDK supports; it has not been
  exercised from this Job.
- **Secret size.** The Runner configuration is delivered as a Container
  Apps secret mounted as a file; a very large configuration may exceed
  the platform's secret value limit.

A first deployment should therefore be watched end to end: start with a
staging CA, one target, and `--log-level debug` on the Conductor.
