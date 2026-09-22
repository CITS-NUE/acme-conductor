# Deploying to Azure Container Apps (Phase 4)

`main.bicep` provisions a complete ACME Conductor deployment on Azure
Container Apps: the Conductor as a single-replica Container App, the
Runner as a manually triggered Container Apps Job that the Conductor
starts once per run, two managed identities with disjoint grants, and
the storage the two exchange documents over. It is the reviewable,
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
| `<prefix>-id-conductor` (user-assigned identity) | The Conductor's identity. Granted the **Conductor Job Starter** custom role on the Runner Job only. |
| `<prefix>-id-runner` (user-assigned identity) | The Runner's identity. Granted the **Runner DNS TXT Writer** custom role on the challenge zone and the **Runner Key Vault Certificate Writer** custom role on the vault. |
| `<prefix>-runner` (Container Apps Job) | The Runner image with the Runner configuration mounted at `/etc/acme-runner/config.json`, `/exchange`, `/state`, and an ephemeral `/work`. Manual trigger, one replica, no retries. |
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
  groups or subscriptions; the deployer needs the right to create role
  assignments there (Owner or User Access Administrator), and to create
  role definitions at subscription scope.
- Container images for both binaries, pinned by digest. Phase 4 has no
  release workflow; build them with `make images` and push them to a
  registry the environment can pull from (GHCR public images need no
  registry credential).
- A job-signing key pair:

  ```sh
  acme-conductor keygen --private job-signing.pem --public job-signing.pub
  ```

  The command prints `keyId:` and `publicKey:` (the one-line form of the
  public key). The private key file goes in as a secure parameter; the
  public key goes into the Runner configuration.

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

The Runner authenticates to Key Vault with its user-assigned identity
(`credential: managed-identity` in the store binding; the template sets
`AZURE_CLIENT_ID` in the Job's environment). `lego`'s `azuredns`
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

**Rotating the signing key.** Add the new public key to the Runner
configuration first (`jobSigning.publicKeys` takes several), deploy,
then switch the Conductor to the new private key, then remove the old
public key.

## Not verified by this repository

This template compiles (`bicep build`, `bicep lint`) and its configuration
documents load with the same validators the binaries use
(`internal/conductor/config`, `internal/runner/config`). It has **not**
been deployed to a subscription by the project, so the following are
documented from the platform's reference documentation, not observed:

- **Execution template override.** The Conductor starts each execution
  with a template that repeats the Job's container (name, image,
  environment, resources) with only `args` replaced. Volume mounts are
  not part of the execution template model and are expected to be
  inherited from the Job; if the platform drops them on an override, the
  Runner would not see `/exchange` and every run would end
  `Internal`/"runner ended without reporting a result".
- **Role action names.** `Microsoft.App/jobs/executions/read`,
  `Microsoft.App/jobs/start/action`, `Microsoft.App/jobs/stop/action`,
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
