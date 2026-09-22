# 0014: Azure Container Apps Job launcher

- Status: Accepted
- Date: 2026-09-22

## Context

Phase 4 gives the Conductor its first platform launcher: the Runner runs
as an Azure Container Apps Job, one execution per run, under a managed
identity of its own, so that no DNS or Store credential exists in the
Conductor's environment any more (the Phase 2 local launcher's
`passthroughEnv` residual, threat model T10). The `launcher.Launcher`
interface fixes what a launcher does — start an execution for a
`JobSpec`, report a platform id, wait for a `Result` — but leaves open
how the two documents cross the boundary on that platform, what the
Conductor's identity must be allowed to do, how a run is bounded and
stopped, and how the infrastructure is provisioned.

## Decision

- **A pre-provisioned Job, started per run with its arguments.** The
  Job — image, identity, volumes, secrets, Runner configuration — is
  declared in Bicep (`deploy/azure`) and never touched by the Conductor.
  For each run the Conductor reads the Job's template, copies its
  containers (name, image, command, environment, resources) into an
  execution template with only the Runner container's `args` replaced by
  `reconcile --job <path> --result <path>`, and starts an execution with
  it. Nothing else about an execution is expressible through the start
  operation, which is the point: the Conductor chooses *what run* the
  Runner executes, never *what the Runner is*. A stray manual start of
  the Job runs `--version` and exits.
- **Documents travel over a file share both containers mount.** The
  Conductor writes `<exchangeDir>/run-<runId>/job.json`, the Runner
  writes `result.json` next to it, and the Conductor removes the
  directory when the execution ends. The share holds no certificate
  material and no credential, only these two contract documents. It is
  not a transport the Conductor owns (anyone with the storage key or a
  mount can write it), so the job is always a **signed envelope**
  ([ADR 0015](0015-signed-job-envelope.md)); the launcher refuses to be
  built without a signer and the configuration refuses an
  `azure-container-apps-job` binding without `jobSigning`. The Result is
  read with the strict contract decoder, must name the run and target it
  was started for, and must agree with the platform's own verdict (an
  execution that ended `Succeeded` with a `failed` Result, or the
  reverse, is a mismatch, not a result).
- **Four permissions, on one resource.** The Conductor's identity is
  granted a custom role with `Microsoft.App/jobs/read`,
  `jobs/start/action`, `jobs/stop/action` and `jobs/executions/read` on
  the Runner Job only. It cannot change the Job, cannot read its
  secrets, and holds no DNS, Key Vault or storage data permission. The
  Runner's identity is granted a custom role with the four DNS zone/TXT
  actions on the challenge zone and a custom role with
  `certificates/read` and `certificates/import/action` on the vault
  ([ADR 0013](0013-azure-key-vault-store-adapter.md)), and nothing on the
  Job, the app or the storage account. The roles are custom rather than
  built-in so that each grant is an explicit, reviewable list.
- **Polling, timeout, stop.** The Conductor polls the execution's status
  (`pollIntervalSeconds`, 10 s) until it is terminal; transient read
  errors are retried up to a bound. When the run's context ends (an
  operator cancel, shutdown, or the binding's `timeoutSeconds`) the
  execution is stopped through the platform, polled for a bounded grace,
  and whatever Result the Runner managed to write (normally `Cancelled`)
  is reported. The Job's own `replicaTimeout` is a second bound below the
  Conductor's. `replicaRetryLimit` is zero: a retried replica would
  present the same signed job again and be refused by the Runner's
  replay ledger.
- **Errors are fixed wording.** An ARM error becomes `<op>: HTTP <status>
  (<code>)`, a transport failure its kind, anything else the Go type of
  the innermost error; response bodies are never wrapped in. The run
  record gets Conductor-owned summaries only, as for the local launcher.
- **The Conductor runs in the same environment, without ingress.** Its
  API keeps `localhost-dev` authentication ([ADR 0012](0012-localhost-only-dev-auth.md))
  and is reachable only from the replica's loopback. An optional
  administration sidecar in the same replica (a shell with `curl`,
  reached with `az containerapp exec`) is the operator's way in until
  Phase 5; Azure RBAC on the Container App gates who can do that.
- **Tests run against a fake ARM.** An in-process fake of the four REST
  operations executes the fake Runner as a subprocess with the arguments
  the launcher supplied, so the whole exchange — signed job in, Result
  out, stop on cancel, timeout, mismatch detection, error wording — is
  exercised on disk without an Azure subscription (principle 8). The
  Azure SDK is confined to `internal/conductor/launcher/acajob`.

## Alternatives considered

- **Passing the JobSpec in the execution's environment or arguments and
  the Result through blob storage or a queue.** Rejected for Phase 4: a
  return channel is needed either way, and a blob or queue adds a second
  Azure data-plane permission to both identities plus SDK code on the
  Runner side, whereas the share keeps the Runner's file-based contract
  (`--job`/`--result`) unchanged. The envelope makes the share's
  weakness (writable by others) explicit and detectable.
- **A Runner callback into the Conductor's API to deliver the Result.**
  Rejected: the Conductor has no authenticated, network-reachable API
  before Phase 5, and a callback would make a Runner depend on the
  Conductor being up, which the architecture forbids.
- **Letting the Conductor create or update the Job per run.** Rejected:
  it would require `jobs/write`, with which a compromised Conductor could
  change the Runner's image, identity or mounts — exactly the escalation
  T10 is about.
- **Built-in roles (Contributor on the Job, DNS Zone Contributor, Key
  Vault Certificates Officer).** Rejected: each grants far more than
  needed (write on the Job; all record types; certificate deletion and
  purge). Custom roles are a subscription-level resource the deployer
  must be allowed to create, which is accepted.

## Consequences

- The Conductor's environment carries no Runner credential in this
  deployment shape: T10's Phase 2 residual is closed for it.
- The launcher's behaviour against the real platform (template override
  inheriting volume mounts, role action names, SQLite and `flock` on an
  SMB share, Result propagation delay) is documented from the reference
  documentation and verified only by a first real deployment, not by
  CI; `deploy/azure/README.md` lists each item.
- Administration before Phase 5 is `az containerapp exec` into the
  sidecar; the audit log still records every caller as `localhost-dev`.
- Cancelling a run now involves a platform call; a stop the platform
  does not honour ends as `Timeout`/`Cancelled` without a Result after
  the stop grace, and the Job's `replicaTimeout` eventually ends the
  execution regardless.
