# 0014: Azure Container Apps Job launcher

- Status: Accepted
- Date: 2026-09-22

## Context

Phase 4 gives the Conductor its first platform launcher: the Runner runs
as an Azure Container Apps Job, one execution per run, under a managed
identity of its own, so that no DNS or Store credential exists in the
Conductor's environment any more (the Phase 2 local launcher's
`passthroughEnv` residual, threat model T10). The `launcher.Launcher`
interface fixes what a launcher does — obtain an execution for a
`JobSpec`, report a platform id, wait for a `Result` — but leaves open
how the two documents cross the boundary on that platform, what the
Conductor's identity must be allowed to do (and, decisively, what it
must not be allowed to do), how a run is bounded and stopped, and how
the infrastructure is provisioned.

## Decision

- **A scheduled Job that takes its work; the Conductor never starts an
  execution.** The Job — image, identity, volumes, secrets, Runner
  configuration, and a fixed command `reconcile --exchange /exchange` —
  is declared in Bicep (`deploy/azure`) and never touched by the
  Conductor. Its trigger is a schedule (every minute, the finest the
  platform offers): each execution takes the oldest job the Conductor has
  offered on the exchange share, or exits at once when there is none.
  The platform's *start* operation was rejected as the trigger because it
  accepts an execution template that can replace the image, the command
  and the environment of the Job's containers: an identity holding
  `Microsoft.App/jobs/start/action` can run any image under the Job's
  managed identity, so a compromise of the Conductor's identity would
  have escalated to the Runner's DNS and Key Vault permissions whatever
  the launcher code refrained from doing. The Conductor's identity
  therefore does not hold it. What the Conductor chooses is *what run*
  a Runner executes; *what the Runner is* is fixed in infrastructure.
- **One run is one execution, with one replica.** The platform's
  `parallelism` is the number of replicas *within* one execution; they
  would share the execution name, and stop and verdict are per
  execution, so replicas taking different runs would tie those runs
  together. The Job fixes `parallelism` and `replicaCompletionCount` at
  1; concurrency is executions of successive schedule ticks overlapping.
- **Documents travel over a file share both containers mount, through a
  claim protocol** (`internal/exchange`). The Conductor writes the signed
  job under `staging/run-<runId>/` and moves the directory to `pending/`
  in one rename; a Runner takes it by renaming it to `claimed/`, so of
  several executions exactly one wins; the Runner records its execution
  name (`CONTAINER_APP_JOB_EXECUTION_NAME`) in the claimed directory,
  works, and writes `result.json` next to the job. The Conductor learns
  the execution from that marker, confirms with the platform that it is
  an execution of this Job, watches it, and removes the directory when
  it ends. If no execution takes the job within `claimTimeoutSeconds`
  the Conductor withdraws it by the same rename, so a job is either taken
  or withdrawn, never both. Once a job is taken, the Conductor never
  abandons the Runner behind it: the recorded execution name is
  confirmed with the platform (a name the platform does not know ends
  the run, a platform that cannot be asked does not — the execution is
  watched unconfirmed), and the run directory is removed only once the
  execution has been seen to end; otherwise it is kept and reported, so
  a Runner that may still be working keeps its result path. The share
  holds no certificate material and
  no credential, only these documents. It is not a transport the
  Conductor owns (anyone with the storage key or a mount can write it),
  so both directions are authenticated: the job is a **signed envelope**
  and the Result must be a **signed Result** that verifies against the
  Runners' public keys ([ADR 0015](0015-signed-job-envelope.md)); the
  launcher refuses to be built without a signer and a verifier, and the
  configuration refuses an `azure-container-apps-job` binding without
  `jobSigning` and `resultSigning`. The Result must also name the run and
  target it was offered for and agree with the platform's own verdict (an
  execution that ended `Succeeded` with a `failed` Result, or the
  reverse, is a mismatch, not a result).
- **Three permissions, on one resource.** The Conductor's identity is
  granted a custom role with `Microsoft.App/jobs/execution/read`,
  `jobs/executions/read` and `jobs/stop/execution/action` on the Runner
  Job only — read one execution, list them, stop one. It cannot start an
  execution, cannot change the Job, cannot read its secrets, and holds no
  DNS, Key Vault or storage data permission. The Runner's identity is
  granted a custom role with the four DNS zone/TXT actions on the
  challenge zone and a custom role with `certificates/read` and
  `certificates/import/action` on the vault
  ([ADR 0013](0013-azure-key-vault-store-adapter.md)), and nothing on the
  Job, the app or the storage account. The roles are custom rather than
  built-in so that each grant is an explicit, reviewable list, and they
  are assignable in the deployment's subscription only, so the zone and
  the vault must live in that subscription in Phase 4.
- **Polling, timeout, stop.** The Conductor polls the execution's status
  (`pollIntervalSeconds`, 10 s) until it is terminal; transient read
  errors are retried up to a bound. Whenever polling ends without a
  terminal status — the run's context ended (an operator cancel,
  shutdown, or the binding's `timeoutSeconds`), or the status could not
  be read any more — the execution is stopped through the platform
  before the run directory is removed, since it may still be running and
  a Runner that loses its result path would otherwise finish unobserved;
  the execution is then polled for a bounded grace and whatever Result
  the Runner managed to write (normally `Cancelled`) is reported. The
  Job's own `replicaTimeout` is a second bound below the Conductor's.
  `replicaRetryLimit` is zero: a retried replica would present the same
  signed job again and be refused by the Runner's replay ledger.
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
- **Tests run against a fake platform.** An in-process fake of the two
  REST operations the launcher uses starts executions of the fake Runner
  in claim mode on its own cadence, as the platform's schedule would, so
  the whole exchange — signed job offered, taken, execution confirmed,
  signed Result back, stop on cancel, timeout, polling failure, mismatch
  and tampering detection, error wording — is exercised on disk without
  an Azure subscription (principle 8). The Azure SDK is confined to
  `internal/conductor/launcher/acajob`.

## Alternatives considered

- **Starting each execution from the Conductor with an execution
  template that only replaces the Runner's arguments** (the first draft
  of this phase). Rejected in review: the restraint is in the code, not
  in the permission. `jobs/start/action` lets the holder submit any
  template, and the platform documents that an identity with it "can use
  an execution template to reference job secrets ... and use managed
  identities configured to be available to the container". A compromised
  Conductor process or identity would run an attacker's image under the
  Runner's identity. The schedule trigger removes the permission
  altogether at the cost of up to a minute of start latency.
- **An event-driven Job (a queue scaler) instead of a schedule.** Not
  taken for Phase 4: it needs a queue, a data-plane permission on it for
  the Conductor (to enqueue) and for the scaler or the Runner (to read
  and delete), and queue SDK code in a second package; the schedule gives
  the same property — a fixed template, no start permission — with
  nothing but a cron expression. It remains the natural next step if the
  one-minute cadence or the idle executions become a cost.
- **A broker (a Function or Logic App) that starts the Job with a fixed
  template on the Conductor's behalf.** Rejected: another component with
  its own identity and code to review, holding the very permission the
  design is removing.
- **Passing the JobSpec in the execution's environment or arguments and
  the Result through blob storage or a queue.** Rejected for Phase 4: a
  return channel is needed either way, and a blob or queue adds a second
  Azure data-plane permission to both identities plus SDK code on the
  Runner side, whereas the share keeps the Runner's file-based contract
  unchanged. The envelopes make the share's weakness (writable by
  others) explicit and detectable in both directions.
- **A Runner callback into the Conductor's API to deliver the Result.**
  Rejected: the Conductor has no authenticated, network-reachable API
  before Phase 5, and a callback would make a Runner depend on the
  Conductor being up, which the architecture forbids.
- **Letting the Conductor create or update the Job per run.** Rejected:
  it would require `jobs/write`, with which a compromised Conductor could
  change the Runner's image, identity or mounts — exactly the escalation
  T10 is about.
- **Built-in roles (Container Apps Jobs Operator, DNS Zone Contributor,
  Key Vault Certificates Officer).** Rejected: each grants far more than
  needed (start and `listSecrets` through the `jobs/*/action` wildcard;
  all record types; certificate deletion and purge). Custom roles are a
  subscription-level resource the deployer must be allowed to create,
  which is accepted.

## Consequences

- The Conductor's environment carries no Runner credential in this
  deployment shape, and its identity cannot make the Runner Job run
  anything but the Runner image declared in Bicep: T10's Phase 2 residual
  is closed for it, and a Conductor compromise is bounded to choosing
  which runs execute (T1).
- A run starts up to a minute plus the platform's start latency after it
  is queued, at most one run per tick, and the platform runs one short,
  idle execution per tick while nothing is pending; the scheduler's
  `maxConcurrentRuns` bounds how many runs wait for or hold an execution
  at once.
- A run directory can outlive its run when the execution was never seen
  to end; the operator guide says how to recognize and remove it.
- Both signing keys are operator-owned secrets: the Conductor's
  job-signing key and the Runner's result-signing key, each mounted for
  its own binary only. Rotation is additive on the verifying side.
- The launcher's behaviour against the real platform (schedule cadence
  and overlap of executions across ticks, rename atomicity on an SMB
  share, role
  action names, SQLite and `flock` on an SMB share, Result propagation
  delay) is documented from the reference documentation and verified only
  by a first real deployment, not by CI; `deploy/azure/README.md` lists
  each item.
- Administration before Phase 5 is `az containerapp exec` into the
  sidecar; the audit log still records every caller as `localhost-dev`.
- Cancelling a run now involves a platform call; a stop the platform
  does not honour ends as `Timeout`/`Cancelled` without a Result after
  the stop grace, and the Job's `replicaTimeout` eventually ends the
  execution regardless.
