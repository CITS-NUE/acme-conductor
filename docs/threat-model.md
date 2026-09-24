# Threat Model

This document covers the ACME Conductor system as designed in
[`docs/architecture.md`](architecture.md). It is written and maintained
alongside the code. **Phase 0** shipped the versioned JobSpec/Result
contract, FQDN normalization and CI; **Phase 1** added the Runner
(`internal/runner`), its trusted configuration and authorization wiring,
the bundled `lego` CLI, and the filesystem Certificate Store (see
[`docs/runner.md`](runner.md)); **Phase 2** added the Conductor MVP: the
SQLite registries, the append-only audit log, the scheduler with
per-target run exclusion, the local-process launcher and a loopback-only
REST API with development authentication (see
[`docs/conductor.md`](conductor.md)); **Phase 3** added the Azure Key Vault
Certificate Store; **Phase 4** added the signed job envelope with expiry
and a Runner-side replay ledger, the Azure Container Apps Job launcher
(the Runner under its own managed identity) and the Bicep that provisions
both identities with disjoint grants (see
[ADR 0014](adr/0014-azure-container-apps-job-launcher.md) and
[ADR 0015](adr/0015-signed-job-envelope.md)); **Phase 5** added OIDC
bearer-token authentication with named principals and an admin/viewer
role, a TLS listener or an explicit behind-ingress statement, a minimal
static GUI, and a release pipeline that publishes both images with an
SBOM and provenance from digest-pinned bases (see
[ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md) and
[ADR 0017](adr/0017-release-pipeline.md)). Some mitigations below still
describe where a control lands once a later phase ships, not what exists today. The
[residual risks](#residual-risks--not-yet-mitigated) section is explicit
about that gap.

## Assets

- **Private keys** for issued certificates (highest-value asset; must never
  exist outside a Runner's temporary area and the Certificate Store).
- **Issued certificates** (public, but their issuance and validity are
  security-relevant).
- **DNS write credentials / workload identity** used to complete ACME
  DNS-01 challenges.
- **Certificate Store write (and, for the Store, read) credentials /
  workload identity**.
- **ACME account material**, including any External Account Binding (EAB)
  HMAC key.
- **The `Target` registry and `CertificatePolicy`** — control over which
  FQDNs may receive a certificate and under what constraints; tampering
  here is a path to unauthorized issuance.
- **The audit log** — the record relied on to detect and investigate misuse.
- **The `JobSpec`/`Result` contract itself** — the only channel between the
  control plane and the data plane; its integrity is what makes the
  Conductor/Runner split meaningful at all.
- **Conductor and Runner identities** (whatever credentials or workload
  identity each process runs as).

## Trust boundaries

```
                         (untrusted network)
   Administrator / UI  ------------------------->  [ acme-conductor ]
                                                    control plane
                                                    - Target / Policy / Audit / Run registries
                                                    - NO DNS credential
                                                    - NO Store credential
                                                    - NO private key, ever
                                                          |
                                                          | JobSpec (v1alpha1, strictly
                                                          | decoded, self-consistency
                                                          | checked on the far side)
                                                          v
                                                    [ acme-runner ]
                                                    data plane, one-shot job
                                                    - workload identity scoped to
                                                      ONE DnsBinding + ONE StoreBinding
                                                    - private key lives here only
                                                      transiently
                                                    ------ trust boundary ------
                                                     |                    |
                                                     v                    v
                                              [ DNS provider ]   [ Certificate Store ]
                                              (lego built-in)    (filesystem / Key Vault)
                                                     ^
                                                     |
                                              [ ACME CA ] (external, e.g. Let's Encrypt)
```

Boundaries that matter:

1. **Administrator/UI ↔ Conductor** — the only boundary that accepts
   free-form external input; everything past it is either an opaque
   identifier, a normalized value, or a logical binding name (see
   [binding model](architecture.md#binding-model)).
2. **Conductor ↔ Runner** — crossed only by the `JobSpec` and `Result`
   documents. This is the boundary the versioned, strictly-decoded contract
   exists to protect.
3. **Runner ↔ execution platform** — the Runner's workload identity is
   provisioned by whatever launched it (a local process today, an Azure
   Container Apps Job from Phase 4), never by the Conductor handing it a
   credential.
4. **Runner ↔ DNS provider / Certificate Store / ACME CA** — external
   systems the Runner, and only the Runner, talks to.

## Actors / attackers

- **External network attacker** — no credentials, reachable at the
  Conductor's API/GUI surface (since Phase 5 over a TLS ingress in
  `oidc` mode; loopback-only in `localhost-dev`), at the identity
  provider, and at CI. Can present arbitrary tokens and pages.
- **Local user or local web page on the Conductor host** — in
  `localhost-dev` mode the API trusts any loopback peer, so a second user
  on the same host, or a web page a local browser loads, is a distinct
  attacker (see T13). In `oidc` mode a local peer is nobody without a
  token.
- **Holder of a stolen or over-scoped token** — an access token taken
  from a browser tab, a terminal or a log, or one issued by the
  provider to a principal that should not hold the admin role (see T14).
- **Malicious or compromised administrator/API caller** — can submit
  arbitrary `Target`/`CertificatePolicy` values through the API surface the
  Conductor exposes, but only through the schema that surface accepts.
  This is the boundary the invariant "API input can never specify
  commands, images, resource IDs, credentials or provider configuration"
  is aimed at.
- **Compromised Conductor process** — has database access and can produce
  arbitrary `JobSpec` documents, but by design holds no DNS, Key Vault, or
  long-lived cloud credential itself.
- **Compromised Runner process (single run)** — has whatever workload
  identity its `ExecutionBinding` was granted for the duration of one run;
  scoped, by design, to one DNS zone and one store.
- **Malicious or buggy CI job / dependency** — supply-chain angle: a
  compromised dependency, base image, or `lego` release.
- **Insider with repository or registry access** — can attempt to push an
  unpinned or malicious image, or alter a workflow.

## Threats

| # | Threat | Description | Impact | Mitigation (existing / planned) | Phase |
|---|---|---|---|---|---|
| T1 | Conductor compromise | An attacker gains code execution or database access on the Conductor. | Attacker can create/modify `Target`s and `CertificatePolicy`, submit arbitrary jobs, or read audit data — but **cannot** obtain private keys, DNS credentials, or Store credentials, because the Conductor never holds them. `JobSpec.Validate` only checks that a document is internally self-consistent (T5), so a compromised Conductor can produce a self-consistent `JobSpec` for any FQDN and any registered binding name; the Runner-side authorization policy below is what actually bounds that. | Principle 1/2/5 (no secrets, no DNS/Store credential, separate identity from Runner); closed schema, strict decoding and well-formed logical binding names only (T2/T5) constrain what a compromised Conductor can even express, not what it may cause to be issued; append-only audit log for detection; SQLite behind a `Registry` interface so a compromise is contained to one process/host (no multi-replica blast radius in the MVP) — **implemented (Phase 2)**: `internal/conductor/sqlite`, with the audit log written in the same transaction as each change and made append-only by schema triggers ([ADR 0011](adr/0011-conductor-storage-and-run-model.md)); a compromised Conductor process can still write to its own database, so the audit log detects misuse through the API, not a compromise of the process itself. **Implemented (Phase 1)**: a Runner-side `policy.RunnerAuthorizationPolicy`, loaded from trusted administrator configuration and never from the JobSpec, bounds what a JobSpec can cause to be issued to the configured suffixes, wildcard setting and binding allow-lists, regardless of JobSpec content; within those bounds a compromised Conductor can still request issuance for any name — see [`docs/runner.md`](runner.md#execution-flow). **Implemented (Phase 4)**: the signed job envelope ([ADR 0015](adr/0015-signed-job-envelope.md)) with expiry and a replay ledger narrows the window to "what the Conductor signed, within `validitySeconds`, once" — it authenticates the producer and bounds replay, but a compromised Conductor that holds the signing key still signs whatever it likes; the Runner's trusted policy remains the bound. In the Container Apps deployment the Conductor's identity can observe and stop executions of the Runner Job and nothing else — in particular it cannot **start** one, because the platform's start operation takes an execution template that can replace the Runner's image and so would let a compromised Conductor run any code under the Runner's identity; executions start on the Job's own schedule and take the jobs the Conductor offers ([ADR 0014](adr/0014-azure-container-apps-job-launcher.md)). A compromise therefore cannot change what the Runner is (image, identity, mounts), only which runs it executes. | Existing (principles, contract, shape-only limits, Runner authorization, registry/audit since Phase 2, signed envelope and least-privilege launcher identity since Phase 4) |
| T2 | JobSpec tampering in transit or at rest | A `JobSpec` is modified between production by the Conductor and consumption by the Runner (e.g. a compromised launcher, a tampered queue message, a modified file). | A tampered `JobSpec` could redirect issuance to an unauthorized FQDN, point at a different binding, or otherwise escape the policy the Conductor intended. | Strict decoding (`pkg/api/v1alpha1/decode.go`: unknown fields, duplicate keys, trailing data, 64 KiB cap all rejected) limits the *shape* of a tampered document only. A tampered document that remains self-consistent — `target.fqdn` and the embedded `policy` snapshot changed together, or one registered binding name swapped for another well-formed registered binding name — passes `Validate` unchanged (T5); `Validate` cannot detect that kind of tampering by itself. **Implemented (Phase 1)**: a Runner-side `RunnerAuthorizationPolicy`, evaluated against trusted configuration that is not part of the document, bounds issuance independently of anything a tampered `JobSpec` claims. **Implemented (Phase 4)**: a `SignedCertificateReconcileJob` envelope (`pkg/api/v1alpha1/signedjob.go`, [ADR 0015](adr/0015-signed-job-envelope.md)) — Ed25519 over the exact JobSpec bytes plus a strict header with `issuedAt`/`expiresAt`/`nonce` — is verified by the Runner against public keys in its trusted configuration before anything is resolved; a changed FQDN, a swapped binding or an edited expiry fails verification (`InvalidJobSpec`). A Runner configured with keys refuses bare JobSpecs; the Container Apps launcher refuses to run without a signer, because its transport (a file share) is writable by others. The same transport carries the `Result` back, whose `expiresAt`, `fingerprintSha256` and `storeObjectRef` the Conductor persists and schedules on, so the Runner signs every Result with a key of its own (`SignedCertificateReconcileResult`, `resultSigning`) and a Conductor configured with the Runners' public keys accepts nothing else — a Result altered or substituted on the share is refused and the run fails rather than records it. Signing addresses tampering, not a compromised producer legitimately emitting a bad document (see T1). | Existing (decoding limits shape; Runner authorization; signed envelope since Phase 4) |
| T3 | JobSpec replay and expiry | An old, previously-valid `JobSpec` is re-submitted (e.g. replayed from a log, a retried platform execution, or a captured artifact) after the `Target` it names has since changed or been disabled. | Certificate issuance or renewal against stale policy or a disabled target; potential double execution when combined with T7. | **Implemented (Phase 2)**: the Conductor cancels a queued run whose target was disabled or changed revision before it starts, and every launcher checks that a `Result` names the run it started. **Implemented (Phase 4)**: the signed envelope carries `issuedAt`/`expiresAt` (validity `jobSigning.validitySeconds`, 15 minutes by default, 24 hours at most) and a `nonce`; the Runner refuses an expired envelope, one issued more than `clockSkewSeconds` in the future, and — through its replay ledger (`stateDir/jobs.d/<runId>`, written under an advisory lock before any work) — any run it or a Runner sharing its state directory has accepted before, so the same job cannot execute twice within its window ([ADR 0015](adr/0015-signed-job-envelope.md)). The Runner does not consult the run registry (it has no access to it); the window plus the ledger give the same guarantee for the time that matters. | Conductor-side stale-run check (Phase 2); Runner-side expiry and replay check (Phase 4) |
| T4 | DNS permission abuse | The Runner's DNS credential/workload identity is used (by a compromised Runner, or by DNS-provider-side misconfiguration) to write records outside the one zone the current run needs. | Ability to complete ACME challenges for FQDNs outside the intended scope, or to otherwise tamper with DNS beyond the TXT challenge record. | `DnsBinding` configuration is now loaded and validated by the Runner (`internal/runner/config`): a binding names a `lego` provider plus non-secret `env` and the names of `passthroughEnv` variables the platform is expected to supply (the `exec`/`manual` providers are denied outright, since they run arbitrary programs or need interactive input). The actual credential or workload identity behind those names is still expected to be scoped by the administrator who provisions it to the challenge zone and TXT records only — never zone-wide or account-wide DNS write; **the Runner has no way to verify that scoping itself**, it can only refuse to start `lego` if a required `passthroughEnv` variable is missing. This scoping remains an operational requirement on how each `DnsBinding` is provisioned, not something the JobSpec contract or the Runner's own code can enforce. | Binding model and config loading implemented (Phase 1); real workload-identity provisioning (e.g. Managed Identity) remains an operational/deployment concern, Phase 3+ |
| T5 | FQDN policy bypass | An attacker crafts an FQDN or suffix list to slip past the intended policy: mismatched label boundaries, case differences, a trailing dot, an IDNA/punycode label, an unintended wildcard, or a duplicate JSON key that causes two validators to disagree on which value "wins". | Certificate issued for a domain the operator did not intend to authorize (e.g. `evil-example.ac.jp` treated as under `example.ac.jp`). | **Validation** (implemented, both sides of the boundary): `internal/policy/fqdn.go` normalizes before comparing (lower-case, single trailing dot stripped, ASCII-only) and matches suffixes on whole label boundaries only (`MatchesSuffix`), so `evil-example.ac.jp` is correctly rejected against the suffix `example.ac.jp`. `xn--` (IDNA A-label) input is rejected outright rather than silently accepted (see ADR 0006). Wildcards are accepted only as the whole left-most label. `pkg/api/v1alpha1/decode.go` rejects duplicate JSON keys before any validator sees the document, closing the classic "two parsers disagree" bypass. `JobSpec.Validate` checks that `target.fqdn` is consistent with the `policy` snapshot embedded in the same document — this is a self-consistency check of untrusted input, never authorization (see the doc comment on `JobSpec.Validate` and `TestJobSpecValidateIsSelfConsistencyNotAuthorization`). **Authorization** (implemented and wired, Phase 1): `internal/policy.RunnerAuthorizationPolicy.Authorize` decides, against a trusted allowed-suffix/wildcard/binding-name configuration that is loaded on the execution platform (`internal/runner/config`) and never taken from the JobSpec, whether the Runner may act at all. `Reconcile` calls it — deny-by-default — before resolving any binding or invoking `lego`; see [`docs/runner.md`](runner.md#execution-flow). This closes the gap T1/T2 previously described for a self-consistent-but-malicious document; it does not, and cannot, verify that the *content* behind an allowed binding (e.g. a DNS credential's actual zone scope) is itself correct — see T4. | Validation existing (`internal/policy`, decode/validate); authorization implemented and wired in the Runner (Phase 1) |
| T6 | Secret leakage into logs/results/errors | A credential, private key, EAB HMAC, access token, or temporary PFX password ends up in a log line, a `Result.error.summary`, or an exception message. | Credential compromise even without direct access to the Conductor or Runner process — e.g. via log aggregation, error trackers, or a leaked `Result` document. | `validate.go`'s `validateOpaqueText` rejects non-printable characters (control characters, Unicode line/paragraph separators, bidi/format characters) and a case-insensitive-where-meaningful set of secret markers (`-----BEGIN`, `private key`, `eyJ` JWT/JWS/EAB-shaped base64, `AKIA`, `ghp_`, `github_pat_`, `bearer `, `basic `, `authorization:`, `password=`, `secret=`, `token=`, `sig=`, `key=`, and similar) in any `Result` free-text field. This is a **defense-in-depth heuristic, not a secret detector**: it catches common accidental leaks by known shape but cannot recognize an arbitrary secret or an unknown format. `storeObjectRef` is now a strict logical name (`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`, max 128, `..` rejected) — never a URL, path, query string, or credential-bearing value. `ResultError` is a fixed machine code plus a short summary; the field rules above are a supporting control only — character class, length and known-marker checks cannot, by themselves, keep a raw error, a command line, or environment contents out of a summary. **Implemented (Phase 1) — the real control**: `internal/runner/reconcile.go` never copies a raw external command/SDK error, `lego` stdout, or `lego` stderr into a `Result`; `error.summary` is generated only from a fixed set of Runner-owned safe templates keyed by `error.code` (see [`docs/runner.md`](runner.md#result-and-error-codes)), and if a templated summary would still fail the `Result` contract's own checks, the Runner falls back to a generic, code-specific summary rather than skip producing a `Result`. Raw `lego` output goes only to internal logs, and only after redaction: `internal/runner/lego.Redactor` masks resolved `passthroughEnv`/EAB secret values and PEM-shaped lines before a `lego` output line is logged at debug level. This redaction is **value-based and heuristic** — it masks the specific secret values the Runner itself resolved and known PEM markers, not an arbitrary or unknown-format secret — and it covers `lego` output specifically, not every log statement in the codebase; a dedicated redaction test suite across the rest of the codebase's log statements is still open (Phase 3+). **Phase 2**: the Conductor never copies a Runner's stderr into a run record or an audit event — a run's `error.summary` comes only from the `Result` (contract-validated) or from Conductor-owned templates, and the Runner's stderr is relayed to the debug log only, bounded and with non-printable characters replaced; audit details are Conductor-owned sentences over validated values. | Existing (Result field validation, marker heuristic, Runner-owned safe-summary templates, lego-output redaction, Conductor-owned run/audit text); log-wide redaction test suite Phase 3+ |
| T7 | Double execution / concurrent reconcile of the same target | Two `Run`s for the same `Target` execute concurrently (e.g. a retried scheduler tick, a re-delivered queue message, or an operator manually triggering a run while one is already in flight). | Wasted ACME rate-limit budget, two ACME orders, or two Runners fighting over the same DNS TXT record. The Certificate Store and the account state themselves are not corrupted by it: writes and reads are serialized by advisory locks (`internal/fslock`), and the last writer wins. | **Existing (Phase 1)**: store/state consistency under concurrent runs (advisory locks, atomic link swaps). **Implemented (Phase 2)**: at most one queued/starting/running run per target, enforced by a partial unique index in the registry so no code path (scheduler tick, operator request, restart) can create a second one; optimistic locking on `Target.revision` (every update names the revision it acts on); each run records the revision it was requested for and is cancelled, not started, if the target was disabled or moved on in the meantime; an operator request may name the revision it acts on and a second request answers `409 run_active`. See [ADR 0011](adr/0011-conductor-storage-and-run-model.md). A second Conductor process on the same database (another port, same `database.path`) is refused at startup by an exclusive `flock` on `<database.path>.lock`, taken before recovery or any other state change, so two schedulers cannot plan against one registry and a newcomer cannot mark the owner's in-flight runs failed. Bookkeeping follows the registry's actual status (each transition is written against the last recorded status, retried on transient failure, reconciled on conflict), and a run whose outcome could not be recorded is closed by the loop's sweep, so a Runner's outcome is not lost to one failed write and a stranded run does not hold the target's slot until a restart. **Residual**: a Runner orphaned by a hard kill of the Conductor (its run is marked failed/"outcome unknown" at the next start) can still be finishing when the next due run starts; and a Runner started by hand or by another launcher is outside the registry entirely. | Store/state consistency (Phase 1); run-level exclusion and single-process ownership implemented (Phase 2); orphaned-Runner residual accepted |
| T8 | Supply chain | A malicious or vulnerable dependency, base image, GitHub Action, or `lego` release is pulled into a build. | Compromised build output; a vulnerable component shipped in a released image. | `lego` is pinned to a specific, version-checked release (Phase 1) rather than "latest". **Implemented (Phase 5)** ([ADR 0017](adr/0017-release-pipeline.md)): both Dockerfiles build from base images pinned by digest (`golang:1.25-bookworm@sha256:…`, `gcr.io/distroless/static-debian12:nonroot@sha256:…` — minimal attack surface, no shell), Dependabot proposes updates to bases, Go modules and Actions as CI-tested pull requests, and a version tag publishes both images to GHCR with a BuildKit SPDX SBOM and SLSA provenance (`mode=max`) attached in the registry plus a GitHub-signed artifact attestation (`gh attestation verify`), after the CI workflow has passed on the same commit and the workflow has checked that the commit is in `main`'s history (a tag on a branch commit publishes nothing). CI runs `govulncheck` on every push/PR. Deployments pin images by digest, never `latest`; the OIDC verifier is written in the repository on the standard library rather than pulling a JWT library. **Residual**: GitHub Actions are pinned by major tag, not by commit digest; the release workflow's first run is its verification. | Implemented (Phase 5): digest-pinned bases, SBOM, provenance, attestation; Actions digest pinning open |
| T9 | Denial of service via oversized/hostile documents | A very large or deeply-nested `JobSpec`/`Result` document is submitted to exhaust memory or CPU during decoding. | Resource exhaustion on the Conductor or Runner. | `decodeStrict` reads through an `io.LimitReader` capped at `MaxDocumentSize` (64 KiB) and rejects anything larger before decoding. The size cap alone does not bound CPU: a 64 KiB document of nothing but nested brackets can make a naive recursive walker superlinear. The duplicate-key walker therefore also enforces `MaxNestingDepth` (8 levels; the contract needs 3) and renders diagnostic paths only on error, so the cost of any accepted-size document is linear in its length (`TestDecodeRejectsDeepNestingQuickly`). | Existing (`pkg/api/v1alpha1/decode.go`) |
| T10 | Privilege separation failure between Conductor and Runner identities | The Conductor is accidentally granted DNS write, Certificate Store read, or other Runner-scoped permissions (e.g. through shared service-principal reuse or overly broad IAM at deployment time), collapsing the intended separation. | A Conductor compromise (T1) escalates to full DNS/Store compromise instead of being contained. | Principle 5 is a deployment-time requirement as much as a code-time one: Conductor and Runner identities must be provisioned separately, with the Conductor's identity granted neither DNS write nor Store read. **Implemented (Phase 4)**: Azure resources are declared in Bicep (`deploy/azure`, [ADR 0014](adr/0014-azure-container-apps-job-launcher.md)), so the IAM grants are reviewable, versioned artifacts: two user-assigned identities; the Conductor's holds one custom role on the Runner Job (`jobs/execution/read`, `jobs/executions/read`, `jobs/stop/execution/action` — read, list and stop executions; deliberately not `jobs/start/action`, whose execution template could replace the Runner's image) and no DNS, Key Vault or storage data permission; the Runner's holds one custom role on the DNS zone (zone read, TXT read/write/delete) and one on the vault (`certificates/read`, `certificates/import/action`) and nothing on the Job, the app or storage. The Runner authenticates to DNS and Key Vault with that identity, so no credential exists in either environment. **Residual (local launcher only)**: the local-process launcher's `passthroughEnv` forwards a Runner credential from the Conductor's own environment on a development host; it remains documented as development-only in [`docs/conductor.md`](conductor.md#configuration-reference). What Bicep cannot enforce: that the deployer does not add further grants by hand afterwards. | Enforced in infrastructure (Phase 4); local launcher remains dev only |
| T11 | Disable vs purge confusion | An operator (or a bug) treats "disable" as if it deletes data, or conversely expects "disable" to also revoke/destroy the certificate. | Either a false sense that sensitive history has been removed, or an unexpected loss of audit trail / certificate availability. | There is no purge operation in the MVP at all (see [ADR 0008](adr/0008-no-purge-in-mvp.md)): `Target.enabled = false` stops future issuance/renewal but leaves the `Target`, its `Run` history, and its `AuditEvent`s intact. A future purge is scoped to be a separate, explicitly audited operation, never a side effect of disable. **Implemented (Phase 2)**: `enabled` on targets and policies, `POST …/disable` and `…/enable` endpoints (each audited), and schema triggers that abort any `DELETE` on targets, runs or policies and any `UPDATE`/`DELETE` on audit events. | Existing (design and schema, Phase 2) |
| T12 | Production CA misuse from tests | An automated test accidentally issues a real certificate against a production ACME CA (e.g. Let's Encrypt production), burning rate limits or leaving orphaned certificates. | Rate-limit exhaustion affecting real issuance; unintended public certificates for test domains. | Principle 8: production ACME CAs are never called from automated tests. **Implemented (Phase 1)**: `internal/runner/config` allows an `ACMEBinding.directoryURL` without `allowProductionCA` only when it is explicitly recognized as a staging/test/local directory (a loopback, private or link-local IP literal, or a host with a whole label such as `staging`, `test`, `sandbox`, `pebble`, `localhost`, `dev`, `local`, `internal`); every other directory is treated as production and refused unless `allowProductionCA: true` is set explicitly. This is a fail-closed allow-rule, not a denylist of known CAs, so an unknown production CA cannot be reached by accident either; Runner tests exercise `reconcile` against `internal/runner/fakelego`, a test double that imitates `lego`'s file/exit-code behavior with no network access at all, never a real or staging ACME server. This is also a per-PR review checklist item (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)). | Enforced (Phase 1): fail-closed staging/test allow-rule plus a fake `lego` in tests |
| T13 | API reached by an unintended caller | `localhost-dev` authenticates nothing finer than "a loopback peer": another user on the same host, or a web page loaded in a local browser (DNS rebinding to a name that resolves to `127.0.0.1`, cross-site `fetch`/form posts), reaches the API. In `oidc` mode: a network caller without a token, with a forged, expired, replayed-from-elsewhere (other issuer or audience) or algorithm-confused token, or with a valid token that carries no role. | Full administrative control of targets and policies (issuance requests for any name the Runner's policy allows), and reading of audit data. Never key material or credentials (T1). | `internal/conductor/api.LocalhostDev` ([ADR 0012](adr/0012-localhost-only-dev-auth.md)): configuration refuses a non-loopback `server.listen` host (names are rejected, not resolved) and `Serve` re-checks the bound address; the TCP peer must be loopback; the `Host` header must be a loopback name on the listener's port (defeats DNS rebinding); an `Origin` header must be the API's own loopback origin (`null` and foreign origins refused); `Sec-Fetch-Site` must be `same-origin`/`none`; a request with a body must be `application/json` (a simple-request form post cannot be); every request body is strictly decoded and capped at 64 KiB (T9). Each rule has a test. **Implemented (Phase 5)** ([ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)): mode `oidc` (`internal/conductor/oidc`) accepts only an `Authorization: Bearer` token (never a cookie or query parameter) that is a compact JWS signed with RS256/PS256/ES256 (`none` and HMAC refused; the key's type must match the algorithm) by a key id in the provider's published set (RSA ≥ 2048 bits, P-256; discovery document must name the configured issuer; bounded reads; cached, refreshed on age or unknown key id at most once a minute), whose `iss` equals the configured issuer, `aud` contains the configured audience, `exp`/`nbf`/`iat` admit now within a bounded skew, whose header and claims decode strictly (duplicates refused, `crit` refused), whose principal claim is a bounded printable string, and whose roles claim maps to admin or viewer; a viewer's non-`GET` request and a role-less token are `403`, everything else `401` with a challenge, enforced in the one middleware every API endpoint sits behind. Every rule has a test against an in-process provider. **Residual**: in `localhost-dev` a local user with loopback access is an administrator and the audit log's actor is `localhost-dev`; the mode is for one development host and is named in configuration. | Implemented: `oidc` (Phase 5) for production, `localhost-dev` (Phase 2) for development |
| T14 | Stolen, leaked or over-granted bearer token | An access token is taken from a browser tab, a terminal history, a proxy log or a pasted command, or the provider issues an admin-role token to a principal that should not hold it (misassigned app role, compromised provider account). | Whatever the token's role allows until it expires: administration of targets and policies (admin) or reading of the registry and audit log (viewer). Never key material (T1). | The token is accepted only over TLS unless the configuration states that a platform ingress terminates it (`server.tls` or `server.behindTlsProxy`; a non-loopback plaintext listener is refused), so it does not travel in the clear; the GUI keeps it in the tab's session storage (gone with the tab, never in a URL or a cookie) under a Content-Security-Policy that admits no foreign script; the Conductor never logs a token or echoes one in an error; expiry is enforced with a small skew and the Conductor adds no lifetime of its own; the audience check keeps a token issued for another API out; the audit log names the principal by a stable identifier (`sub`, or `oid` for Entra ID) rather than a renamable display name, qualified by the authority that asserted it (the issuer URL; [ADR 0018](adr/0018-authority-qualified-principals.md)), so misuse is attributable to a person even after the deployment changes tenant or provider. **Residual**: no revocation or introspection check — a stolen token is valid until the provider's expiry (about an hour for Entra ID); role assignment is provider-side administration this project cannot audit; the session-storage copy is readable by script on the page's origin, which the CSP confines to the page's own script. | Implemented (Phase 5); revocation not modelled |
| T15 | The GUI as an attack surface | A page served by the Conductor is used against its operator: markup injected through an FQDN, owner, error summary or audit detail (XSS), a cross-site request that rides the operator's session (CSRF), the page framed by another site (clickjacking), or a sign-in response forged or replayed (authorization code injection). | With XSS, the operator's token and therefore their role; with CSRF, an action in the operator's name; with a forged sign-in, a session under an attacker's account. | The GUI renders everything through DOM methods (`textContent`, `createElement`) — nothing from the API or the URL becomes markup — and ships under `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' <token endpoint origin>; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` with `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, so injected markup cannot execute and no third-party asset loads; the API is called with a bearer header and no cookie, so a cross-site request carries no credential (in `localhost-dev` the `Origin`/`Sec-Fetch-Site`/content-type rules of T13 apply); the sign-in is the authorization code flow with PKCE (S256) and a random `state` bound to the tab, so a code cannot be injected or replayed into another tab's flow; the code exchange goes only to the token endpoint the Conductor read from the provider's discovery document. **Residual**: the GUI trusts `/ui/config`, which is the Conductor's own, unauthenticated statement of the provider; a Conductor compromise (T1) could point the page at another provider — and already holds everything the page can reach. | Implemented (Phase 5) |

## Assurance levels

A single "is it secure" question does not fit this system; these three
lists say precisely what today's code (Phases 0–5) guarantees, what it
does not, and what closes the gap.

**Guaranteed today:**

- A closed schema: unknown fields, duplicate JSON keys, trailing data,
  oversized documents (> 64 KiB), and over-deep documents (> 8 levels) are
  all rejected before a validator ever sees them.
- `target.fqdn` and the embedded `policy` snapshot are internally
  consistent within a `JobSpec` — `Validate` rejects a document where they
  disagree.
- ACME/DNS/Store bindings are accepted only as restricted-form logical
  names (`bindingNameRe`), never as a URL, path, command, or credential.
- `Result` free text (`error.summary`) is bounded in size, restricted to
  printable characters, and checked against a known-marker heuristic.
- `storeObjectRef` is a restricted logical name
  (`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`, max 128, `..`
  rejected) — never a URL or a path.
- **A Runner-side trusted authorization policy is implemented and wired
  (Phase 1)**: before acting on any `JobSpec`, the Runner loads
  `RunnerAuthorizationPolicy` from its own trusted configuration
  (`internal/runner/config`, never from the JobSpec) and denies by
  default — an FQDN outside `allowedDnsSuffixes`, an unwanted wildcard, or
  an ACME/DNS/Store binding name outside its allow-list is rejected before
  any binding is resolved or `lego` is invoked. See
  [`docs/runner.md`](runner.md#execution-flow).
- **Safe error translation is implemented (Phase 1)**: the Runner never
  copies a raw external command/SDK error, or raw `lego` stdout/stderr,
  into a `Result`; `error.summary` is generated only from Runner-owned
  templates, with a generic fallback if a templated summary would itself
  fail the `Result` contract.
- **`lego` output redaction is implemented (Phase 1)** for known secret
  values (resolved `passthroughEnv`/EAB values) and PEM blocks before any
  `lego` output line is written to a log — see
  [`docs/runner.md`](runner.md#logging-and-redaction). This is
  value-based/heuristic, not a general secret detector, and a dedicated
  redaction test suite across the rest of the codebase's log statements is
  still Phase 3+ work.
- **Per-target run exclusion and stale-run cancellation are implemented
  (Phase 2)**: within one Conductor, at most one run per target is ever
  active (a schema constraint, not just code), a run is cancelled rather
  than started if its target was disabled or changed revision after it
  was requested, and every target update is optimistically locked on
  `revision`.
- **The Conductor's records carry no external output (Phase 2)**: run
  records and audit events are built from contract-validated `Result`
  fields and Conductor-owned templates only; the audit log is append-only
  and written atomically with each change; targets, runs and policies
  cannot be deleted.
- **API input is shape-limited (Phase 2)**: strictly decoded, capped,
  identifiers and binding names syntax-checked, FQDNs and suffixes
  normalized and label-boundary matched before storage, no field for a
  command/image/path/credential; and in `localhost-dev` the API is
  reachable only from a loopback peer with a loopback `Host`/`Origin`.
- **Named, role-bound callers in `oidc` mode (Phase 5)**: every API
  request carries a bearer token that verified against the provider's
  published key for the configured issuer and audience within its
  validity window, with `none`/HMAC refused, duplicate claims refused
  a key published with an `alg` verifying that algorithm only, and an
  unknown key id refreshed at most once a minute; the caller's identity
  is the configured claim (a stable identifier: `sub`, or `oid` for
  Entra ID), its role is admin or viewer, and a
  viewer cannot write — enforced in one middleware for every endpoint.
  A bearer token never travels on a non-loopback plaintext listener
  unless the configuration states TLS is terminated in front of it.
- **The GUI executes nothing but its own script (Phase 5)**: static,
  embedded, DOM-rendered, under a CSP that admits no inline or foreign
  script and no framing; sign-in is PKCE with a tab-bound state.
- **What a release is built from is fixed (Phase 5)**: base images by
  digest, `lego` by checksum, Go modules by `go.sum`; a published image
  carries an SBOM and provenance and a GitHub-signed attestation, and is
  published only after the CI workflow passed on its commit.

- **Job authenticity, integrity and expiry (Phase 4)**: with
  `jobSigning` configured, a Runner acts only on a
  `SignedCertificateReconcileJob` whose Ed25519 signature verifies
  against one of its trusted public keys, whose validity window includes
  now, and whose `runId` it has not accepted before (replay ledger). A
  bare JobSpec is refused. The Container Apps launcher cannot send an
  unsigned job at all.
- **Disjoint platform identities (Phase 4)**: in the Bicep deployment the
  Conductor's identity can start, observe and stop executions of one
  Job, and the Runner's can write TXT records in one zone and import
  certificates into one vault; neither holds any other grant, and no
  credential exists in either environment.

**Not guaranteed today:**

- That the entity that holds the signing key is the legitimate
  Conductor: signing authenticates the producer, it does not detect a
  compromised producer (T1); the Runner's trusted policy bounds that.
- That the `policy` snapshot embedded in a `JobSpec` is trustworthy
  (it is authentic when signed, but it is still the producer's claim).
- That a DNS credential/workload identity a `DnsBinding` resolves to is
  actually scoped to its intended zone — the Runner has no way to verify
  that from inside a run (see T4).
- Replay prevention for a Runner run **without** `jobSigning` (a bare
  JobSpec carries no expiry and no nonce), or across Runners that do not
  share a state directory.
- Complete detection of arbitrary secrets by the `error.summary` marker
  check, or by the `lego`-output redactor — both are heuristics for known
  shapes/values, not general secret detectors.
- Removal of secrets from all log output across the codebase (the
  `lego`-output redactor covers only `lego`'s own stdout/stderr).
- Mutual exclusion against a Runner the Conductor did not launch (one
  started by hand or by another launcher), or against a Runner orphaned
  by a hard kill of the Conductor: both can issue. (The filesystem store
  and the account state are each protected by an advisory lock held by
  writers and readers, so neither is corrupted or observed half-swapped
  by it, but the double issuance itself is not prevented in those cases.)
- Any identity finer than "a process on the Conductor host" for API
  callers in `localhost-dev` mode (T13); in `oidc` mode, that the
  provider assigned the admin role to the right people, or that a
  stolen token is refused before it expires (T14).
- That a Runner started by the local-process launcher holds a credential
  the Conductor's environment does not also hold (T10, `passthroughEnv`).

**Planned:**

- Log redaction tests across the codebase (Phase 3+).
- GitHub Actions pinned by commit digest (T8, [ADR 0017](adr/0017-release-pipeline.md)).

## Residual risks / not yet mitigated

Phase 0 shipped the contract, the FQDN policy engine, and CI. Phase 1 added
the Runner runtime, its trusted configuration, authorization wiring, the
bundled `lego` CLI, and the filesystem Certificate Store. Phase 2 added the
Conductor MVP: registries, audit log, scheduler, local launcher and the
loopback-only API. Phase 5 added OIDC authentication, the GUI and the
release pipeline. Being explicit about what remains open:

- **Signing authenticates the producer, not the decision (T1, T2, T3).**
  Since Phase 4 a `JobSpec` can travel as a signed, expiring envelope and
  the Runner refuses tampered, expired and replayed ones — but only when
  the Runner is configured with `jobSigning` (the local launcher may
  still hand over bare JobSpecs, which is acceptable over its private
  per-run directory on one host and nowhere else). A compromised
  Conductor holds the signing key and signs whatever it likes; the
  Runner's trusted authorization policy is what bounds that, unchanged.
  The replay ledger is per state directory: Runners with separate state
  directories do not see each other's accepted runs, and its `flock` has
  the same network-filesystem caveat as the account state's.
- **JobSpec-controlled cost levers.** `policy.renewBeforeDays` and
  `policy.keyType` are taken from the `JobSpec` and are not bounded by the
  Runner's trusted policy: a producer that is authorized for a name can
  force a reissue on every run (`renewBeforeDays` near 365) or an
  expensive key type. This is a cost/rate-limit lever within an already
  authorized scope, not an escalation; bounding both in
  `RunnerAuthorizationPolicy` is a candidate for Phase 3.
- **Concurrency control covers only runs the Conductor launches (T7).**
  Within one Conductor, at most one run per target is active, a stale
  run is cancelled before it starts, and a second Conductor on the same
  database is refused at startup. Outside it — a Runner started by
  hand, by another launcher, or one orphaned when the Conductor is killed
  hard while it runs (its run is then recorded as failed/"outcome
  unknown") — two Runner processes for the same target can still both
  talk to the CA (double issuance, rate-limit cost). Publishing account
  state and writing the filesystem store are serialized by advisory locks
  (last writer wins; readers hold the lock shared), so neither is
  corrupted, but that duplicate work is not prevented.
- **The filesystem Certificate Store is dev/test only.** The filesystem
  Store (`internal/store/filesystem`) has no access control beyond
  filesystem permissions and is not a production secrets store; it exists
  to make the Runner runnable end-to-end without a cloud dependency. The
  Azure Key Vault Store (Phase 3, `internal/store/keyvault`,
  [ADR 0013](adr/0013-azure-key-vault-store-adapter.md)) is the store
  for deployments: the Runner imports the bundle as a Key Vault
  certificate and reads back only the certificate's public part, so its
  identity needs `certificates/get` and `certificates/import` and never
  `secrets/get`. What is *not* enforced by code: that the identity's
  role assignment is actually that narrow beyond what
  `deploy/azure` declares (a deployer can add grants by hand), and who
  else holds `secrets/get` on the vault — an
  imported certificate's key is exportable through its secret by design,
  because that is how consumers obtain it.
- **`credential: default` is a development posture (T4/T10).** A Key
  Vault binding that selects the SDK's `DefaultAzureCredential` chain
  lets the Runner authenticate from service-principal variables in its
  own environment or by executing `az`/`azd`/PowerShell from `PATH`; the
  Runner image carries none of those, and the binding's `credential`
  is named in configuration so that a production deployment says
  `managed-identity` explicitly. The Key Vault store is tested against
  an in-process fake of the vault's API, never a real vault (principle
  8), so the real import operation's acceptance rules are documented,
  not CI-verified.
- **`lego` output redaction is value-based and heuristic, not exhaustive
  (T6).** `internal/runner/lego.Redactor` masks the specific secret values
  the Runner itself resolved (`passthroughEnv`, EAB) and known PEM
  markers; it cannot redact a secret it was never told about, or one
  embedded in `lego` output in a form its heuristics do not recognize.
- **No real DNS, ACME, or Store credentials/workload identity are
  provisioned by this repository.** T4 and T10 remain design commitments
  enforced by configuration shape (Phase 1: `DnsBinding`/`ACMEBinding`/
  `StoreBinding` loading and validation) rather than by verifying the
  credential itself — the Runner cannot confirm that a DNS credential it
  is handed is actually scoped to its intended zone, only that the
  binding it selected is one an administrator registered and the policy
  allows. The Key Vault store authenticates with a managed identity
  (Phase 3); Phase 4 provisions that identity and its role assignments
  in Bicep, but the template has not been deployed by this repository
  (see `deploy/azure/README.md` for what is documented rather than
  observed).
- **The secret-marker heuristic is not a secret detector (T6).** It cannot
  detect an arbitrary or unknown-format secret; it is defense-in-depth on
  top of the Phase 1 Runner behavior of never copying raw external output
  into a `Result` at all.
- **No log-scrubbing test suite across the codebase.** T6's mitigations
  cover the `Result` document (code-enforced) and `lego`'s own
  stdout/stderr (code-enforced, value-based redaction) but not every log
  statement elsewhere in the codebase; that relies on code review and the
  per-PR checklist until a dedicated test exists (Phase 3+).
- **GitHub Actions are pinned by tag, not digest; the release workflow
  has not run yet (T8).** Base images, `lego` and Go modules are pinned
  by digest or checksum and releases carry an SBOM, provenance and a
  signed attestation, but the Actions a build runs are selected by major
  version tag (kept current by Dependabot), and the first version tag
  is what verifies the workflow end to end.
- **`localhost-dev` is still a development mode (T13).** It trusts every
  loopback peer: any local user is an administrator, and the audit log
  cannot tell two of them apart. It is for one development host; the
  mode is named in configuration so a deployment cannot be in it
  silently, and `oidc` is the production mode.
- **A bearer token is valid until it expires (T14).** The Conductor
  checks signature, issuer, audience, validity window and role; it does
  not consult the provider about revocation, and it cannot see whether
  the provider assigned a role to the right person. Role assignment and
  token lifetime are provider-side controls.
- **The local-process launcher puts a Runner credential in the
  Conductor's environment (T10).** `passthroughEnv` is the only way a DNS
  credential or EAB secret reaches a Runner started by the local
  launcher, and it is forwarded from the Conductor process's own
  environment — acceptable on a single-user development host only. The
  Azure Container Apps Job launcher (Phase 4) needs no passthrough: the
  Runner Job carries its own managed identity.
- **The Container Apps deployment is verified by compilation and fakes,
  not by a real subscription.** The launcher is tested against an
  in-process fake of the platform API, and the Bicep compiles and lints;
  the execution-template override inheriting volume mounts, the role
  action names, SQLite and `flock` on an SMB share, and the Result
  propagation delay are documented expectations until a first deployment
  confirms them (`deploy/azure/README.md`).
- **The Container Apps ingress and peer encryption are documented, not
  observed (T14).** The Bicep sets `allowInsecure: false` and enables
  the environment's peer-traffic encryption so the hop from the ingress
  to the replica is not plaintext; `server.behindTlsProxy: true` in the
  Conductor's configuration is the operator's statement that this holds.
  A first deployment should confirm it before an admin token is used.
- **A hard kill leaves the outcome of in-flight runs unknown.** They are
  recorded as `failed`/`Internal` at the next start, never resumed or
  guessed; an orphaned Runner may still have finished its work in the
  Store, which the next due run then finds (`noop`).

## See also

- [Architecture](architecture.md)
- [Architecture Decision Records](adr/README.md)
