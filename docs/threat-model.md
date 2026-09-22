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
[`docs/conductor.md`](conductor.md)). Some mitigations below still describe
where a control lands once a later phase ships, not what exists today. The
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

- **External network attacker** — no credentials, reachable only at the
  Conductor's UI/API surface (loopback-only in Phase 2, so effectively
  unreachable from the network) and at CI.
- **Local user or local web page on the Conductor host** — in Phase 2 the
  API trusts any loopback peer, so a second user on the same host, or a
  web page a local browser loads, is a distinct attacker (see T13).
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
| T1 | Conductor compromise | An attacker gains code execution or database access on the Conductor. | Attacker can create/modify `Target`s and `CertificatePolicy`, submit arbitrary jobs, or read audit data — but **cannot** obtain private keys, DNS credentials, or Store credentials, because the Conductor never holds them. `JobSpec.Validate` only checks that a document is internally self-consistent (T5), so a compromised Conductor can produce a self-consistent `JobSpec` for any FQDN and any registered binding name; the Runner-side authorization policy below is what actually bounds that. | Principle 1/2/5 (no secrets, no DNS/Store credential, separate identity from Runner); closed schema, strict decoding and well-formed logical binding names only (T2/T5) constrain what a compromised Conductor can even express, not what it may cause to be issued; append-only audit log for detection; SQLite behind a `Registry` interface so a compromise is contained to one process/host (no multi-replica blast radius in the MVP) — **implemented (Phase 2)**: `internal/conductor/sqlite`, with the audit log written in the same transaction as each change and made append-only by schema triggers ([ADR 0011](adr/0011-conductor-storage-and-run-model.md)); a compromised Conductor process can still write to its own database, so the audit log detects misuse through the API, not a compromise of the process itself. **Implemented (Phase 1)**: a Runner-side `policy.RunnerAuthorizationPolicy`, loaded from trusted administrator configuration and never from the JobSpec, bounds what a JobSpec can cause to be issued to the configured suffixes, wildcard setting and binding allow-lists, regardless of JobSpec content; within those bounds a compromised Conductor can still request issuance for any name — see [`docs/runner.md`](runner.md#execution-flow). **Planned**: an authenticated `JobSpec` with expiry/nonce narrows the window further (Phase 4). | Existing (principles, contract, shape-only limits, Runner authorization, registry/audit since Phase 2); signed envelope Phase 4 |
| T2 | JobSpec tampering in transit or at rest | A `JobSpec` is modified between production by the Conductor and consumption by the Runner (e.g. a compromised launcher, a tampered queue message, a modified file). | A tampered `JobSpec` could redirect issuance to an unauthorized FQDN, point at a different binding, or otherwise escape the policy the Conductor intended. | Strict decoding (`pkg/api/v1alpha1/decode.go`: unknown fields, duplicate keys, trailing data, 64 KiB cap all rejected) limits the *shape* of a tampered document only. A tampered document that remains self-consistent — `target.fqdn` and the embedded `policy` snapshot changed together, or one registered binding name swapped for another well-formed registered binding name — passes `Validate` unchanged (T5); `Validate` cannot detect that kind of tampering by itself. **Implemented (Phase 1)**: a Runner-side `RunnerAuthorizationPolicy`, evaluated against trusted configuration that is not part of the document, bounds issuance independently of anything a tampered `JobSpec` claims. **Planned**: a signed/authenticated `JobSpec` envelope with expiry (Phase 4) detects tampering in transit — but signing addresses tampering, not a compromised producer legitimately emitting a bad document in the first place (see T1). | Existing (decoding limits shape; Runner authorization); signed envelope Phase 4 |
| T3 | JobSpec replay and expiry | An old, previously-valid `JobSpec` is re-submitted (e.g. replayed from a log, a retried queue message, or a captured artifact) after the `Target` it names has since changed or been disabled. | Certificate issuance or renewal against stale policy or a disabled target; potential double execution when combined with T7. | **Planned**: a signed envelope around the `JobSpec` carrying `issuedAt`/`expiresAt` and a `nonce`, checked by the Runner against the run registry before it does anything (a `runId` that is not `queued`/`starting` in the registry, or whose `expiresAt` has passed, is refused). The `target.revision` field already lets a `Result` be matched to the exact target state a job was produced for, which is the building block this check is layered on. **Partial (Phase 2)**: the run registry now exists and the Conductor itself cancels a queued run whose target was disabled or changed revision before it starts, and the local launcher checks that a `Result` names the run it started; but the Runner still does not consult the registry, so a replayed document handed to a Runner by other means is not detected. | Conductor-side stale-run check Phase 2; Runner-side replay/expiry check Phase 4 |
| T4 | DNS permission abuse | The Runner's DNS credential/workload identity is used (by a compromised Runner, or by DNS-provider-side misconfiguration) to write records outside the one zone the current run needs. | Ability to complete ACME challenges for FQDNs outside the intended scope, or to otherwise tamper with DNS beyond the TXT challenge record. | `DnsBinding` configuration is now loaded and validated by the Runner (`internal/runner/config`): a binding names a `lego` provider plus non-secret `env` and the names of `passthroughEnv` variables the platform is expected to supply (the `exec`/`manual` providers are denied outright, since they run arbitrary programs or need interactive input). The actual credential or workload identity behind those names is still expected to be scoped by the administrator who provisions it to the challenge zone and TXT records only — never zone-wide or account-wide DNS write; **the Runner has no way to verify that scoping itself**, it can only refuse to start `lego` if a required `passthroughEnv` variable is missing. This scoping remains an operational requirement on how each `DnsBinding` is provisioned, not something the JobSpec contract or the Runner's own code can enforce. | Binding model and config loading implemented (Phase 1); real workload-identity provisioning (e.g. Managed Identity) remains an operational/deployment concern, Phase 3+ |
| T5 | FQDN policy bypass | An attacker crafts an FQDN or suffix list to slip past the intended policy: mismatched label boundaries, case differences, a trailing dot, an IDNA/punycode label, an unintended wildcard, or a duplicate JSON key that causes two validators to disagree on which value "wins". | Certificate issued for a domain the operator did not intend to authorize (e.g. `evil-example.ac.jp` treated as under `example.ac.jp`). | **Validation** (implemented, both sides of the boundary): `internal/policy/fqdn.go` normalizes before comparing (lower-case, single trailing dot stripped, ASCII-only) and matches suffixes on whole label boundaries only (`MatchesSuffix`), so `evil-example.ac.jp` is correctly rejected against the suffix `example.ac.jp`. `xn--` (IDNA A-label) input is rejected outright rather than silently accepted (see ADR 0006). Wildcards are accepted only as the whole left-most label. `pkg/api/v1alpha1/decode.go` rejects duplicate JSON keys before any validator sees the document, closing the classic "two parsers disagree" bypass. `JobSpec.Validate` checks that `target.fqdn` is consistent with the `policy` snapshot embedded in the same document — this is a self-consistency check of untrusted input, never authorization (see the doc comment on `JobSpec.Validate` and `TestJobSpecValidateIsSelfConsistencyNotAuthorization`). **Authorization** (implemented and wired, Phase 1): `internal/policy.RunnerAuthorizationPolicy.Authorize` decides, against a trusted allowed-suffix/wildcard/binding-name configuration that is loaded on the execution platform (`internal/runner/config`) and never taken from the JobSpec, whether the Runner may act at all. `Reconcile` calls it — deny-by-default — before resolving any binding or invoking `lego`; see [`docs/runner.md`](runner.md#execution-flow). This closes the gap T1/T2 previously described for a self-consistent-but-malicious document; it does not, and cannot, verify that the *content* behind an allowed binding (e.g. a DNS credential's actual zone scope) is itself correct — see T4. | Validation existing (`internal/policy`, decode/validate); authorization implemented and wired in the Runner (Phase 1) |
| T6 | Secret leakage into logs/results/errors | A credential, private key, EAB HMAC, access token, or temporary PFX password ends up in a log line, a `Result.error.summary`, or an exception message. | Credential compromise even without direct access to the Conductor or Runner process — e.g. via log aggregation, error trackers, or a leaked `Result` document. | `validate.go`'s `validateOpaqueText` rejects non-printable characters (control characters, Unicode line/paragraph separators, bidi/format characters) and a case-insensitive-where-meaningful set of secret markers (`-----BEGIN`, `private key`, `eyJ` JWT/JWS/EAB-shaped base64, `AKIA`, `ghp_`, `github_pat_`, `bearer `, `basic `, `authorization:`, `password=`, `secret=`, `token=`, `sig=`, `key=`, and similar) in any `Result` free-text field. This is a **defense-in-depth heuristic, not a secret detector**: it catches common accidental leaks by known shape but cannot recognize an arbitrary secret or an unknown format. `storeObjectRef` is now a strict logical name (`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`, max 128, `..` rejected) — never a URL, path, query string, or credential-bearing value. `ResultError` is a fixed machine code plus a short summary; the field rules above are a supporting control only — character class, length and known-marker checks cannot, by themselves, keep a raw error, a command line, or environment contents out of a summary. **Implemented (Phase 1) — the real control**: `internal/runner/reconcile.go` never copies a raw external command/SDK error, `lego` stdout, or `lego` stderr into a `Result`; `error.summary` is generated only from a fixed set of Runner-owned safe templates keyed by `error.code` (see [`docs/runner.md`](runner.md#result-and-error-codes)), and if a templated summary would still fail the `Result` contract's own checks, the Runner falls back to a generic, code-specific summary rather than skip producing a `Result`. Raw `lego` output goes only to internal logs, and only after redaction: `internal/runner/lego.Redactor` masks resolved `passthroughEnv`/EAB secret values and PEM-shaped lines before a `lego` output line is logged at debug level. This redaction is **value-based and heuristic** — it masks the specific secret values the Runner itself resolved and known PEM markers, not an arbitrary or unknown-format secret — and it covers `lego` output specifically, not every log statement in the codebase; a dedicated redaction test suite across the rest of the codebase's log statements is still open (Phase 3+). **Phase 2**: the Conductor never copies a Runner's stderr into a run record or an audit event — a run's `error.summary` comes only from the `Result` (contract-validated) or from Conductor-owned templates, and the Runner's stderr is relayed to the debug log only, bounded and with non-printable characters replaced; audit details are Conductor-owned sentences over validated values. | Existing (Result field validation, marker heuristic, Runner-owned safe-summary templates, lego-output redaction, Conductor-owned run/audit text); log-wide redaction test suite Phase 3+ |
| T7 | Double execution / concurrent reconcile of the same target | Two `Run`s for the same `Target` execute concurrently (e.g. a retried scheduler tick, a re-delivered queue message, or an operator manually triggering a run while one is already in flight). | Wasted ACME rate-limit budget, two ACME orders, or two Runners fighting over the same DNS TXT record. The Certificate Store and the account state themselves are not corrupted by it: writes and reads are serialized by advisory locks (`internal/fslock`), and the last writer wins. | **Existing (Phase 1)**: store/state consistency under concurrent runs (advisory locks, atomic link swaps). **Implemented (Phase 2)**: at most one queued/starting/running run per target, enforced by a partial unique index in the registry so no code path (scheduler tick, operator request, restart) can create a second one; optimistic locking on `Target.revision` (every update names the revision it acts on); each run records the revision it was requested for and is cancelled, not started, if the target was disabled or moved on in the meantime; an operator request may name the revision it acts on and a second request answers `409 run_active`. See [ADR 0011](adr/0011-conductor-storage-and-run-model.md). A second Conductor process on the same database (another port, same `database.path`) is refused at startup by an exclusive `flock` on `<database.path>.lock`, taken before recovery or any other state change, so two schedulers cannot plan against one registry and a newcomer cannot mark the owner's in-flight runs failed. Bookkeeping follows the registry's actual status (each transition is written against the last recorded status, retried on transient failure, reconciled on conflict), and a run whose outcome could not be recorded is closed by the loop's sweep, so a Runner's outcome is not lost to one failed write and a stranded run does not hold the target's slot until a restart. **Residual**: a Runner orphaned by a hard kill of the Conductor (its run is marked failed/"outcome unknown" at the next start) can still be finishing when the next due run starts; and a Runner started by hand or by another launcher is outside the registry entirely. | Store/state consistency (Phase 1); run-level exclusion and single-process ownership implemented (Phase 2); orphaned-Runner residual accepted |
| T8 | Supply chain | A malicious or vulnerable dependency, base image, GitHub Action, or `lego` release is pulled into a build. | Compromised build output; a vulnerable component shipped in a released image. | `lego` is pinned to a specific, version-checked release (Phase 1) rather than "latest". Both Dockerfiles build from `golang:1.24-bookworm`, and are documented to switch to a digest-pinned base image at release time; runtime images are `gcr.io/distroless/static-debian12:nonroot` (minimal attack surface, no shell). CI runs `govulncheck` on every push/PR (`.github/workflows/ci.yml`). Deployments are required to pin images by commit SHA or digest, never `latest`. SBOM and provenance generation land in Phase 5. | Partial now (govulncheck, distroless, CGO disabled); digest pinning and SBOM/provenance Phase 5 |
| T9 | Denial of service via oversized/hostile documents | A very large or deeply-nested `JobSpec`/`Result` document is submitted to exhaust memory or CPU during decoding. | Resource exhaustion on the Conductor or Runner. | `decodeStrict` reads through an `io.LimitReader` capped at `MaxDocumentSize` (64 KiB) and rejects anything larger before decoding. The size cap alone does not bound CPU: a 64 KiB document of nothing but nested brackets can make a naive recursive walker superlinear. The duplicate-key walker therefore also enforces `MaxNestingDepth` (8 levels; the contract needs 3) and renders diagnostic paths only on error, so the cost of any accepted-size document is linear in its length (`TestDecodeRejectsDeepNestingQuickly`). | Existing (`pkg/api/v1alpha1/decode.go`) |
| T10 | Privilege separation failure between Conductor and Runner identities | The Conductor is accidentally granted DNS write, Certificate Store read, or other Runner-scoped permissions (e.g. through shared service-principal reuse or overly broad IAM at deployment time), collapsing the intended separation. | A Conductor compromise (T1) escalates to full DNS/Store compromise instead of being contained. | Principle 5 is a deployment-time requirement as much as a code-time one: Conductor and Runner identities must be provisioned separately, with the Conductor's identity granted neither DNS write nor Store read. Azure resources are declared in Bicep (Phase 4), not created ad hoc from code, so the IAM grants for each identity are reviewable, versioned artifacts rather than one-off console changes. **Phase 2 residual**: the local-process launcher's `passthroughEnv` is the only way a DNS credential reaches a Runner it starts, and it forwards that variable from the Conductor's own environment — i.e. on a development host the Conductor process environment carries a Runner credential. The Conductor never reads or logs the value and forwards only names listed in configuration, but the separation is not real in that deployment shape; it is documented as development-only in [`docs/conductor.md`](conductor.md#configuration-reference). | Principle established now; not real with the local launcher (Phase 2, dev only); enforced in infra from Phase 4 |
| T11 | Disable vs purge confusion | An operator (or a bug) treats "disable" as if it deletes data, or conversely expects "disable" to also revoke/destroy the certificate. | Either a false sense that sensitive history has been removed, or an unexpected loss of audit trail / certificate availability. | There is no purge operation in the MVP at all (see [ADR 0008](adr/0008-no-purge-in-mvp.md)): `Target.enabled = false` stops future issuance/renewal but leaves the `Target`, its `Run` history, and its `AuditEvent`s intact. A future purge is scoped to be a separate, explicitly audited operation, never a side effect of disable. **Implemented (Phase 2)**: `enabled` on targets and policies, `POST …/disable` and `…/enable` endpoints (each audited), and schema triggers that abort any `DELETE` on targets, runs or policies and any `UPDATE`/`DELETE` on audit events. | Existing (design and schema, Phase 2) |
| T12 | Production CA misuse from tests | An automated test accidentally issues a real certificate against a production ACME CA (e.g. Let's Encrypt production), burning rate limits or leaving orphaned certificates. | Rate-limit exhaustion affecting real issuance; unintended public certificates for test domains. | Principle 8: production ACME CAs are never called from automated tests. **Implemented (Phase 1)**: `internal/runner/config` allows an `ACMEBinding.directoryURL` without `allowProductionCA` only when it is explicitly recognized as a staging/test/local directory (a loopback, private or link-local IP literal, or a host with a whole label such as `staging`, `test`, `sandbox`, `pebble`, `localhost`, `dev`, `local`, `internal`); every other directory is treated as production and refused unless `allowProductionCA: true` is set explicitly. This is a fail-closed allow-rule, not a denylist of known CAs, so an unknown production CA cannot be reached by accident either; Runner tests exercise `reconcile` against `internal/runner/fakelego`, a test double that imitates `lego`'s file/exit-code behavior with no network access at all, never a real or staging ACME server. This is also a per-PR review checklist item (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)). | Enforced (Phase 1): fail-closed staging/test allow-rule plus a fake `lego` in tests |
| T13 | API reached by an unintended local caller | The Phase 2 API authenticates nothing finer than "a loopback peer": another user on the same host, or a web page loaded in a local browser (DNS rebinding to a name that resolves to `127.0.0.1`, cross-site `fetch`/form posts), reaches the API. | Full administrative control of targets and policies (issuance requests for any name the Runner's policy allows), and reading of audit data. Never key material or credentials (T1). | `internal/conductor/api.LocalhostDev` ([ADR 0012](adr/0012-localhost-only-dev-auth.md)): configuration refuses a non-loopback `server.listen` host (names are rejected, not resolved) and `Serve` re-checks the bound address; the TCP peer must be loopback; the `Host` header must be a loopback name on the listener's port (defeats DNS rebinding); an `Origin` header must be the API's own loopback origin (`null` and foreign origins refused); `Sec-Fetch-Site` must be `same-origin`/`none`; a request with a body must be `application/json` (a simple-request form post cannot be); every request body is strictly decoded and capped at 64 KiB (T9). Each rule has a test. **Residual**: a local user with loopback access is an administrator; there is no principal finer than `localhost-dev` in the audit log. | Implemented (Phase 2) as a development mode; OIDC with named principals Phase 5 |

## Assurance levels

A single "is it secure" question does not fit this system; these three
lists say precisely what today's code (Phases 0–2) guarantees, what it
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
  command/image/path/credential; and the API is reachable only from a
  loopback peer with a loopback `Host`/`Origin`.

**Not guaranteed today:**

- That the entity that produced a `JobSpec` is legitimate.
- That the `policy` snapshot embedded in a `JobSpec` is trustworthy.
- That a DNS credential/workload identity a `DnsBinding` resolves to is
  actually scoped to its intended zone — the Runner has no way to verify
  that from inside a run (see T4).
- Replay prevention (an old, previously-valid `JobSpec` being rejected).
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
  callers (T13); the audit log's actor is `localhost-dev` for every API
  action.
- That a Runner started by the local-process launcher holds a credential
  the Conductor's environment does not also hold (T10, `passthroughEnv`).

**Planned:**

- `JobSpec` authentication, integrity, and expiry (Phase 4).
- Log redaction tests across the codebase (Phase 3+).
- A platform launcher with workload identity so the Conductor's
  environment carries no Runner credential (Phase 4).
- OIDC authentication with named principals for the API (Phase 5).

## Residual risks / not yet mitigated

Phase 0 shipped the contract, the FQDN policy engine, and CI. Phase 1 added
the Runner runtime, its trusted configuration, authorization wiring, the
bundled `lego` CLI, and the filesystem Certificate Store. Phase 2 added the
Conductor MVP: registries, audit log, scheduler, local launcher and the
loopback-only API. Being explicit about what remains open:

- **No signing or authentication of the `JobSpec` itself yet (T2, T3).**
  Today's mitigation is shape-only: strict decoding limits what a tampered
  document can express, but a self-consistent tampered document (fqdn and
  policy changed together, or a binding name swapped) still passes
  `Validate`. There is no cryptographic integrity check on the document in
  transit. This is acceptable while the only transport is a private
  per-run directory on the same host written by the Conductor and read by
  its own child process (Phase 2) but must land before the Conductor and
  Runner run on separate hosts trusting an untrusted transport — and even then, signing only addresses tampering, not a
  compromised Conductor legitimately producing a bad `JobSpec` (see T1).
- **JobSpec-controlled cost levers.** `policy.renewBeforeDays` and
  `policy.keyType` are taken from the `JobSpec` and are not bounded by the
  Runner's trusted policy: a producer that is authorized for a name can
  force a reissue on every run (`renewBeforeDays` near 365) or an
  expensive key type. This is a cost/rate-limit lever within an already
  authorized scope, not an escalation; bounding both in
  `RunnerAuthorizationPolicy` is a candidate for Phase 3.
- **No Runner-side replay/expiry enforcement yet (T3).** The run registry
  exists (Phase 2) and the Conductor cancels a stale queued run itself,
  but the Runner does not consult the registry and a `JobSpec` carries no
  expiry, so a document replayed to a Runner by other means is actioned.
  Runner-side checks are Phase 4.
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
  role assignment is actually that narrow (a deployment/IAM concern,
  Bicep in Phase 4), and who else holds `secrets/get` on the vault — an
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
  (Phase 3); provisioning that identity and its role assignments in
  infrastructure is Phase 4 work.
- **The secret-marker heuristic is not a secret detector (T6).** It cannot
  detect an arbitrary or unknown-format secret; it is defense-in-depth on
  top of the Phase 1 Runner behavior of never copying raw external output
  into a `Result` at all.
- **No log-scrubbing test suite across the codebase.** T6's mitigations
  cover the `Result` document (code-enforced) and `lego`'s own
  stdout/stderr (code-enforced, value-based redaction) but not every log
  statement elsewhere in the codebase; that relies on code review and the
  per-PR checklist until a dedicated test exists (Phase 3+).
- **No SBOM/provenance, no digest pinning at build time.** T8 is partially
  mitigated (govulncheck, pinned Go toolchain by tag, distroless runtime);
  digest pinning and SBOM/provenance are explicitly Phase 5 work.
- **The API's authentication is a development mode (T13).** `localhost-dev`
  trusts every loopback peer: any local user is an administrator, and the
  audit log cannot tell two of them apart. The loopback/`Host`/`Origin`/
  `Sec-Fetch-Site`/content-type rules keep a local browser and a rebound
  DNS name out, nothing more. The mode is named in configuration so a
  deployment cannot be in it silently; OIDC is Phase 5.
- **The local-process launcher puts a Runner credential in the
  Conductor's environment (T10).** `passthroughEnv` is the only way a DNS
  credential or EAB secret reaches a Runner in Phase 2, and it is
  forwarded from the Conductor process's own environment — acceptable on
  a single-user development host only. The Azure Container Apps Job
  launcher with workload identity (Phase 4) removes the need.
- **A hard kill leaves the outcome of in-flight runs unknown.** They are
  recorded as `failed`/`Internal` at the next start, never resumed or
  guessed; an orphaned Runner may still have finished its work in the
  Store, which the next due run then finds (`noop`).

## See also

- [Architecture](architecture.md)
- [Architecture Decision Records](adr/README.md)
