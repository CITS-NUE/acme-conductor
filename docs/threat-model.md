# Threat Model

This document covers the ACME Conductor system as designed in
[`docs/architecture.md`](architecture.md). It is written and maintained
alongside the code. **Phase 0** shipped the versioned JobSpec/Result
contract, FQDN normalization and CI; **Phase 1** added the Runner
(`internal/runner`), its trusted configuration and authorization wiring,
the bundled `lego` CLI, and the filesystem Certificate Store (see
[`docs/runner.md`](runner.md)). Some mitigations below still describe
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
  Conductor's UI/API surface (once it exists) and at CI.
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
| T1 | Conductor compromise | An attacker gains code execution or database access on the Conductor. | Attacker can create/modify `Target`s and `CertificatePolicy`, submit arbitrary jobs, or read audit data — but **cannot** obtain private keys, DNS credentials, or Store credentials, because the Conductor never holds them. `JobSpec.Validate` only checks that a document is internally self-consistent (T5), so a compromised Conductor can produce a self-consistent `JobSpec` for any FQDN and any registered binding name; the Runner-side authorization policy below is what actually bounds that. | Principle 1/2/5 (no secrets, no DNS/Store credential, separate identity from Runner); closed schema, strict decoding and well-formed logical binding names only (T2/T5) constrain what a compromised Conductor can even express, not what it may cause to be issued; append-only audit log for detection; SQLite behind a `Registry` interface so a compromise is contained to one process/host (no multi-replica blast radius in the MVP). **Implemented (Phase 1)**: a Runner-side `policy.RunnerAuthorizationPolicy`, loaded from trusted administrator configuration and never from the JobSpec, bounds what a JobSpec can cause to be issued to the configured suffixes, wildcard setting and binding allow-lists, regardless of JobSpec content; within those bounds a compromised Conductor can still request issuance for any name — see [`docs/runner.md`](runner.md#execution-flow). **Planned**: an authenticated `JobSpec` with expiry/nonce narrows the window further (Phase 4). | Existing (principles, contract, shape-only limits, Runner authorization); registry/audit implementation Phase 2; signed envelope Phase 4 |
| T2 | JobSpec tampering in transit or at rest | A `JobSpec` is modified between production by the Conductor and consumption by the Runner (e.g. a compromised launcher, a tampered queue message, a modified file). | A tampered `JobSpec` could redirect issuance to an unauthorized FQDN, point at a different binding, or otherwise escape the policy the Conductor intended. | Strict decoding (`pkg/api/v1alpha1/decode.go`: unknown fields, duplicate keys, trailing data, 64 KiB cap all rejected) limits the *shape* of a tampered document only. A tampered document that remains self-consistent — `target.fqdn` and the embedded `policy` snapshot changed together, or one registered binding name swapped for another well-formed registered binding name — passes `Validate` unchanged (T5); `Validate` cannot detect that kind of tampering by itself. **Implemented (Phase 1)**: a Runner-side `RunnerAuthorizationPolicy`, evaluated against trusted configuration that is not part of the document, bounds issuance independently of anything a tampered `JobSpec` claims. **Planned**: a signed/authenticated `JobSpec` envelope with expiry (Phase 4) detects tampering in transit — but signing addresses tampering, not a compromised producer legitimately emitting a bad document in the first place (see T1). | Existing (decoding limits shape; Runner authorization); signed envelope Phase 4 |
| T3 | JobSpec replay and expiry | An old, previously-valid `JobSpec` is re-submitted (e.g. replayed from a log, a retried queue message, or a captured artifact) after the `Target` it names has since changed or been disabled. | Certificate issuance or renewal against stale policy or a disabled target; potential double execution when combined with T7. | **Planned**: a signed envelope around the `JobSpec` carrying `issuedAt`/`expiresAt` and a `nonce`, checked by the Runner against the run registry before it does anything (a `runId` that is not `queued`/`starting` in the registry, or whose `expiresAt` has passed, is refused). The `target.revision` field already lets a `Result` be matched to the exact target state a job was produced for, which is the building block this check is layered on. | Planned, Phase 4 |
| T4 | DNS permission abuse | The Runner's DNS credential/workload identity is used (by a compromised Runner, or by DNS-provider-side misconfiguration) to write records outside the one zone the current run needs. | Ability to complete ACME challenges for FQDNs outside the intended scope, or to otherwise tamper with DNS beyond the TXT challenge record. | `DnsBinding` configuration is now loaded and validated by the Runner (`internal/runner/config`): a binding names a `lego` provider plus non-secret `env` and the names of `passthroughEnv` variables the platform is expected to supply (the `exec`/`manual` providers are denied outright, since they run arbitrary programs or need interactive input). The actual credential or workload identity behind those names is still expected to be scoped by the administrator who provisions it to the challenge zone and TXT records only — never zone-wide or account-wide DNS write; **the Runner has no way to verify that scoping itself**, it can only refuse to start `lego` if a required `passthroughEnv` variable is missing. This scoping remains an operational requirement on how each `DnsBinding` is provisioned, not something the JobSpec contract or the Runner's own code can enforce. | Binding model and config loading implemented (Phase 1); real workload-identity provisioning (e.g. Managed Identity) remains an operational/deployment concern, Phase 3+ |
| T5 | FQDN policy bypass | An attacker crafts an FQDN or suffix list to slip past the intended policy: mismatched label boundaries, case differences, a trailing dot, an IDNA/punycode label, an unintended wildcard, or a duplicate JSON key that causes two validators to disagree on which value "wins". | Certificate issued for a domain the operator did not intend to authorize (e.g. `evil-example.ac.jp` treated as under `example.ac.jp`). | **Validation** (implemented, both sides of the boundary): `internal/policy/fqdn.go` normalizes before comparing (lower-case, single trailing dot stripped, ASCII-only) and matches suffixes on whole label boundaries only (`MatchesSuffix`), so `evil-example.ac.jp` is correctly rejected against the suffix `example.ac.jp`. `xn--` (IDNA A-label) input is rejected outright rather than silently accepted (see ADR 0006). Wildcards are accepted only as the whole left-most label. `pkg/api/v1alpha1/decode.go` rejects duplicate JSON keys before any validator sees the document, closing the classic "two parsers disagree" bypass. `JobSpec.Validate` checks that `target.fqdn` is consistent with the `policy` snapshot embedded in the same document — this is a self-consistency check of untrusted input, never authorization (see the doc comment on `JobSpec.Validate` and `TestJobSpecValidateIsSelfConsistencyNotAuthorization`). **Authorization** (implemented and wired, Phase 1): `internal/policy.RunnerAuthorizationPolicy.Authorize` decides, against a trusted allowed-suffix/wildcard/binding-name configuration that is loaded on the execution platform (`internal/runner/config`) and never taken from the JobSpec, whether the Runner may act at all. `Reconcile` calls it — deny-by-default — before resolving any binding or invoking `lego`; see [`docs/runner.md`](runner.md#execution-flow). This closes the gap T1/T2 previously described for a self-consistent-but-malicious document; it does not, and cannot, verify that the *content* behind an allowed binding (e.g. a DNS credential's actual zone scope) is itself correct — see T4. | Validation existing (`internal/policy`, decode/validate); authorization implemented and wired in the Runner (Phase 1) |
| T6 | Secret leakage into logs/results/errors | A credential, private key, EAB HMAC, access token, or temporary PFX password ends up in a log line, a `Result.error.summary`, or an exception message. | Credential compromise even without direct access to the Conductor or Runner process — e.g. via log aggregation, error trackers, or a leaked `Result` document. | `validate.go`'s `validateOpaqueText` rejects non-printable characters (control characters, Unicode line/paragraph separators, bidi/format characters) and a case-insensitive-where-meaningful set of secret markers (`-----BEGIN`, `private key`, `eyJ` JWT/JWS/EAB-shaped base64, `AKIA`, `ghp_`, `github_pat_`, `bearer `, `basic `, `authorization:`, `password=`, `secret=`, `token=`, `sig=`, `key=`, and similar) in any `Result` free-text field. This is a **defense-in-depth heuristic, not a secret detector**: it catches common accidental leaks by known shape but cannot recognize an arbitrary secret or an unknown format. `storeObjectRef` is now a strict logical name (`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`, max 128, `..` rejected) — never a URL, path, query string, or credential-bearing value. `ResultError` is a fixed machine code plus a short summary; the field rules above are a supporting control only — character class, length and known-marker checks cannot, by themselves, keep a raw error, a command line, or environment contents out of a summary. **Implemented (Phase 1) — the real control**: `internal/runner/reconcile.go` never copies a raw external command/SDK error, `lego` stdout, or `lego` stderr into a `Result`; `error.summary` is generated only from a fixed set of Runner-owned safe templates keyed by `error.code` (see [`docs/runner.md`](runner.md#result-and-error-codes)), and if a templated summary would still fail the `Result` contract's own checks, the Runner falls back to a generic, code-specific summary rather than skip producing a `Result`. Raw `lego` output goes only to internal logs, and only after redaction: `internal/runner/lego.Redactor` masks resolved `passthroughEnv`/EAB secret values and PEM-shaped lines before a `lego` output line is logged at debug level. This redaction is **value-based and heuristic** — it masks the specific secret values the Runner itself resolved and known PEM markers, not an arbitrary or unknown-format secret — and it covers `lego` output specifically, not every log statement in the codebase; a dedicated redaction test suite across the rest of the codebase's log statements is still Phase 2+ work. | Existing (Result field validation, marker heuristic, Runner-owned safe-summary templates, lego-output redaction); log-wide redaction test suite Phase 2+ |
| T7 | Double execution / concurrent reconcile of the same target | Two `Run`s for the same `Target` execute concurrently (e.g. a retried scheduler tick, a re-delivered queue message, or an operator manually triggering a run while one is already in flight). | Wasted ACME rate-limit budget, two ACME orders, or two Runners fighting over the same DNS TXT record. The Certificate Store and the account state themselves are not corrupted by it: writes and reads are serialized by advisory locks (`internal/fslock`), and the last writer wins. | **Existing (Phase 1)**: store/state consistency under concurrent runs (advisory locks, atomic link swaps). **Planned**: per-target mutual exclusion in the scheduler/launcher, an idempotency key derived from `(targetId, targetRevision)`, and optimistic locking on `Target.revision` so a stale `JobSpec` cannot be actioned against a target that has since moved on. | Store/state consistency existing (Phase 1); run-level exclusion Phase 2 |
| T8 | Supply chain | A malicious or vulnerable dependency, base image, GitHub Action, or `lego` release is pulled into a build. | Compromised build output; a vulnerable component shipped in a released image. | `lego` is pinned to a specific, version-checked release (Phase 1) rather than "latest". Both Dockerfiles build from `golang:1.24-bookworm`, and are documented to switch to a digest-pinned base image at release time; runtime images are `gcr.io/distroless/static-debian12:nonroot` (minimal attack surface, no shell). CI runs `govulncheck` on every push/PR (`.github/workflows/ci.yml`). Deployments are required to pin images by commit SHA or digest, never `latest`. SBOM and provenance generation land in Phase 5. | Partial now (govulncheck, distroless, CGO disabled); digest pinning and SBOM/provenance Phase 5 |
| T9 | Denial of service via oversized/hostile documents | A very large or deeply-nested `JobSpec`/`Result` document is submitted to exhaust memory or CPU during decoding. | Resource exhaustion on the Conductor or Runner. | `decodeStrict` reads through an `io.LimitReader` capped at `MaxDocumentSize` (64 KiB) and rejects anything larger before decoding. The size cap alone does not bound CPU: a 64 KiB document of nothing but nested brackets can make a naive recursive walker superlinear. The duplicate-key walker therefore also enforces `MaxNestingDepth` (8 levels; the contract needs 3) and renders diagnostic paths only on error, so the cost of any accepted-size document is linear in its length (`TestDecodeRejectsDeepNestingQuickly`). | Existing (`pkg/api/v1alpha1/decode.go`) |
| T10 | Privilege separation failure between Conductor and Runner identities | The Conductor is accidentally granted DNS write, Certificate Store read, or other Runner-scoped permissions (e.g. through shared service-principal reuse or overly broad IAM at deployment time), collapsing the intended separation. | A Conductor compromise (T1) escalates to full DNS/Store compromise instead of being contained. | Principle 5 is a deployment-time requirement as much as a code-time one: Conductor and Runner identities must be provisioned separately, with the Conductor's identity granted neither DNS write nor Store read. Azure resources are declared in Bicep (Phase 4), not created ad hoc from code, so the IAM grants for each identity are reviewable, versioned artifacts rather than one-off console changes. | Principle established now; enforced in infra from Phase 4 |
| T11 | Disable vs purge confusion | An operator (or a bug) treats "disable" as if it deletes data, or conversely expects "disable" to also revoke/destroy the certificate. | Either a false sense that sensitive history has been removed, or an unexpected loss of audit trail / certificate availability. | There is no purge operation in the MVP at all (see [ADR 0008](adr/0008-no-purge-in-mvp.md)): `Target.enabled = false` stops future issuance/renewal but leaves the `Target`, its `Run` history, and its `AuditEvent`s intact. A future purge is scoped to be a separate, explicitly audited operation, never a side effect of disable. | Existing as a design decision; `enabled` field implemented Phase 2 |
| T12 | Production CA misuse from tests | An automated test accidentally issues a real certificate against a production ACME CA (e.g. Let's Encrypt production), burning rate limits or leaving orphaned certificates. | Rate-limit exhaustion affecting real issuance; unintended public certificates for test domains. | Principle 8: production ACME CAs are never called from automated tests. **Implemented (Phase 1)**: `internal/runner/config` rejects an `ACMEBinding.directoryURL` that matches a well-known production ACME directory (Let's Encrypt, ZeroSSL, Google Trust Services, Buypass) unless `allowProductionCA: true` is set explicitly, so a test or development configuration cannot reach a production CA by accident; Runner tests exercise `reconcile` against `internal/runner/fakelego`, a test double that imitates `lego`'s file/exit-code behavior with no network access at all, never a real or staging ACME server. This is also a per-PR review checklist item (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)). | Enforced (Phase 1): production-directory denylist plus a fake `lego` in tests |

## Assurance levels

A single "is it secure" question does not fit this system; these three
lists say precisely what today's code (Phase 0 + Phase 1) guarantees, what
it does not, and what closes the gap.

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
  still Phase 2+ work.

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
- Mutual exclusion between two Runner *runs* for the same target: both
  can issue. (The filesystem store and the account state are each
  protected by an advisory lock held by writers and readers, so neither
  is corrupted or observed half-swapped by it, but the double issuance
  itself is not prevented.)

**Planned:**

- `JobSpec` authentication, integrity, and expiry (Phase 4).
- Log redaction tests across the codebase (Phase 2+).
- Per-target run-level mutual exclusion (Phase 2). The on-disk stores
  (`stateDir`, filesystem Certificate Store) are already serialized by
  advisory locks; what is missing is preventing two runs for one target
  from both executing `lego`.

## Residual risks / not yet mitigated

Phase 0 shipped the contract, the FQDN policy engine, and CI. Phase 1 added
the Runner runtime, its trusted configuration, authorization wiring, the
bundled `lego` CLI, and the filesystem Certificate Store. Being explicit
about what remains open:

- **No signing or authentication of the `JobSpec` itself yet (T2, T3).**
  Today's mitigation is shape-only: strict decoding limits what a tampered
  document can express, but a self-consistent tampered document (fqdn and
  policy changed together, or a binding name swapped) still passes
  `Validate`. There is no cryptographic integrity check on the document in
  transit. This is acceptable while the only transport is "the same local
  process passes a Go struct" (Phase 0/1) but must land before the
  Conductor and Runner run on separate hosts trusting an untrusted
  transport — and even then, signing only addresses tampering, not a
  compromised Conductor legitimately producing a bad `JobSpec` (see T1).
- **JobSpec-controlled cost levers.** `policy.renewBeforeDays` and
  `policy.keyType` are taken from the `JobSpec` and are not bounded by the
  Runner's trusted policy: a producer that is authorized for a name can
  force a reissue on every run (`renewBeforeDays` near 365) or an
  expensive key type. This is a cost/rate-limit lever within an already
  authorized scope, not an escalation; bounding both in
  `RunnerAuthorizationPolicy` is a candidate for Phase 2.
- **No replay/expiry enforcement yet (T3).** `RunID` and `target.revision`
  exist in the contract, but nothing currently checks them against a run
  registry — there is no run registry yet.
- **No concurrency control yet (T7).** There is still no scheduler,
  launcher, or run registry: nothing outside the Runner itself prevents
  two `reconcile` invocations for the same target from running at once.
  A Phase 1 Runner runtime now exists, which sharpens this specific
  residual risk rather than removing it: two Runner processes for the
  same target both talk to the CA (double issuance, rate-limit cost) and
  both register or refresh account state. Publishing account state and
  writing the filesystem store are serialized by advisory locks (last
  writer wins; readers hold the lock shared), so neither is corrupted,
  but the duplicate work is not prevented. Per-target mutual exclusion across runs is Phase 2 work
  (the Conductor's run registry/scheduler).
- **The filesystem Certificate Store is dev/test only.** The only Store
  implementation shipped so far (`internal/store/filesystem`) has no
  access control beyond filesystem permissions and is not a production
  secrets store; it exists to make Phase 1 runnable end-to-end without a
  cloud dependency. A production-grade store (Azure Key Vault) is Phase 3.
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
  allows. Real workload-identity provisioning is Phase 3/4 work.
- **The secret-marker heuristic is not a secret detector (T6).** It cannot
  detect an arbitrary or unknown-format secret; it is defense-in-depth on
  top of the Phase 1 Runner behavior of never copying raw external output
  into a `Result` at all.
- **No log-scrubbing test suite across the codebase.** T6's mitigations
  cover the `Result` document (code-enforced) and `lego`'s own
  stdout/stderr (code-enforced, value-based redaction) but not every log
  statement elsewhere in the codebase; that relies on code review and the
  per-PR checklist until a dedicated test exists (Phase 2+).
- **No SBOM/provenance, no digest pinning at build time.** T8 is partially
  mitigated (govulncheck, pinned Go toolchain by tag, distroless runtime);
  digest pinning and SBOM/provenance are explicitly Phase 5 work.
- **No REST API exists yet**, so the Administrator/UI trust boundary in the
  diagram above is aspirational — there is nothing to attack there today,
  but there is also no authentication or authorization design finalized
  beyond "localhost-only dev auth" for the Phase 2 MVP.

## See also

- [Architecture](architecture.md)
- [Architecture Decision Records](adr/README.md)
