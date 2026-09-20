# Threat Model

This document covers the ACME Conductor system as designed in
[`docs/architecture.md`](architecture.md). It is written and maintained
alongside the code; **Phase 0** implements only the versioned JobSpec/Result
contract, FQDN normalization and CI, so most mitigations below describe
where a control lands once its phase ships, not what exists today. The
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
| T1 | Conductor compromise | An attacker gains code execution or database access on the Conductor. | Attacker can create/modify `Target`s and `CertificatePolicy`, submit arbitrary jobs, or read audit data — but **cannot** obtain private keys, DNS credentials, or Store credentials, because the Conductor never holds them. `JobSpec.Validate` only checks that a document is internally self-consistent (T5), so a compromised Conductor can produce a self-consistent `JobSpec` for any FQDN and any registered binding name; nothing on the Runner side bounds that today beyond the document's shape. | Principle 1/2/5 (no secrets, no DNS/Store credential, separate identity from Runner); closed schema, strict decoding and well-formed logical binding names only (T2/T5) constrain what a compromised Conductor can even express, not what it may cause to be issued; append-only audit log for detection; SQLite behind a `Registry` interface so a compromise is contained to one process/host (no multi-replica blast radius in the MVP). **Planned**: a Runner-side `policy.RunnerAuthorizationPolicy`, loaded from trusted administrator configuration and never from the JobSpec, bounds issuance regardless of JobSpec content (Phase 1); an authenticated `JobSpec` with expiry/nonce narrows the window further (Phase 4). | Existing (principles, contract, shape-only limits); Runner authorization Phase 1; registry/audit implementation Phase 2 |
| T2 | JobSpec tampering in transit or at rest | A `JobSpec` is modified between production by the Conductor and consumption by the Runner (e.g. a compromised launcher, a tampered queue message, a modified file). | A tampered `JobSpec` could redirect issuance to an unauthorized FQDN, point at a different binding, or otherwise escape the policy the Conductor intended. | Strict decoding (`pkg/api/v1alpha1/decode.go`: unknown fields, duplicate keys, trailing data, 64 KiB cap all rejected) limits the *shape* of a tampered document only. A tampered document that remains self-consistent — `target.fqdn` and the embedded `policy` snapshot changed together, or one registered binding name swapped for another well-formed registered binding name — passes `Validate` unchanged (T5); `Validate` cannot detect that kind of tampering by itself, so today's mitigation is shape-only. **Planned**: a Runner-side `RunnerAuthorizationPolicy`, evaluated against trusted configuration that is not part of the document, bounds issuance independently of anything a tampered `JobSpec` claims (Phase 1); a signed/authenticated `JobSpec` envelope with expiry (Phase 4) detects tampering in transit — but signing addresses tampering, not a compromised producer legitimately emitting a bad document in the first place (see T1). | Existing (decoding limits shape only); Runner authorization Phase 1; signed envelope Phase 4 |
| T3 | JobSpec replay and expiry | An old, previously-valid `JobSpec` is re-submitted (e.g. replayed from a log, a retried queue message, or a captured artifact) after the `Target` it names has since changed or been disabled. | Certificate issuance or renewal against stale policy or a disabled target; potential double execution when combined with T7. | **Planned**: a signed envelope around the `JobSpec` carrying `issuedAt`/`expiresAt` and a `nonce`, checked by the Runner against the run registry before it does anything (a `runId` that is not `queued`/`starting` in the registry, or whose `expiresAt` has passed, is refused). The `target.revision` field already lets a `Result` be matched to the exact target state a job was produced for, which is the building block this check is layered on. | Planned, Phase 4 |
| T4 | DNS permission abuse | The Runner's DNS credential/workload identity is used (by a compromised Runner, or by DNS-provider-side misconfiguration) to write records outside the one zone the current run needs. | Ability to complete ACME challenges for FQDNs outside the intended scope, or to otherwise tamper with DNS beyond the TXT challenge record. | The Runner's DNS-side workload identity is provisioned per `DnsBinding` and is expected to be scoped by the administrator who registers that binding to the challenge zone and TXT records only — never zone-wide or account-wide DNS write. This scoping is an operational requirement on how each `DnsBinding` is provisioned, not something the JobSpec contract can enforce by itself. | Binding model exists (Phase 0); real DNS credentials wired Phase 1+ |
| T5 | FQDN policy bypass | An attacker crafts an FQDN or suffix list to slip past the intended policy: mismatched label boundaries, case differences, a trailing dot, an IDNA/punycode label, an unintended wildcard, or a duplicate JSON key that causes two validators to disagree on which value "wins". | Certificate issued for a domain the operator did not intend to authorize (e.g. `evil-example.ac.jp` treated as under `example.ac.jp`). | **Validation** (implemented, both sides of the boundary): `internal/policy/fqdn.go` normalizes before comparing (lower-case, single trailing dot stripped, ASCII-only) and matches suffixes on whole label boundaries only (`MatchesSuffix`), so `evil-example.ac.jp` is correctly rejected against the suffix `example.ac.jp`. `xn--` (IDNA A-label) input is rejected outright rather than silently accepted (see ADR 0006). Wildcards are accepted only as the whole left-most label. `pkg/api/v1alpha1/decode.go` rejects duplicate JSON keys before any validator sees the document, closing the classic "two parsers disagree" bypass. `JobSpec.Validate` checks that `target.fqdn` is consistent with the `policy` snapshot embedded in the same document — this is a self-consistency check of untrusted input, never authorization (see the doc comment on `JobSpec.Validate` and `TestJobSpecValidateIsSelfConsistencyNotAuthorization`). **Authorization** (decision function implemented; not yet wired): `internal/policy.RunnerAuthorizationPolicy.Authorize` decides, against a trusted allowed-suffix/wildcard/binding-name configuration that is loaded on the execution platform and never taken from the JobSpec, whether the Runner may act at all. Loading that configuration and calling it from the Runner is Phase 1 work; until it lands, nothing independently bounds a JobSpec beyond the self-consistency check above (see T1, T2). | Validation existing (`internal/policy`, decode/validate); authorization decision function existing (`internal/policy/authorize.go`), Runner wiring Phase 1 |
| T6 | Secret leakage into logs/results/errors | A credential, private key, EAB HMAC, access token, or temporary PFX password ends up in a log line, a `Result.error.summary`, or an exception message. | Credential compromise even without direct access to the Conductor or Runner process — e.g. via log aggregation, error trackers, or a leaked `Result` document. | `validate.go`'s `validateOpaqueText` rejects non-printable characters (control characters, Unicode line/paragraph separators, bidi/format characters) and a case-insensitive-where-meaningful set of secret markers (`-----BEGIN`, `private key`, `eyJ` JWT/JWS/EAB-shaped base64, `AKIA`, `ghp_`, `github_pat_`, `bearer `, `basic `, `authorization:`, `password=`, `secret=`, `token=`, `sig=`, `key=`, and similar) in any `Result` free-text field. This is a **defense-in-depth heuristic, not a secret detector**: it catches common accidental leaks by known shape but cannot recognize an arbitrary secret or an unknown format. `storeObjectRef` is now a strict logical name (`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`, max 128, `..` rejected) — never a URL, path, query string, or credential-bearing value. `ResultError` is a fixed machine code plus a short summary — never a raw error, command line, or environment dump, by field shape alone. **Planned real control** (Phase 1): the Runner never copies raw external command/SDK errors, stdout, or stderr into a `Result`; `error.summary` is generated only from Runner-owned safe templates; raw external details go to redacted internal logs only; `error.code` is the primary machine-readable signal for API consumers. Structured JSON logging rules require `runId`/`targetId` on every line and forbid credentials, private keys, and the ACME EAB HMAC by policy. | Existing (Result field validation, marker heuristic); template-based safe error translation Phase 1; log redaction tests Phase 2+ |
| T7 | Double execution / concurrent reconcile of the same target | Two `Run`s for the same `Target` execute concurrently (e.g. a retried scheduler tick, a re-delivered queue message, or an operator manually triggering a run while one is already in flight). | Wasted ACME rate-limit budget, racing writes to the Certificate Store, or two Runners fighting over the same DNS TXT record. | **Planned**: per-target mutual exclusion in the scheduler/launcher, an idempotency key derived from `(targetId, targetRevision)`, and optimistic locking on `Target.revision` so a stale `JobSpec` cannot be actioned against a target that has since moved on. | Planned, Phase 2 |
| T8 | Supply chain | A malicious or vulnerable dependency, base image, GitHub Action, or `lego` release is pulled into a build. | Compromised build output; a vulnerable component shipped in a released image. | `lego` is pinned to a specific, version-checked release (Phase 1) rather than "latest". Both Dockerfiles build from `golang:1.24-bookworm`, and are documented to switch to a digest-pinned base image at release time; runtime images are `gcr.io/distroless/static-debian12:nonroot` (minimal attack surface, no shell). CI runs `govulncheck` on every push/PR (`.github/workflows/ci.yml`). Deployments are required to pin images by commit SHA or digest, never `latest`. SBOM and provenance generation land in Phase 5. | Partial now (govulncheck, distroless, CGO disabled); digest pinning and SBOM/provenance Phase 5 |
| T9 | Denial of service via oversized/hostile documents | A very large or deeply-nested `JobSpec`/`Result` document is submitted to exhaust memory or CPU during decoding. | Resource exhaustion on the Conductor or Runner. | `decodeStrict` reads through an `io.LimitReader` capped at `MaxDocumentSize` (64 KiB) and rejects anything larger before decoding. The size cap alone does not bound CPU: a 64 KiB document of nothing but nested brackets can make a naive recursive walker superlinear. The duplicate-key walker therefore also enforces `MaxNestingDepth` (8 levels; the contract needs 3) and renders diagnostic paths only on error, so the cost of any accepted-size document is linear in its length (`TestDecodeRejectsDeepNestingQuickly`). | Existing (`pkg/api/v1alpha1/decode.go`) |
| T10 | Privilege separation failure between Conductor and Runner identities | The Conductor is accidentally granted DNS write, Certificate Store read, or other Runner-scoped permissions (e.g. through shared service-principal reuse or overly broad IAM at deployment time), collapsing the intended separation. | A Conductor compromise (T1) escalates to full DNS/Store compromise instead of being contained. | Principle 5 is a deployment-time requirement as much as a code-time one: Conductor and Runner identities must be provisioned separately, with the Conductor's identity granted neither DNS write nor Store read. Azure resources are declared in Bicep (Phase 4), not created ad hoc from code, so the IAM grants for each identity are reviewable, versioned artifacts rather than one-off console changes. | Principle established now; enforced in infra from Phase 4 |
| T11 | Disable vs purge confusion | An operator (or a bug) treats "disable" as if it deletes data, or conversely expects "disable" to also revoke/destroy the certificate. | Either a false sense that sensitive history has been removed, or an unexpected loss of audit trail / certificate availability. | There is no purge operation in the MVP at all (see [ADR 0008](adr/0008-no-purge-in-mvp.md)): `Target.enabled = false` stops future issuance/renewal but leaves the `Target`, its `Run` history, and its `AuditEvent`s intact. A future purge is scoped to be a separate, explicitly audited operation, never a side effect of disable. | Existing as a design decision; `enabled` field implemented Phase 2 |
| T12 | Production CA misuse from tests | An automated test accidentally issues a real certificate against a production ACME CA (e.g. Let's Encrypt production), burning rate limits or leaving orphaned certificates. | Rate-limit exhaustion affecting real issuance; unintended public certificates for test domains. | Principle 8: production ACME CAs are never called from automated tests. Test fixtures and CI use a local/staging ACME server (`pebble` or the ACME staging directory) exclusively; this is a per-PR review checklist item (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)). | Principle established now; enforced by test-harness setup from Phase 1 |

## Assurance levels

A single "is it secure" question does not fit this system; these three
lists say precisely what today's Phase 0 code guarantees, what it does not,
and what closes the gap.

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

**Not guaranteed today:**

- That the entity that produced a `JobSpec` is legitimate.
- That the `policy` snapshot embedded in a `JobSpec` is trustworthy.
- That issuance scope is bounded when the Conductor itself is compromised.
- Replay prevention (an old, previously-valid `JobSpec` being rejected).
- Complete detection of arbitrary secrets by the `error.summary` marker
  check — it is a heuristic for known shapes, not a secret detector.
- Removal of secrets from all log output across the codebase.

**Planned:**

- Runner-side trusted authorization policy
  (`policy.RunnerAuthorizationPolicy`, Phase 1).
- ACME/DNS/Store binding allow-lists enforced from trusted configuration
  (Phase 1, part of the same policy).
- Safe error translation that never forwards raw external errors, stdout,
  or stderr into a `Result` (Phase 1).
- `JobSpec` authentication, integrity, and expiry (Phase 4).
- Log redaction tests (Phase 2+).

## Residual risks / not yet mitigated

Phase 0 has shipped the contract, the FQDN policy engine, and CI — no
runtime exists yet. Being explicit about what that means:

- **No Runner-side authorization wired yet (T1, T2, T5).** The decision
  function (`policy.RunnerAuthorizationPolicy.Authorize`) exists and is
  tested, but nothing loads trusted configuration or calls it from a
  Runner yet — there is no Runner runtime in Phase 0. Until Phase 1 wires
  it in, the only control on a `JobSpec`'s content is `Validate`'s
  self-consistency check, which a compromised or malicious producer of the
  document can satisfy for any FQDN or registered binding name.
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
- **No replay/expiry enforcement yet (T3).** `RunID` and `target.revision`
  exist in the contract, but nothing currently checks them against a run
  registry — there is no run registry yet.
- **No concurrency control yet (T7).** There is no scheduler, launcher, or
  run registry in Phase 0, so nothing prevents double execution because
  there is no execution.
- **No real DNS, ACME, or Store credentials exist yet.** T4 and T10 are
  currently design commitments, not enforced permissions, because no
  binding is wired to a real credential or workload identity until Phase
  1/3/4.
- **The secret-marker heuristic is not a secret detector (T6).** It cannot
  detect an arbitrary or unknown-format secret; it is defense-in-depth on
  top of the Phase 1 plan of never copying raw external output into a
  `Result` at all.
- **No log-scrubbing test.** T6's mitigation covers the `Result` document
  (code-enforced) but not arbitrary log statements elsewhere in the
  codebase; that relies on code review and the per-PR checklist until a
  dedicated test exists.
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
