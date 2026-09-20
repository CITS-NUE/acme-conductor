# 0005: Conductor never touches secrets

- Status: Accepted
- Date: 2026-09-20

## Context

A single compromised process holding certificate private keys, DNS write
credentials, and Certificate Store credentials all at once would be a
catastrophic single point of failure — one bug anywhere in a large,
long-running, network-facing control plane would be enough to leak every
secret in the system. ACME Conductor's control plane (`acme-conductor`) is
exactly that kind of process: long-running, reachable by a UI/API, and the
most likely first target of compromise (see
[`docs/threat-model.md`](../threat-model.md), T1).

## Decision

The Conductor is architecturally prevented from ever holding certificate
private keys or any long-lived cloud/DNS/Key Vault credential:

- **Identity separation.** The Conductor and the Runner run under separate
  identities. The Conductor's identity is granted no DNS write permission
  and no Certificate Store read permission, ever.
- **No secret columns.** The Conductor's database schema (`Target`,
  `CertificatePolicy`, `Run`, `AuditEvent`) has no column for a private
  key, a certificate body, a PFX blob, or a cloud credential. If a table
  would need one, that is a sign the design is wrong, not a sign a column
  should be added.
- **No key-bearing API endpoint.** No Conductor API endpoint returns a
  private key, ever — there is nothing to leak through an
  authorization bug at the API layer, because the data simply is not
  there.
- **Private keys are Runner-only and transient.** Private keys are
  generated in the Runner's temporary area, written directly into the
  external Certificate Store, and then destroyed. They exist only for the
  duration of one Runner execution and never transit through the
  Conductor, the `JobSpec`, or the `Result`.
- **Workload identity, not static secrets, on the Runner side.** The Runner
  authenticates to DNS providers and the Certificate Store using the
  execution platform's workload identity (Azure Managed Identity today's
  target, with AWS IAM Role / GCP Service Account as the pattern for any
  future platform) rather than a credential baked into configuration.

## Consequences

- A full compromise of the Conductor process or its database yields no
  private key, no DNS credential, and no Store credential — the blast
  radius of the most likely compromise target is deliberately limited to
  "can request issuance jobs," not "can exfiltrate every certificate the
  system manages." Requesting a job is not itself bounded by this ADR: a
  compromised Conductor can produce any self-consistent `JobSpec`, and it
  is the Runner-side trusted authorization policy (Phase 1; see
  `docs/threat-model.md`, T1) — not this identity-and-secrets separation —
  that is meant to bound what such a job can actually cause to be issued.
- This rules out several conveniences a simpler design might have: the
  Conductor cannot show a certificate's private key or PFX in a UI, cannot
  back up key material as part of its own database backup, and cannot
  itself renew a certificate without going through a Runner execution.
  These are accepted costs.
- Enforcing this is partly a database-schema review concern (no secret
  columns, checked per PR — see the checklist in
  [`CONTRIBUTING.md`](../../CONTRIBUTING.md)) and partly a deployment/IAM
  concern (the Conductor's actual granted permissions have to match this
  decision, not just its code) — see
  [`docs/threat-model.md`](../threat-model.md), T10.
