# Security Policy

## Supported versions

ACME Conductor has not made a versioned release yet (see
[`docs/architecture.md`](docs/architecture.md#roadmap): only Phase 0 is
implemented). Until a `v1` release exists, only the `main` branch is
supported and receives security fixes; there is no older version to
report against.

## Reporting a vulnerability

Please report suspected security vulnerabilities using **GitHub private
vulnerability reporting** on this repository:
[CITS-NUE/acme-conductor](https://github.com/CITS-NUE/acme-conductor) →
**Security** tab → **Report a vulnerability**. This opens a private
advisory visible only to maintainers, so the report does not need to go
through a public issue.

Do not open a public issue for a suspected vulnerability, and do not post
it in a public discussion channel.

## Response expectations

This is a young, actively-developed project without a dedicated security
team or a formal SLA. As a working expectation: an initial acknowledgement
within a few business days, and a plan for a fix (or an explanation of why
the report is out of scope) as soon as the maintainers have had a chance to
triage it. Given the project's current stage — Phase 0, not yet used to
issue real certificates — response times are best-effort.

## Scope

In scope (things that count as a security bug in this project):

- **FQDN / policy bypass** — any input that causes a certificate to be
  considered authorized for an FQDN it should not be (label-boundary
  matching, normalization, wildcard, or IDNA-related bypasses).
- **Secret leakage** — a private key, DNS/Key Vault/cloud credential, ACME
  EAB HMAC, access token, or temporary PFX password appearing anywhere it
  should not: in a `Result`, in a log line, in an error message, or in the
  Conductor's database.
- **Identity separation breaks** — anything that lets the Conductor obtain
  DNS write access, Certificate Store read access, or otherwise act with
  Runner-scoped privilege, or that lets one Runner execution's identity be
  used beyond the single run/binding it was granted for.
- **JobSpec/Result contract bypasses** — strict-decoding bypasses (unknown
  fields, duplicate keys, oversized documents being accepted), or a
  `JobSpec`/`Result` that should be rejected being accepted instead.
- **Supply-chain issues** — a vulnerable or tampered dependency, base
  image, or pinned `lego` release shipped in a released artifact.
- **Container/runtime hardening regressions** — for example a released
  image running as root, with a writable root filesystem where one is not
  needed, or with `latest`/an unpinned tag deployed.

## Out of scope

- Findings that require the reporter to already have Conductor or Runner
  administrator access (issues that only matter once you already control
  the system are still welcome as a regular issue, just not as a security
  advisory unless they demonstrate a privilege escalation beyond what that
  access should grant).
- Issues in third-party dependencies with no ACME-Conductor-specific
  impact (please report those upstream; we do still want to know if a
  vulnerable version is pinned here — that is in scope as a supply-chain
  issue above).
- Social engineering, physical access, or denial-of-service against
  infrastructure ACME Conductor does not control.
- Missing security hardening in a phase that has not shipped yet (check
  [`docs/threat-model.md`](docs/threat-model.md#residual-risks--not-yet-mitigated)
  first — several controls are explicitly planned for a later phase and
  are tracked there, not hidden).

## Disclosure policy

We ask reporters to give us a reasonable opportunity to investigate and fix
a reported issue before any public disclosure. We will credit reporters
(unless they prefer to remain anonymous) once a fix is available. As the
project has no released version yet, coordinated disclosure timing will be
worked out directly with the reporter through the private advisory.

## Security invariants we consider bugs if violated

These come directly from the project's design (see
[`docs/architecture.md`](docs/architecture.md#security-principles) and
[`docs/threat-model.md`](docs/threat-model.md)). Any code change that
violates one of these is a bug, regardless of whether a test currently
catches it:

- No private key, certificate body, PFX, or cloud credential column exists
  in the Conductor's database.
- No Conductor API endpoint returns a private key.
- No Runner `Result` contains a private key, certificate body, or
  credential.
- The Runner stays one-shot: no HTTP server, no cron, no long-running
  listener.
- The Conductor being down never prevents an already-scheduled Runner job
  from running to completion.
- Deployed images are pinned by commit SHA or digest, never by the
  `latest` tag.
- Cloud SDKs live only in launcher/store adapter implementations, never in
  Conductor core.
- Azure (and any future cloud) resources are declared in Bicep, never
  created ad hoc from application code.
- FQDN policy is validated by the Conductor when it accepts a `Target`/
  `CertificatePolicy`, and the Runner both validates the `JobSpec`
  document it receives (self-consistency) and authorizes it against its
  own trusted policy (`policy.RunnerAuthorizationPolicy`) before acting —
  see `docs/architecture.md`'s "Validation vs. authorization".
- `JobSpec`/`Result` documents are strictly decoded: unknown fields,
  duplicate keys, and trailing data are always rejected.
- Production ACME certificate authorities are never called from automated
  tests.
