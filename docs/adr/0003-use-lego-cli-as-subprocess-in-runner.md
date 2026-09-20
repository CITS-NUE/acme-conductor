# 0003: Use the lego CLI as a subprocess in the Runner

- Status: Accepted
- Date: 2026-09-20

## Context

The Runner needs to perform the ACME protocol (account registration,
DNS-01 challenge, certificate issuance/renewal) against a wide range of DNS
providers. [go-acme/lego](https://github.com/go-acme/lego) already
implements this, is widely used, is actively maintained, and ships both a
Go library and an official CLI binary. ACME Conductor's stated purpose is
to be a certificate-management *control plane*, not a new ACME client or a
new set of DNS provider integrations (see
[non-goals](../architecture.md#non-goals)).

Two integration shapes were available: import `lego` as a Go library
inside `acme-runner`, or invoke the official `lego` CLI binary as a
subprocess. There is also the question of *how* to invoke it: build a
command string and hand it to a shell, or build an explicit argument
vector (`argv`) and exec it directly.

## Decision

The Runner invokes the official, version-pinned `lego` CLI binary as a
subprocess, once per run, with an explicit argument vector built
programmatically from the validated `JobSpec`. It is never invoked through
a shell string (`sh -c "..."` or equivalent), and the Runner never
constructs command text from untrusted input.

We use the **CLI**, not the **library**, for now:

- The CLI is the artifact upstream actually releases, version-tags, and
  documents as their supported entry point; pinning a specific CLI release
  gives a clear, auditable version boundary (see
  [ADR 0007](0007-container-baseline.md) on how that pin is fetched and
  verified) that a library dependency pinned in `go.mod` would blur (a
  `go.mod` pin tracks a commit of a library, not a release the `lego`
  project itself declares stable for third-party use in this way).
  A future ADR can revisit the library integration if the subprocess
  boundary turns out to cost more (in startup latency or output-parsing
  fragility) than it is worth.
- A subprocess boundary is also a natural place to enforce "the Runner
  never runs a shell, never accepts a caller-supplied command, image, or
  executable path" (see [`docs/threat-model.md`](../threat-model.md), T2):
  the argument vector is built entirely from validated, typed `JobSpec`
  fields (a normalized FQDN, a bounded key type enum, resolved binding
  configuration), never from a raw string the caller supplied.

We do **not** reimplement ACME or any DNS provider ourselves: that
functionality, and its correctness and security properties, stays owned by
upstream `lego`.

## Consequences

- Certificate issuance correctness and DNS provider coverage track
  upstream `lego` directly; ACME Conductor does not need to keep its own
  ACME state machine or DNS provider list up to date.
- The Runner image bundles a specific `lego` release (Phase 1), fetched and
  checksum-verified at image build time, not resolved at runtime — so the
  exact `lego` version in a given Runner image is pinned and reproducible.
- Parsing `lego`'s CLI output/exit codes into the `Result` contract's fixed
  error taxonomy (`ErrorCode`) is Runner-side integration work and a
  potential source of drift if `lego`'s CLI output format changes across
  releases; this is a cost accepted in exchange for the version-boundary
  clarity above.
- Because invocation is always `argv`, never a shell string, there is no
  shell-metacharacter injection surface between the `JobSpec` and the
  subprocess, by construction — this is enforced by code shape, not by
  escaping.
