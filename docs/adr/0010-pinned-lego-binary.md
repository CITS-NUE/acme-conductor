# 0010: Pinned lego binary

- Status: Accepted
- Date: 2026-09-20

## Context

[ADR 0003](0003-use-lego-cli-as-subprocess-in-runner.md) decided the
Runner invokes the official `lego` CLI as a subprocess rather than
importing it as a Go library, specifically because a release artifact
gives "a clear, auditable version boundary" that a `go.mod` pin of a
library commit would blur. That boundary is only real if the exact bytes
of the `lego` binary that end up in a Runner image are pinned and
verified at build time, not resolved from a mutable tag or fetched
unverified at container start.

## Decision

`Dockerfile.runner` fetches the official, pre-built `lego` release
artifact from its GitHub release and verifies it against a pinned SHA-256
checksum **before it is ever extracted or run**, in a dedicated build
stage:

- `LEGO_VERSION` (currently `4.35.2`) and per-architecture checksums
  `LEGO_SHA256_AMD64` / `LEGO_SHA256_ARM64` are Dockerfile build `ARG`s.
- The stage downloads
  `lego_v${LEGO_VERSION}_linux_${arch}.tar.gz` over HTTPS
  (`--proto '=https' --tlsv1.2`) from
  `https://github.com/go-acme/lego/releases/download/...`, then runs
  `sha256sum -c` against the pinned checksum for the resolved
  `TARGETARCH`. The build fails outright if the checksum does not match.
- Only after that check does the stage extract the single `lego` binary
  from the archive and `chmod` it `0755`.
- This build stage reuses the `golang:1.24-bookworm` image already used
  as the Go builder (it already has `curl` and `tar`), rather than pulling
  in another base image just for this fetch.
- The final runtime stage (`gcr.io/distroless/static-debian12:nonroot`,
  see [ADR 0007](0007-container-baseline.md)) only ever `COPY`s the
  already-verified binary in from that stage, at
  `/usr/local/bin/lego`; it never contains `curl`, `tar`, or any other
  fetching capability.
- The image is labeled `io.acme-conductor.lego.version` with the pinned
  version, so `docker inspect` on a built image reports exactly which
  `lego` release it bundles without needing to run the binary.

### Bumping the version

Bumping `lego` means changing `LEGO_VERSION` **and** both
`LEGO_SHA256_AMD64`/`LEGO_SHA256_ARM64` in `Dockerfile.runner` to the new
release's published checksums, in the same commit. CI
(`.github/workflows/ci.yml`) builds this Dockerfile on every push and pull
request, so a stale, missing, or wrong checksum for either architecture
fails CI immediately — not silently at deploy time or, worse, not at all
until an operator notices the wrong binary shipped.

## Alternatives considered

- **Build `lego` from source in the builder stage.** Rejected: it would
  add real build time and a much larger dependency surface (`lego`'s own
  module graph) to every Runner image build, and it blurs exactly the
  version boundary ADR 0003 was written to keep clear — "the Runner
  bundles `lego` vX.Y.Z" should mean the same release artifact upstream
  tags and publishes, not a local rebuild of that tag's source that could
  drift for reasons upstream's own release process does not control
  (toolchain differences, build tag differences, and so on).
- **Fetch the release tarball at container start or at runtime instead of
  at image build time.** Rejected on two grounds: it defers the integrity
  check past build time, so a bad or compromised fetch would only be
  caught (if at all) by whatever runs the container, not by CI; and it
  requires network egress from a running container purely to bootstrap
  itself, which sits awkwardly next to the rest of the Runner's posture
  (its only expected egress is to the DNS provider, the Certificate
  Store, and the ACME CA for the one binding it was launched with). It
  would also break the "same Dockerfile + build args always yield the
  same image" reproducibility property the checksum-verified build-time
  fetch gives for free.
- **Track `lego`'s `latest` release automatically (e.g. a bot that bumps
  the pin on every upstream release).** Not adopted for Phase 1: an
  automatic bump would still need to pass CI's checksum-and-build gate, so
  it is compatible with this design later, but Phase 1 keeps the bump a
  deliberate, reviewed PR like any other dependency version change.

## Consequences

- A Runner image is fully reproducible: the same `Dockerfile.runner` plus
  the same build args always produces the same `lego` binary bytes,
  independent of when or where the image is built.
- Bumping `lego` is an explicit, auditable change (a diff to two or three
  `ARG` lines) rather than an implicit one; a security fix in `lego`
  requires that PR before it reaches a built image — there is no
  automatic pickup.
- If GitHub's release asset for a pinned version ever became unavailable,
  the build would fail closed (the `curl --fail` and the `sha256sum -c`
  both fail loudly) rather than silently falling back to something else.
- The checksum pin is per-architecture; adding a new target architecture
  requires adding both a `case` arm in the fetch script and a new
  `LEGO_SHA256_<ARCH>` build arg — this is a deliberate small piece of
  friction so an unpinned architecture can never silently be shipped
  unverified.
