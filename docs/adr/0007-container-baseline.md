# 0007: Container baseline

- Status: Accepted
- Date: 2026-09-20

## Context

Both `acme-conductor` and `acme-runner` ship as container images
(`ghcr.io/cits-nue/acme-conductor`, `ghcr.io/cits-nue/acme-runner`). The
Runner in particular briefly holds private key material during a run (see
[ADR 0005](0005-conductor-never-touches-secrets.md)), so the runtime
environment it executes in is itself part of the system's security
posture, not just a packaging detail.

## Decision

Both images share a common baseline (`Dockerfile.conductor`,
`Dockerfile.runner`):

- **Distroless, static, non-root.** The runtime stage is
  `gcr.io/distroless/static-debian12:nonroot` — no shell, no package
  manager, no OS userland beyond what the static Go binary needs. The
  process runs as uid/gid `65532` (`nonroot:nonroot`), set explicitly in
  the Dockerfile even though it is already the base image's default, so
  the intent survives a future base-image change.
- **Read-only root filesystem.** Neither binary writes to its own
  filesystem at startup, so both images are safe to run with
  `--read-only` / Kubernetes `readOnlyRootFilesystem: true`. The Runner's
  future scratch space and certificate staging area (Phase 1+) are
  supplied by the caller as a writable tmpfs/emptyDir mount, not baked
  into the image; no `VOLUME` is declared, since a `VOLUME` instruction
  would create anonymous volumes on every `docker run`, which is not
  wanted.
- **No `latest` tag in deployment.** CI builds and smoke-tests images
  tagged `:ci`/local development tags only; it never pushes to the
  registry. Deployments are required to pin images by commit SHA or digest
  — `latest` (or any other floating tag) is never an acceptable deployment
  reference.
- **Digest pinning of the base image at release time.** The builder stage
  currently pins `golang:1.24-bookworm` by tag for Phase 0 development
  velocity; a release build pins the same base image by digest
  (`golang:1.24-bookworm@sha256:<digest>`) instead, so a released image's
  build is fully reproducible and immune to a tag being silently
  repointed. This pinning is done at release time, not in the
  Phase-0-era Dockerfile itself.
- **Version via ldflags, not baked at COPY time.** `VERSION`, `COMMIT`, and
  `BUILD_DATE` build args are injected into `internal/version` via
  `-ldflags -X ...` at compile time (mirrored in `Makefile`'s `LDFLAGS`),
  so the same source tree produces a differently self-identifying binary
  per build without needing a separate source change, and `--version`
  always reports the exact commit an image was built from.

## Consequences

- The runtime attack surface of both images is minimal: no shell means no
  interactive foothold even if a container is somehow gained access to,
  and a read-only root filesystem means no on-disk persistence within the
  container across a restart.
- Running as a fixed non-root uid (`65532`) is required by any deployment
  target that enforces `runAsNonRoot`, and is already the CI smoke test's
  assumption (`docker run --read-only --user 65532:65532 ... --version`).
- Digest pinning at release time (rather than in every Phase-0 commit)
  keeps day-to-day development friction-free while still giving released
  artifacts a fully reproducible, tamper-evident base image reference;
  this tradeoff is revisited if Phase 0's tag-pinned builder stage ever
  causes a build to silently pick up an unwanted base image change.
- Because the Runner needs a writable scratch area at runtime despite a
  read-only root filesystem, every deployment target (local `docker run`,
  Azure Container Apps Job from Phase 4, etc.) must supply that mount
  explicitly; this is documented per-launcher as launchers are added,
  rather than assumed.
