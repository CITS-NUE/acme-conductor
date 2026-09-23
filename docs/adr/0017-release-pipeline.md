# 0017: Release pipeline — GHCR images with SBOM and provenance, digest-pinned bases

- Status: Accepted
- Date: 2026-09-23

## Context

Until Phase 5 nothing published an image: CI built both Dockerfiles and
smoke-tested them, and a deployer built and pushed images by hand to a
registry of their choice. The threat model's supply-chain entry (T8) left
three things open for this phase: releases with an SBOM and provenance,
digest pinning of base images, and a canonical registry that
`deploy/azure` can pin digests from. Any release mechanism also has to
keep the property that a published image is exactly what CI verified.

## Decision

- **A version tag is a release, and CI gates it.** `release.yml` runs on
  a `v*.*.*` tag, first as the CI workflow itself (`workflow_call`), then
  builds and pushes `ghcr.io/cits-nue/acme-conductor` and
  `ghcr.io/cits-nue/acme-runner` for `linux/amd64` and `linux/arm64`,
  tagged `<major>.<minor>.<patch>`, `<major>.<minor>` and, for a
  non-prerelease, `latest`. The published image is smoke-tested by
  digest (`--version` must name the tag) and the digest is written to
  the run's summary, which is where a deployer copies it from.
- **Two attestations per image.** BuildKit attaches an SPDX SBOM and SLSA
  provenance (`mode=max`, including the build definition) to the image
  index in the registry; GitHub's artifact attestation adds a second,
  GitHub-signed provenance statement, pushed to the registry under the
  image digest and verifiable with `gh attestation verify
  oci://<image>:<tag> --owner CITS-NUE`. The registry copy is what a
  cluster-side policy can read; the GitHub statement is what an operator
  can verify from a workstation with nothing but the CLI.
- **Least permissions, no long-lived secret.** The job's token holds
  `packages: write`, `id-token: write` (for the signed attestation) and
  `attestations: write`; the CI workflow it calls holds `contents: read`.
  There is no registry credential to rotate.
- **Base images are pinned by digest in the Dockerfiles**, tag and digest
  side by side (`golang:1.25-bookworm@sha256:…`,
  `gcr.io/distroless/static-debian12:nonroot@sha256:…`), and Dependabot
  proposes updates to Docker bases, Go modules and GitHub Actions as
  pull requests that CI builds and tests. A mutable tag cannot silently
  change what a release is built from.
- **Actions stay pinned by major version tag for now.** Pinning them by
  commit digest is the stronger form; it was not done in this phase
  because the digests were not verified against the upstream
  repositories from where this change was made, and an unverified digest
  is worse than a tag. Dependabot keeps the tags current; switching to
  digests is a one-line-per-action follow-up that the same Dependabot
  configuration then maintains.

## Consequences

- `deploy/azure/main.bicepparam` pins image digests from a release, and
  the deploy README says how to verify a release before pinning it.
- A release is reproducible from its provenance: the workflow, the
  commit and the Dockerfile inputs are in the attestation; the SBOM lists
  what is in the image (both Go binaries' modules, the pinned `lego`
  binary, the distroless base).
- The pipeline is not verified by a run from this repository yet: it
  needs a tag on `main` and the repository's packages permission. Its
  first run is the verification, and the smoke test fails the release if
  the published image does not answer.
- Rollback of a release is deleting or re-tagging in GHCR by hand; a
  digest that was published stays valid and verifiable, so a deployer
  pinned to it is unaffected either way.
