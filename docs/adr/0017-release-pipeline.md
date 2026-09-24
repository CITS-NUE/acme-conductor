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

- **A version tag on `main` is a release, and CI gates it.** `release.yml`
  runs on a `v*.*.*` tag, first as the CI workflow itself
  (`workflow_call`) and, in parallel, as a check that the tagged commit
  is in the history of `origin/main` (`git merge-base --is-ancestor`,
  on a full clone); a tag on any other commit publishes nothing, so a
  feature branch cannot be released by tagging it, whatever the
  repository's tag rules say. Only then does it build and push `ghcr.io/cits-nue/acme-conductor` and
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
- The `main` check is enforced in the workflow, where the invariant is
  reviewed with the code; a repository ruleset restricting who may
  create `v*` tags is a second layer an administrator can add, not a
  substitute. The check is `scripts/release-guard.sh`, and the
  dispatch-only workflow `release-guard-check.yml` runs the same script
  against any ref with an expected outcome, so both the positive case
  (a `main` commit passes) and the negative case (a branch commit is
  refused) can be verified on demand without a tag and without a
  publish. A version tag on a branch is never the way to test it: that
  runs the real release workflow.
- The pipeline was verified by the first release, `v0.5.0`
  (2026-09-24, [issue #19](https://github.com/CITS-NUE/acme-conductor/issues/19)).
  Observed as designed: the guard passed for a tag on `main` and, in
  the dispatch-only check, refused a branch commit; both images were
  published for `linux/amd64` and `linux/arm64` with an SPDX SBOM and
  SLSA provenance attestation manifest per platform in the index; the
  GitHub attestation was created, recorded in Rekor, pushed to the
  registry under a `sha256-<digest>` tag, and verified with
  `gh attestation verify`; the images ran by digest and reported the
  tag. Observed and not designed: (1) GitHub created both packages
  **private** on the first push, whatever the repository's visibility,
  so anonymous pulls and `gh attestation verify` against the registry
  failed until an organization owner set them public, a one-time step
  per package that the workflow cannot perform; (2) the first tag,
  pushed before a date-dependent test fix reached `main`, failed the
  CI gate and published nothing, exactly the property the gate exists
  for, and the tag was deleted and re-created on the fixed commit.
- Rollback of a release is deleting or re-tagging in GHCR by hand; a
  digest that was published stays valid and verifiable, so a deployer
  pinned to it is unaffected either way. A version tag is re-pointed
  only while nothing has been published under it (the image jobs were
  skipped); once an image carries the version, the next version is the
  only way forward.
