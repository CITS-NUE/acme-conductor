# Contributing to ACME Conductor

Thanks for your interest in ACME Conductor. This project is early
(Phase 5 — see [`docs/architecture.md`](docs/architecture.md#roadmap)) and
its security properties depend on a strict, boundary-respecting design;
please read this document before opening a pull request.

## Workflow

- **One PR = one purpose.** A pull request does one coherent thing: a
  feature, a fix, a refactor, a docs update. Do not bundle unrelated
  changes.
- **Phases are separate PRs.** The [roadmap](docs/architecture.md#roadmap)
  defines a strict phase order (Phase 0 bootstrap → Phase 1 Runner →
  Phase 2 Conductor MVP → ...). Do not implement functionality from a
  later phase inside a PR scoped to an earlier one, even if it seems
  convenient — for example, do not add real DNS provider credentials or
  a REST API while Phase 0/1 is in flight. If a PR's scope turns out to
  need part of a later phase, say so in the PR description and split the
  work instead of expanding scope silently.
- **Do not implement beyond the requested phase.** If you are asked to
  implement Phase 1, implement Phase 1 — not a preview of Phase 2 or 3,
  even a small one. This keeps each PR reviewable against a fixed, known
  scope and keeps the phase boundaries in
  [`docs/architecture.md`](docs/architecture.md#roadmap) meaningful.

## Local checks

Run these before opening a PR (they also run in CI —
`.github/workflows/ci.yml`):

```sh
make verify    # gofmt check, go vet, go test, go test -race
make vulncheck # govulncheck against the module
make images    # build both container images and confirm they build cleanly
```

Changes under `deploy/azure` should also compile and lint with the Bicep
CLI (`bicep build deploy/azure/main.bicep`, `bicep lint
deploy/azure/main.bicep`); CI does not run it yet.

## Releases

A release is a version tag on `main` (`git tag v0.5.0 && git push origin
v0.5.0`). The release workflow (`.github/workflows/release.yml`) runs
the CI workflow and checks that the tagged commit is in `origin/main`'s
history (a tag on any other commit publishes nothing), then publishes
both images to GHCR for
`linux/amd64` and `linux/arm64` with an SBOM and provenance attached
([ADR 0017](docs/adr/0017-release-pipeline.md)); the image digests are
in the run's summary. Nothing is published from a branch or a pull
request. Dependabot proposes updates to the digest-pinned base images,
Go modules and GitHub Actions; treat those pull requests like any other
(CI must pass, read what changed).

## Coding rules

- **No inline script or third-party asset in the GUI.** The page is
  served under `default-src 'none'`; everything it renders goes through
  DOM methods (`textContent`, `createElement`), never through markup
  built from API data or the URL. A change that needs `unsafe-inline` or
  an external origin is a design change, not a tweak.
- **No secrets in logs, config, the database, or `Result` documents.**
  Credentials, private keys, the ACME EAB HMAC, access tokens, and
  temporary PFX passwords must never appear in a log line, a config file
  checked into the repo, a database column, or a `Result.error.summary` —
  see [`docs/threat-model.md`](docs/threat-model.md), T6.
- **No cloud SDK in Conductor core.** Azure/AWS/GCP SDK imports belong only
  in launcher and Certificate Store adapter implementations
  (`internal/store/keyvault` and `internal/conductor/launcher/acajob`
  today), never in `acme-conductor`'s core packages (Target Registry,
  Policy, Audit Log, Run Registry, Scheduler).
  Keep the SDK's pinned versions within the Go version `go.mod` declares.
- **Strict decoders.** Any new wire format follows the same rule the
  `v1alpha1` contract does: reject unknown fields, duplicate keys, and
  trailing/oversized data rather than accepting and ignoring them.
- **Tests first, or with the implementation.** New behavior — especially
  validation logic — should land with tests that cover it, not as a
  follow-up. A validation rule with no test asserting it rejects the
  invalid case it claims to reject is not done.
- **Race tests.** Anything touching shared state (the run registry,
  scheduler, per-target locking once it exists) must be exercised by
  `go test -race`; `make verify` runs this automatically.

## Commit / PR description expectations

A pull request description should cover:

- **Plan** — what you set out to do and why.
- **Changed files** — the files touched, grouped by purpose if the change
  spans several concerns (it usually should not, per "one PR = one
  purpose").
- **Design decisions** — anything non-obvious, and whether it belongs in a
  new ADR (see [`docs/adr/README.md`](docs/adr/README.md)).
- **Test results** — what you ran (`make verify`, `make vulncheck`, `make
  images`, anything manual) and what passed.
- **Unverified items** — anything you could not test or confirm (a real
  cloud credential you don't have, a code path CI doesn't exercise, and so
  on). Say so explicitly rather than implying full coverage.
- **Rollback** — how to revert this change if it turns out to be wrong
  (usually "revert the commit," but call out anything that would not be,
  e.g. a schema/migration change).

## Per-PR security checklist

Copy this into the PR description and check off each item (or explain why
it does not apply):

- [ ] Can the Conductor access private keys? (It must not be able to.)
- [ ] Can an arbitrary command, image, environment variable, or resource ID
      be injected via API input?
- [ ] Does FQDN suffix validation handle label boundary, trailing dot,
      case, and IDNA correctly?
- [ ] Can wildcard issuance be prohibited by policy?
- [ ] Are tampered, expired, or replayed job specs rejected?
- [ ] Is double issuance for the same target prevented?
- [ ] Are the EAB HMAC, access tokens, and temporary PFX passwords kept out
      of logs?
- [ ] Do error messages contain command lines or environment dumps?
- [ ] Are Conductor and Runner identity permissions kept separate?
- [ ] Are disable and purge kept distinct?
- [ ] Are migration/backup/restore/rollback steps documented for this
      change?
- [ ] Do any tests call a production ACME CA? (They must not.)
- [ ] Is validation (self-consistency) kept distinct from authorization
      (trusted Runner policy) in code comments and docs?
- [ ] Does the Runner copy raw external output into a `Result`?

See [`docs/threat-model.md`](docs/threat-model.md) for the reasoning behind
each of these.
