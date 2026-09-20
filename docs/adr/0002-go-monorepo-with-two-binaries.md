# 0002: Go monorepo with two binaries

- Status: Accepted
- Date: 2026-09-20

## Context

ACME Conductor is split into a control plane (`acme-conductor`) and a data
plane (`acme-runner`) that must never share a process, a set of
credentials, or a deploy lifecycle (see
[`docs/architecture.md`](../architecture.md#control-plane-vs-data-plane)).
They do, however, need to share a versioned wire contract
(`pkg/api/v1alpha1`) and FQDN policy logic (`internal/policy`) byte-for-byte
— the whole point of the Runner re-validating policy independently is that
it runs the *same* validation code, not a reimplementation of it that could
drift.

## Decision

Both binaries live in one Go module (`github.com/CITS-NUE/acme-conductor`),
as two `cmd/` entry points (`cmd/acme-conductor`, `cmd/acme-runner`) sharing
`internal/` and `pkg/` packages. Each binary is built and containerized
independently (`Dockerfile.conductor`, `Dockerfile.runner`) and each ships
its own image, but the source lives in one repository and one module.

## Consequences

- The contract and policy code the Conductor and Runner both depend on
  cannot drift out of sync the way it could across two repositories with
  two copies of the same logic, or two dependency versions of a shared
  library.
- A single `go build ./...`, `go test ./...`, and `go vet ./...` cover both
  binaries; CI is one workflow (`.github/workflows/ci.yml`) with a matrix
  over the two container images.
  `internal/` is enforced by the Go compiler to be unimportable outside
  this module, which keeps helper packages from leaking into an external
  API by accident.
- The two binaries must still be deployed and operated as if they were
  separate services with separate identities (see
  [ADR 0005](0005-conductor-never-touches-secrets.md)) — sharing a
  repository and a module must never become an excuse to blur that
  operational boundary, and code review treats any import that would let
  Conductor-only code reach into Runner-only secret handling (or vice
  versa) as a defect.
- A future split into separate repositories, if ever needed (for example
  for independent release cadences), would require re-vendoring or
  publishing `pkg/api/v1alpha1` and `internal/policy` as their own module;
  this ADR does not rule that out, it just says it is not needed now.
