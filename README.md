# ACME Conductor

ACME Conductor is a cloud-agnostic certificate-management control plane. It
is not a new ACME client: ACME issuance itself is delegated to the existing,
version-pinned [go-acme/lego](https://github.com/go-acme/lego) CLI, invoked
as a subprocess by a one-shot Runner job. The Conductor owns the FQDN
registry, certificate policy, an append-only audit log, run scheduling, and
a pluggable job launcher; it never holds a private key, a DNS credential, or
a Certificate Store credential.

**Status: Phase 4 (Azure Container Apps Job launcher, Bicep, signed
jobs).** The `acme-conductor` control plane keeps targets, certificate
policies, runs and an append-only audit log in a SQLite registry, exposes
them over a REST API on the local host only (`localhost-dev`
authentication), decides when a target is due, and launches the Runner —
as a local child process for development, or since Phase 4 by offering
the job to a scheduled Azure Container Apps Job that runs under its own
managed identity (the Conductor cannot start executions) — at most one
active run per target. Jobs travel as signed, expiring envelopes that the
Runner verifies and refuses to replay, and Results come back signed by
the Runner. The
`acme-runner` data-plane binary validates and authorizes a `JobSpec`
against its own trusted configuration, invokes the pinned `lego` CLI, and
stores certificates either in a filesystem Certificate Store (dev/test
only) or, since Phase 3, in Azure Key Vault. `deploy/azure` holds the
Bicep that provisions the environment, both identities and their
least-privilege roles. See [`docs/conductor.md`](docs/conductor.md),
[`docs/runner.md`](docs/runner.md) and
[`deploy/azure/README.md`](deploy/azure/README.md) for how to run,
configure and deploy each part, and the
[roadmap](docs/architecture.md#roadmap) for what each phase adds. Automated tests never call a real ACME CA or DNS provider —
they run against fake `lego`/`acme-runner` test doubles.

## Architecture

```
 Web UI / REST API
        |
        v
 +---------------------------------------------------------------+
 |                        acme-conductor                          |
 |  Target Registry | CertificatePolicy | Audit Log (append-only) |
 |  Run Registry     | Scheduler         | Job Launcher interface |
 +---------------------------------------------------------------+
        |
        | versioned JobSpec (CertificateReconcileJob, v1alpha1)
        v
 +---------------------------------------------------------------+
 |                          acme-runner                           |
 |  JobSpec validation (strict) | lego invocation (argv, once)    |
 |  Result normalization        | Certificate Store adapter       |
 +---------------------------------------------------------------+
        |                                   |
        v                                   v
   DNS provider                     Certificate Store
   (lego built-in)                  (filesystem / Key Vault / ...)
```

Full write-up: [`docs/architecture.md`](docs/architecture.md).

## Quick start

```sh
make verify   # gofmt, go vet, go test, go test -race
make build    # build ./bin/acme-conductor and ./bin/acme-runner
./bin/acme-conductor --version
./bin/acme-runner --version
make images   # build both container images (ghcr.io/cits-nue/acme-conductor, acme-runner)
```

`acme-conductor serve --config FILE` runs the control plane (REST API on
`127.0.0.1:8080` by default, scheduler, local-process launcher) — see
[`docs/conductor.md`](docs/conductor.md) for the command line, the
configuration file format and the API. `acme-runner reconcile` handles one
`JobSpec` end to end — see [`docs/runner.md`](docs/runner.md). Example
configurations for both, and an example job, are under
[`deploy/examples/`](deploy/examples/).

## Repository layout

```
cmd/acme-conductor/   control-plane binary
cmd/acme-runner/      data-plane binary
internal/conductor/   Conductor: config, registry (SQLite), scheduler, launchers, REST API
internal/runner/      Runner: config, reconcile loop, lego invocation
internal/store/       Certificate Store contract, the filesystem store and the Azure Key Vault store
internal/policy/      FQDN normalization and suffix-matching
internal/version/     build metadata (injected via -ldflags)
pkg/api/v1alpha1/     the versioned JobSpec/Result contract
schemas/v1alpha1/     JSON Schema mirror of the contract
docs/                 architecture, threat model, ADRs
```

## Documentation

- [Architecture](docs/architecture.md)
- [Conductor operator guide](docs/conductor.md)
- [Runner operator guide](docs/runner.md)
- [Threat model](docs/threat-model.md)
- [Architecture Decision Records](docs/adr/README.md)

## Security principles

- The Conductor never stores, retrieves or distributes certificate private
  keys.
- The Conductor holds no DNS, Key Vault, or long-lived cloud credential.
- The Runner authenticates using the execution platform's workload identity
  (Azure Managed Identity, AWS IAM Role, GCP Service Account), never a
  static secret.
- Private keys are generated in the Runner's temporary area, written
  directly into the Certificate Store, and then destroyed.
- Conductor and Runner identities are separate; the Conductor is granted no
  DNS write and no Certificate Store read permission.
- API input can only name administrator-registered logical bindings —
  never a command, image, resource ID, credential, or provider
  configuration.
- FQDN policy is validated by the Conductor; the Runner validates the
  `JobSpec` document it receives and authorizes it against its own
  trusted policy (Phase 1) — validating the document is not itself
  authorization.
- Production ACME certificate authorities are never called from automated
  tests.

Full detail, including the threat table these principles are traced to:
[`docs/threat-model.md`](docs/threat-model.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Found a security issue? See
[`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
