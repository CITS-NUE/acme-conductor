# ACME Conductor

ACME Conductor is a cloud-agnostic certificate-management control plane. It
is not a new ACME client: ACME issuance itself is delegated to the existing,
version-pinned [go-acme/lego](https://github.com/go-acme/lego) CLI, invoked
as a subprocess by a one-shot Runner job. The Conductor owns the FQDN
registry, certificate policy, an append-only audit log, run scheduling, and
a pluggable job launcher; it never holds a private key, a DNS credential, or
a Certificate Store credential.

**Status: Phase 1 (Runner with bundled lego and filesystem store); the
Conductor is still a skeleton.** The `acme-runner` data-plane binary
validates and authorizes a `JobSpec` against its own trusted configuration,
invokes the pinned `lego` CLI, and stores certificates in a filesystem
Certificate Store (dev/test only). The `acme-conductor` control plane still
implements only `--version`/`--help`; nothing yet schedules a `Target` or
launches a Runner job automatically. See
[`docs/runner.md`](docs/runner.md) for how to run and configure the Runner,
and the [roadmap](docs/architecture.md#roadmap) for what each phase adds.
Automated tests never call a real ACME CA or DNS provider — they run
against a fake `lego` test double.

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

`acme-conductor` still implements only `--version` and `--help`.
`acme-runner` additionally implements `reconcile`, which handles one
`JobSpec` end to end — see [`docs/runner.md`](docs/runner.md) for the
command line, the configuration file format, and an example config/job
pair under [`deploy/examples/`](deploy/examples/).

## Repository layout

```
cmd/acme-conductor/   control-plane binary
cmd/acme-runner/      data-plane binary
internal/policy/      FQDN normalization and suffix-matching
internal/version/     build metadata (injected via -ldflags)
pkg/api/v1alpha1/     the versioned JobSpec/Result contract
schemas/v1alpha1/     JSON Schema mirror of the contract
docs/                 architecture, threat model, ADRs
```

## Documentation

- [Architecture](docs/architecture.md)
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
