# ACME Conductor

ACME Conductor is a cloud-agnostic certificate-management control plane. It
is not a new ACME client: ACME issuance itself is delegated to the existing,
version-pinned [go-acme/lego](https://github.com/go-acme/lego) CLI, invoked
as a subprocess by a one-shot Runner job. The Conductor owns the FQDN
registry, certificate policy, an append-only audit log, run scheduling, and
a pluggable job launcher; it never holds a private key, a DNS credential, or
a Certificate Store credential.

**Status: Phase 0 (contracts and skeleton); not usable for issuing
certificates yet.** Phase 0 provides `JobSpec` validation and the
`policy.RunnerAuthorizationPolicy` authorization decision function, but no
Runner wiring of that policy yet. See the
[roadmap](docs/architecture.md#roadmap) for what each phase adds.

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

Phase 0 binaries implement only `--version` and `--help`; there are no
functional subcommands yet.

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
