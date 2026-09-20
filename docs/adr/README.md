# Architecture Decision Records

This directory records the architecturally significant decisions for ACME
Conductor, in the lightweight MADR-like format described in
[0001](0001-record-architecture-decisions.md).

| ADR | Title |
|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions |
| [0002](0002-go-monorepo-with-two-binaries.md) | Go monorepo with two binaries |
| [0003](0003-use-lego-cli-as-subprocess-in-runner.md) | Use the lego CLI as a subprocess in the Runner |
| [0004](0004-versioned-jobspec-result-contract.md) | Versioned JobSpec/Result contract |
| [0005](0005-conductor-never-touches-secrets.md) | Conductor never touches secrets |
| [0006](0006-ascii-only-fqdn-in-v1alpha1.md) | ASCII-only FQDN in v1alpha1 |
| [0007](0007-container-baseline.md) | Container baseline |
| [0008](0008-no-purge-in-mvp.md) | No purge in the MVP |
| [0009](0009-runner-execution-model.md) | Runner execution model |
| [0010](0010-pinned-lego-binary.md) | Pinned lego binary |

See also [`docs/architecture.md`](../architecture.md) and
[`docs/threat-model.md`](../threat-model.md).
