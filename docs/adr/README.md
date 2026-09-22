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
| [0011](0011-conductor-storage-and-run-model.md) | Conductor storage and run model |
| [0012](0012-localhost-only-dev-auth.md) | Localhost-only development authentication |
| [0013](0013-azure-key-vault-store-adapter.md) | Azure Key Vault store adapter |
| [0014](0014-azure-container-apps-job-launcher.md) | Azure Container Apps Job launcher |
| [0015](0015-signed-job-envelope.md) | Signed job envelope and replay ledger |

See also [`docs/architecture.md`](../architecture.md) and
[`docs/threat-model.md`](../threat-model.md).
