# Architecture Decision Records

このディレクトリには，ACME Conductor にとってアーキテクチャ上重要な決定を，
[0001](0001-record-architecture-decisions.md) に記述した MADR 風の軽量な形式で
記録する．

| ADR | 題名 |
|---|---|
| [0001](0001-record-architecture-decisions.md) | アーキテクチャ決定を記録する |
| [0002](0002-go-monorepo-with-two-binaries.md) | 2 つのバイナリを持つ Go モノレポ |
| [0003](0003-use-lego-cli-as-subprocess-in-runner.md) | Runner で lego CLI をサブプロセスとして使う |
| [0004](0004-versioned-jobspec-result-contract.md) | バージョン付きの JobSpec/Result コントラクト |
| [0005](0005-conductor-never-touches-secrets.md) | Conductor は決してシークレットに触れない |
| [0006](0006-ascii-only-fqdn-in-v1alpha1.md) | v1alpha1 では ASCII のみの FQDN |
| [0007](0007-container-baseline.md) | コンテナの基本方針 |
| [0008](0008-no-purge-in-mvp.md) | MVP では purge しない |
| [0009](0009-runner-execution-model.md) | Runner の実行モデル |
| [0010](0010-pinned-lego-binary.md) | lego バイナリのバージョン固定 |
| [0011](0011-conductor-storage-and-run-model.md) | Conductor のストレージと run モデル |
| [0012](0012-localhost-only-dev-auth.md) | ローカルホスト限定の開発用認証 |
| [0013](0013-azure-key-vault-store-adapter.md) | Azure Key Vault の store アダプタ |
| [0014](0014-azure-container-apps-job-launcher.md) | Azure Container Apps Job ランチャー |
| [0015](0015-signed-job-envelope.md) | 署名付きジョブエンベロープとリプレイ台帳 |
| [0016](0016-oidc-bearer-auth-and-gui.md) | OIDC ベアラートークン認証と 2 つのロールと静的 GUI |
| [0017](0017-release-pipeline.md) | リリースパイプライン: SBOM と provenance 付きの GHCR イメージとダイジェスト固定のベース |
| [0018](0018-authority-qualified-principals.md) | 監査プリンシパルは権威 (issuer，`localhost-dev`，`scheduler`) で修飾する |
| [0019](0019-provider-boundary.md) | プロバイダ境界: 公開コントラクト，合成層のレジストリ，単一モジュール，`deploy/azure` は残す |
| [0020](0020-migration-from-cert-infra.md) | cert-infra からの移行: 一覧の取り込み，shadow 比較，target-source フラグ |
| [0021](0021-keyvault-pkcs12-content-type.md) | Key Vault store のコンテンツタイプ: パスワードなし PKCS #12 での取り込みを選べるようにする |

[`docs/architecture.md`](../architecture.md) と
[`docs/threat-model.md`](../threat-model.md) も参照．
