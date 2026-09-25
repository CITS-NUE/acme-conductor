# ACME Conductor

ACME Conductor は，クラウドに依存しない証明書管理のコントロールプレーンである．
新しい ACME クライアントではない．ACME による発行そのものは，既存でバージョン固定した
[go-acme/lego](https://github.com/go-acme/lego) CLI に委ね，ワンショットの
Runner ジョブがサブプロセスとして起動する．Conductor が持つのは FQDN の
レジストリ，証明書ポリシー，追記専用の監査ログ，実行のスケジューリング，
差し替え可能なジョブランチャーであり，秘密鍵・DNS の資格情報・Certificate Store
の資格情報を保持することは決してない．

コントロールプレーン `acme-conductor` は，対象（target）・証明書ポリシー・実行（run）・
追記専用の監査ログを SQLite のレジストリに保持し，REST API と最小限の GUI で
公開する．本番では OIDC のベアラートークンにより操作者を名前付きプリンシパルとして
認証し admin / viewer のロールを与え，開発時はローカルホストのみを信頼する．
対象の更新期限を判断し，Runner を起動する．開発ではローカルの子プロセスとして，
本番では自身のマネージド ID で動くスケジュール実行の Azure Container Apps Job に
ジョブを差し出す形で（Conductor は実行を開始できない）．対象ごとに同時に
アクティブな実行は最大 1 つ．ジョブは署名付き・期限付きのエンベロープとして運ばれ，
Runner はこれを検証しリプレイを拒否する．Result は Runner の署名付きで返る．
データプレーンのバイナリ `acme-runner` は，`JobSpec` を検証し，自身の信頼された設定に
照らして認可し，固定バージョンの `lego` CLI を起動し，証明書をファイルシステムの
Certificate Store（開発・テスト専用）または Azure Key Vault に格納する．
`deploy/azure` には，環境・両方の ID とその最小権限ロール・API と GUI が応答する
HTTPS ingress をプロビジョニングする Bicep がある．バージョンタグを打つと両方の
イメージが SBOM と provenance 付きで `ghcr.io/cits-nue` に公開される．
`acme-conductor migrate` は既存のインフラ定義からホスト一覧を読み，レジストリと
比較して取り込む（既定は dry-run．更新も削除も決して行わない）．また
`migration.targetSource` フラグにより，操作者が切り替えるまで Conductor は発行を
行わず，フラグを戻せばロールバックになる．各部の実行・設定・デプロイ・移行の方法は
[`docs/conductor.md`](docs/conductor.md)，[`docs/runner.md`](docs/runner.md)，
[`deploy/azure/README.md`](deploy/azure/README.md)，
[`docs/migration.md`](docs/migration.md) を，各部で何が実装済みかは
[実装済みの機能](docs/architecture.md#実装済みの機能)を参照．自動テストは本物の ACME CA や
DNS プロバイダを決して呼ばない．`lego` / `acme-runner` の偽物（テストダブル）に対して
実行される．

## アーキテクチャ

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

詳細: [`docs/architecture.md`](docs/architecture.md)．

## クイックスタート

```sh
make verify   # gofmt，句読点，go vet，go test，go test -race
make build    # ./bin/acme-conductor と ./bin/acme-runner をビルド
./bin/acme-conductor --version
./bin/acme-runner --version
make images   # 両方のコンテナイメージをビルド (ghcr.io/cits-nue/acme-conductor, acme-runner)
```

`acme-conductor serve --config FILE` でコントロールプレーンが動く（REST API は既定で
`127.0.0.1:8080`，スケジューラ，ローカルプロセスのランチャー）．コマンドライン・
設定ファイルの形式・API は [`docs/conductor.md`](docs/conductor.md) を参照．
`acme-runner reconcile` は 1 つの `JobSpec` を最初から最後まで処理する．
[`docs/runner.md`](docs/runner.md) を参照．両方の設定例とジョブの例は
[`deploy/examples/`](deploy/examples/) にある．

## リポジトリの構成

```
cmd/acme-conductor/   コントロールプレーンのバイナリ
cmd/acme-runner/      データプレーンのバイナリ
internal/conductor/   Conductor: 設定，レジストリ (SQLite)，スケジューラ，ランチャー，REST API
internal/runner/      Runner: 設定，reconcile ループ，lego の起動
internal/store/       ファイルシステム store と Azure Key Vault store
internal/policy/      FQDN の正規化とサフィックス照合
internal/exchange/    自ら起動する Runner にジョブを渡すディスク上の受け渡しプロトコル
internal/keygen/      両バイナリ共通の keygen サブコマンド (Ed25519 の署名鍵)
internal/fslock/      Runner のディスク上の store が使うアドバイザリファイルロック
internal/strictjson/  未知フィールド・重複キー・末尾データを拒否する厳密な JSON デコーダ
internal/version/     ビルド情報 (-ldflags で注入)
pkg/api/v1alpha1/     バージョン付きの JobSpec/Result コントラクト
pkg/store/            すべての store アダプタが実装する Certificate Store コントラクト
pkg/launcher/         すべてのランチャーアダプタが実装する Job Launcher コントラクト
schemas/v1alpha1/     コントラクトを写した JSON Schema
docs/                 アーキテクチャ，脅威モデル，ADR
```

## ドキュメント

- [図解入りの解説サイト](https://cits-nue.github.io/acme-conductor/)（導入を検討する方向け．ソースは [`site/`](site/)）
- [アーキテクチャ](docs/architecture.md)
- [Conductor 運用ガイド](docs/conductor.md)
- [Runner 運用ガイド](docs/runner.md)
- [脅威モデル](docs/threat-model.md)
- [Architecture Decision Records](docs/adr/README.md)

## セキュリティ原則

- Conductor は証明書の秘密鍵を保存・取得・配布しない．
- Conductor は DNS，Key Vault，長期有効なクラウド資格情報を持たない．
- Runner は実行基盤のワークロード ID（Azure Managed Identity，AWS IAM Role，
  GCP Service Account）で認証し，静的なシークレットは使わない．
- 秘密鍵は Runner の一時領域で生成され，Certificate Store に直接書き込まれた後，
  破棄される．
- Conductor と Runner の ID は分離されている．Conductor には DNS の書き込み権限も
  Certificate Store の読み取り権限も与えない．
- API の入力で指定できるのは，管理者が登録した論理的な binding の名前だけである．
  コマンド，イメージ，リソース ID，資格情報，プロバイダ設定は決して指定できない．
- FQDN ポリシーは Conductor が検証する．Runner は受け取った `JobSpec` 文書を
  検証し，自身の信頼されたポリシーに照らして認可する．文書の検証は
  それ自体では認可ではない．
- 本番の ACME 認証局を自動テストから呼ぶことは決してない．

これらの原則がどの脅威に対応するかを含む詳細:
[`docs/threat-model.md`](docs/threat-model.md)．

## コントリビューション

[`CONTRIBUTING.md`](CONTRIBUTING.md) を参照．セキュリティ上の問題を見つけた場合は，
公開の issue を立てずに [`SECURITY.md`](SECURITY.md) を参照．

## ライセンス

Apache License 2.0．[`LICENSE`](LICENSE) を参照．
