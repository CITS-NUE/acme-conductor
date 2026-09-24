# ACME Conductor へのコントリビューション

ACME Conductor に関心を持ってくれてありがとう．このプロジェクトはまだ初期段階
（Phase 6 — [`docs/architecture.md`](docs/architecture.md#ロードマップ) を参照）
であり，そのセキュリティ特性は境界を尊重する厳格な設計に依存している．PR を
開く前にこの文書を読んでほしい．

## ワークフロー

- **1 つの PR = 1 つの目的．** PR は一貫した 1 つのことだけを行う．機能追加，
  修正，リファクタリング，ドキュメント更新のいずれかである．無関係な変更を
  まとめてはならない．
- **Phase は別々の PR にする．** [ロードマップ](docs/architecture.md#ロードマップ)
  は厳密な Phase の順序（Phase 0 ブートストラップ → Phase 1 Runner →
  Phase 2 Conductor MVP → ...）を定めている．たとえ便利に思えても，前の Phase に
  限定された PR の中で後の Phase の機能を実装してはならない — 例えば，Phase 0/1
  が進行中のあいだに本物の DNS プロバイダの資格情報や REST API を追加しては
  ならない．PR の範囲が後の Phase の一部を必要とすることが判明した場合は，PR の
  説明にそう書き，黙って範囲を広げるのではなく作業を分割すること．
- **要求された Phase を超えて実装しない．** Phase 1 の実装を求められたなら，
  Phase 1 を実装する — Phase 2 や 3 のプレビューは，たとえ小さくても実装しない．
  これにより各 PR を固定された既知の範囲に対してレビューでき，
  [`docs/architecture.md`](docs/architecture.md#ロードマップ) の Phase の境界が
  意味を持ち続ける．

## ローカルでの検査

PR を開く前に以下を実行すること（CI でも実行される —
`.github/workflows/ci.yml`）:

```sh
make verify    # gofmt の検査，go vet，go test，go test -race
make vulncheck # モジュールに対する govulncheck
make images    # 両方のコンテナイメージをビルドし，問題なくビルドできることを確認
```

`deploy/azure` 配下の変更は，Bicep CLI でのコンパイルと lint も通すべきである
（`bicep build deploy/azure/main.bicep`，`bicep lint
deploy/azure/main.bicep`）．CI はまだこれを実行しない．

## リリース

リリースとは `main` 上のバージョンタグである（`git tag v0.5.0 && git push origin
v0.5.0`）．リリースワークフロー（`.github/workflows/release.yml`）は CI
ワークフローを実行し，タグ付けされたコミットが `origin/main` の履歴に含まれる
ことを検査する（`scripts/release-guard.sh`．それ以外のコミットに打たれたタグは
何も公開しない．`Release guard check` ワークフローは公開せずに任意の ref に
対して同じスクリプトを実行する）．その後，両方のイメージを `linux/amd64` と
`linux/arm64` 向けに SBOM と provenance を付けて GHCR に公開する
（[ADR 0017](docs/adr/0017-release-pipeline.md)）．イメージのダイジェストは
その実行のサマリにある．ブランチや PR からは何も公開されない．バージョンタグを
打ち直してよいのは，その実行が何も公開しなかった（イメージのジョブがスキップ
された）あいだだけである．いったんイメージがそのバージョンを持ったら，次の
バージョンを切ること．GitHub が初回プッシュ時に作成するパッケージは非公開で
ある．組織のオーナーが一度だけ公開に設定する．Dependabot はダイジェスト固定の
ベースイメージ，Go モジュール，GitHub Actions の更新を提案する．それらの PR も
他の PR と同様に扱うこと（CI が通ること，何が変わったかを読むこと）．

## コーディング規則

- **GUI にインラインスクリプトやサードパーティの資産を置かない．** ページは
  `default-src 'none'` の下で配信される．描画するものはすべて DOM のメソッド
  （`textContent`，`createElement`）を通し，API のデータや URL から組み立てた
  マークアップを決して通さない．`unsafe-inline` や外部オリジンを必要とする変更は
  設計変更であり，微調整ではない．
- **ログ，設定，データベース，`Result` 文書にシークレットを入れない．** 資格情報，
  秘密鍵，ACME の EAB HMAC，アクセストークン，一時的な PFX パスワードは，ログ行，
  リポジトリにチェックインされた設定ファイル，データベースの列，
  `Result.error.summary` に決して現れてはならない —
  [`docs/threat-model.md`](docs/threat-model.md) の T6 を参照．
- **Conductor のコアにクラウド SDK を入れない．** Azure/AWS/GCP の SDK の import
  は，ランチャーと Certificate Store アダプタの実装（現在は
  `internal/store/keyvault` と `internal/conductor/launcher/acajob`）にのみ属し，
  `acme-conductor` のコアパッケージ（Target Registry，Policy，Audit Log，
  Run Registry，Scheduler）には決して置かない．アダプタは `pkg/store` または
  `pkg/launcher` のコントラクトを実装し，`ParseConfig`（自身の `config`
  オブジェクトの厳密デコード）と `Open`/`Build` を公開し，
  `cmd/<binary>/providers.go` で登録される．汎用の設定パッケージはプロバイダの
  型名もキー名も知らず，コアは `internal/runner/stores` と
  `internal/conductor/launchers` のレジストリを通してのみ store を開き
  ランチャーを組み立てる．ランチャーアダプタが組み立てに必要とするものは，
  自身のパッケージ内の自身の `Deps` 型である．合成層はすべてのアダプタに同じ
  汎用の `launchers.BuildDeps`（signer，verifier，logger）を渡し，あるアダプタ
  だけが必要とするものは `providers.go` の登録クロージャで束縛する．公開
  コントラクト（`pkg/store`，`pkg/launcher`）はビルド依存を持たない．同様に
  Runner のコアは `internal/runner/transport.Source` を通してジョブを受け取り，
  プラットフォームの環境を決して読まない．トランスポート
  （`internal/runner/transport/claim`）とプラットフォームの実行 ID
  （`internal/runner/platform/azurecontainerapps`）は別々の部品であり，
  `cmd/acme-runner` がそれらを合成する．
  SDK の固定バージョンは `go.mod` が宣言する Go のバージョンの範囲内に保つこと．
- **厳密なデコーダ．** 新しいワイヤ形式はすべて `v1alpha1` コントラクトと同じ
  規則に従う．未知のフィールド，重複キー，末尾の余分なデータや過大なデータは，
  受理して無視するのではなく拒否する．
- **テストを先に，または実装と同時に．** 新しい振る舞い — 特に検証ロジック — は
  後追いではなく，それを網羅するテストとともに取り込むべきである．拒否すると
  主張する不正なケースを本当に拒否することを表明するテストのない検証規則は，
  完成していない．
- **レース検出テスト．** 共有状態（run レジストリ，スケジューラ，将来導入される
  target ごとのロック）に触れるものはすべて `go test -race` で検査しなければ
  ならない．`make verify` はこれを自動的に実行する．

## コミットと PR の説明に求めること

PR の説明には以下を含めるべきである:

- **計画** — 何をしようとしたのか，そしてなぜか．
- **変更したファイル** — 触れたファイル．変更が複数の関心事にまたがる場合は
  目的ごとにまとめる（「1 つの PR = 1 つの目的」に従えば通常はまたがらない
  はずである）．
- **設計上の判断** — 自明でないことすべてと，それを新しい ADR にすべきかどうか
  （[`docs/adr/README.md`](docs/adr/README.md) を参照）．
- **テスト結果** — 何を実行し（`make verify`，`make vulncheck`，`make
  images`，手動で行ったこと），何が通ったか．
- **未検証の項目** — テストや確認ができなかったことすべて（持っていない本物の
  クラウド資格情報，CI が実行しないコードパス，など）．完全に網羅したように
  ほのめかすのではなく，明示的にそう書くこと．
- **ロールバック** — この変更が誤りだと判明した場合に元に戻す方法（通常は
  「コミットを revert する」だが，それでは戻らないもの，例えばスキーマや
  マイグレーションの変更があれば明記する）．

## PR ごとのセキュリティチェックリスト

これを PR の説明にコピーし，各項目にチェックを付ける（または該当しない理由を
説明する）:

- [ ] Conductor は秘密鍵にアクセスできるか？（できてはならない．）
- [ ] 任意のコマンド，イメージ，環境変数，リソース ID を API の入力経由で
      注入できるか？
- [ ] FQDN のサフィックス検証は，ラベル境界，末尾のドット，大文字小文字，IDNA を
      正しく扱っているか？
- [ ] ワイルドカードの発行をポリシーで禁止できるか？
- [ ] 改ざんされた，期限切れの，またはリプレイされたジョブ仕様は拒否されるか？
- [ ] 同じ target に対する二重発行は防がれているか？
- [ ] EAB HMAC，アクセストークン，一時的な PFX パスワードはログに出ないように
      なっているか？
- [ ] エラーメッセージにコマンドラインや環境変数のダンプが含まれているか？
- [ ] Conductor と Runner の ID の権限は分離されているか？
- [ ] disable と purge は区別されているか？
- [ ] この変更について，マイグレーション／バックアップ／復元／ロールバックの
      手順は文書化されているか？
- [ ] 本番の ACME CA を呼ぶテストはあるか？（あってはならない．）
- [ ] 検証（自己整合性）と認可（信頼された Runner のポリシー）は，コードの
      コメントとドキュメントで区別されているか？
- [ ] Runner は外部の生の出力を `Result` にコピーしているか？

これらそれぞれの根拠は [`docs/threat-model.md`](docs/threat-model.md) を参照．
