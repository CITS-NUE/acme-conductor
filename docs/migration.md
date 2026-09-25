# cert-infra からの移行

既存の `cert-infra` デプロイ（固定されたホスト一覧を `lego` で更新し Key Vault に
取り込む，Bicep で定義された Container Apps Job）を，切替日を設けずに
ACME Conductor へ移す方法と，shadow フェーズの結果から必要だと分かった場合に
元へ戻す方法を述べる．決定は
[ADR 0020](adr/0020-migration-from-cert-infra.md) に記録されている．

`cert-infra` リポジトリ自体はこのプロジェクトによって **変更されない**．その
`infra/main.bicepparam` は読まれるだけで決して書かれず，そのジョブは操作者が
止めるまで動き続ける．

## 移行するものとしないもの

移行するのは **管理対象の名前の集合** である．`cert-infra` はそれを
`infra/main.bicepparam` の `targetDomains` 配列に保持し，Conductor は target
レジストリに，FQDN ごとに 1 つの `Target` として，それぞれ `CertificatePolicy` と
バインディングの集合の下に保持する
（[`docs/conductor.md`](conductor.md#target)）．移行ツールは一覧を読み，
レジストリと比較し，レジストリに欠けている target を作成する．移すのはそれが
すべてである:

- **ACME アカウントは移行しない．** Runner の `lego` は自身の状態ディレクトリの
  下に自身のアカウントを登録する
  （[`docs/runner.md`](runner.md#ディレクトリとコンテナでの利用)）．
  両方のアカウントは CA 側で共存できる．Let's Encrypt のアカウントは固有の
  クォータを持たない．
- **証明書は移行しない．** Runner は切替後の初回の実行で，取り込んだ各 target に
  新しい証明書を発行し，Conductor のオブジェクト名
  （[`docs/runner.md`](runner.md#certificate-store-azure-key-vault)）の下に
  格納する．これは `cert-infra` が使っていた名前（ドットを置き換えた
  `leaf-cerdad-…`）ではない．Key Vault の証明書を名前で参照している利用側
  （たとえば Application Gateway のリスナー）は，新しいオブジェクトができた
  時点で操作者が向け直す．古いオブジェクトは手で削除されるまで残る．これが
  移行の中で利用側から見える唯一の手順であり，このリポジトリの外にある．
- **ポリシーは導出しない．** どのサフィックスを許可するか，どの ACME
  バインディングを使うか，どれだけ早く更新するかは管理者の決定であり，取り込み
  プロファイルが名指すポリシーの中で一度だけ決める．一覧はそのいずれにも
  参照されない．

## target source フラグ

Conductor 設定の `migration.targetSource` が誰が発行するかを定める
（[`docs/conductor.md`](conductor.md#migration)）:

| `targetSource` | Conductor が発行する | Conductor が比較する | 意味 |
|---|---|---|---|
| `iac` | しない | しない | インフラの一覧が別の場所（`cert-infra` のジョブ）での発行を駆動する．レジストリは編集できるが何もスケジュールされず，`POST /targets/{id}/runs` は `409 issuance_disabled` を返す．移行前の状態であり，ロールバックで戻る先でもある． |
| `shadow` | しない | する（`compareIntervalSeconds` ごと） | `iac` と同じだが，加えて設定された一覧を一定間隔でレジストリと比較する．すべての比較はログに記録され，結果が変わるたびに監査イベント（`migration.compared`）になる．`GET /migration` と GUI の Migration ページに最新のレポートが表示される． |
| `registry` | する | しない | レジストリが正であり，スケジューラが run を計画し開始する．既定であり，移行後の状態である． |

このフラグは起動時に読まれる．変更は設定変更と再起動（Container Apps では新しい
リビジョン）であり，それ以外は何もない．データは移動せず，何も再計算されない．
`iac` と `shadow` の値は，移行完了を宣言したリリースの後，少なくとも 1 つの
マイナーリリースの間はサポートされ続けるので，ロールバックにはフラグ以外に
何も要らない．

`iac` と `shadow` の下では，フラグが設定される前にキューに入っていた run は
キューに残り，フラグが `registry` に戻ったときに開始される．それを望まない
場合は API でキャンセルすること．

## 比較

比較は一覧を読み，API と同じ方法ですべての名前を正規化し（小文字化，末尾の
ドット 1 つを除去，構文検査．Conductor が完全には読めない一覧には一切手を
つけないため，1 つでも不正な項目があれば一覧全体が失敗する），各名前を 1 つの
カテゴリに振り分ける:

| カテゴリ | 意味 | 取り込みが行うこと |
|---|---|---|
| `added` | 一覧にあり，レジストリにない． | プロファイルから target を作成する． |
| `changed` | 両方にあるが，レジストリの target が無効化されているか，プロファイルと異なるポリシーまたはバインディングを名指している． | 何もしない．操作者が判断する．レポートはどのフィールドが異なるかを示す． |
| `missing` | レジストリにあり，一覧にない． | 何もしない．移行は何も削除しない（[ADR 0008](adr/0008-no-purge-in-mvp.md)）．不要なら target を無効化すること． |
| `unchanged` | 両方にあり，同じ． | 何もしない． |
| `rejected` | 一覧にあるが，プロファイルのポリシーがその名前を許可しない（サフィックスまたはワイルドカードの規則）． | 何もせず，他の何も行わない．拒否された項目を含む一覧は，一覧かポリシーが修正されるまで一切取り込まれない． |

所有者は比較しない．一覧は所有者を知らず，取り込み後に操作者が target ごとに
プロファイルの所有者を精緻化することは十分にありうる．

取り込みは **冪等** である．同じ一覧に対してもう一度実行しても何も作成されず，
存在する target は，プロファイルが今何を言っていようと，取り込みによって決して
更新されない．**既定では dry-run** である．何かを作成するには API では
`dryRun: false` を，CLI では `--apply` を渡す．作成された各 target には，呼び出し元と
元になった一覧を記した `target.imported` 監査イベントが付く．

## ソース

一覧は次のいずれかから読む:

- **Bicep パラメータファイル**（`bicepParamFile`，`parameter` 付き，既定は
  `targetDomains`）: `cert-infra` のファイルそのまま．リーダは
  `param <name> = [ … ]` 文，`//` と `/* */` のコメント，Bicep のエスケープを
  含む単一引用符の文字列リテラルを理解し，評価が必要になるもの（補間文字列，
  変数，関数呼び出し）はすべて拒否する．Conductor は Bicep を実行できないので，
  評価が必要な一覧はまず TargetList に書き出す．
- **TargetList 文書**（`jsonFile`）: 厳密にデコードされる JSON ファイル．
  `{"apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1", "kind": "TargetList", "fqdns": [ … ]}`
  （[`deploy/examples/targets.example.json`](../deploy/examples/targets.example.json)）．
  `acme-conductor migrate list --bicepparam FILE --output json` がこれを書き出す．
- **インライン一覧**（`fqdns`）: 設定そのものに書いた名前．Container Apps
  デプロイはこの方法で一覧を得る．`migration` Bicep パラメータはこのセクション
  そのままなので，`targetDomains` 配列を `source.fqdns` に貼り付けられる．

ソースはサーバ側で設定され（`migration.source`），shadow 比較が比較する対象と，
独自の一覧を持たない差分や取り込みが使う対象になる．CLI はファイルをローカルで
読んで見つけた名前を送ることもできるので，操作者の手元の `cert-infra` の
チェックアウトがあれば足りる．

一覧が寄与する名前はすべて FQDN であり，それ以外の何物でもない．取り込まれた
target のポリシー，実行・DNS・store のバインディング，所有者は，管理者の設定内の
`migration.profile` から来る
（[原則 6](architecture.md#セキュリティ原則)）．ホスト一覧は，どこから来た
ものであれ，決してバインディングを選べない．

## 手順

[`deploy/azure/README.md`](../deploy/azure/README.md) のとおりにデプロイされた
Conductor（またはリハーサル用の 1 台のホスト）があり，Runner が `cert-infra` の
委任先と同じゾーンでチャレンジを完了でき，Key Vault に書き込めることを前提と
する．`cert-infra` のジョブの環境変数のうち，`AZURE_ZONE_NAME`，
`AZURE_RESOURCE_GROUP`，`AZURE_SUBSCRIPTION_ID` は DNS バインディングの `env` に，
`AZURE_CLIENT_ID` は `passthroughEnv` に対応する．`LEGO_DISABLE_CNAME_SUPPORT`
などの `LEGO_*` は予約済みで持ち込めず，CNAME をたどる動作は既定なので不要である
（[`docs/runner.md`](runner.md#dnsbindingsname)）．

1. **暗転状態で始める．** `targetSource: shadow`（または `iac`），
   `migration.source` としての `cert-infra` の一覧，そして移行対象ホストの
   ために作ったポリシー（その `allowedDnsSuffixes` がホストを覆い，その
   `acmeBinding` はリハーサルが終わるまでステージング CA を指す）を名指す
   `migration.profile` で Conductor をデプロイする．`cert-infra` のジョブは
   更新を続ける．ここから先，Conductor が行うことは何一つ，証明書を発行せず，
   DNS レコードを変更せず，Azure リソースに触れない．
2. **差分を見る．**

   ```sh
   acme-conductor migrate diff --bicepparam ~/src/cert-infra/infra/main.bicepparam \
     --server https://acme-conductor.example.ac.jp --token-file token
   ```

   すべての名前が `added` に入り，`rejected` には何もないことを期待する．
   `rejected` の名前はポリシーがそれを覆っていないことを意味する．拒否された
   項目を含む一覧は一切取り込まれないので，取り込む前にポリシー（または一覧）を
   修正する．
3. **取り込み，そして適用する．** 同じコマンドを `import` で実行すると，
   `--apply` が何を作成するかを示す dry-run になる．`--apply` はそれを作成する．
   監査ログは各 target を `target.imported` として記録する．もう一度実行すると
   何も作成されず（冪等），すべての名前が `unchanged` になる．
4. **shadow．** `cert-infra` の一覧がまだ変わりうる間は `targetSource: shadow`
   のままにしておく．GUI の Migration ページ（と `GET /migration`）は最新の
   比較を示し，`migration.compared` 監査イベントが結果の変化のたびに記録される．
   したがって `cert-infra` に追加されたホストは `added` として現れ（再度
   取り込む），レジストリで無効化された target は `changed` として，レジストリ
   にだけ作られた target は `missing` として現れる．この間もレジストリは完全に
   編集可能である．何も発行せずにポリシー・所有者・バインディングを準備できる．
5. **切り替える．** `targetSource: registry` を設定して再起動する．スケジューラは
   取り込んだすべての target（一度も reconcile されていない）に run を計画し，
   Runner が発行して格納し，各 target に証明書の概要が現れる．次に利用側を
   新しい Key Vault オブジェクトへ向け直し，操作者が選んだタイミングで
   `cert-infra` のジョブを止める（スケジュールを一時停止するか，デプロイを
   削除する）．両者は別々の ACME アカウントと別々のオブジェクト名を使うので
   重なっていてもよいが，その代償として CA のレート制限に対してホストごとに
   1 回余分な発行が生じる．
6. **ロールバック** は `targetSource: iac`（または `shadow`）を設定して再起動する
   ことで行う．Conductor は直ちに計画を止め，進行中の run は通常どおり完了するか
   シャットダウン時にキャンセルされ，レジストリは shadow フェーズと切替が
   記録したすべてを保持する．`cert-infra` のジョブを止めていたなら再開する．
   復元すべきデータはない．何も削除されていない．

## コマンドライン

```
acme-conductor migrate list   (--bicepparam FILE [--parameter NAME] | --json FILE) [--output text|json]
acme-conductor migrate diff   [SOURCE] [--server URL] [--token-file FILE] [--output text|json]
acme-conductor migrate import [SOURCE] [--server URL] [--token-file FILE] [--apply] [--output text|json]
```

`SOURCE` は `--bicepparam FILE [--parameter NAME]` または `--json FILE` であり，
ローカルで読んで一覧として送られる．これがない場合，`diff` と `import` は
サーバに設定された一覧を使う．`--server` の既定は `$ACME_CONDUCTOR_SERVER`，
次いで `http://127.0.0.1:8080`（`localhost-dev` リスナー．トークン不要）である．
`oidc` サーバに対しては，`--token-file` に API のオーディエンス向けのベアラー
アクセストークンを収めたファイルを指定するか，`$ACME_CONDUCTOR_TOKEN` に
トークンそのものを入れる．トークンは `https` 上でのみ送られる．`list` は
サーバを必要としない．ソースが読み取った正規化済みの名前を印字し，
`--output json` なら TargetList 文書を印字する．

`--output text` は概要行に続いて名前ごとに 1 行を，カテゴリを先頭にして印字する．
`--output json` は API のレポート（または取り込み結果）を印字する．終了コード:
`0`．レポートに拒否された項目がある，またはそれが理由で `--apply` が拒否された
場合は `1`．使い方の誤り（読めないソースを含む）は `2`．リクエストが失敗した
場合は `3`．

## API

| メソッドとパス | 目的 |
|---|---|
| `GET /api/v1alpha1/migration` | フラグ，発行が有効かどうか，設定されたソースとプロファイル，および `shadow` の下では最新の比較（`lastComparison.report`，または直前の試行が失敗した場合は `lastComparison.error` と最後に成功したレポート）． |
| `GET /api/v1alpha1/migration/diff` | 設定された一覧を比較する → レポート．viewer が読める． |
| `POST /api/v1alpha1/migration/diff` | `{"fqdns": […]}` を比較する → レポート． |
| `POST /api/v1alpha1/migration/import` | `{"fqdns": […], "dryRun": true}` を取り込む．どちらも任意で，`dryRun` の既定は `true`，`fqdns` がなければ設定された一覧．→ `{"dryRun", "applied", "report", "created"}`．`applied` は dry-run のときと一覧に拒否された項目があるとき（何も作成されない）に `false` になる．何かを作成したときはスケジューラを起こす． |

`migration.profile` が設定されていないかそのポリシーが存在しない場合は
`409 migration_unconfigured`．設定された一覧が読めない場合は
`409 source_unreadable`．リクエストが一覧を名指さず設定にもない場合，または
名指した一覧が不正な形式の場合は `400 invalid_request`．

## 移行のテスト

テストは CA やクラウド API を決して呼ばない．移行パッケージのテストはリーダを
[`internal/conductor/migration/testdata/cert-infra-main.bicepparam`](../internal/conductor/migration/testdata/cert-infra-main.bicepparam)
に対して実行する．これは `cert-infra` の `infra/main.bicepparam` と同じ文，
コメントスタイル，コメントアウトされた項目を持つフィクスチャ（名前は例）で
ある．比較と取り込みは本物の SQLite レジストリに対して実行する．Conductor の
テストはプロセス全体を `shadow` モードで偽の Runner に対して起動し，比較が
記録されること，期限到来の target が決して計画されないこと，run の要求が
拒否されることを確認し，さらに `acme-conductor migrate` を動作中の Conductor に
対してエンドツーエンドで動かす．本物の一覧でリハーサルするには，
`acme-conductor migrate list --bicepparam …/main.bicepparam` がサーバなしで
リーダの解釈結果を示す．
