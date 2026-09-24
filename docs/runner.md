# Runner 運用ガイド

これは，[`docs/architecture.md`](architecture.md) で説明するワンショットの
データプレーンジョブ `acme-runner` の，操作者向けリファレンスである．
コマンドライン，設定ファイルの形式，1 回の `reconcile` 起動が実際に何を行うか，
2 つの Certificate Store（開発・テスト用のファイルシステム store と，
実際のデプロイ向けの Azure Key Vault），コンテナの動かし方，`Result` と
エラーコードのコントラクト，そして Runner が現時点で保証すること・しないことを
扱う．

Phase 1 では，公式の `lego` CLI とファイルシステムの Certificate Store を同梱した
ワンショットの Runner を提供する．Phase 2 以降は Conductor が target を
スケジュールし，Runner をローカルの子プロセスとして起動する
（[`docs/conductor.md`](conductor.md) を参照）．Runner 自体はそれによって
変わらず，ここで説明する通りに手動で起動することもできる．Phase 3 では
実行基盤のマネージド ID で認証する Azure Key Vault の Certificate Store が
加わる．[Certificate Store (Azure Key Vault)](#certificate-store-azure-key-vault)
を参照．Phase 4 では署名付きジョブエンベロープが加わる．[`jobSigning`](#jobsigning)
を設定すると，Runner は Conductor が署名したジョブだけを，その有効期間内に，
1 度だけ受け付ける．さらに Runner は自身のマネージド ID の下で
Azure Container Apps Job として動く
（[Container Apps Job として動かす](#container-apps-job-として動かす) と
[ロードマップ](architecture.md#ロードマップ) を参照）．

## 概要

`acme-runner` はプロセス起動 1 回につき，ちょうど 1 つの `JobSpec`
（`CertificateReconcileJob`，`pkg/api/v1alpha1`）を処理する．文書を検証し，
自身の信頼された設定に照らして認可し，設定された Certificate Store に
証明書の発行または更新が必要かを問い合わせ，必要なら同梱の `lego` CLI を
1 度だけ実行し，`lego` が生成したものを検証し，証明書を格納し，`Result`
（`CertificateReconcileResult`）を書き出す．HTTP サーバも，スケジューラも，
データベースも，cron も持たない．実行基盤が run ごとに 1 つのプロセスを
開始することを想定している．

## コマンドライン

```
acme-runner reconcile --job FILE --result FILE [--config FILE] [--log-level LEVEL]
acme-runner reconcile --exchange DIR [--execution-name NAME] [--config FILE] [--log-level LEVEL]
acme-runner keygen --private FILE --public FILE
acme-runner --version
acme-runner --help
```

- `--exchange DIR` — `--job`/`--result` の代わりとなる *claim トランスポート*．
  Conductor が `DIR/pending/` に差し出した最も古いジョブを取り，
  `DIR/claimed/` に移動し，このプロセスの **実行 ID** をその隣に記録し，
  Result をジョブの隣に書く．pending が何もなければ，その旨をログに出して
  Result なしで `0` で終了する．`--job`/`--result` と組み合わせることは
  できない．トランスポートは他の書き手と共有されるため，設定に
  [`resultSigning`](#resultsigning) が必要である．それがなければプロセスは
  ジョブを取らずに `2` で終了する．反対側の Conductor は署名付きの Result
  しか受け付けないからである．
- `--execution-name NAME` — `--exchange` と併用: claim したジョブに記録する
  ID であり，Conductor がそのプラットフォーム上でこのプロセスを観測・停止
  するための名前である．省略時はプラットフォームから読み取る．公式バイナリが
  知っている，自律的に Runner を開始するプラットフォームは Azure Container
  Apps の 1 つであり，その `CONTAINER_APP_JOB_EXECUTION_NAME` が実行を
  命名する（[Container Apps Job として動かす](#container-apps-job-として動かす)）．
  ID が一切得られない場合，ジョブは Result なしで取られたままとなり，
  プロセスは `2` で終了する．Conductor がその実行を観測も停止もできない
  からである．トランスポート（`internal/runner/transport/claim`）と
  プラットフォーム（`internal/runner/platform/azurecontainerapps`）は
  コマンドが合成する別々の部品であり，reconcile 処理のコアはどちらも
  知らない．
- `keygen` — Ed25519 の Result 署名鍵ペアを生成する
  （[`resultSigning`](#resultsigning)）．秘密鍵ファイルは `0600` で作成され
  決して上書きされず，Conductor の `resultSigning.publicKeys` 用の 1 行の
  公開鍵が表示される．
- `--job FILE`（必須）— `CertificateReconcileJob` 文書のパス．
- `--result FILE`（必須）— `CertificateReconcileResult` をアトミックに
  書き出すパス（同じディレクトリ内の一時ファイル，`fsync`，`rename`）．
  Result は `--result` とは無関係に，常に 1 行の JSON として stdout にも
  表示される．
- `--config FILE`（任意）— Runner 設定文書のパス．環境変数
  `$ACME_RUNNER_CONFIG` が設定されていればそれが既定値，なければ
  `/etc/acme-runner/config.json`．
- `--log-level LEVEL`（任意，既定 `info`）— `debug`，`info`，`warn`，`error`
  のいずれか（大文字小文字を区別しない）．ログは stderr に書かれる構造化
  JSON で，常に UTC であり，判明した時点から `runId`/`targetId` を持つ．

### 終了コード

| コード | 意味 |
|---|---|
| `0` | `status: succeeded` の `Result` が書き出された（stdout と，指定があれば `--result` に）． |
| `1` | `status: failed` の `Result` が書き出された． |
| `2` | `Result` をまったく届けられなかった．ジョブファイルを読めなかったか，厳密な検証に失敗し，かつ緩い読み取りでも run の ID（`runId`/`target.id`）を復元できなかった．詳細は stderr のみにある． |

終了コードは stdout に表示された `Result` に従う．`--result` ファイルを
書けない場合（たとえばパスがディレクトリである，親ディレクトリが存在しない）
はエラーレベルでログに記録されるが，`Result` は stdout に届けられているので
終了コードは依然 `0`/`1` である．ファイルに依存する利用者は，ファイルの欠落を
「stdout を確認せよ」と扱わなければならない．

## 設定リファレンス

設定ファイルは Runner の **信頼された** 入力である．管理者が管理する読み取り
専用の JSON 文書で，`JobSpec` とは別物であり，決して `JobSpec` から派生しない．
厳密にデコードされ（未知のフィールドと末尾の余分なデータは拒否される），
256 KiB を上限とする．**シークレットの値は含まない**．バインディングが
資格情報（DNS プロバイダのトークン，ACME External Account Binding の HMAC）
を必要とする場合，設定はその値を Runner プロセスに提供することを実行基盤に
期待する環境変数の名前だけを記す．Runner はその値を `lego` に受け渡すだけで，
決してログにも報告にも出さない．

トップレベル:

| フィールド | 型 | 備考 |
|---|---|---|
| `apiVersion` | string | `acme-conductor.cits-nue.github.io/v1alpha1` と一致しなければならない． |
| `kind` | string | `RunnerConfig` と一致しなければならない． |
| `authorization` | object | Runner の信頼された `RunnerAuthorizationPolicy`．後述． |
| `lego` | object | バイナリのパスとディレクトリ．後述． |
| `acmeBindings` | map | 1 件以上必要．キーはバインディング名（`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`，63 文字以下）． |
| `dnsBindings` | map | 1 件以上必要．キーの規則は同じ． |
| `storeBindings` | map | 1 件以上必要．キーの規則は同じ． |
| `jobSigning` | object | 任意．存在する場合，署名付きジョブエンベロープだけを受け付ける．後述． |

### `authorization`

これは `policy.RunnerAuthorizationPolicy` である．`JobSpec`（偽造であれ
なかれ）が `JobSpec` 自身の主張とは無関係に，この Runner に何をさせられるかを
限定する境界である．すべてのリストは **既定で拒否** であり，必須リストが
空または欠けていれば何も認可しない．

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `allowedDnsSuffixes` | []string | —（必須，空でないこと） | 各エントリはあらかじめ正規化された形（`internal/policy.NormalizeSuffix`）でなければならない．target の FQDN はラベル境界全体で照合されるため，`evil-example.ac.jp` が `example.ac.jp` に一致することは決してない． |
| `allowWildcard` | bool | `false` | 許可されたサフィックスの下でワイルドカードの target（`*.example.ac.jp`）を許すかどうか． |
| `allowedAcmeBindings` | []string | —（必須，空でないこと） | 名前は整形式のバインディング名であり，**かつ** `acmeBindings` に定義されていなければならない． |
| `allowedDnsBindings` | []string | —（必須，空でないこと） | 同上．`dnsBindings` に対して． |
| `allowedStoreBindings` | []string | —（必須，空でないこと） | 同上．`storeBindings` に対して． |

### `lego`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `binary` | string | —（必須） | バージョン固定した `lego` 実行ファイルへの，クリーンな絶対パス． |
| `stateDir` | string | —（必須） | クリーンな絶対パス．ACME アカウントの状態（アカウント鍵と登録）を run をまたいで永続化する．証明書の秘密鍵を **決して** 保持しない．`workDir` と異なっていなければならない． |
| `workDir` | string | —（必須） | クリーンな絶対パス．`lego` が実行される run ごとの一時ディレクトリの親で，証明書の秘密鍵が一時的に存在する場所．`tmpfs` か `emptyDir` にすべきである． |
| `timeoutSeconds` | int | `900`（`0` のとき適用） | 1 回の `lego` 起動の上限．`1` 以上 `86400` 以下でなければならない． |

### `acmeBindings.<name>`

| フィールド | 型 | 備考 |
|---|---|---|
| `directoryURL` | string | userinfo もフラグメントも持たない `https://` URL でなければならない． |
| `email` | string | 1 つのメールボックスアドレス（空白・引用符・スラッシュを含まず，`@` はちょうど 1 つで，先頭・末尾が `@` でない）． |
| `eab` | object，任意 | `{ "kidEnv": "...", "hmacEnv": "..." }` — 実行時に EAB のキー ID と HMAC を運ぶ環境変数の **名前**（決して値ではない）．`kidEnv` と `hmacEnv` は有効な環境変数名で，互いに異なっていなければならない． |
| `allowProductionCA` | bool，既定 `false` | ステージング／テスト／ローカルと認識されないディレクトリを使うには明示的に設定しなければならない（後述）． |

ディレクトリは，そのホストがループバック・プライベート・リンクローカルの
IP リテラルであるか，ホストのラベル（`.` と `-` で分割）のいずれかが
`staging`，`stage`，`test`，`testing`，`sandbox`，`pebble`，`localhost`，
`dev`，`local`，`internal` のいずれかであるとき，**非本番** と認識される
（たとえば `acme-staging-v02.api.letsencrypt.org`，`pebble.internal`，
`ca-test.example.ac.jp`）．**それ以外のディレクトリはすべて本番として扱われ**，
`allowProductionCA: true` がなければ拒否される．これは既知の CA の拒否リスト
ではなく，テストらしく見えるホストに対する許可規則として意図的に設計されて
いる．未知の本番 CA（SSL.com，Sectigo，大学独自の ACME サービスなど）に
誤って到達することが決してないようにするためである．ホスト名にこれらの
ラベルを 1 つも含まないプライベート CA は，明示的にフラグを設定しなければ
ならない．ラベルは全体で照合される．`attestation.example` や
`devices.example` はテストホストとはみなされない．

### `dnsBindings.<name>`

| フィールド | 型 | 備考 |
|---|---|---|
| `provider` | string | `lego` の DNS プロバイダ名（`^[a-z0-9]{1,32}$`，例: `azuredns`）．`exec` と `manual` は即座に拒否される．`exec` は任意のプログラムを実行し，`manual` は対話的な入力を必要とし，どちらも明示的な非目標である． |
| `env` | map[string]string，任意 | 環境変数として `lego` に渡す，シークレットでないプロバイダ設定（例: `AZURE_ZONE_NAME`）．各値は 1 行（`\0`，`\r`，`\n` を含まない）で 4096 バイト以下． |
| `passthroughEnv` | []string，任意 | 実行時にそのまま `lego` に転送する **Runner プロセス** の環境変数の名前．プラットフォームが提供する資格情報（環境変数として公開されたマウント済みシークレット）が，このファイルに一切現れずに DNS プロバイダに届く仕組みである．パススルー変数が欠けている場合，`lego` を中途半端な設定で起動するのではなく，run を閉じた側に倒して失敗させる（`DnsFailure`）． |
| `propagationWaitSeconds` | int，`0`〜`3600` | 設定時（`> 0`），`lego` 自身の権威ネームサーバによる伝播確認を無効化し，固定の待機に置き換える． |
| `resolvers` | []string，任意 | `lego` が伝播確認に使う再帰リゾルバを上書きする．各要素は `"host:port"`． |

`env` と `passthroughEnv` は合わせて 64 エントリが上限である．環境変数名
（`env` と `passthroughEnv` のいずれでも）は `^[A-Z][A-Z0-9_]{0,63}$` に
一致しなければならず，**予約済み** の名前であってはならない．すなわち
`LEGO_` または `LD_` で始まるもの，あるいはちょうど `PATH`，`HOME`，`TMPDIR`
である．これらは `lego` 自身の設定やプロセスのロード方法を変えてしまうため，
バインディングは設定もパススルーもできない．同じ名前を `env` と
`passthroughEnv` の両方に置くことはできない．

### `storeBindings.<name>`

| フィールド | 型 | 備考 |
|---|---|---|
| `type` | string | store の種別名（`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`）．どの種別を提供するかは Runner バイナリが決める．公式バイナリは `filesystem`（開発・テスト用）と `azure-keyvault` を提供する．このバイナリが提供しない種別は，ジョブを処理する前の設定読み込み時に拒否される． |
| `config` | object | その種別の設定で，種別のプロバイダが厳密にデコードする（未知のフィールドは拒否，重複キーは拒否，それ以外は受け付けない）．内容は汎用の設定からは不透明であり，store の種別を追加してもここには何も加わらない． |

公式バイナリのプロバイダ設定:

**`type: filesystem`** — `config`:

| フィールド | 型 | 備考 |
|---|---|---|
| `directory` | string | クリーンな絶対パス．ファイルシステム store のルート．必須． |

**`type: azure-keyvault`** — `config`:

| フィールド | 型 | 備考 |
|---|---|---|
| `vaultURL` | string | vault のベース URL．`https://<vault-name>.vault.azure.net`（または `.vault.azure.cn` / `.vault.usgovcloudapi.net` 配下の同等のもの．これはそのクラウドの ID エンドポイントの選択も兼ねる）．それ以外は不可: ポート・パス・クエリ・フラグメント・資格情報を含まず，ホストはこれら 3 つのサフィックスのいずれかの下にあり，整形式の vault 名でなければならない．必須． |
| `credential` | string | Runner が Azure に認証する方法: `managed-identity`（プラットフォームのマネージド ID のみ．本番ではこれを使う）または `default`（SDK の `DefaultAzureCredential`．環境変数，ワークロード ID，マネージド ID，その後に開発者ツール `az`/`azd`/Azure PowerShell をこの順に試す．開発用）．省略時の既定値は `default`．資格情報の値がこのファイルに置かれることは決してない． |
| `managedIdentityClientId` | string | `credential: managed-identity` のときのみ．ユーザー割り当てマネージド ID のクライアント ID（GUID）．省略時はシステム割り当て ID を意味する． |

```json
"storeBindings": {
  "keyvault-prod": {
    "type": "azure-keyvault",
    "config": { "vaultURL": "https://kv-acme.vault.azure.net", "credential": "managed-identity" }
  }
}
```

### `jobSigning`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `publicKeys` | []string | —（必須） | 1〜8 個の Conductor 署名用公開鍵（Ed25519）．各要素は PEM の `PUBLIC KEY` ブロックか，その DER SubjectPublicKeyInfo の標準 base64（`acme-conductor keygen` が表示する 1 行の `publicKey:`）のいずれか．複数の鍵を置けるため，Conductor はここを同時に変更することなく鍵をローテーションできる．重複は拒否される． |
| `clockSkewSeconds` | int | `300` | エンベロープの `issuedAt` が，この Runner の時計よりどれだけ未来にあっても拒否しないか．有効期限には猶予がない．`1`〜`3600`． |

`jobSigning` が存在するとき，Runner は **両方向に厳密** である．素の
`CertificateReconcileJob` は拒否され（`InvalidJobSpec`，"signed job envelopes
only"），`SignedCertificateReconcileJob` は，その署名がこれらの鍵のいずれかで
検証でき，有効期間が現在を含み，かつその `runId` が過去に受け付けられて
いない場合にのみ処理される（[実行フロー](#実行フロー) を参照）．
`jobSigning` がないときは素の JobSpec だけを受け付け，エンベロープは
拒否される．Runner は検証できない署名を決して無視しない．どちらを使うかは
デプロイ上の判断である．1 台のホスト上でプライベートなディレクトリを介する
ローカルランチャーは未署名で動かしてもよい．共有ボリュームやプラットフォームを
介してジョブを渡すものはすべて署名しなければならない
（[ADR 0015](adr/0015-signed-job-envelope.md)）．

### `resultSigning`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `privateKeyFile` | string | —（必須） | `acme-runner keygen` で作った PEM の `PRIVATE KEY`（PKCS #8，Ed25519）ファイルのクリーンな絶対パス．Conductor に対する Runner の ID であり，DNS・Store・クラウドの資格情報では決してない． |
| `validitySeconds` | int | `3600` | 署名付き Result が発行後どれだけの間 Conductor に受け付けられるか．`1`〜`86400`． |

`resultSigning` が存在するとき，Runner はすべての Result（成功も失敗も）を
`SignedCertificateReconcileResult`
（[ADR 0015](adr/0015-signed-job-envelope.md)）で包む．厳密な署名付き
ヘッダの下に `Result` のバイト列そのものを置いたもので，stdout にも
Result ファイルにも同じものが出る．対応する公開鍵を設定した Conductor
（[`docs/conductor.md`](conductor.md#resultsigning)）はそれ以外を
受け付けず，これによって共有の交換用ボリュームへの別の書き手が Result を
すり替えたり改変したりできなくなる．Runner は閉じた側に倒れる．鍵を読めない
場合，素の成功を報告するのではなく run が失敗し（`Internal`，"result signing
key could not be loaded"），`lego` は実行されない．Phase 4 のデプロイでは
必須である．プライベートなディレクトリを介するローカルランチャーは
これなしで動かしてもよい．

### Container Apps Job として動かす

Phase 4 のデプロイ（[`deploy/azure`](../deploy/azure/README.md)）では，
Runner はユーザー割り当てマネージド ID を持つ Container Apps Job であり，
DNS と Key Vault の両方がこの ID で認証する．store バインディングは
`credential: managed-identity` を **その ID のクライアント ID を
`managedIdentityClientId` に設定した上で** 指定し（Bicep が注入する．
クライアント ID のないマネージド ID 資格情報はシステム割り当て ID を
要求するが，Job はそれを持たない），`azuredns` の DNS バインディングは
**`AZURE_AUTH_METHOD` を設定しない**．`lego` の `azuredns` プロバイダは
`AZURE_AUTH_METHOD=msi` では `ManagedIdentityCredential` をクライアント ID
なしで生成するため（`providers/dns/azuredns/credentials.go`，4.35 と 5.3 で
同じ），`AZURE_CLIENT_ID` が無視されてシステム割り当て ID が要求され，この
Job では失敗する．未設定なら `DefaultAzureCredential` の経路になり，
`AZURE_CLIENT_ID` が選ぶユーザー割り当て ID で認証する（`cert-infra` の
本番ジョブが同じ経路で動いている）．Container Apps は
`IDENTITY_ENDPOINT` と `IDENTITY_HEADER` の環境変数を通じて ID をコンテナに
公開する（また Job テンプレートは `AZURE_CLIENT_ID` に ID のクライアント ID
を設定する）．Runner は `lego` の環境をゼロから組み立てるため，DNS
バインディングはちょうどこれらの名前を転送しなければならない:

```json
"azure-dns-staging": {
  "provider": "azuredns",
  "env": {
    "AZURE_ZONE_NAME": "example.ac.jp",
    "AZURE_RESOURCE_GROUP": "rg-dns-example",
    "AZURE_SUBSCRIPTION_ID": "00000000-0000-0000-0000-000000000000"
  },
  "passthroughEnv": ["AZURE_CLIENT_ID", "IDENTITY_ENDPOINT", "IDENTITY_HEADER"]
}
```

ファイルに資格情報の値はない．`IDENTITY_HEADER` はローカル ID
エンドポイントのコンテナごとのトークンであり，他のすべてのパススルー値と
同様に Runner のログから秘匿される．

Job は固定コマンド `reconcile --exchange /exchange` で **スケジュール実行**
（毎分）され，Conductor から開始されることは決してない
（[ADR 0014](adr/0014-azure-container-apps-job-launcher.md)）．各実行は
差し出されたジョブを最大 1 つ取るか即座に終了し，Conductor のために
実行 ID（プラットフォームの実行名）を記録し，
`/etc/acme-runner/result-signing.pem` にマウントされた Result 署名鍵で
Result に署名する．
[`deploy/examples/runner-config.aca.example.json`](../deploy/examples/runner-config.aca.example.json)
がそのデプロイ向けの完全で検証済みの例である（パスは `/state` と `/work`，
`jobSigning` と `resultSigning` は必須）．

### 例

完全で検証済みの例は
[`deploy/examples/runner-config.example.json`](../deploy/examples/runner-config.example.json)
を参照（Let's Encrypt の **ステージング**，シークレットでない `env` だけを
持つ `azuredns` の DNS バインディング — Phase 3 以降はマネージド ID を
前提とするため `passthroughEnv` はない．代わりにサービスプリンシパルに対して
ローカル開発する場合は，`passthroughEnv` に `AZURE_CLIENT_SECRET` を加え，
Runner 自身の環境でそれを export する — さらに `/store` をルートとする
`filesystem` store と，システム割り当てマネージド ID で認証する
`azure-keyvault` store）．対応する `JobSpec` の例は
[`deploy/examples/job.example.json`](../deploy/examples/job.example.json)
にある．

## 実行フロー

1 回の `reconcile` 起動:

1. ジョブファイルを読む（上限 128 KiB．64 KiB の JobSpec を包む署名付き
   エンベロープの大きさ）．文書が `SignedCertificateReconcileJob` なら，
   エンベロープの構造を厳密にデコードし，そのペイロードから JobSpec の
   バイト列を取り出す．この時点ではまだ未検証である．まずそのバイト列から
   `runId` と `target.id` を緩く覗き見ておき，文書がこの後の検証や厳密な
   検証に失敗しても，その `runId` に対する `Result` を生成できるようにする．
2. Runner の設定を読み込む（厳密な JSON: 未知のフィールド，重複キー，末尾の
   余分なデータ，深すぎるネストは拒否．上限 256 KiB．JobSpec と同じデコーダ
   `internal/strictjson`）．
3. **署名付きエンベロープ**（Phase 4，[`jobSigning`](#jobsigning)）:
   `protected.payload` のバイト列そのものに対する Ed25519 署名を信頼された
   公開鍵（`kid` で鍵を選ぶ）で検証し，`expiresAt` が過ぎていないこと，
   `issuedAt` が `clockSkewSeconds` 以上先でないことを確認してから，
   `runId` をリプレイ台帳に記録する．台帳は `stateDir/jobs.d/` 配下の
   run ごとのマーカーファイルで，`stateDir/.jobs.lock` のロックの下で
   排他的に作成され，エンベロープの有効期限を保持する．有効期限に猶予を
   足した時刻を過ぎたマーカーは，その過程で削除される．すでに台帳にある
   run は拒否される（"already executed"）．ここでの失敗はすべて
   `InvalidJobSpec` であり，台帳の I/O の問題は `Internal` である．
   `jobSigning` が設定されていれば素の JobSpec はこのステップで拒否され，
   なければエンベロープが拒否される．その後にはじめて `JobSpec` を厳密に
   デコードして検証する（`v1alpha1.DecodeJobSpec` / `JobSpec.Validate`）．
   未知のフィールド，重複キー，末尾の余分なデータはすべて拒否される．
   これは文書の自己整合性の検査であり，認可ではない．
4. その設定から組み立てた `RunnerAuthorizationPolicy` で要求を認可する．
   既定で拒否，サフィックスはラベル境界で照合，ワイルドカードは
   `allowWildcard` で制御，3 つのバインディング名はすべて許可リストに
   照らして検査する．
5. 3 つのバインディング名（`acme`，`dns`，`store`）を
   `acmeBindings`/`dnsBindings`/`storeBindings` に対して解決する．認可された
   名前が定義されていなければ `BindingNotFound` で失敗する．
6. 解決した store バインディングの Certificate Store を開く．
7. FQDN に対する store のオブジェクト名（`Store.ObjectName`．命名規則は
   後述の各 store を参照）について，現在の証明書を store に問い合わせる
   （`Store.Current`）．
8. 何かする必要があるかを判断する．証明書が格納されており，その SAN
   リストが target の FQDN を含み，すでに有効で（`NotBefore` が時計のずれの
   許容範囲内），公開鍵がポリシーの `keyType` であり，`NotAfter` が依然として
   `now + renewBeforeDays` より後であれば，run はここで **noop** として
   停止する．`lego` は決して起動されない．そうでなければ（格納済みの
   証明書がない，SAN が FQDN を含まない，まだ有効でない，鍵の種別が
   `policy.keyType` と異なる — この run で適用されるポリシー変更 — または
   `renewBeforeDays` 以内に期限が来る）Runner は発行に進む．
9. run ごとのプライベートな作業ディレクトリ `<workDir>/run-<runId>-<rand>`
   を作成する（モード `0700`）．
10. `stateDir` の `accounts` サブツリーを作業ディレクトリにコピーし，
    既存の ACME アカウント登録があれば `lego` がそれを再利用できるように
    する．
11. `lego` の引数ベクトルと，ゼロから組み立てた環境を構築する（後述）．
12. `lego` を 1 度だけ，タイムアウト付きで，独自のプロセスグループで実行する．
    タイムアウトまたはキャンセル時にはグループ全体に `SIGTERM` を送り，
    猶予期間内に終了しなければ `SIGKILL` を続けて送る．出力は `os/exec` が
    駆動する writer シンクを通じて消費されるため，`lego` の出力パイプを
    継承した子孫（切り離されたヘルパー）が復帰を遅らせられる時間も同じ
    猶予期間で抑えられる．猶予期間の後はパイプを強制的に閉じ，実際の
    終了ステータスを使う．
13. （更新された可能性のある）`accounts` サブツリーを新しいバージョンとして
    `stateDir` に公開し，`accounts` リンクを付け替える（クラッシュ安全性を
    参照）．これは `lego` の成否にかかわらず行い，run をまたぐアカウントの
    継続性がこの run の結果に依存しないようにする．
14. `lego` が書いたものを検証する．証明書がパースでき，subject alternative
    name をちょうど 1 つ持ち，それが target の FQDN であること
    （ワイルドカードを考慮した照合はしない．`*.example.ac.jp` のジョブは
    SAN が文字通り `*.example.ac.jp` である証明書を生成しなければならない），
    秘密鍵が証明書の公開鍵と一致すること，鍵のアルゴリズムとサイズが
    要求された `keyType` と一致すること，証明書がすでに失効していないこと，
    `NotBefore` が 5 分以上未来でないこと．
15. 検証済みのバンドル（証明書，チェーン，秘密鍵）を Certificate Store に
    `Put` する．
16. 作業ディレクトリを破棄する（`defer` により，どの復帰経路でも常に
    実行される）．これが秘密鍵の唯一のローカルコピーを破棄する処理である．
17. `Result` を出力する．

報告される `action` は次の通り:

- **`issued`** — このオブジェクトについて store に証明書が以前存在しなかった．
- **`renewed`** — 証明書が以前存在し，新たに格納された証明書のフィンガー
  プリントがそれと異なる．
- **`noop`** — ステップ 8 の早期終了の場合（`lego` の起動なし），または
  原理的には，`lego` が起動されたが生成された証明書のフィンガープリントが
  格納済みのものと変わらなかった場合（実際には `lego` は発行のたびに新しい
  鍵を生成するのでこれは起きないが，Runner はそれを前提にしない）．

### `lego` の起動

引数ベクトルは，正確にこの順序で構築される（`internal/runner/lego`）:

```
<binary> --accept-tos \
  --email <acme.email> \
  --server <acme.directoryURL> \
  --dns <dns.provider> \
  --domains <target.fqdn> \
  --key-type <policy.keyType> \
  --path <workDir> \
  [--dns.propagation-wait <N>s] \
  [--dns.resolvers <a,b,...>] \
  [--eab] \
  run
```

`--dns.propagation-wait` と `--dns.resolvers` は DNS バインディングが
`propagationWaitSeconds`/`resolvers` を設定している場合にのみ現れる．
`--eab` は ACME バインディングが `eab` セクションを持つ場合にのみ現れる．
`JobSpec` の内容がシェル文字列に補間されることは決してなく，Runner は
決してシェルを起動しない．

環境はゼロから構築される（バインディングが明示的に名指ししたもの以外，
Runner プロセスから何も継承しない）:

```
HOME=<workDir>
TMPDIR=<workDir>
PATH=/usr/local/bin:/usr/bin:/bin
<dns.env，キー順にソート>
<dns.passthroughEnv の名前ごとに 1 エントリ，値は Runner 自身の環境から引く>
LEGO_EAB_KID=<acme.eab.kidEnv の値>        (eab が設定されている場合のみ)
LEGO_EAB_HMAC=<acme.eab.hmacEnv の値>      (eab が設定されている場合のみ)
```

EAB の素材は `lego` 自身の環境変数（`LEGO_EAB_KID`/`LEGO_EAB_HMAC`）を通じて
運ばれ，**決して** `argv` を通らないため，プロセス一覧には見えない．

## Certificate Store (ファイルシステム)

ファイルシステムの Certificate Store（`internal/store/filesystem`）は
ローカルディレクトリを後ろ盾とする．**ローカル開発とテスト専用である**．
[制限事項](#制限事項) を参照．

store の `directory` 配下のレイアウト:

```
<root>/<object>/versions/<fp16>-<nanos>/cert.pem
<root>/<object>/versions/<fp16>-<nanos>/chain.pem
<root>/<object>/versions/<fp16>-<nanos>/fullchain.pem
<root>/<object>/versions/<fp16>-<nanos>/privkey.pem
<root>/<object>/current -> versions/<fp16>-<nanos>        (シンボリックリンク)
```

`<fp16>` は証明書の SHA-256 フィンガープリントの先頭 16 桁の 16 進文字，
`<nanos>` は Unix ナノ秒のタイムスタンプであり，バージョンディレクトリは
整列可能で一意になる．`Put` は完全な新しいバージョンディレクトリ
（モード `0700`，ファイルはモード `0600`，すべて fsync 済み）を書き，その後に
はじめて 1 回の `rename` で `current` シンボリックリンクを差し替える．
そのため読み手は常に完全な旧バージョンか完全な新バージョンのどちらかを観測し，
書きかけを見ることは決してない．`Put` は操作全体にわたって排他的な
アドバイザリロック（`<object>/.lock`，`flock`）を保持するので，同じ
オブジェクトへの書き手は直列化される．最後にロックを取った書き手が勝ち，
差し替えの後に続く古いバージョンディレクトリの削除が，並行する書き手が
公開したばかりのバージョンを消すことは決してない．`Current` は同じロックを
共有モードで保持し，`current` リンクを 1 度だけ解決してその 1 つの
バージョンから両ファイルを読むため，読み手が差し替えをまたいだり，削除
途中のバージョンを観測したりすることはない．`Current` が `ErrNotFound` を
返すのは `current` リンクが存在しない場合だけである．リンク先やファイルが
欠けているリンク，オブジェクトディレクトリの外を指すリンク，欠けているか
`cert.pem` と一致しない `privkey.pem` は，空または健全な store としてではなく
エラーとして報告される．`Put` は鍵が証明書と一致しないバンドルを拒否する．

耐久性: ファイルデータを fsync し，次にバージョンディレクトリ，次に
バージョンを公開する rename の後に `versions` ディレクトリ，次に `current`
の差し替えの後にオブジェクトディレクトリを fsync する．fsync を尊重する
ファイルシステムでは，これによりプロセスのクラッシュと同様に電源断でも，
以前の完全なバージョンか新しいバージョンのどちらかが参照された状態が残る．

`<object>` は `store.ObjectName` により target の FQDN から導かれる．
人間が読める接頭辞（`wiki.example.ac.jp`，ワイルドカード名なら
`wildcard.example.ac.jp`）に，FQDN そのものの SHA-256 の先頭 8 バイト
（64 ビット）である 16 桁の 16 進文字の接尾辞を付けたものである．この接尾辞が，
ワイルドカード名と文字通り `wildcard` というホストとを区別し，同じ可読接頭辞に
切り詰められる 2 つの長い名前を互いに区別する．登録された 2 つの名前の衝突は
64 ビットでは実用上の懸念にならないが，不可能ではなく，その影響は 2 つの
target が 1 つの store オブジェクトを共有することである（可用性の障害であり，
鍵の漏洩では決してない）．

## Certificate Store (Azure Key Vault)

Azure Key Vault の Certificate Store（`internal/store/keyvault`，
バインディング種別 `azure-keyvault`，
[ADR 0013](adr/0013-azure-key-vault-store-adapter.md)）は，target ごとに
1 つの Key Vault **証明書** を保持する．実際のデプロイ向けの store である．
vault は利用者が（証明書のシークレットを通じて）証明書を読み出す場所であり，
独自のアクセス制御と監査を持ち，Runner 自身の vault へのアクセスは狭く
短命である．この store が書くのは **PEM** の証明書であり，どの利用者がそれを
使えるかは後述の [利用者とコンテンツタイプ](#certificate-store-azure-key-vault) に
まとめる．

**オブジェクト名．** Result の `storeObjectRef` は Key Vault の証明書名である．
Key Vault は証明書名に英字・数字・ハイフンのみ（127 文字以下）を許すため，
論理的な `store.ObjectName` はその制約の下で導かれ，`.` と `_` はすべて `-`
になる．`wiki.example.ac.jp` は `wiki-example-ac-jp-<16 hex>` として，
`*.example.ac.jp` は `wildcard-example-ac-jp-<16 hex>` として格納される．
16 桁の 16 進文字の接尾辞はファイルシステム store と同じ，FQDN そのものの
SHA-256 の接頭部分であるため，可読部分だけが異なる 2 つの名前も別々の
証明書に対応する．

**`Put` が行うこと．** バンドルをローカルで検証した後（証明書がパースでき，
秘密鍵がそれと一致し，チェーンが証明書のみを含む），Runner は秘密鍵を
暗号化なしの PKCS #8 に再エンコードし（`lego` は EC 鍵を SEC 1 で書く），
リーフ + チェーン + 鍵を 1 つの PEM 文書に連結して，vault の
*import certificate* 操作を呼ぶ（`POST /certificates/<name>/import`，
コンテンツタイプ `application/x-pem-file`，タグ `managed-by=acme-conductor`，
有効化済み）．Key Vault は鍵を自身の鍵ストアに保持し，証明書の新しい
*バージョン* を作成し（その名前の既存の証明書は決して上書きされず，以前の
バージョンは読み取り可能なまま残る），証明書のシークレットを通じて利用者に
証明書を公開する．続いて Runner は vault が報告する証明書が取り込んだもの
（同じ SHA-256 フィンガープリント，同じ名前）であることを確認し，そうで
なければ run を失敗させる．PFX も PFX パスワードもどの時点でも関与しない．

**利用者とコンテンツタイプ．** この store はコンテンツタイプ
`application/x-pem-file` でのみ取り込むため，証明書のシークレットは証明書
チェーンと秘密鍵を PEM として保持する．これは `secrets/get` でシークレットを
読み，PEM の内容を受け付ける利用者に役立つ．自らシークレットを取得する
アプリケーションやサイドカー，Key Vault 参照を通じてシークレットを受け取る
仮想マシンやコンテナ，そして Key Vault 連携が PEM を受け付けるあらゆる
サービスである．PKCS #12（`application/x-pkcs12`）を必要とする組み込みの
Key Vault 連携には役立た **ない**．
[App Service](https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-certificate#import-a-certificate-from-key-vault)
は vault から PKCS #12 の証明書だけを取り込み，
[Azure Front Door](https://learn.microsoft.com/en-us/azure/frontdoor/domain#certificate-requirements)
は PFX を必要とする（そして EC 証明書をまったく受け付けない）．証明書を
これらのサービスに届けなければならない target には PKCS #12 での取り込みが
必要だが，Phase 3 では実装していない（システム内に PFX も PFX パスワードも
存在しない．[ADR 0013](adr/0013-azure-key-vault-store-adapter.md)）．
この store が管理する証明書を利用者に向ける前に，その利用者自身の文書で
コンテンツタイプと鍵種別の要件を確認すること．Application Gateway は
どちらとも検証していない．

**`Current` が行うこと．** `GET /certificates/<name>/` — 証明書の現在の
バージョンで，*公開部分のみ*（`cer`，属性）．Key Vault はこの呼び出しに
`certificates/get` 権限で応答する．秘密鍵は `secrets/get` の背後にあり，
Runner はこれを決して呼ばず，付与してはならない．証明書がない場合
（HTTP 404．論理削除された証明書も同じ応答を返す）は「何も格納されていない」
であり，発行に進む．存在するが *無効化されている*，本体がない，あるいは
要求したものと異なる証明書はエラー（`StoreFailure`）であり，決して不在とは
扱わない．vault で証明書を無効化するのは操作者の判断であり，Runner が新しい
証明書を発行してそれを覆い隠してはならない．

**権限．** Runner の ID に必要なのは vault に対する `certificates/get` と
`certificates/import` のちょうど 2 つである．Azure RBAC では組み込みの
*Key Vault Certificates Officer* ロールがこれにあたる（必要以上の権限を
含むため，この 2 つのデータアクションだけを持つカスタムロールのほうが
厳密である）．`secrets/*`，`keys/*`，およびいかなる purge 権限も必要なく，
持つべきでない（Runner は決して削除しない．
[ADR 0008](adr/0008-no-purge-in-mvp.md)）．利用者は証明書のシークレットに
対する `secrets/get` で証明書を読む．Conductor の ID には vault に対して
何も付与しない（[ADR 0005](adr/0005-conductor-never-touches-secrets.md)）．

**論理削除．** Key Vault は既定で論理削除する．同じ名前の証明書が削除され
まだ purge されていない場合，vault は取り込みを拒否する（`HTTP 409 Conflict`，
コード `Conflict` / `ObjectIsDeletedButRecoverable`）．run は `StoreFailure`
で失敗し，操作者が削除済みの証明書を復旧するか purge する．Runner は
どちらも決して行わない．

**認証とネットワーク．** すべての要求は TLS で vault 自身のホストへ送られる．
設定はそのホストが既知の Key Vault DNS サフィックスのいずれかの下にあることを
要求し，SDK の認証チャレンジポリシーも，トークンを送る前に vault がトークンを
要求するリソースがそのホストと一致することを検証する．トークンは選択した
`credential`（[`storeBindings.<name>`](#storebindingsname) を参照）から
得る．`managed-identity` では Runner は vault とプラットフォームの ID
エンドポイント（IMDS，またはプラットフォームが環境に注入する ID エンド
ポイント）だけと通信する．`default` では `DefaultAzureCredential` チェーンが
さらに Runner 自身の環境の `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` /
`AZURE_CLIENT_SECRET` / `AZURE_FEDERATED_TOKEN_FILE` 変数を読み，
`login.microsoftonline.com`（または選択したクラウドの authority）に接続し，
Runner の `PATH` から `az`，`azd`，`pwsh` を実行することがある．Runner の
コンテナイメージにはこれらのプログラムは 1 つも含まれておらず，本番の
バインディングはそのどれも試みられないよう `managed-identity` を指定すべき
である．vault のエラー応答はログ行に達する前に HTTP ステータスとエラー
コードに切り詰められ（`key vault get: HTTP 403 (Forbidden)`），ID エンド
ポイントのエラー応答も同様にステータスに切り詰められる（後述の **エラー**
を参照）．応答本文・ヘッダ・トークンは決してログに出ず，他のすべての失敗と
同様に固定のテンプレートだけが `Result` に達する．

**エクスポート可能な鍵．** 取り込まれた証明書の鍵は，そのシークレットを
通じてエクスポート可能である．これが利用者が証明書を得る方法であり，vault を
store として使う目的である．vault に対する `secrets/get` を持つ者は誰でも
秘密鍵を読めるため，それが誰かを決めるのは vault のアクセスポリシー／ロール
割り当てであって，このコードではない．

**エラー．** SDK やトランスポートが何を生成しようと，store はそれがログ行や
`Result` の cause に達する前に固定の文言に切り詰める．vault の応答は
`key vault <op>: HTTP <status> (<code>)` に，トークン取得の失敗は
`key vault <op>: authentication failed (identity endpoint HTTP <status>)`
または `(credential unavailable)` になり，SDK 自身のエラーが表示する ID
エンドポイントの応答本文は決して含まない．トランスポートの失敗は
`request timed out` または `connection failed`（URL なし）になり，それ以外は
エラーの Go の型名だけを示す．キャンセルまたは期限切れの run は依然として
Runner が認識する（`Cancelled`/`Timeout`）．

**自動テストで扱わないこと．** この store は REST API の形を模倣する
プロセス内の偽物の vault（ベアラーチャレンジ認証，PEM 取り込みの検証，get，
エラー本文）に対して試験され，原則 8 に従い本物の vault に対しては決して
試験されない．したがって実際の取り込み操作の正確な受け入れ規則（PEM の
レイアウト，PKCS #8 の鍵，チェーンの扱い）はサービスの文書に基づいて記述
されているのであって，CI で検証されたものではない．本物の vault に対する
最初の実行がその検証となる．

## ディレクトリとコンテナでの利用

`Dockerfile.runner` の実行時イメージ
（`gcr.io/distroless/static-debian12:nonroot`，uid/gid `65532`，シェルなし）
の内部:

| パス | 用途 |
|---|---|
| `/usr/local/bin/acme-runner` | Runner のバイナリ（エントリポイント）． |
| `/usr/local/bin/lego` | バージョン固定しチェックサム検証済みの `lego` v4.35.2 バイナリ（[ADR 0010](adr/0010-pinned-lego-binary.md) を参照）． |
| `/etc/acme-runner/config.json` | Runner の設定．**読み取り専用** でマウントする． |
| `/work` | `lego.workDir`．書き込み可能な `tmpfs`/`emptyDir` でなければならない．証明書の秘密鍵はここに 1 回の run の間だけ一時的に存在する． |
| `/state` | `lego.stateDir`．書き込み可能で **永続的な** ボリュームでなければならない．ACME アカウントの鍵と登録，および Phase 4 以降はリプレイ台帳（`jobs.d/`）だけを保持し，証明書の秘密鍵は決して置かれない． |
| `/store` | `filesystem` store のルートの例（開発・テスト専用）． |

イメージは `--read-only` / Kubernetes の `readOnlyRootFilesystem: true` に
対応する．上記の書き込み可能なパスはすべて呼び出し側が明示的なマウントとして
供給するもので，イメージには焼き込まれていない．

例:

```sh
docker run --rm \
  --read-only \
  --tmpfs /work \
  -v acme-runner-state:/state \
  -v $PWD/runner-config.json:/etc/acme-runner/config.json:ro \
  -v ./in:/input:ro \
  -v ./out:/output \
  -v acme-runner-store:/store \
  ghcr.io/cits-nue/acme-runner:dev \
  reconcile --job /input/job.json --result /output/result.json
```

## Result とエラーコード

`Result`（`CertificateReconcileResult`）は常に 1 行の JSON として stdout に
表示され，`--result` が指定されていればそのパスにアトミックに書き出される．
成功時は `action`（`issued`/`renewed`/`noop`），`expiresAt`，
`fingerprintSha256`，`storeObjectRef` を持つ．失敗時は
`error: { code, summary }` を持ち，それ以外では `error` は `null` である．
フィールドの全一覧は
[コントラクト](architecture.md#certificatereconcileresult-result) を参照．

`error.summary` は `lego` の生の出力，コマンドライン，環境変数のダンプでは
**決して** なく，Runner が所有する少数のテンプレートからのみ生成される．
テンプレート化された要約自体が `Result` のコントラクトに違反する場合
（たとえば攻撃者が制御する FQDN がたまたまシークレットのマーカーに似た
部分文字列を含む場合），Runner はコード固有の汎用的な要約にフォールバック
し，`Result` は常に生成される．

| `error.code` | 条件 | 要約テンプレート（省略形） |
|---|---|---|
| `InvalidJobSpec` | ジョブ文書が厳密なデコード／検証に失敗した． | `job spec rejected: <validation error>` |
| `PolicyViolation` | `RunnerAuthorizationPolicy.Authorize` が要求を拒否した． | `runner authorization policy rejected the job: <reason>` |
| `BindingNotFound` | 認可されたバインディング名が Runner の設定に定義されていない． | `<kind> binding "<name>" is not defined in runner configuration` |
| `DnsFailure` | DNS バインディングの `passthroughEnv` 変数が Runner 自身の環境に設定されていない． | `dns binding "<name>" requires an environment variable that is not set` |
| `AcmeFailure` | ACME バインディングの EAB の `kidEnv`/`hmacEnv` 変数が設定されていない． | `acme binding "<name>" requires EAB credentials that are not set` |
| `AcmeFailure` | `lego` が非ゼロのステータスで終了した． | `lego exited with status <n>` |
| `AcmeFailure` | `lego` が `0` で終了したが，読める証明書／鍵ファイルを書かなかった． | `lego exited successfully but produced no usable certificate` |
| `AcmeFailure` | `lego` が書いた証明書をパースできなかった． | `lego produced an unreadable certificate` |
| `AcmeFailure` | 発行された証明書の SAN リストが target の FQDN を正確に含んでいない． | `issued certificate does not cover the target fqdn` |
| `AcmeFailure` | 発行された証明書と `lego` が書いた秘密鍵が一致しない． | `issued certificate and private key do not match` |
| `AcmeFailure` | 発行された証明書がすでに失効している． | `issued certificate is already expired` |
| `StoreFailure` | Certificate Store を開けなかった，読めなかった（`Current`），または書けなかった（`Put`）． | `certificate store could not be opened` / `... read failed` / `... write failed` |
| `Timeout` | `lego` が `lego.timeoutSeconds` 以内に終わらなかった． | `lego did not finish within <n> seconds` |
| `Cancelled` | `lego` の起動前または実行中，あるいは store／状態のロック待ちの間に，run がシグナルでキャンセルされた． | `run was cancelled before lego started` / `... while lego was running` / `run was cancelled by signal while waiting for …` |
| `Internal` | 設定を読み込めなかった，作業ディレクトリを準備できなかった，ACME アカウントの状態を読めなかった，環境変数の欠落以外の理由で `lego` の起動を組み立てられなかった，または `lego` を開始すらできなかった． | 例: `runner configuration could not be loaded` |

## ログと秘匿

ログは stderr への構造化 JSON で，常に UTC であり，判明した時点から
`runId` / `targetId` を持つ．`lego` の stdout/stderr の各行は，秘匿処理の
後，ストリームごとに **debug** レベルでログに記録される:

- Runner がシークレットとみなす値（解決済みの `passthroughEnv` の値，または
  EAB の `kid`/`hmac` の値．長さを問わない）は，行中に現れるすべての箇所で
  `[REDACTED]` に置き換えられる．長い値は，それに含まれる短い値より先に
  マスクされる．非常に短い値は debug レベルの lego 出力の可読性を損なうが，
  漏洩には決してならない．
- PEM ブロックはストリームごとに状態を持って抑制される．`-----BEGIN ...-----`
  行は `[REDACTED PEM]` に置き換えられ，それに続く `-----END ...-----` 行
  までの各行（その行を含む）は捨てられるため，鍵の base64 本体がログに
  達することは決してない．`PRIVATE KEY` という文字列を含む行も丸ごと
  置き換えられる．
- 残りの表示不能文字（Unicode の行区切り／段落区切りを含む）は `?` に
  置き換えられ，`lego` からの悪意ある行が追加のログレコードやターミナル
  エスケープを注入できないようにする．
- 8 KiB を超える行は切り詰めて記録される（`"truncated":true` 付き）．
  行の残りは読んで捨てられるため，`lego` がどれだけ出力しようとパイプが
  満杯になってブロックすることは決してない．

`lego` の終了後，1 行の要約（`exitCode`，`durationMs`，`timedOut`，
`cancelled`）が info/error レベルで記録される．**`lego` の生の出力が
`Result` に達することは決してない**．上記の固定テンプレートだけが達する．

この秘匿は **値ベースかつヒューリスティック** である．Runner 自身が解決した
特定のシークレット値と既知の PEM マーカーをマスクするのであって，任意の，
あるいは未知の形式のシークレットをマスクするのではない．コードベースの
残りのログ文にわたる専用の秘匿テストスイートは依然として Phase 3 以降の
作業である（[`docs/threat-model.md`](threat-model.md) を参照）．

## セキュリティ境界

- HTTP サーバも cron もデータベースもない．1 つのジョブ，1 つのプロセス，
  1 回の終了．
- **署名付きジョブが証明するのは誰が作ったかであって，実行すべきかでは
  ない．** `jobSigning` があれば，Runner はバインディングを解決する前に
  改竄・期限切れ・リプレイされたエンベロープを拒否する．取り出された
  `JobSpec` はその後，未署名のものとまったく同様に信頼された設定に照らして
  検証・認可される．Runner が持つのは公開鍵だけであり，別の Runner が
  信頼するジョブを作ることはできない．
- Runner に必要なのは，`JobSpec` が選択しそのバインディングが名指しする
  ちょうど 1 つの store バインディングに対する store の **読み取り**
  （更新判断のため）と **書き込み**（新しいバンドルの格納のため）だけである．
  それ以外は不要である．Key Vault ではそれは `certificates/get` と
  `certificates/import` であり，Runner は秘密鍵を決して読み戻さず
  （`secrets/get`），決して削除しない．
- `lego` は常に明示的な `argv` で起動され，シェル文字列は決して使わない．
  その環境はゼロから構築され，バインディングが宣言した `env`/`passthroughEnv`
  を通じる以外に Runner プロセスから継承されることは決してない．
- `lego` サブプロセスはタイムアウト付きで独自のプロセスグループで動く．
  まずグループ全体に `SIGTERM` を送り，必要なら猶予期間（既定 10 秒）の後に
  `SIGKILL` が続き，run の終了時にグループを再度 kill するため，グループに
  留まるヘルパープロセスが run より長生きすることはできない．グループを
  離脱した子孫（`setsid`）はプロセスグループの kill の届く範囲外である．
  猶予期間はそれが Runner を遅らせられる時間を依然として抑えるが，実際に
  それを封じ込めるのは PID 名前空間（run ごとに 1 コンテナ）だけである．
- ステージング／テスト／ローカルと認識されない ACME ディレクトリは，ACME
  バインディングが `allowProductionCA: true` を設定しない限り拒否される
  （上記の規則を参照）．
- `RunnerAuthorizationPolicy` は既定で拒否である．空または未設定の許可
  リストは何も認可しない．
- 自動テストは本物の ACME CA や本物の DNS プロバイダを決して呼ばない．
  テストは `internal/runner/fakelego` に対して実行される．これは `lego` の
  観測可能なファイル／終了コードの振る舞いをネットワークアクセスなしで
  模倣するテストダブルである（Phase 1 は
  [`docs/architecture.md`](architecture.md#セキュリティ原則) の原則 8 を
  強制する）．
- **並行性について正確に．** ディスク上の 2 つの store は 1 台のホスト上で
  並行安全である．アカウント状態の公開と run 開始時のコピーインは
  `stateDir/.lock` のアドバイザリ `flock` で直列化され（公開側は排他，
  読み手は共有），ファイルシステムの Certificate Store もオブジェクトごとに
  同じことを行う．*Runner が* 提供し *ない* のは run レベルの排他である．
  同じ target に対する 2 つの Runner プロセスは依然として両方とも `lego` を
  実行し，2 つの ACME オーダーを出し，DNS チャレンジで競合しうる．
  Conductor の run レジストリとスケジューラは，自身が起動する run について
  その排他を提供する（Phase 2．
  [`docs/conductor.md`](conductor.md#run-のライフサイクルとスケジューリング)
  を参照）．それはこれらの store の性質ではなく，他の手段で開始された
  Runner はその対象外である．
- **ロックとキャンセル．** ロックの取得はカーネル内で決してブロックしない．
  run のコンテキストを尊重しつつ，10〜100 ms のバックオフで非ブロッキングの
  `flock` を再試行する．そのため別の Runner がロックを保持している間に
  受け取った SIGTERM/SIGINT は，ハングしたり `Internal`/`StoreFailure` を
  報告したりするのではなく，`Cancelled` の Result（呼び出し側の期限が過ぎて
  いれば `Timeout`）で run を速やかに終わらせる．キャンセルされた run の
  後もアカウント状態は独自の 30 秒の上限の下で公開されるため，kill された
  `lego` が登録したアカウントは失われない．
- **ロックの意味論**（`internal/fslock`）: アドバイザリ，ホストローカル，
  `O_NOFOLLOW` で開いた 0600 のロックファイル上で保持（あらかじめ仕込まれた
  シンボリックリンクは拒否される）．保持者が終了するか記述子を閉じるとカーネルが
  解放するため，クラッシュした保持者が古いロックを残すことはない．開いた
  ファイル記述ごとに 1 つのロック．共有ロックが排他に昇格されることは
  決してない．ネットワークファイルシステム（NFS，SMB）での `flock` の
  振る舞いはさまざまなので，これらの store はローカルファイルシステム向け
  である．`stateDir` をネットワークマウントに置くデプロイは，まずそこでの
  `flock` の意味論を検証しなければならない．
- **アカウント状態のレイアウトは厳密で，`stateDir` に閉じている．**
  すべての読み手と書き手が最初に検査する不変条件（`validateAccountsLayout`．
  `Lstat` を使うのでリンクはリンクとして見え，決して辿られない）:

  ```
  stateDir/accounts.d/        存在しないか，実ディレクトリ (決してリンクではない)
  stateDir/accounts.d/<v>/    実ディレクトリ．<v> は <unix-nanos>-<8 hex>
  stateDir/accounts           存在しないか，リンク先が正確に相対パス
                              accounts.d/<v> であるシンボリックリンク
  ```

  `accounts.d` がリンクやファイルであること，`accounts` が通常のディレクトリ
  であること（`ErrLegacyAccountsLayout`．`rename` だけではクラッシュ安全に
  できないため，その場での移行は試みない），そして `accounts` のリンク先が
  絶対パス，外へ抜ける（`../outside`），宙ぶらりん，奇妙な名前，または
  リンク型であることは，すべて拒否される（`ErrAccountsCorrupt`）．その場合
  run は `lego` の開始前に `Internal` で失敗し，作業ディレクトリには何も
  コピーされず，`stateDir` の外のいかなるパスにも書き込みも削除も行われない．
  `accounts.d` は検査の後に通常の `Mkdir` で作成され，削除はバージョン形式に
  名前が一致する実ディレクトリだけを対象とする．壊れた状態が初回実行のように
  見えることは決してない．そうなれば新しい ACME アカウントを黙って登録して
  しまうからである．
- **レイアウト検査が扱わないこと．** これは `stateDir` を所有するのと同じ
  ユーザーによる，ある時点での検査である．同じ UID を持つプロセスがこれと
  競合する（検査と書き込みの間に `accounts.d` をリンクに置き換える）ことは
  Phase 1 の脅威モデルの範囲外であり，脅威モデルは Runner のユーザーが
  所有するローカルファイルシステムを前提とする．

## クラッシュ安全性

- run ごとの作業ディレクトリは，すべての通常の終了経路で遅延クリーンアップ
  により削除される．捕捉不能なシグナル（SIGKILL，OOM）で kill された
  Runner はそれを実行できないため，各起動時にも `workDir` 配下の期限を
  過ぎた `run-*` ディレクトリを掃除する．各 run は作成時に自身の期限
  （now + 2 × `lego.timeoutSeconds` + 終了猶予期間 + 5 分の余裕）を
  ディレクトリ内の `.sweep-after` ファイルに記録し，掃除はそのファイルを
  尊重するため，1 つの `workDir` を共有する異なるタイムアウトの Runner が
  互いの生きている run を掃除することは決してない．ファイルのない
  ディレクトリは，その更新時刻に掃除する Runner 自身の閾値を足した時刻に
  フォールバックする．`workDir` はコンテナと共に消える tmpfs/emptyDir として
  マウントし，何も残らないようにすること．
- ACME アカウントの状態は `stateDir/accounts.d/` 配下のバージョン付き
  ディレクトリとして公開され，`stateDir/accounts` は 1 回の `rename` で
  差し替えられるシンボリックリンクである．古いバージョンはその後に削除
  される．ファイル，バージョンディレクトリ，`accounts.d`，最後に `stateDir`
  の順に fsync されるため，プロセスのクラッシュでも電源断でも，`accounts` が
  存在しなかったり不完全なバージョンを指したりすることはない．公開は
  `stateDir/.lock` の排他ロックの下で行われ，run 開始時のコピーインはそれを
  共有モードで保持するため，`stateDir` を共有する並行 Runner は状態そのもの
  について直列化され（最後の公開者が勝つ），読み手が削除中のバージョンを
  コピーすることはない．
- ファイルシステム store は，オブジェクトまたは `versions` の階層で
  シンボリックリンクを通じた書き込みを拒否し，オブジェクトごとに
  アドバイザリロックで `Put` を直列化し，そのロックの下でのみ削除を行うため，
  並行する書き手が `current` を宙ぶらりんにすることはできない（上記の
  Certificate Store を参照）．
- `NotBefore` が 5 分以上未来にある証明書は，lego が生成した時点で拒否され
  （`AcmeFailure`），store で見つかった場合は使用不能として扱われ再発行される．

## 制限事項

- ファイルシステムの Certificate Store は **ローカル開発とテスト専用** である．
  ファイルシステムの権限以外に独自のアクセス制御を持たず，本物のシークレット
  ストアの代替にはならない．それ以外の用途には Azure Key Vault store を使う
  こと．
- Key Vault store は本物の vault ではなく，vault API のプロセス内の偽物に
  対して試験されている（原則 8）．実際の取り込み操作に対する振る舞いは
  文書化されているが，CI で検証されてはいない．取り込みを妨げる論理削除
  済みの証明書を復旧も purge も決して行わず，自身の ID のロール割り当てが
  文書通りに狭いことを検証することもできない．
- Key Vault store は PEM のみを書く．App Service と Azure Front Door の
  組み込みの Key Vault 連携は PKCS #12 を必要とし，この store では役立たない．
  PKCS #12 での取り込みは Phase 3 の範囲外である
  （[利用者とコンテンツタイプ](#certificate-store-azure-key-vault) を参照）．
- `credential: default` では，SDK の `DefaultAzureCredential` チェーンが
  Runner の環境からサービスプリンシパルの変数を読み，`PATH` から開発者
  ツールを実行することがある．これは開発上の利便性であって本番の姿勢では
  ない．`managed-identity` を指定すること．
- claim モードでジョブを取る操作のアトミック性は，交換用ボリューム上で
  ディレクトリの rename がアトミックであることに依存する．SMB 共有では
  そうであると期待されるが，最初の実際のデプロイでしか検証されない
  （[`deploy/azure/README.md`](../deploy/azure/README.md)）．
- Runner 自体には run レベルの並行制御がない．同じ target に対する 2 つの
  Runner プロセスは両方とも発行しうる（二重発行，ACME レート制限の消費）．
  ファイルシステム store とアカウント状態はそれに耐える（最後の書き手が
  勝つ）．Conductor（Phase 2）は自身が起動する run についてはこれを防ぐ
  （target ごとにアクティブな run は最大 1 つ）が，手動や別のランチャーで
  開始された Runner については防がない．
- リプレイ台帳は `stateDir` ごとである．別々の状態ディレクトリを持つ
  Runner は互いに受け付けた run を見ず，`jobSigning` のない Runner には
  有効期限やリプレイの検査がまったくない（素の JobSpec はどちらも持たない）．
  台帳のロックにはアカウント状態と同じネットワークファイルシステムの注意
  事項がある．
- 署名は生成者の *判断* を検証しない．署名鍵を持つ Conductor はどんな名前の
  ジョブにも署名できる．それを限定するのは信頼された認可ポリシーである
  （`docs/threat-model.md`，T1）．
- Runner には，渡された DNS の資格情報／ワークロード ID が実際に必要な
  チャレンジゾーンに限定されているかを検証する手段がない．その限定は各
  `DnsBinding` をどうプロビジョニングするかという運用上の要件であり，
  このコードが検査できるものではない．
- `lego` 出力のログ秘匿は値ベースかつヒューリスティック（既知のシークレット
  値，既知の PEM マーカー）であり，汎用のシークレット検出器ではなく，この
  パッケージの外にはまだ専用のテストスイートがない．
- Container Apps のデプロイ（Phase 4）は偽物とコンパイル済み Bicep に対して
  試験されており，本物のサブスクリプションに対してではない．Container Apps
  の ID エンドポイントを通じた `lego` の `azuredns` プロバイダのマネージド
  ID 認証と，プラットフォームの実行テンプレート上書きは，最初のデプロイが
  確認するまでは文書上の期待である（`deploy/azure/README.md`）．上記の
  コマンドラインが示すように，`JobSpec` を手動で生成し `Result` を手動で
  消費することは依然として可能である．
