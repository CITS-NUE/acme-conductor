# Conductor 運用ガイド

本書は，[`docs/architecture.md`](architecture.md) で説明するコントロールプレーン
`acme-conductor` の操作者向けリファレンスである．コマンドライン，設定ファイル，
REST API と GUI，`Target` がどのように `Run` になり `Run` がどのように完了まで
駆動されるか，2 つの認証モード，ディスク上の状態とそのバックアップ方法，そして
現時点で Conductor が保証すること・しないことを扱う．

Phase 2 では Conductor の MVP を出荷した．target・ポリシー・run・監査イベントを
SQLite に保持するレジストリ，REST API，スケジューラ，そして `acme-runner`
（[`docs/runner.md`](runner.md) を参照）を子プロセスとして動かすローカルプロセスの
ランチャーであり，**単一ホスト・単一ユーザーの開発およびテスト用デプロイ** である．
Phase 4 では第 2 のランチャー `azure-container-apps-job` が加わる．これは run ごとに，
別途プロビジョニングされた Azure Container Apps Job の実行を 1 つ開始する
（Runner は自身のマネージド ID を持ち，資格情報が Conductor を経由することは
決してない）．さらに **ジョブ署名** が加わる．どのランチャーも Runner に生の
`JobSpec` ではなく署名付き・期限付きのエンベロープを渡すことができ，Container Apps
ランチャーは常にそうする．Phase 5 では本番の認証モード `oidc` が加わる．OpenID
Connect プロバイダのベアラートークン，名前付きプリンシパル，admin と viewer の
ロール，TLS リスナーまたはその前段のプラットフォーム ingress である．さらに
Conductor 自身が配信する最小限の **GUI** が加わる（[認証](#認証)と [GUI](#gui) を
参照）．`localhost-dev` モードは開発ホスト 1 台向けに残る．Phase 6 では
**移行ツール** が加わる．既存のインフラ定義のホスト一覧を読み，レジストリと比較して
足りないものを取り込む `migrate` コマンドと API，および操作者が切り替えるまで
Conductor に何も発行させない `migration.targetSource` フラグである
（[`docs/migration.md`](migration.md) と [`migration`](#migration) を参照）．

## 概要

`acme-conductor serve` は 1 つのプロセスで次を動かす:

- **REST API**（`/api/v1alpha1/...`，および `/healthz` と `/readyz`）と
  **GUI**（`/ui/`）．`localhost-dev` モードではループバックアドレスで，`oidc`
  モードでは設定で指定した場所で待ち受ける．
- **レジストリ** — `Target`，`CertificatePolicy`，`Run`，追記専用の `AuditEvent`
  ログ — を 1 つの SQLite ファイルに保持する．
- **スケジューラ**．`tickSeconds` ごとに（および API が何かを変更するたびに），
  有効で期限到来したすべての target について待機中（queued）の `Run` を記録し，
  待機中の run をランチャーを通じて一度に `maxConcurrentRuns` 個まで開始する．
- 設定された実行バインディングごとに 1 つの **ランチャー**．`local-process` は
  `acme-runner reconcile` を子プロセスとして動かし，`azure-container-apps-job` は
  Container Apps Job の次のスケジュール実行にジョブを差し出す
  （[実行バインディング: Azure Container Apps Job](#実行バインディング-azure-container-apps-job) を参照）．

Conductor が ACME CA，DNS プロバイダ，Certificate Store と通信することは決してない．
Conductor は `JobSpec` を生成し `Result` を消費する．証明書について Conductor が
知っていること（有効期限，フィンガープリント，論理的な store 名）はすべて，最後に
成功した `Result` が伝えた内容である．

## コマンドライン

```
acme-conductor serve [--config FILE] [--log-level LEVEL]
acme-conductor keygen --private FILE --public FILE
acme-conductor migrate (list|diff|import) [flags]
acme-conductor --version
acme-conductor --help
```

`migrate` は Bicep のパラメータファイルまたは TargetList 文書からホスト一覧を読み，
稼働中の Conductor のレジストリと API 経由で比較し，レジストリにない名前を取り込む
（`--apply` を指定しない限り dry-run）．
[`docs/migration.md`](migration.md#コマンドライン) に説明がある．

`keygen` は[ジョブ署名](#jobsigning)用の Ed25519 鍵ペアを生成する．秘密鍵は
`--private` に書き込まれ（`0600` で作成．既存のファイルを上書きすることは決して
ない），公開鍵は `--public` に PEM で書き込まれ，鍵 ID と公開鍵の 1 行形式が
Runner の `jobSigning.publicKeys` に貼り付けるために出力される．設定は不要で，
それ以外には何も触れない．

- `--config FILE` — 設定文書のパス．既定は `$ACME_CONDUCTOR_CONFIG` が設定されて
  いればその値，そうでなければ `/etc/acme-conductor/config.json`．
- `--log-level LEVEL` — `debug`，`info`（既定），`warn`，`error` のいずれか．
  `debug` では Runner 自身のログ行（Runner がすでに秘匿処理済み）が Conductor の
  ログに中継される．

`serve` は `SIGTERM` または `SIGINT` を受け取るまで動き続ける．受け取ると API
リクエストの受け付けを止め，新しい run の計画を止め，実行中の run を最大
`server.shutdownGraceSeconds` まで待ち，まだ動いているものをキャンセルし
（Runner は `Cancelled` を報告する），終了する．2 回目のシグナルでプロセスは
即座に強制終了される．[シャットダウンと復旧](#シャットダウンと復旧)を参照．

### 終了コード

| コード | 意味 |
|---|---|
| `0` | シグナルを受けて正常に停止した． |
| `1` | 設定が拒否された，設定からランチャーを構築できなかった，`localhost-dev` モードで待ち受けアドレスがループバックでなかった，または TLS 証明書を読み込めなかった． |
| `2` | 致命的な実行時エラー: 別の Conductor プロセスがデータベースを所有している（[シャットダウンと復旧](#シャットダウンと復旧)を参照），レジストリを開けないか移行できない，実行中だった run を復旧できない，リスナーをバインドできない，または HTTP サーバが失敗した． |

## 設定リファレンス

設定は厳密にデコードされる JSON 文書であり（未知のフィールド，重複キー，末尾の
余分なデータ，深すぎるネストは拒否される．上限 256 KiB），**シークレットを一切
含まない**．Conductor は ACME・DNS・Store のバインディングを **名前だけで** 知って
いる．名前が何に解決されるかは Runner の設定（`docs/runner.md`）である．
バインディング名が Runner の例と一致する完全な例は
[`deploy/examples/conductor-config.example.json`](../deploy/examples/conductor-config.example.json)
を，Container Apps 向けの形（プラットフォームの ingress の背後で `oidc`）は
[`deploy/examples/conductor-config.aca.example.json`](../deploy/examples/conductor-config.aca.example.json)
を，Conductor 自身の TLS リスナーを持つセルフホストの `oidc` デプロイは
[`deploy/examples/conductor-config.oidc.example.json`](../deploy/examples/conductor-config.oidc.example.json)
を参照．

トップレベル:

| フィールド | 型 | 備考 |
|---|---|---|
| `apiVersion` | string | `acme-conductor.cits-nue.github.io/v1alpha1` と等しくなければならない． |
| `kind` | string | `ConductorConfig` と等しくなければならない． |
| `server` | object | リスナー，認証，シャットダウン — 後述． |
| `database` | object | `{ "path": "..." }` — SQLite ファイルのクリーンな絶対パス（なければ `0600` で作成される．シンボリックリンクは拒否される）．そのディレクトリは存在し，書き込み可能でなければならない．SQLite はその隣に `<path>-wal` と `<path>-shm` も作成し，`serve` は所有権ロックを `<path>.lock` に保持する（[シャットダウンと復旧](#シャットダウンと復旧)を参照）． |
| `scheduler` | object | ペース配分 — 後述． |
| `executionBindings` | map | 1 つ以上．キーはバインディング名（`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`，63 文字以下）． |
| `acmeBindings` | []string | ポリシーが選択できるバインディング名．空でなく，重複しないこと． |
| `dnsBindings` | []string | target が選択できるバインディング名．空でなく，重複しないこと． |
| `storeBindings` | []string | target が選択できるバインディング名．空でなく，重複しないこと． |
| `jobSigning` | object | 省略可．`azure-container-apps-job` バインディングがある場合は必須．後述． |
| `migration` | object | 省略可．インフラで定義されたホスト一覧からの移行: `targetSource` フラグ，一覧，取り込みプロファイル．[`migration`](#migration) を参照．省略時は `targetSource: registry` で一覧なし． |

### `server`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `listen` | string | `127.0.0.1:8080` | `host:port`．`auth.mode: localhost-dev` ではホストは `localhost` またはループバック IP リテラル（`127.0.0.1`，`[::1]`）でなければならない．それ以外の名前やアドレスは拒否され，名前が解決されることは決してない．`oidc` では任意のホストが許されるが，ループバック以外には `tls` か `behindTlsProxy` が必要．ポート `0` は空きポートを選ぶ（テスト用）． |
| `auth.mode` | string | `localhost-dev` | `localhost-dev`（開発ホスト 1 台）または `oidc`（本番）．[認証](#認証)を参照． |
| `auth.oidc` | object | — | `oidc` で必須，かつ `oidc` でのみ許される — 後述． |
| `tls` | object | — | `oidc` のみ．`{ "certFile": "...", "keyFile": "..." }`，PEM の証明書チェーンと秘密鍵のクリーンな絶対パス．リスナーは HTTPS（TLS 1.2 以上）で応答する．両ファイルは起動時に一度だけ読まれる．`behindTlsProxy` とは排他． |
| `behindTlsProxy` | bool | `false` | `oidc` のみ．プラットフォームの ingress またはリバースプロキシがこのポートの前段で TLS を終端し，それがこのポートへの唯一の経路であることを表明する．これによりループバック以外の平文リスナーが許容される．便利だからという理由で設定してはならない．平文のベアラートークンは盗まれたセッションである． |
| `shutdownGraceSeconds` | int | `900` | 停止シグナルの後，実行中の run がキャンセルされるまでに継続してよい時間．`1`–`86400`． |

### `server.auth.oidc`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `issuer` | string | —（必須） | プロバイダの issuer URL．`https://…`（平文の `http://` はテスト用にループバックホストへのみ可）．ユーザー情報，クエリ，フラグメントは不可．ディスカバリ文書は `<issuer>/.well-known/openid-configuration` から読まれ，同じ issuer を名乗っていなければならない．すべてのトークンの `iss` はこれと完全に一致しなければならない．Entra ID v2: `https://login.microsoftonline.com/<tenant-id>/v2.0`． |
| `audience` | string | —（必須） | すべてのトークンの `aud` が含んでいなければならない値．プロバイダが書き込む形式のまま指定する．Entra ID v2 のアクセストークンは，どのスコープを要求したかにかかわらず，API アプリ登録の **Application (client) ID**（GUID）を `aud` に持ち，アプリケーション ID URI を持つことは決してない．検証にのみ使い，ここから何かを導出することはない．空白を含まない印字可能 ASCII，256 バイト以下． |
| `clientId` | string | — | GUI がサインインに使う公開クライアント（Entra ID: リダイレクト URI `https://<host>/ui/` を持つシングルページアプリケーションの登録）．これがないと GUI はサインインできない．API は他所で取得したトークンを引き続き受け付ける． |
| `scopes` | []string | —（`clientId` がある場合は必須） | GUI がサインイン時に要求するもの．クライアントが要求するスコープとプロバイダが書き込む audience は別の識別子なので，`audience` からは導出しない．Entra ID: `openid`，`profile`，および `<application ID URI>/.default`（例: `api://<api-client-id>/.default`）．相異なる値 16 個以下．`clientId` がある場合のみ． |
| `principalClaim` | string | `sub` | その値が監査のアクターおよび `requestedBy` として記録されるクレーム．表示名ではなくサブジェクトの **安定した識別子** であること（`preferred_username`，`email`，`name` はユーザーの改名で変わる）．Entra ID: `oid` を設定する（Entra ID の `sub` はクライアントごとに異なるペアワイズ値）．印字可能文字の文字列で 256 バイト以下でなければならない． |
| `rolesClaim` | string | `roles` | その値（文字列または文字列の配列）が `roles` と照合されるクレーム． |
| `roles.admin` | []string | —（必須，空でない） | **admin** ロールを与える値: すべてのエンドポイント． |
| `roles.viewer` | []string | — | **viewer** ロールを与える値: `GET` のみ．1 つの値はどちらか一方の一覧にしか現れてはならない．両方の値を持つトークンは admin． |
| `clockSkewSeconds` | int | `60` | `exp`，`nbf`，`iat` に適用する許容差．`1`–`300`． |
| `keyCacheSeconds` | int | `3600` | ディスカバリ文書と署名鍵を再取得するまで再利用する時間．未知の鍵 ID は早期の再取得を引き起こす（最大で 1 分に 1 回）．`60`–`86400`． |

Conductor は **クライアントシークレットを持たない**．プロバイダが公開する鍵で
トークンを検証し，自身ではサインインを行わない
（[ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)）．

### `scheduler`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `tickSeconds` | int | `60` | 期限到来した target を調べ，待機中の run をディスパッチする間隔．API の変更もスケジューラを即座に起こす．`1`–`86400`． |
| `maxConcurrentRuns` | int | `2` | すべての実行バインディングを合わせて，同時に実行中にできる Runner 実行の数．`1`–`64`． |
| `retryBackoffSeconds` | int | `300` | 失敗またはキャンセルされた run の後，その target を再試行するまでの待ち時間． |
| `maxRetryBackoffSeconds` | int | `21600` | バックオフは連続失敗ごとに 2 倍になり，この上限で頭打ちになる（`retryBackoffSeconds` 以上，7 日以下）． |

### `executionBindings.<name>`

| フィールド | 型 | 備考 |
|---|---|---|
| `type` | string | ランチャーの型名（`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`）．どの型を提供するかは Conductor のバイナリが決める．公式バイナリは `local-process` と `azure-container-apps-job` を提供する．このバイナリが提供しない型は，他の何よりも先に，起動時に拒否される． |
| `config` | object | その型の設定．型のプロバイダが厳密にデコードする（未知のフィールドは拒否，重複キーは拒否，それ以外は何も受け付けない）．その内容は汎用の設定からは不透明であり，ランチャーの型を追加してもここには何も加わらない．型が `jobSigning`/`resultSigning` を必要とするかどうかもプロバイダの規則であり，ランチャーの構築時に検査される． |

```json
"executionBindings": {
  "local": {
    "type": "local-process",
    "config": { "runnerBinary": "/usr/local/bin/acme-runner", "runnerConfig": "/etc/acme-runner/config.json", "workDir": "/var/lib/acme-conductor/runs" }
  }
}
```

### `type: local-process` の `config`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `runnerBinary` | string | —（必須） | `acme-runner` 実行ファイルのクリーンな絶対パス． |
| `runnerConfig` | string | —（必須） | **Runner の** 設定のクリーンな絶対パス．`--config` として渡される．Conductor がこれを読むことは決してない． |
| `workDir` | string | —（必須） | クリーンな絶対パス．run の実行中に `job.json` と `result.json` を保持する run ごとのディレクトリ（`run-<runId>/`，モード `0700`）の親．証明書の素材を保持することは決してない — Runner は自身の `workDir`/`stateDir` を持つ．なければ作成される． |
| `timeoutSeconds` | int | `1200` | Conductor から見た Runner 実行 1 回の上限．Runner の `lego.timeoutSeconds` より大きく設定し，Runner 自身のより正確な `Timeout` 結果が勝つようにする．`1`–`86400`． |
| `passthroughEnv` | []string | `[]` | **Conductor プロセス** の環境変数のうち，Runner の子プロセスへそのまま転送する変数名（`^[A-Z][A-Z0-9_]{0,63}$`．`PATH`，`HOME`，`TMPDIR`，`LD_*` は予約済み）．それ以外はすべて渡されない．子プロセスが受け取るのは `HOME`/`TMPDIR`（その run のディレクトリ），固定の `PATH`，およびここに列挙した変数だけである．列挙されているが設定されていない変数は警告としてログに記録され省略される．その場合 Runner 自身が run をフェイルクローズで失敗させる（バインディング名を示す `DnsFailure`/`AcmeFailure`）．下記のセキュリティ注記を参照． |

**`passthroughEnv` に関するセキュリティ注記．** これは，ローカルランチャーで
起動された Runner に DNS の資格情報や EAB シークレットが届く唯一の手段であり，
Conductor プロセスの環境がその資格情報を抱えることを意味する — セキュリティ
原則 2（「Conductor は DNS の資格情報を持たない」）の正反対である．これが
許容されるのは単一ユーザーの開発ホスト上だけであり，それ以外の場所では許容
されない．Azure Container Apps Job ランチャーは Runner を自身のマネージド ID で
動かし，パススルーを一切持たない．脅威モデルはこれを T10 のローカルランチャーの
残存リスクとして記録している．

### 実行バインディング: Azure Container Apps Job

`type: azure-container-apps-job` は各 run を **既存の**，**スケジュール実行される**
Container Apps Job に渡す．その Job は，自身のマネージド ID・設定・状態ボリューム・
交換用ボリューム・固定コマンド `reconcile --exchange /exchange` を持つ Runner
イメージであり，すべてインフラでプロビジョニングされる
（[`deploy/azure`](../deploy/azure/README.md)，
[ADR 0014](adr/0014-azure-container-apps-job-launcher.md)）．Conductor が Job を
作成・変更・**開始** することは決してない．プラットフォームの開始操作は，Job の
コンテナのイメージ・コマンド・環境を置き換えられる実行テンプレートを受け付ける
ため，Job を開始できる ID は Runner の ID のもとで任意のイメージを実行できてしまう．
Conductor の ID にはそれが許されていない．1 つの run について Conductor は次を行う:

1. 署名付きジョブを交換用ボリューム（両コンテナがマウントするファイル共有）に
   差し出す．`<exchangeDir>/staging/run-<runId>/job.json` を書き，その
   ディレクトリを 1 回のリネームで `<exchangeDir>/pending/` に移動する．
2. プラットフォームのスケジュール（Bicep では毎分）が開始する次の実行がジョブを
   取るのを待つ — Runner がディレクトリを `<exchangeDir>/claimed/` に移動し
   （ちょうど 1 つの実行が勝つ），そこに自身の実行名を記録する — そして，記録
   された名前がこの Job の実行であることをプラットフォームに確認する（毎回の
   試行で一貫してプラットフォームが知らない名前は run を終わらせる．問い合わせ
   できないプラットフォームや，持続しない 404 は終わらせない — 数回の試行の後，
   その実行は未確認のまま監視される．Runner がジョブを保持しているからである）．
   `claimTimeoutSeconds` 以内にどの実行も取らなければ，差し出しは取り下げられ
   （同じリネームによるので，遅れて取ろうとするものと競合しない），run は失敗
   する．キャンセルされた run も同じ方法で取り下げられ，`cancelled` で終わる．
3. 実行の状態を `pollIntervalSeconds` ごとにポーリングし，終端状態（`Succeeded`，
   `Failed`，`Stopped`，`Degraded`）になるまで続ける．終端状態に至らずに
   ポーリングが終わった場合はいつでも — run がキャンセルされた，`timeoutSeconds`
   が経過した，状態を読めなくなった — run ディレクトリを削除する *前に*
   プラットフォームを通じて実行を停止し，その後，終了までの猶予を有限に与える．
4. `result.json` を読む（共有に現れるまで最大 `resultGraceSeconds` 待つ）．これは
   `resultSigning.publicKeys`（後述）で検証できる `SignedCertificateReconcileResult`
   でなければならない．この run と target を名指ししていること，およびその状態が
   プラットフォームの判定と一致すること（`Succeeded` なのに `Result` が失敗，
   または `Failed` なのに成功，は不一致 → `Internal`）を確認し，run ディレクトリを
   削除する — ただし実行が終了したことを確認できた場合に限る．状態を読めない
   ままで停止も確認できなかった実行はディレクトリを残し（Runner がまだ書き込んで
   いるかもしれない），操作者が削除できるよう「run directory kept」としてログに
   記録する．

run の `externalExecutionId` は `azure-container-apps-job:<execution
name>` である．Conductor の ID に必要なのは，Job リソースに対してのみ，Bicep が
付与する 3 つのアクション（`jobs/execution/read`，`jobs/executions/read`，
`jobs/stop/execution/action`）である — Job の開始や変更はできず，DNS，Key Vault，
ストレージのデータ権限は持たない．したがって run は，待機状態になってから最大で
スケジュール間隔 1 回分にプラットフォームの起動遅延を加えた時間の後に開始し，
スケジュールの 1 ティックにつき最大 1 つの run が開始する（各実行は 1 レプリカで
動き，1 つのジョブを取る）．

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `subscriptionId` | string | —（必須） | Job を保持するサブスクリプションの GUID． |
| `resourceGroup` | string | —（必須） | Job のリソースグループ． |
| `jobName` | string | —（必須） | Container Apps Job の名前（小文字・数字・ハイフンで 2–32 文字，`--` は不可）． |
| `cloud` | string | `public` | `public`，`china`，`government` のいずれか: Resource Manager のエンドポイントと ID の authority を選ぶ． |
| `credential` | string | `default` | Conductor が Resource Manager に認証する方法: `managed-identity`（プラットフォームの ID — 本番ではこれを使う）または `default`（SDK の `DefaultAzureCredential` チェーン．交換用共有をマウントした開発者ホストで Conductor を動かす場合向け）． |
| `managedIdentityClientId` | string | — | `managed-identity` のみ: ユーザー割り当て ID のクライアント ID．省略時はシステム割り当て． |
| `exchangeDir` | string | —（必須） | **Conductor の** ファイルシステムで交換用ボリュームがマウントされているクリーンな絶対パス（Bicep では `/mnt/exchange`）．なければ作成される．Runner は自身のマウントパスをインフラ側の固定引数で知らされる． |
| `claimTimeoutSeconds` | int | `300` | 差し出したジョブをスケジュール実行が取るのを待ち，取り下げるまでの時間．`jobSigning.validitySeconds` を超えてはならない（期限切れ後に取られたジョブは Runner に拒否される）．`1`–`86400`． |
| `timeoutSeconds` | int | `1200` | Conductor から見た実行 1 回の上限．ジョブを取った時点から数え，これを過ぎると実行は停止される．Job の `replicaTimeout` より大きく設定し，`replicaTimeout` は Runner の `lego.timeoutSeconds` より大きくする．`1`–`86400`． |
| `pollIntervalSeconds` | int | `10` | 交換用ディレクトリと実行の状態を読む間隔．`1`–`300`． |
| `resultGraceSeconds` | int | `30` | 実行の終了後に `result.json` を待つ時間（ファイル共有は書き込みの反映に遅延がある）．`0`–`600`． |

`azure-container-apps-job` バインディングがあるのに `jobSigning` または
`resultSigning` がない設定は拒否される．交換用ボリュームは Conductor が所有する
トランスポートではないので，そこに置くジョブはすべて署名され，そこにある Result は
すべて署名されていなければならない．
[`deploy/examples/conductor-config.aca.example.json`](../deploy/examples/conductor-config.aca.example.json)
を参照．

### `migration`

既存のインフラで定義されたホスト一覧からの移行
（[`docs/migration.md`](migration.md)）．このセクション全体が省略可であり，
その構成要素は次の通り:

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `targetSource` | string | `registry` | 誰が発行するか．`registry`: スケジューラがレジストリの target について run を計画し開始する．`shadow`: 計画も開始もせず，設定された一覧を `compareIntervalSeconds` ごとにレジストリと比較する．`iac`: 計画も開始もせず，それだけである．`shadow` と `iac` のもとでは `POST /targets/{id}/runs` は `409 issuance_disabled` を返す．レジストリは編集可能なまま． |
| `source` | object | — | 一覧の読み込み元: `bicepParamFile`（クリーンな絶対パス．`parameter` を併用可，既定は `targetDomains`），`jsonFile`（TargetList 文書，クリーンな絶対パス），`fqdns`（インラインの一覧，最大 10000 個の名前）のうちちょうど 1 つ．`shadow` では必須．それ以外では `GET /migration/diff` および `fqdns` なしの取り込みの既定の一覧となる．`profile` が必要． |
| `profile` | object | — | 取り込まれる各 target を FQDN 以外に何で構成するか: `policyRef`（識別子．プロファイルが使われる時点でそのポリシーが存在しなければならない），`executionBinding`・`dnsBinding`・`storeBinding`（それぞれこの設定が登録するバインディング），`owner`（印字可能，最大 128 バイト）．`source` がある場合に必須で，差分や取り込みを行うには必ず必要． |
| `compareIntervalSeconds` | int | `300` | shadow 比較を実行する間隔．`10`–`86400`． |

一覧が寄与するのは FQDN だけであり，それ以外は何も寄与しない．target が名前以外に
必要とするものはすべて，プロファイル，すなわち管理者が決める．

### `jobSigning`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `privateKeyFile` | string | —（必須） | `acme-conductor keygen` が生成した PEM `PRIVATE KEY`（PKCS #8，Ed25519）ファイルのクリーンな絶対パス．起動時に一度だけ読まれる．読めない鍵や型の違う鍵は設定エラー（終了コード 1）． |
| `validitySeconds` | int | `900` | 署名付きジョブが発行後に受け付けられる時間．Runner は何かをする前にこれを検査するので，プラットフォームの起動遅延をカバーできれば十分である．`1`–`86400`． |

`jobSigning` があると，**すべての** ランチャーが Runner に
`SignedCertificateReconcileJob`（[ADR 0015](adr/0015-signed-job-envelope.md)）を
渡す．これは `JobSpec` の正確なバイト列を base64url にしたものを，鍵 ID・`issuedAt`・
`expiresAt`・ランダムなノンスを持つ厳密なヘッダのもとに置き，Ed25519 で署名した
ものである．Runner は対応する公開鍵を自身の `jobSigning.publicKeys`
（[`docs/runner.md`](runner.md#jobsigning)）に列挙しなければならず，生の JobSpec を
拒否する．`jobSigning` がなければ，ローカルランチャーは Phase 2 と同様に生の
`JobSpec` を渡す．この秘密鍵は Conductor が読む唯一のシークレットである．これは
Runner に対する Conductor の ID であって，DNS・Store・クラウドの資格情報ではない．
ローテーションするには，まず新しい公開鍵を Runner に追加し，次に `privateKeyFile`
を切り替え，最後に古い公開鍵を削除する．鍵 ID は起動時の `job signing enabled`
ログ行に現れる．

### `resultSigning`

| フィールド | 型 | 既定値 | 備考 |
|---|---|---|---|
| `publicKeys` | []string | —（必須） | Runner の Result 署名用公開鍵（Ed25519）1–8 個．それぞれ PEM の `PUBLIC KEY` ブロック，またはその DER SubjectPublicKeyInfo の標準 base64 — `acme-runner keygen` が出力する 1 行の `publicKey:` — のどちらか．複数の鍵により Runner の鍵をローテーションできる．重複は拒否される． |
| `clockSkewSeconds` | int | `300` | 署名付き Result の `issuedAt` が，この Conductor の時計に対してどれだけ未来にあっても拒否されないかの許容差．期限切れには許容差がない．`1`–`3600`． |

`resultSigning` があると，**すべての** ランチャーが，これらの鍵のいずれかで署名を
検証でき，ペイロードが妥当な `Result` である `SignedCertificateReconcileResult`
（[ADR 0015](adr/0015-signed-job-envelope.md)）だけを受け付ける．生の `Result` は
「結果なし」となり，run は `Internal` で終わる．Runner は対応する秘密鍵を自身の
`resultSigning.privateKeyFile`（[`docs/runner.md`](runner.md#resultsigning)）に
設定しなければならない．`resultSigning` がなければ署名付き Result が同じように
拒否されるので，署名するかどうかは設定によって一度だけ決まり，文書によって決まる
ことは決してない．Container Apps ランチャーはこれを必須とする．プライベートな
ディレクトリ越しのローカルランチャーはどちらでも動く．Conductor が保持するのは
公開鍵だけである．

## REST API

すべてのリソースエンドポイントは `/api/v1alpha1` の下にある．リクエストと
レスポンスは JSON（`Content-Type: application/json`）で，すべてのリクエスト本文は
厳密にデコードされ（未知のフィールド，重複キー，末尾の余分なデータ，8 段より深い
ネストはすべて拒否），64 KiB に制限される．レスポンスには
`Cache-Control: no-store` と `X-Content-Type-Options: nosniff` が付く．

識別子（`id`，`policyRef`，`targetId`，`runId`，`before`）は Conductor が生成する
ULID である（1 つのプロセス内で単調増加なので，作成順にソートされる）．
`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` に合致しないパスやクエリの識別子には，
レジストリに触れずに `404`/`400` を返す．

### エラー

```json
{ "error": { "code": "stale_revision", "message": "target 01J… is at revision 3, not 2", "details": { } } }
```

| HTTP | `code` | 発生条件 |
|---|---|---|
| 400 | `invalid_request` | 不正な本文，フィールド検証の失敗，未知のフィールド，未登録のバインディング名，不正な FQDN/サフィックス，不正なクエリパラメータ． |
| 400 | `policy_violation` | target の FQDN が，指定したポリシーで許可されていない（ラベル境界でのサフィックス照合，ワイルドカード規則）．`policy.rejected` として監査される． |
| 401 | `unauthenticated` | `oidc` モード: ベアラートークンがない，または検証に通らない（署名，issuer，audience，期限，未知の鍵）．`WWW-Authenticate: Bearer realm="acme-conductor"` を伴う． |
| 403 | `forbidden` | `localhost-dev`: モードの規則により拒否．`oidc`: トークンは検証に通ったが，この API が与えるロールを持たない，または viewer が `GET` 以外を呼んだ． |
| 404 | `not_found` | 該当するポリシー，target，run，エンドポイントがない． |
| 409 | `conflict` | 同じ FQDN に対する 2 つ目の target．既存の target をカバーしなくなるポリシー編集．キャンセルできない run のキャンセル． |
| 409 | `stale_revision` | リクエストの `revision` が target の現在のリビジョンではない． |
| 409 | `run_active` | その target について run がすでに queued/starting/running である（`details.activeRunId`，`details.status`）． |
| 409 | `target_disabled` | 無効化された target に run が要求された． |
| 409 | `issuance_disabled` | `migration.targetSource` が `shadow` または `iac` の間に run が要求された（[`docs/migration.md`](migration.md)）． |
| 409 | `migration_unconfigured` | 移行の差分または取り込みが要求されたが，`migration.profile` が設定されていない，またはそれが指すポリシーが存在しない． |
| 409 | `source_unreadable` | 設定された `migration.source` を読めなかった（ファイルがない，形式が不正，ホスト名でない名前がある）． |
| 413 | `too_large` | 本文が 64 KiB を超えている． |
| 415 | `unsupported_media_type` | `Content-Type: application/json` のない本文． |
| 500 | `internal` | レジストリまたはその他の内部障害．詳細はログにのみ記録される． |

### エンドポイント

| メソッドとパス | 目的 |
|---|---|
| `GET /healthz` | 生存確認: `{"status":"ok"}`．認証不要． |
| `GET /readyz` | 準備確認: レジストリに ping する．失敗時は `503` `{"status":"unavailable"}`．認証不要． |
| `GET /` | `/ui/` にリダイレクトする． |
| `GET /ui/`, `/ui/app.js`, `/ui/app.css` | GUI の 3 つの静的ファイル．認証不要（データを含まない）． |
| `GET /ui/config` | GUI のサインイン方法: `{"auth":{"mode":"oidc","issuer":…,"clientId":…,"scopes":[…],"authorizationEndpoint":…,"tokenEndpoint":…}}` または `{"auth":{"mode":"localhost-dev"}}`．認証不要．プロバイダのディスカバリ文書が利用できない間は `503`． |
| `GET /api/v1alpha1/bindings` | 登録されたバインディング名: `{"execution":[…],"acme":[…],"dns":[…],"store":[…]}`． |
| `GET /api/v1alpha1/policies` | `{"items":[Policy…]}`，古い順． |
| `POST /api/v1alpha1/policies` | ポリシーを作成 → `201` Policy，`Location`． |
| `GET /api/v1alpha1/policies/{id}` | ポリシー 1 件． |
| `PUT /api/v1alpha1/policies/{id}` | ポリシーを置き換え → `200`．その下のいずれかの target が満たさなくなる場合は拒否（`409`）． |
| `GET /api/v1alpha1/targets[?enabled=&policyRef=]` | `{"items":[Target…]}`，古い順． |
| `POST /api/v1alpha1/targets` | target を作成 → `201` Target，`Location`．スケジューラを起こす． |
| `GET /api/v1alpha1/targets/{id}` | target 1 件．証明書と最後の run の要約を含む． |
| `PUT /api/v1alpha1/targets/{id}` | 指定した `revision` で変更可能なフィールドを更新 → `200`．スケジューラを起こす． |
| `POST /api/v1alpha1/targets/{id}/enable` | `enabled: true` に設定 → `200` Target（変化があればリビジョンが上がる）． |
| `POST /api/v1alpha1/targets/{id}/disable` | `enabled: false` に設定 → `200` Target．何も削除せず，実行中の run も止めない． |
| `GET /api/v1alpha1/targets/{id}/runs[?status=&limit=&before=]` | その target の run，新しい順． |
| `POST /api/v1alpha1/targets/{id}/runs` | 今すぐ run を要求 → `202` Run，`Location`．本文 `{"revision": N}` は省略可． |
| `GET /api/v1alpha1/runs[?targetId=&status=&limit=&before=]` | run の一覧，新しい順．`status` はコンマ区切りの一覧． |
| `GET /api/v1alpha1/runs/{id}` | run 1 件． |
| `POST /api/v1alpha1/runs/{id}/cancel` | キャンセル: 待機中の run は即座にキャンセルされる（`200`）．starting/running の run には停止が要求される（`202`．結果は Runner の報告時に記録される）． |
| `GET /api/v1alpha1/audit[?targetId=&runId=&policyId=&limit=&before=]` | 監査イベント，新しい順． |
| `GET /api/v1alpha1/migration` | 移行の状態: `targetSource`，`issuanceEnabled`，設定されたソースとプロファイル，および `shadow` では最新の比較結果． |
| `GET /api/v1alpha1/migration/diff` | 設定された一覧をレジストリと比較 → レポート． |
| `POST /api/v1alpha1/migration/diff` | `{"fqdns": […]}` をレジストリと比較 → レポート． |
| `POST /api/v1alpha1/migration/import` | 一覧を取り込む: `{"fqdns": […], "dryRun": true}`，どちらも省略可（`dryRun` の既定は `true`．`fqdns` がなければ設定された一覧）→ 取り込み結果．レジストリにない名前についてのみ target を作成し，更新も削除も決して行わない．何かを作成したときはスケジューラを起こす．[`docs/migration.md`](migration.md#api) を参照． |

ページングする一覧（`runs`，`audit`）は `limit`（`1`–`1000`，既定 `100`）と
`before=<id>`（その id より前にソートされる項目を返す．id は作成時刻順にソート
される）を取る．

### Policy

リクエスト本文（`POST`，`PUT`）:

```json
{
  "allowedDnsSuffixes": ["example.ac.jp"],
  "allowWildcard": false,
  "acmeBinding": "letsencrypt-staging",
  "renewBeforeDays": 30,
  "keyType": "ec256",
  "maxSANs": 1,
  "enabled": true
}
```

- `allowedDnsSuffixes` — 1–64 個のエントリ．それぞれ入力時に正規化される
  （`internal/policy.NormalizeSuffix`: 前後の空白除去，小文字化，末尾のドット除去．
  ワイルドカード不可．ASCII のみで `xn--` 不可）．正規化後に重複するものは
  拒否される．
- `acmeBinding` — 設定の `acmeBindings` に列挙されていなければならない．
- `renewBeforeDays` — `1`–`365`．`keyType` — `ec256`，`ec384`，`rsa2048`，
  `rsa3072`，`rsa4096` のいずれか．
- `maxSANs` — 省略可．`1` でなければならない（FQDN 1 つにつき証明書 1 枚）．
- `enabled` — 省略可．作成時の既定は `true`，更新時の既定は現在の値．無効化された
  ポリシーは，その下のすべての target をスケジューリングから遠ざける．

レスポンスには `id`，`createdAt`，`updatedAt` が加わる．

**ポリシー変更が効力を持つ時点．** ポリシーはバージョン管理されず，target は
ポリシーのリビジョンを持たない．更新は，ポリシーの下の既存の target がすべて
なおそれを満たす場合にのみ受け付けられ（そうでなければ違反する target を示す
`409 conflict`），新しい値は各 target の **次の run** で読まれる．次の run が
期限到来するのは，証明書が `renewBeforeDays` の窓に入ったとき，target 自体が
変わったとき（リビジョンが進んだとき），または操作者が要求したとき
（`POST /targets/{id}/runs`）である．ポリシーの更新だけでは run は待機状態に
ならず，target のリビジョンも上がらない．その次の run で各フィールドが何をするか:

- `keyType` — Runner は保存されている証明書の鍵種別を要求されたものと比較し，
  不一致なら，証明書がそれ以外の点で最新であっても再発行する．したがって
  `keyType` の変更後は，各 target への手動 run が今すぐローテーションし，
  そうでなければ更新の窓が後でローテーションする．
- `renewBeforeDays` — スケジューラが期限到来の検査のたびに読むので，窓を広げると
  次のティックで target が期限到来になり得る．
- `acmeBinding` — 次の ACME オーダーの CA を選ぶだけである．以前の CA による最新の
  証明書がこの変更だけを理由に再発行されることはないので，target は次の更新時に
  （または再発行すべき別の理由を見つけた手動 run で）新しい CA に移る．Phase 2 は
  バインディング変更による強制再発行を行わない
  （[ADR 0011](adr/0011-conductor-storage-and-run-model.md)）．
- `allowedDnsSuffixes`，`allowWildcard` — 更新そのものにおいて既存の target に
  対して強制され，その後の target の作成・更新のたびにも強制される．Runner は
  受け取ったスナップショットを再検証する．

Runner に渡される `JobSpec` はポリシーの値をスナップショットとして運ぶので，
run の監査証跡には常に，その run が実行された時点の値が示される．

### Target

作成:

```json
{
  "fqdn": "wiki.example.ac.jp",
  "owner": "web-team",
  "policyRef": "01JPOLICY…",
  "executionBinding": "local",
  "dnsBinding": "azure-dns-staging",
  "storeBinding": "filesystem-dev",
  "enabled": true
}
```

- `fqdn` — 入力時に正規化され（`internal/policy.NormalizeFQDN`），一意である．
  指定したポリシーを満たさなければならず（ラベル境界でのサフィックス照合．
  ワイルドカードはポリシーが許す場合のみ），そうでなければリクエストは
  `policy_violation` で拒否され，監査される．FQDN はその後 **不変** である．
  target は 1 つの FQDN である．
- `owner` — 印字可能な UTF-8 で 1–128 バイト．人間向けの自由記述．
- `policyRef` — 既存のポリシー id．3 つのバインディング名は設定に列挙されて
  いなければならない．

更新（`PUT`）: `{"revision": N, …}` に `owner`，`policyRef`，`executionBinding`，
`dnsBinding`，`storeBinding`，`enabled` のいずれかを添える．省略したフィールドは
値を保つ．`revision` は現在の値でなければならず（そうでなければ
`stale_revision`），成功時にインクリメントされる．

レスポンス:

```json
{
  "id": "01JTARGET…", "fqdn": "wiki.example.ac.jp", "enabled": true, "owner": "web-team",
  "policyRef": "01JPOLICY…", "executionBinding": "local", "dnsBinding": "azure-dns-staging",
  "storeBinding": "filesystem-dev", "createdAt": "…", "updatedAt": "…", "revision": 1,
  "certificate": {
    "expiresAt": "2026-12-21T…", "fingerprintSha256": "…", "storeObjectRef": "wiki.example.ac.jp-…",
    "lastSucceededAt": "…", "lastSucceededRunId": "01JRUN…"
  },
  "lastRun": { "id": "01JRUN…", "status": "succeeded", "requestedAt": "…", "finishedAt": "…" }
}
```

`certificate` は run が成功するまで `null` であり，最後に成功した `Result` が
報告した内容そのものである．Store から読んだものでは決してない．`lastRun` は
run が存在するまで `null` であり，run が失敗した場合は `errorCode` を持つ．

### Run

```json
{
  "id": "01JRUN…", "targetId": "01JTARGET…", "targetRevision": 1,
  "status": "succeeded", "requestedBy": "scheduler", "requestedByAuthority": "scheduler",
  "requestedAt": "…", "startedAt": "…", "finishedAt": "…",
  "action": "issued", "expiresAt": "…", "fingerprintSha256": "…", "storeObjectRef": "…",
  "error": null, "externalExecutionId": "local-process:12345"
}
```

`status` は `queued`，`starting`，`running`，`succeeded`，`failed`，`cancelled` の
いずれかである．`action`，`expiresAt`，`fingerprintSha256`，`storeObjectRef`，
`error` は Runner の `Result`
（[コントラクト](architecture.md#certificatereconcileresult-result)）を写したもので，
`error` は失敗またはキャンセル時に `{ "code", "summary" }` となる．`requestedBy` は
`scheduler` または API のプリンシパル（`localhost-dev`，または `oidc` モードでは
`principalClaim` の値．Entra ID の `oid` のような識別子）であり，
`requestedByAuthority` はその値が一意である名前空間，すなわち `scheduler`，
`localhost-dev`，または OIDC の issuer URL（run 時点の
`server.auth.oidc.issuer`）である．この組が永続的な ID である
（[ADR 0018](adr/0018-authority-qualified-principals.md)）．Conductor がこれを
保存するようになる前（スキーマバージョン 1）に記録された run では
`requestedByAuthority` は `""` である．

### 監査イベント

```json
{ "id": "01JEVENT…", "time": "…", "actor": "localhost-dev", "actorAuthority": "localhost-dev",
  "action": "target.created", "targetId": "01JTARGET…", "runId": "", "policyId": "",
  "detail": "target created: fqdn=… policy=… …" }
```

`actor` と `actorAuthority` は，run の `requestedBy` と `requestedByAuthority` と
同じ方法で，誰が行為したかを識別する．actor の値はその authority（OIDC の
issuer URL，`localhost-dev`，`scheduler`）の中でのみ一意なので，ID プロバイダの
変更をまたいでプリンシパルを名指しするのは actor 単独ではなくこの組である．
Conductor がこれを保存するようになる前に記録されたイベントでは `actorAuthority` は
`""` であり，そのような行が書き換えられることは決してない（監査ログは追記専用）．

アクション: `policy.created`，`policy.updated`，`policy.rejected`，
`target.created`，`target.updated`，`target.enabled`，`target.disabled`，
`target.imported`（移行の取り込みで作成された target．由来の一覧を伴う），
`run.requested`，`run.started`，`run.succeeded`，`run.failed`，`run.cancelled`，
`migration.compared`（結果が前回と異なる shadow 比較．actor と authority は
ともに `migration`，すなわち Conductor 自身の比較ループであり，`scheduler` が
それ自身の authority であるのと同じ）．`detail` は Conductor が検証済みの値から
組み立てる短い文（最大 512 バイト）であり，Runner の出力を含むことは決してない．
イベントは，それが記述する変更と同じトランザクションで書き込まれ，更新も削除も
できない．

### セッション例

```sh
C=http://127.0.0.1:8080/api/v1alpha1
P=$(curl -s -H 'Content-Type: application/json' -d '{"allowedDnsSuffixes":["example.ac.jp"],"acmeBinding":"letsencrypt-staging","renewBeforeDays":30,"keyType":"ec256"}' $C/policies | jq -r .id)
T=$(curl -s -H 'Content-Type: application/json' -d "{\"fqdn\":\"wiki.example.ac.jp\",\"owner\":\"web-team\",\"policyRef\":\"$P\",\"executionBinding\":\"local\",\"dnsBinding\":\"azure-dns-staging\",\"storeBinding\":\"filesystem-dev\"}" $C/targets | jq -r .id)
curl -s $C/targets/$T | jq .lastRun          # スケジューラが即座に run を待機状態にする
curl -s -X POST $C/targets/$T/runs             # または明示的に要求する (アクティブな run がある間は 409)
curl -s "$C/audit?targetId=$T" | jq '.items[].action'
```

## Run のライフサイクルとスケジューリング

```
 scheduler tick / API request
        |
        v
    queued ──(claimed by scheduler)──> starting ──(runner started)──> running ──(Result)──> succeeded
        |                                 |                               |                  failed
        |                                 | target disabled / revision    |                  cancelled
        |                                 | changed / policy disabled     |
        └── cancel via API ──> cancelled  └──────────> cancelled          └── cancel ──> cancelled
```

1. **期限到来の検査**（ティックごと，および起こされるたび）．ポリシーが有効で
   アクティブな run のない各有効 target について，target が一度も成功していない，
   リビジョンが最後に成功した run の対象リビジョンと異なる，最後に成功した run が
   有効期限を記録しなかった，または `expiresAt - renewBeforeDays` を過ぎた場合に
   run が待機状態になる．失敗またはキャンセルされた run の後，target は
   `retryBackoffSeconds` 待ち，連続失敗ごとに 2 倍になって `maxRetryBackoffSeconds`
   で頭打ちになる．理由は `run.requested` 監査イベントに記録される．
2. **排他．** target ごとに queued・starting・running の run は最大 1 つである．
   レジストリがこれをスキーマ制約として強制するので，ティック，操作者，再起動が
   競合して 2 つ目の Runner を生み出すことはない．2 つ目の API リクエストには
   アクティブな run を示す `409 run_active` を返す．
3. **クレームと再検査．** 待機中の run を最大 `maxConcurrentRuns` 個までクレーム
   する（`starting`）．それぞれが target とポリシーを読み直す．target または
   ポリシーが無効，または run の要求後にリビジョンが進んだ target なら，Runner を
   起動せずに run を `cancelled` で終える．次に `JobSpec` を組み立て（ポリシーは
   値としてスナップショットにコピー），コントラクト自身の `Validate` で検証する．
   拒否されれば run は `failed`/`PolicyViolation` で終わり，`policy.rejected` として
   監査される．
4. **起動．** `JobSpec` をシリアライズし — `jobSigning` が設定されていれば
   署名付きエンベロープとして — 実行バインディングのランチャーが Runner
   （子プロセス，または Container Apps Job の実行）を開始する．run は
   プラットフォームの実行 id を記録して `running` になる．
5. **Result．** Runner の `Result`（厳密にデコードし，この run と target を名指し
   していることを検査）が終端状態とすべての証明書フィールドを定める．`Cancelled`
   → `cancelled`．それ以外のエラー → `failed`．ランチャーが `Result` をまったく
   得られなければ，run は Conductor 自身の要約で失敗する: `Timeout`（ランチャーの
   タイムアウト），`Cancelled`（報告前に停止），`Internal`（結果がない／使えない／
   不一致，または開始できなかった）．Runner が出力した内容が run のレコードに
   コピーされることはない．
6. **記録．** すべての状態遷移は，スケジューラが意図した状態ではなく，レジストリが
   保持していると分かっている状態に対して書き込まれ，各書き込みは同じ
   トランザクションで監査イベントを伴う．Runner がすでに実行中なのに
   `starting → running` の書き込みが失敗した場合，スケジューラは Runner を待ち
   続け，結果を `starting` に対して記録する（開始の記録をもう一度試みた後に．
   レジストリが回復していれば証跡に `run.started` が残るように）．一時的に失敗
   した終端の書き込みは，最大 2 分間バックオフ付きで再試行される．競合（レジストリ
   が想定と異なる状態を保持している．例えばコミットされたのにエラーを報告した
   書き込みの後）は，run を読み直して実際の状態に対して再試行することで解決し，
   遷移を 2 度記録することは決してない．それでも結果を記録できなければ，run は
   その実行によって `running` のまま残され，次のループ反復で **スイープ** が
   閉じる．スイープは，このプロセスが実行していない `starting` または `running` の
   run をすべて `failed`/`Internal`「run outcome could not be recorded while the
   runner ran; outcome unknown」とし，target の排他スロットを解放して次の run を
   登録できるようにする．スイープはループのゴルーチンでのみ，ディスパッチが
   クレームしたものを登録した後に実行されるので，直前にクレームされた run を
   取り残された run と誤認することは決してない．

証明書を実際に発行または更新しなければならないかどうかの権威は Runner のままである
（Runner が Store に問い合わせる．[ADR 0009](adr/0009-runner-execution-model.md)
を参照）．Conductor が期限到来とみなした run が証明書が最新であることを見つければ，
CA に接触せずに `succeeded`/`noop` で終わる．

### シャットダウンと復旧

`SIGTERM`/`SIGINT` を受けると: リスナーを閉じ，計画を止め，実行中の run は最大
`server.shutdownGraceSeconds` まで継続し，その後キャンセルされる（Runner は
`SIGTERM` を受け取り，通常は `Cancelled` を報告する．10 秒後に `SIGKILL` が続く）．
2 回目のシグナルは Conductor を即座に強制終了し，Runner の子プロセスは単独で
動き続ける．

**データベース 1 つにつき Conductor はちょうど 1 つ．** `serve` はレジストリを
開き，何かを復旧し，ポートをバインドするより前に，`<database.path>.lock` に
排他的なアドバイザリロック（`flock`）を取る．別のプロセスがこれを保持していれば，
`serve` は「another conductor process owns this database; refusing to start」と
ログに記録し，いかなる状態も変更せずに — 特に所有者の実行中の run を失敗扱いに
せずに — 終了コード `2` で終了する．ロックはプロセスの終了時に解放される
（クラッシュ時も同様．カーネルがディスクリプタとともに解放する）ので，再起動
すればデータベースを再び所有できる．ロックが意味を持つためにはデータベースのパスは
ローカルファイルシステム上になければならない（ネットワークファイルシステムでの
`flock` の意味論はまちまちである．Runner の `internal/fslock` と同じ注意点）．
したがって，同じ `database.path` を持つ別ポートの 2 つ目のインスタンスは，単なる
ポートの衝突ではなく拒否される．

起動時，レジストリでまだ `starting` または `running` の run は `Internal` で
`failed` とされ —「conductor stopped while the run was in flight; outcome
unknown」— 監査される．待機中の run は通常通りディスパッチされる．Conductor が
run を再開することは決してない．Runner が完了したかどうかを知り得ないからである．
強制終了で取り残された Runner は Store での作業を完了するかもしれない．その場合，
次の期限到来の検査が新しい run をスケジュールし，それが証明書が最新であることを
見つける（`noop`）か，更新する．

## 認証

`server.auth.mode` で選ぶ 2 つのモードがある．どちらも `/api/` 配下のすべての
リクエストを認証する．`/healthz`，`/readyz`，GUI の静的ファイルには資格情報は
不要であり，`/api/` 配下のすべてのハンドラは同じミドルウェアの後ろでのみ動くため，
それを迂回するエンドポイントを追加することはできない．

### `oidc`（本番）

Conductor は OpenID Connect の **リソースサーバー** である
（[ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)）．受け付けるのは
`Authorization: Bearer <access token>` ヘッダーのみで，Cookie やクエリパラメータは
決して受け付けない．トークンは次の **すべて** が成り立つ場合にのみ受理される．

- `RS256`，`PS256`，`ES256` のいずれかで署名されたコンパクト JWS であること
  （`none` と HMAC は拒否する），key id を名指ししていること，critical 拡張を
  使っていないこと，そしてプロバイダがディスカバリ文書の `jwks_uri` で公開する
  鍵セットの中のその鍵で署名が検証できること（RSA 2048 ビット以上，または P-256）．
- `iss` が `server.auth.oidc.issuer` と等しく，`aud` が
  `server.auth.oidc.audience` を含むこと．
- `exp` があり，（`clockSkewSeconds` の範囲内で）期限切れでないこと．`nbf` と
  `iat` は，あれば未来でないこと．
- ヘッダーとペイロードが厳密にデコードできること（重複したクレームは拒否する）．
- `principalClaim` が印字可能な文字列であること．これが監査ログと `requestedBy`
  における呼び出し元の識別子になる．
- `rolesClaim` が `roles.admin` の値（→ **admin**，すべてのエンドポイント）または
  `roles.viewer` の値（→ **viewer**，`GET` のみ）を含むこと．どちらも含まない
  トークンは検証には通るが `403` で拒否される．

失敗は `WWW-Authenticate: Bearer` チャレンジ付きの `401` で応答し，呼び出し元は
特定できたが許可されていない場合は `403` で応答する．エラーの文言は理由（期限切れ，
audience の不一致，未知の鍵）を述べ，トークンをそのまま返すことは決してない．
ログはすべての拒否をメソッド・パス・理由とともに記録する．

プロバイダのディスカバリ文書と鍵は起動時に一度読む（そのとき到達できなければ
警告となり，応答があるまでトークンは拒否されるが，スケジュールされた更新には
影響しない）．その後は `keyCacheSeconds` ごとに，またはトークンがキャッシュに
ない key id を名指ししたときにはより早く（最大で 1 分に 1 回）読み直す．読み直しに
失敗した場合は以前の鍵を保持する．

**トランスポート．** ベアラートークンはセッションそのものであり，平文で運んでは
ならない．`server.listen` がループバック以外なら，設定は `server.tls`（Conductor
自身の証明書と鍵，TLS 1.2 以上）か `server.behindTlsProxy: true` のどちらかを
要求する．後者は，プラットフォームの ingress またはリバースプロキシが TLS を終端し，
それがポートへの唯一の経路であることの明示的な表明である．Container Apps の
デプロイは後者を環境のピア間トラフィック暗号化と組み合わせて使う
（[`deploy/azure/README.md`](../deploy/azure/README.md)）．

**トークンの取得．** GUI はブラウザ内でこれを行う（[GUI](#gui) を参照）．
ターミナルからは，API のスコープに対するトークンをプロバイダに要求する．Microsoft
Entra ID で，API のアプリ登録のクライアント ID（`audience`）が `1111…`，
アプリケーション ID URI が既定の `api://1111…` の場合:

```sh
token="$(az account get-access-token --scope api://11111111-1111-1111-1111-111111111111/.default --query accessToken -o tsv)"
curl -s -H "Authorization: Bearer $token" https://conductor.example.ac.jp/api/v1alpha1/targets
```

プロバイダ側の準備（アプリロールを持つ API のアプリ登録，GUI 用のパブリック
クライアント）は Azure のデプロイとともに説明している．ディスカバリ文書を公開し，
上記 3 つのアルゴリズムのいずれかでトークンに署名するプロバイダなら，
`principalClaim` と `rolesClaim` をそのプロバイダが発行するものに合わせれば，
どれも同じように動く．

### `localhost-dev`（開発ホスト 1 台）

Phase 2 のモード（[ADR 0012](adr/0012-localhost-only-dev-auth.md)）．
`/api/` 配下へのリクエストは次の **すべて** が成り立つ場合にのみ受理される．

- リスナーがループバックアドレスにバインドされていること（設定で強制し，
  起動時に再確認する）．
- TCP のピアがループバックアドレスであること．
- `Host` ヘッダーが `localhost` またはループバック IP を名指ししており，ポートが
  あればリスナーのポートであること（DNS リバインディングを防ぐ）．
- `Origin` ヘッダーがあれば，同じポートに対する `http://<loopback host>[:port]`
  であること（`null` と外部のオリジンは拒否する）．
- `Sec-Fetch-Site` があれば `same-origin` または `none` であること．
- ボディを持つリクエストが `Content-Type: application/json` を伴うこと．

受理された呼び出し元はすべて admin ロールのプリンシパル `localhost-dev` となり，
監査ログにはその名前が記録される．このモードでは **ループバック接続を開ける
ローカルユーザーは誰でも管理者である**．単一ユーザーの開発・テスト用ホストの外に
公開してはならず，このモードで動くコンテナをネットワークに公開してもならない．
そのためにあるのが `oidc` である．

## GUI

`/ui/` は同じ API の上に載る最小限のインターフェースである．target（一覧，作成，
編集，有効化／無効化，run の要求），ポリシー（一覧，作成，編集），run（ステータスで
絞り込める一覧，詳細，キャンセル），監査ログを扱う．バイナリに埋め込まれた 3 つの
静的ファイル（ページ 1 つ，スクリプト 1 つ，スタイルシート 1 つ）で，フレームワークも
ビルド手順もない．表示するものはすべて DOM のメソッドで描画し，データからマークアップを
組み立てることは決してなく，API の呼び出しは自身のオリジンに対してのみ行う．

`oidc` モードでは，ページは **パブリッククライアント**（`server.auth.oidc.clientId`）
として認可コードフローと PKCE で操作者をサインインさせる．`/ui/config` を読み，
ブラウザをプロバイダの `authorization_endpoint` に送り，返ってきたコードを
code verifier とともに `token_endpoint` で交換し，アクセストークンをタブの
セッションストレージに保持する（タブを閉じれば消え，URL や Cookie には決して
入れない）．トークンはベアラーヘッダーとして送るので，API には Cookie も CSRF
トークンも不要である．`401` を受けると操作者はサインインに戻される．viewer は
すべてを閲覧でき，変更操作には `403` を受ける．ページは，自身のスクリプトと
スタイルシート，自身のオリジンとプロバイダのトークンエンドポイントのオリジンへの
接続のみを許し，それ以外を許さない Content-Security-Policy（`default-src 'none'`，
インラインスクリプトなし，`frame-ancestors 'none'`）に加え，`X-Frame-Options: DENY`
と `Referrer-Policy: no-referrer` を付けて配信される．`localhost-dev` モードでは，
ループバック上の同一オリジンの呼び出し元であるため，同じページがサインインなしで動く．

GUI が表示するのは API が返すものだけである．秘密鍵，証明書本体，資格情報は決して
表示されない．Conductor がそれらを持っていないからである．

## ディレクトリとコンテナでの利用

| パス | 用途 |
|---|---|
| `/usr/local/bin/acme-conductor` | Conductor のバイナリ（イメージのエントリポイント）． |
| `/etc/acme-conductor/config.json` | 設定．**読み取り専用** でマウントする． |
| `/etc/acme-conductor/job-signing.pem` | ジョブ署名の秘密鍵（`jobSigning` を設定した場合）．このコンテナのみに **読み取り専用** でマウントする． |
| `/etc/acme-conductor/tls.crt`, `tls.key` | `server.tls` を設定した場合のリスナーの証明書と鍵（慣例であり，実際のパスは設定が名指しするもの）．**読み取り専用** でマウントする． |
| `/var/lib/acme-conductor/` | 書き込み可能で **永続**: `conductor.db`（および `-wal`/`-shm`）と `runs/`（run ごとの `job.json`/`result.json`．証明書の素材は含まない）． |
| `/mnt/exchange` | Container Apps ランチャーを使う場合: 実行中の run ごとの `job.json`/`result.json` を保持する exchange 共有． |

Conductor のイメージ（`Dockerfile.conductor`）には `acme-runner` も `lego` も
**含まれない**．したがって `local-process` ランチャーは，両方のバイナリが同じホストに
ある場合（開発用チェックアウト，または Runner を追加したカスタムイメージ）にのみ
動く．コンテナでは，`/var/lib/acme-conductor` が書き込み可能なマウントである限り
`--read-only` をサポートする．`localhost-dev` モードではポートをホストの
ループバックのみに公開し（`-p 127.0.0.1:8080:8080`），コンテナ内のプロセスが
ピアをコンテナのループバックとして見るのは，クライアントが同じネットワーク
名前空間にいる場合（`docker exec`，または `--network host`）だけであることに注意する．
公開ポート経由ではピアはブリッジのゲートウェイであってループバックではないため，
すべてのリクエストが拒否される．これはこのモードにおける意図された fail-closed の
挙動である．`oidc` モードでは `0.0.0.0:<port>` で待ち受け，`server.tls`（証明書と鍵を
読み取り専用でマウント）を使うか，TLS を終端する ingress の後ろに置く
（`server.behindTlsProxy: true`）．ピアのアドレスは問わない．

リリースされたイメージは，コミットが `main` 上にあるバージョンタグ（ワークフローは
それ以外を拒否する）で `ghcr.io/cits-nue/acme-conductor` と
`ghcr.io/cits-nue/acme-runner` に，`linux/amd64` と `linux/arm64` 向けに，SBOM と
provenance を添えて公開される（[ADR 0017](adr/0017-release-pipeline.md)）．
`gh attestation verify oci://ghcr.io/cits-nue/acme-conductor:<version> --owner CITS-NUE`
で検証し，そのダイジェストを固定して使うこと．

### バックアップと復元とロールバック

コントロールプレーンの状態はすべて `database.path` にある．バックアップは，プロセスを
止めてファイルをコピーする（`-wal` ファイルは次に開いたときに取り込まれる）か，
オンラインで `sqlite3 conductor.db ".backup out.db"` を使う．復元はプロセスを止めて
ファイルを戻す．新しいバイナリは起動時にスキーマを前方に移行する（バージョンは
`schema_migrations` に記録される．バージョン 2 で `actorAuthority` と
`requestedByAuthority` の列が追加され，既存の行は空のまま残る）．古いバイナリは
新しいスキーマで書かれたデータベースを拒否するため，デプロイのロールバックには
対応するバックアップの復元も伴う．バックアップ時点で実行中だった run は，次の
起動時に `failed`／「結果不明」として復旧される．

## ログ

stderr への構造化 JSON で，常に UTC．run に関するすべての行は `runId` と
`targetId`（判明していれば `fqdn` も）を持つ．`debug` では，Runner の子プロセスの
stderr（Runner 自身が既に秘匿処理を施した構造化ログ）を 1 行ずつ中継する
（1 行あたり 8 KiB に制限し，印字不能な文字は置き換える）．Conductor は，リクエスト
ボディ，binding の解決済み設定（そもそも持っていない），Runner の `Result` のうち
コントラクトが定義するフィールド以外を，決してログに出さない．

## セキュリティ境界

- Conductor は秘密鍵，証明書本体，DNS や Store の資格情報，クラウドの資格情報を
  持たない．データベースにはそれらの列がなく，それらを返すエンドポイントもない
  （[ADR 0005](adr/0005-conductor-never-touches-secrets.md)）．デプロイが自ら
  作り得る唯一の例外はローカルランチャーの `passthroughEnv` である（上記の
  セキュリティ上の注意を参照）．
- API の入力で指定できるのは管理者が登録した binding の名前だけである．コマンド，
  イメージ，パス，環境変数，リソース ID，資格情報のためのフィールドはなく，未知の
  フィールドは拒否されるため，どれも紛れ込ませることはできない．
- `oidc` モードでは，すべての呼び出し元はプロバイダが署名したトークンから決まる
  ロール付きの名前付きプリンシパルであり，すべてのエンドポイントに対して 1 つの
  ミドルウェアで検査される．Conductor はクライアントシークレットを持たず，`none` と
  HMAC アルゴリズムを拒否し，設定が前段での TLS 終端を表明しない限り，ループバック
  以外の平文リスナーにベアラートークンを決して通さない．GUI は静的で，同一オリジン
  で，DOM で描画され，厳格な Content-Security-Policy の下で配信される．
- FQDN とサフィックスは保存前に正規化され，ラベル境界で検査される．ポリシーを
  満たさない target は拒否され監査される．既存の target がポリシーを満たさなく
  なるようなポリシーの編集はできない．Runner はそれとは無関係に `JobSpec` を
  再検証し，自身の信頼された設定に照らして認可する
  （[アーキテクチャ](architecture.md#検証と認可)）．
- target ごとの排他，`revision` による楽観ロック，開始前の再確認により，古い要求や
  重複した要求が実行されることはない（脅威モデル T7）．データベースの所有権ロックに
  より，第 2 の Conductor プロセスが同じレジストリに対して計画したり，所有者の run を
  failed にしたりすることはない．
- 監査ログは追記専用で，各変更と原子的に書き込まれる．target，run，ポリシーは
  削除できない（[ADR 0008](adr/0008-no-purge-in-mvp.md)）．
- Runner の子プロセスには明示的な環境（Conductor の環境のうち `passthroughEnv` に
  挙げたものだけ）が渡され，タイムアウト付きで自身のプロセスグループで動く．その
  `Result` は厳密なコントラクトデコーダでデコードされ，開始した run を名指ししている
  ことが確認される．その stderr はデバッグログにのみ届き，記録には決して残らない．
- `jobSigning` を使う場合，Conductor から出ていくのは署名付き・期限付きの
  エンベロープである．Runner は途中で改変されたジョブ（FQDN の変更，binding の
  差し替え，期限の延長）を検知し，同じ run を 2 度実行することを拒否する．署名は
  Conductor を認証するものであり，Runner にできることを広げはしない．それは
  引き続き Runner 自身の信頼されたポリシーが決める．
- Container Apps ランチャーを使う場合，Conductor の ID は 1 つの Job の実行を開始・
  観測・停止できるだけで，それ以外は何もできない．Runner が何であるかを変えることは
  できず，Runner の DNS と Key Vault へのアクセスは Runner 自身のマネージド ID の
  もので，Bicep により最小権限のカスタムロールとしてプロビジョニングされる．
  プラットフォームのエラーは固定の文言（ステータスとエラーコード）でログに届き，
  レスポンスボディがそのまま届くことはない．

## 制限事項

- **プロバイダは audience の範囲内で信頼される．** この audience に対してプロバイダが
  admin ロールのトークンを発行した相手は誰でも管理者である．ロールの割り当ては
  プロバイダ側の管理であり，本プロジェクトが監査することはできない．盗まれた
  アクセストークンは期限切れまで使える（Conductor は失効確認もイントロスペクションも
  行わない）．プロバイダ側での短い有効期間と全区間の TLS がそれを抑える．ロールは
  2 つだけで，target ごと・ポリシーごとの権限はない．
- **`localhost-dev` は人ではなくホストを認証する．** 開発ホスト 1 台向けである．
- **GUI は最小限である．** API の上の一覧とフォームだけで，ダッシュボードも一括操作も
  独自の状態もない．サインインには `clientId` とプロバイダ側のパブリック
  クライアント登録が必要である．
- **ローカルランチャーは 1 ホストである．** 同じホストに `acme-runner`（とその
  `lego`）が必要で，Runner が必要とする資格情報は Conductor の環境に置かなければ
  ならない（`passthroughEnv`）．Container Apps ランチャーにはどちらの制約もない．
- **Container Apps ランチャーは偽のプラットフォームに対して検証されている．**
  そのテストは Jobs API のプロセス内の偽物に対して exchange 全体を動かし，Bicep は
  コンパイルと lint を通る．実行テンプレートの上書きがボリュームマウントを継承する
  こと，カスタムロールのアクション名，SMB 共有上の SQLite と `flock`，Result の
  伝播遅延は，最初の実機デプロイで確認されるまでは文書化された期待にとどまる
  （[`deploy/azure/README.md`](../deploy/azure/README.md)）．
- **強制終了は Runner を取り残し得る．** 復旧はそのような run を `failed`／
  「結果不明」とする．Runner はなお完了するかもしれず，次の期限到来の run がそれと
  競合する（Store とアカウントの状態はそれに耐えるが，ACME の注文が重複することは
  防がれない）．
- **単一プロセス，単一コネクション．** レジストリはすべてのステートメントを直列化
  する．数百の target と 1 人の操作者には十分だが，多忙なマルチテナント API には
  向かない．マルチレプリカは非目標であり，所有権ロックにより同じデータベース上の
  第 2 のプロセスはサポートされる形ではなく起動時エラーになる．
- **移行が移すのは名前であり，証明書やアカウントではない．** 取り込まれた target は，
  `targetSource` が `registry` になった時点で Conductor 自身のオブジェクト名の下で
  新たに発行される．利用側の参照先の付け替えは操作者が行い，shadow 比較が比べるのは
  一覧であって Store 内の証明書ではない（[`docs/migration.md`](migration.md)）．
- **ポリシーの変更はバージョン管理も push もされない．** ポリシーの更新は各 target の
  次の run で適用される（[Policy](#policy) を参照）．`acmeBinding` の変更は現在の
  証明書の再発行を強制せず，run にポリシーのリビジョンはなく，各 `JobSpec` 内の
  スナップショットがあるだけである．
- **ローカルランチャーでは署名は任意である．** `jobSigning` なしでは，run ごとの
  プライベートなディレクトリ経由で生の `JobSpec` を渡し，それを end-to-end で
  認証するものはない．これが許容できるのは 1 ホスト上のみである．
- **メトリクスエンドポイントはまだない．** `/healthz` と `/readyz` はあるが，
  Prometheus の `/metrics` はない．
- Runner の `renewBeforeDays`/`keyType` というコストのレバーは，Runner 側では
  まだ制限されていない（脅威モデルの残存リスク）．
