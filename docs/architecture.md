# アーキテクチャ

## 概要

ACME Conductor は，クラウドに依存しない証明書管理のコントロールプレーンである．
新しい ACME クライアントでは **ない**．ACME プロトコルの処理はすべて，既存で広く
使われている [go-acme/lego](https://github.com/go-acme/lego) CLI に委ねる．これは
バージョン固定した公式バイナリであり，Runner が引数ベクトル（`argv`）でサブプロセス
として起動する．シェル文字列を経由することは決してない．

システムは 2 つのバイナリに分かれ，その間には厳格な境界がある:

- **`acme-conductor`** はコントロールプレーンである．常駐サービスとして FQDN の
  レジストリ（`Target`），証明書ポリシー，追記専用の監査ログ，run のレジストリ，
  スケジューラ，そして設定された実行基盤上で Runner の実行を開始する
  `Job Launcher` インタフェースを持つ．ACME，DNS，証明書の実体に直接触れることは
  決してない．
- **`acme-runner`** はデータプレーンである．ワンショットの OCI ジョブとして，受け取った
  `JobSpec` を厳格に検証し，自身の信頼された Runner 側ポリシー
  （`policy.RunnerAuthorizationPolicy`，Phase 1）に照らして要求を認可し，`lego` を
  ちょうど 1 回起動し，結果を正規化し，証明書を外部の **Certificate Store**
  （ローカル開発ではファイルシステム，Phase 3 以降は Azure Key Vault）に直接書き込み，
  終了する．自身のサーバもスケジューラも動かさない．

この分割は，2 つの半分をそれぞれ異なる最小限の ID でデプロイできるようにするために
ある．Conductor は調整役だが決してシークレットを預からず，Runner は起動された 1 回の
実行の間だけシークレットを預かる．

## 構成図

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

Conductor が DNS プロバイダや Certificate Store と直接やり取りすることは決してない．
`JobSpec` を生成し，後で `Result` を消費するだけである．両者は 2 つのバイナリが
やり取りする唯一の 2 種類の文書として Conductor/Runner 境界を越え，どちらも
`pkg/api/v1alpha1` のバージョン付きコントラクトで定義される（後述の
[JobSpec/Result コントラクト](#jobspecresult-コントラクト)を参照）．

## コンポーネントと責務

### acme-conductor (コントロールプレーン)

- **Target Registry** — 管理下にある FQDN の正となる一覧
  （[ドメインモデル](#ドメインモデル)を参照）．FQDN の一意性と正規化を司る．
- **CertificatePolicy** — `Target` が発行される際の規則: 許可する DNS サフィックス，
  ワイルドカードの可否，更新ウィンドウ，鍵種別．
- **Audit Log** — 管理操作と run のイベント（target の作成/更新/無効化，ジョブ開始，
  失敗，ポリシー拒否）の追記専用の記録．MVP ではここから何かが削除されることは
  決してない．
- **Run Registry** — すべての reconcile 試行（`Run`）の履歴と現在の状態．どこで
  どのように実行されたかには依存しない．
- **Scheduler** — `Target` の発行または更新の期限が到来したかを判断し，その
  `JobSpec` を生成する．
- **Job Launcher interface** — 「どこかで Runner の実行を開始する」ことの抽象化
  （コントラクトは `pkg/launcher`．実装は Phase 2 以降のローカルプロセスである
  `internal/conductor/launcher/localprocess` と，Phase 4 以降の Azure Container Apps
  Job である `internal/conductor/launcher/acajob`）．クラウド固有のランチャーコードは
  このインタフェースの背後に置き，決して Conductor のコアには置かない．
- **API と GUI** — REST API（`internal/conductor/api`）は自由形式の入力を受け付ける
  唯一の境界である．Phase 5 以降は OIDC ベアラートークンで呼び出し元を認証し，
  admin または viewer のロールを持つ名前付きプリンシパルとして扱い
  （`internal/conductor/oidc`，[ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)），
  同じ API の上で最小限の静的 GUI（`internal/conductor/ui`）を提供する．開発モード
  `localhost-dev` はホスト 1 台向けに残る．

### acme-runner (データプレーン)

- **JobSpec の検証と認可** — 厳格なデコード（[コントラクト](#jobspecresult-コントラクト)
  を参照）に加えて完全な意味的検証（`JobSpec.Validate`．文書そのものの自己整合性の
  検査）を行い，続いて Runner 自身の信頼された `policy.RunnerAuthorizationPolicy`
  （Phase 1）に照らして認可する．後述の[検証と認可](#検証と認可)を参照．
- **lego の起動** — 検証済みの `JobSpec` から組み立てた明示的な引数ベクトルで，固定
  バージョンの `lego` バイナリをサブプロセスとして 1 回だけ呼び出す．このコマンドの
  組み立てにも実行にもシェルは決して使わない．
- **Result の正規化** — `lego` が生成したものを `Result` 文書に変換する: 安定した
  エラー分類，証明書のフィンガープリント，有効期限のタイムスタンプ，論理的な store
  参照．証明書本体，鍵の実体，資格情報が `Result` に現れることは決してない．
- **Certificate Store アダプタ** — 秘密鍵と証明書を設定された store（Phase 1 以降は
  ファイルシステム，Phase 3 以降は Azure Key Vault）に直接書き込み，その後ローカルの
  コピーを破棄する．システム全体で秘密鍵を保持する唯一の場所であり，しかも 1 回の
  実行の間だけである．

### DNS プロバイダ

`DnsBinding` を介して，`lego` 組み込みの DNS プロバイダ対応で解決される．Runner が
持つのは，バインディングが名指しする単一のプロバイダのための資格情報または
ワークロード ID だけであり，チャレンジ用ゾーンにスコープされる．

### Certificate Store

発行された証明書とその秘密鍵を永続的に保持する外部システム（開発ではファイルシステム，
デプロイでは Azure Key Vault．[ADR 0013](adr/0013-azure-key-vault-store-adapter.md)
を参照）で，`StoreBinding` を通じて指し示す．Conductor がここから読み出すことは
決してない．store アダプタはバンドルを書き込み，更新判断のために証明書の公開部分を
読み戻す．store から秘密鍵を読み戻すアダプタは存在しない．Key Vault では，
バインディングごとに PEM かパスワードなし PKCS #12（PFX）での取り込みを選べ，
格納形式がバインディングと異なる証明書は（秘密鍵を読み戻して書き直すのではなく）
再発行される（[ADR 0021](adr/0021-keyvault-pkcs12-content-type.md)）．

## コントロールプレーンとデータプレーン

| | コントロールプレーン (`acme-conductor`) | データプレーン (`acme-runner`) |
|---|---|---|
| 寿命 | 常駐サービス | ワンショットのジョブ．1 回の実行後に終了 |
| 秘密鍵 / 証明書の保持 | 決してない | 1 回の実行中に一時領域で短時間のみ |
| DNS / Key Vault / クラウド資格情報の保持 | 決してない | あり．ワークロード ID 経由で，起動時のバインディングにスコープされる |
| ACME/DNS/Store との通信 | 直接は決してない | あり．Runner のみが行う |
| 停止時の影響 | すでにスケジュール済みの Runner ジョブは完了まで動く | 失敗した実行は Conductor の次のスケジューリングで再試行される |
| ネットワーク露出 | Web UI / REST API（管理者向け） | なし（バッチジョブ．HTTP サーバも cron もない） |

Conductor の停止が，すでに起動された Runner ジョブの完了を妨げることは決してあっては
ならない．Runner は処理のために Conductor を呼び戻すことはなく，完了時に `Result` を
報告するだけである．Phase 2 のローカルプロセスランチャーでは Runner は Conductor の
子プロセスなので，正常停止はそれを（`server.shutdownGraceSeconds` まで）待ってから
キャンセルする．Conductor が結果を取りこぼした実行は，次回起動時に「結果不明」として
失敗と記録され，決して推測されない
（[ADR 0011](adr/0011-conductor-storage-and-run-model.md) を参照）．

## ドメインモデル

Phase 2 で実装済み（`internal/conductor/registry` がモデルと `Registry` インタフェースを
定義し，`internal/conductor/sqlite` が永続化する．
[ADR 0011](adr/0011-conductor-storage-and-run-model.md) と
[`docs/conductor.md`](conductor.md) を参照）．Phase 0 のコントラクトとストレージ設計が
一致するよう，ここに記述する．

- **`Target`** — `{id, fqdn (normalized ASCII, unique), enabled, owner,
  policyRef, executionBinding, dnsBinding, storeBinding, createdAt,
  updatedAt, revision}`．1 つの `Target` は 1 つの FQDN である（MVP: FQDN ごとに
  証明書 1 枚，SAN なし）．`revision` は楽観的ロックのカウンタで，その target 向けに
  生成されるすべての `JobSpec` にも現れるため，`Result` は常にそれが生成された時点の
  正確な target の状態に対応付けられる．
- **`CertificatePolicy`** — `{id, allowedDnsSuffixes, allowWildcard,
  acmeBinding, renewBeforeDays, keyType, maxSANs, enabled}`．`maxSANs` は表現は
  あるものの MVP のドメインモデルでは 1 に固定される．v1alpha1 の JobSpec コントラクト
  には SAN の一覧がそもそもないためである（[非目標](#非目標)を参照）．
- **バインディング** — `ExecutionBinding`，`DnsBinding`，`StoreBinding`，
  `AcmeBinding`: 管理者が登録した論理名で，起動時の設定から読み込まれる．
  [バインディングモデル](#バインディングモデル)を参照．
- **`Run`** — `{id, targetId, targetRevision, status
  (queued|starting|running|succeeded|failed|cancelled), requestedBy,
  requestedByAuthority, requestedAt, startedAt, finishedAt, action, expiresAt,
  fingerprintSha256, storeObjectRef, errorCode, errorSummary,
  externalExecutionId}`．1 つの `Run` は完了すると
  1 組の `JobSpec`/`Result` に対応する．
- **`AuditEvent`** — 追記専用．target の作成/更新/無効化，ジョブ開始，ジョブ失敗，
  ポリシー拒否について記録される．MVP には purge 操作がない
  （[ADR 0008](adr/0008-no-purge-in-mvp.md) を参照）．target の無効化はその履歴の
  削除と同じではない．

## バインディングモデル

API の入力でコマンド，コンテナイメージ，クラウドリソース ID，資格情報，プロバイダ設定を
直接指定することは決してできない．指定できるのは，管理者があらかじめ登録した論理
バインディングの名前だけである:

- **`ExecutionBinding`** — Runner ジョブが実際にどこでどのように動くか（ローカル
  プロセス，のちに Azure Container Apps Job）．
- **`DnsBinding`** — ACME DNS-01 チャレンジをどの DNS プロバイダのどのゾーンに書くか．
- **`StoreBinding`** — 結果をどの Certificate Store に書くか．
- **`AcmeBinding`** — Runner がどの ACME ディレクトリ，アカウント，（任意の）External
  Account Binding として認証するか．

MVP では 4 種類のバインディングすべてが Runner/Conductor の起動時設定から読み込まれる．
実行時にそれらを作成・変更するための管理 API はない．
`ExecutionBinding` と `StoreBinding` は `{ "type", "config" }` の形をとる: 汎用の設定は
型名の形と `config` がオブジェクトであることだけを知っており，バイナリ内でその型に
登録されたプロバイダ（`cmd/<binary>/providers.go`）がオブジェクト自体をデコードして
検証する（[ADR 0019](adr/0019-provider-boundary.md)）．
Conductor の設定（`internal/conductor/config`）は `ExecutionBinding` を定義し，
ポリシーや target が選択してよい ACME/DNS/Store バインディングの **名前** を列挙する．
名前だけである．名前が何に解決されるかは Runner の設定であり，Conductor がそれを
見ることは決してない．
`JobSpec` が運ぶのはバインディングの名前（DNS ラベルに似た短い文字列．
`pkg/api/v1alpha1/validate.go` の `bindingNameRe` を参照）だけであり，Runner はその
名前を自身の設定から実際のディレクトリ URL，資格情報，ワークロード ID に解決する．
これにより任意のインフラ値が API 入力から完全に排除され，Conductor に DNS の
書き込み権限も Certificate Store の読み取り権限もまったく与えずに済む．Conductor は
バインディングが実際に何に解決されるかを知る必要が決してないからである．

## JobSpec/Result コントラクト

`pkg/api/v1alpha1`（`types.go`，`validate.go`，`decode.go`）で定義され，
`schemas/v1alpha1/` 配下に JSON Schema として写される（テストにより Go の検証と同期が
保たれる．常に Go のコードが正である．`schemas/README.md` を参照）．スキーマの
API バージョン: `acme-conductor.cits-nue.github.io/v1alpha1`．

### `CertificateReconcileJob` (`JobSpec`)

Conductor が生成し，Runner がちょうど 1 回消費する．

```json
{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "CertificateReconcileJob",
  "runId": "01JABCDEFGHJKMNPQRSTVWXYZ0",
  "target": {
    "id": "01JABCDEFGHJKMNPQRSTVWXYZ1",
    "fqdn": "www.example.ac.jp",
    "revision": 3
  },
  "policy": {
    "allowedDnsSuffixes": ["example.ac.jp"],
    "allowWildcard": false,
    "renewBeforeDays": 30,
    "keyType": "ec256"
  },
  "acme": { "binding": "letsencrypt-prod" },
  "dns": { "binding": "azure-dns-example" },
  "store": { "binding": "fs-dev" }
}
```

`policy` は参照ではなく **スナップショット** である: Conductor がジョブを作成した
時点で適用したポリシーを値としてコピーしたもので，Conductor に問い合わせることなく
`JobSpec` だけから実行を完全に監査できるようにする．Runner にとっては文書の他の
すべてのフィールドとまったく同様に信頼できない入力である．後述の
[検証と認可](#検証と認可)を参照．

`JobSpec` において，スキーマの構成上禁止されるもの（そのためのフィールドがそもそも
存在せず，厳格なデコードは追加しようとするあらゆる試みを拒否する）: シェルコマンド，
実行ファイルのパス，任意の環境変数，コンテナイメージの参照，クライアントシークレット /
アクセスキー / 秘密鍵，任意のクラウドリソース ID，任意の出力パス．現れるのは
不透明な識別子，正規化された FQDN，ポリシーの値，論理バインディング名だけである．

### 検証と認可

`pkg/api/v1alpha1/validate.go` と `internal/policy` は意図的に 2 つの異なる問いを
分離しており，文書（およびコードコメント）は前者に対して「認可」という語を決して
使わない:

- **検証** — `JobSpec.Validate` が行うこと．文書が整形式であり **内部的に自己整合**
  していることを検査する: 定数と構文，範囲，`target.fqdn` と
  `policy.allowedDnsSuffixes` の各要素がすでに正準形であること，`target.fqdn` が
  **同じ文書に埋め込まれた** `policy` スナップショット内のいずれかのサフィックスの
  下にラベル境界で位置すること，そしてワイルドカードの使用はその同じスナップショットが
  許可する場合に限られること．この検査が比較する値はすべて文書自身に由来する．
  `JobSpec` を生成または改変できる者は（侵害された Conductor を含めて），
  `target.fqdn` と `policy` スナップショットを一緒に書き換えてもこの検査を通過できるし，
  バインディング名を別の，同じく整形式で登録済みのバインディングに向けることもできる．
  `Validate` を通過することは「この文書は首尾一貫している」を意味するのであって，
  「この発行は許可されている」を意味することは決してない．
  `pkg/api/v1alpha1/validate_test.go` の
  `TestJobSpecValidateIsSelfConsistencyNotAuthorization` を参照．
- **認可** — 検証済みの文書に基づいて行動する前に，Runner が自身の信頼された設定を
  用いて行わなければならないこと．これが `policy.RunnerAuthorizationPolicy` とその
  `Authorize` メソッド（`internal/policy/authorize.go`）である: 既定拒否の判断であり，
  実行基盤上で読み込まれた設定に照らして評価され，`JobSpec` 自身の `policy`
  スナップショットに照らすことは決してない．フィールドは以下の通り:
  - `AllowedDnsSuffixes` — この Runner が発行してよい DNS サフィックス．
  - `AllowWildcard` — それらのサフィックス配下でワイルドカード名を許可するか．
  - `AllowedACMEBindings`，`AllowedDNSBindings`，`AllowedStoreBindings` — この
    Runner が選択してよい論理バインディング名の許可リスト．整形式だが列挙されていない
    バインディング名は，Runner がその設定を持っていたとしても拒否される．`JobSpec` の
    バインディング名はこの Runner 側設定へのセレクタにすぎないため，バインディング名が
    別の登録済みの名前にすり替えられた文書は `Validate` では捕捉されず，代わりにここで
    捕捉される．

  `Authorize` は正規化済みの FQDN を要求し（呼び出し元に代わって正規化はしない），
  検証と同じラベル境界の規則でサフィックスを照合する．Phase 0 ではポリシー型と判断
  関数をテスト付きで定義した．Phase 1 以降，Runner は信頼された設定
  （`internal/runner/config`）を読み込み，そこから `RunnerAuthorizationPolicy` を
  組み立てて（`Config.Policy()`）から `JobSpec` に基づいて行動する．正確な手順は
  [`docs/runner.md`](runner.md#実行フロー) を，これが何を閉じ何を閉じないかは
  `docs/threat-model.md`（T1/T2/T5 および「保証レベル」）を参照．
- **署名の範囲．** Phase 4 以降，`JobSpec` は `SignedCertificateReconcileJob`
  エンベロープ（`pkg/api/v1alpha1/signedjob.go`，
  [ADR 0015](adr/0015-signed-job-envelope.md)）に包んで運ぶことができる: JobSpec の
  バイト列そのものに対する Ed25519 の JWS 構成であり，`kid`，`issuedAt`，`expiresAt`，
  `nonce` を持つ厳格な保護ヘッダを備え，Runner が信頼された設定内の公開鍵に照らして
  検証し，状態ディレクトリ内のリプレイ台帳で裏付ける．これは転送中の改ざんから文書を
  守り，リプレイを制限する．しかし，不正な `JobSpec` を正当に生成（そして署名）する
  侵害された Conductor には，それ自体では対処しない．その場合を制限するのは上記の
  Runner 側の信頼された認可ポリシーだけであり，これは従来どおり展開後の文書に対して
  動作する．

### `CertificateReconcileResult` (`Result`)

ちょうど 1 回の Runner 実行が生成し，Conductor が消費する．

成功:

```json
{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "CertificateReconcileResult",
  "runId": "01JABCDEFGHJKMNPQRSTVWXYZ0",
  "targetId": "01JABCDEFGHJKMNPQRSTVWXYZ1",
  "status": "succeeded",
  "action": "issued",
  "expiresAt": "2026-12-19T00:00:00Z",
  "fingerprintSha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "storeObjectRef": "www-example-ac-jp",
  "startedAt": "2026-09-20T00:00:00Z",
  "finishedAt": "2026-09-20T00:02:11Z",
  "error": null
}
```

失敗:

```json
{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "CertificateReconcileResult",
  "runId": "01JABCDEFGHJKMNPQRSTVWXYZ0",
  "targetId": "01JABCDEFGHJKMNPQRSTVWXYZ1",
  "status": "failed",
  "action": "failed",
  "startedAt": "2026-09-20T00:00:00Z",
  "finishedAt": "2026-09-20T00:01:04Z",
  "error": {
    "code": "DnsFailure",
    "summary": "TXT record propagation timed out"
  }
}
```

`storeObjectRef` は **厳格な論理名** である
（`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`，最大 128 文字．Azure Key Vault
の証明書名（1〜127 文字）を収められる長さで，`..` は拒否される）．`/ \ : ? # @ % & =`
や空白はどれも現れ得ないため，資格情報の有無にかかわらず，URL にも URI にもパスにも
クエリ文字列にも決してならない．これは慣習ではなくパターンの構成によって保証される．

`error.summary` は短く，長さが制限され，印字可能文字のみからなる文字列で，さらに
`pkg/api/v1alpha1/validate.go` に記述されたシークレットマーカーのヒューリスティック
（`secretMarkers`）に照らして検査される．大文字小文字に意味が依存しないマーカー
（`bearer `，`basic `，`authorization:`，`password=`，`secret=`，`token=`，`sig=`，
`key=` など）は大文字小文字を区別せずに照合される．この検査は多層防御であって
シークレット検出器ではない: 任意のシークレットや未知の形式を認識することはできない．
`Result` に生の外部出力が入らないことを実際に保証する規則は Runner の責務である
（Phase 1）: Runner は生の外部コマンド/SDK のエラー，stdout，stderr を `Result` に
決してコピーしない．`error.summary` は Runner が持つ安全なテンプレートだけから生成され，
外部の詳細はすべて秘匿処理済みの内部ログにのみ出力される．`error.code` は固定された
追記専用の集合（`InvalidJobSpec`，`PolicyViolation`，`BindingNotFound`，
`AcmeFailure`，`DnsFailure`，`StoreFailure`，`Timeout`，`Cancelled`，`Internal`）の
いずれかであり，API 利用者にとって主となる機械可読なシグナルである．
`error.summary` は人間向けであり，決して解析されることを意図していない．

### デコード規則

両方の文書は **厳格に** デコードされる: 未知のフィールド，重複した JSON オブジェクト
キー，文書の後に続く余分なデータはすべて拒否され，64 KiB を超える文書は即座に拒否され，
8 段階を超えるネストはウォーカーが CPU を費やす前に拒否される
（`pkg/api/v1alpha1/decode.go`）．重複キーの拒否が重要なのは，`encoding/json` が
繰り返されたキーについて黙って最後の値を採用するためで，放置すれば古典的な検証
バイパスの経路になる．

## FQDN の正規化規則

`internal/policy/fqdn.go` に実装され，Conductor と Runner で同一に適用される
（`JobSpec.Validate()` は `policy.Evaluate` を再実行する）．`v1alpha1` は ASCII のみ
である:

- 前後の空白は取り除く．
- 末尾のドット（絶対名）はちょうど 1 つだけ取り除く．
- ASCII の英字は小文字にする．
- 非 ASCII の入力は拒否する（`ErrNonASCII`）．国際化ドメイン名はまだサポートしない．
  [ADR 0006](adr/0006-ascii-only-fqdn-in-v1alpha1.md) を参照．
- ラベルは 1〜63 オクテットで，ASCII の英字，数字，ハイフンのみを含み，ハイフンで
  始まったり終わったりしてはならない．アンダースコアを含むラベルは即座に拒否する:
  有効なホスト名ではなく，そのための証明書が望まれることは決してない．
- `xn--` で始まるラベルは，構文的には有効な ASCII ラベルであっても `v1alpha1` では
  拒否する（`ErrIDNALabel`）．ADR 0006 を参照．
- 少なくとも 2 つのラベルが必要で，全長は 253 オクテットを超えてはならない．
- 最上位（右端）のラベルはすべて数字であってはならない．
- ワイルドカード（`*`）は左端のラベル全体としてのみ受け付け
  （`*.example.ac.jp` は可．`foo*.example.ac.jp` や `*foo.example.ac.jp` は決して
  不可），かつ残りのベース名自体が少なくとも 2 つのラベルを持つ場合に限る
  （`*.ac.jp` 単独は拒否する: TLD 全体のワイルドカードが有効であることは決してない）．

`CertificatePolicy` の許可 DNS サフィックスも同じ正規化（`NormalizeSuffix`）を通り，
加えてサフィックス自体がワイルドカードを決して含まないことを検査する．

### ラベル境界でのサフィックス照合

`Target` の FQDN はポリシーの許可サフィックスに対して **ラベル単位** で検査され，
生の文字列サフィックスで検査されることは決してない．`evil-example.ac.jp` は
`example.ac.jp` という文字で終わっていても，許可サフィックス `example.ac.jp` の下には
**ない**: 照合には完全一致か，境界がちょうどラベル区切りに落ちるように直前に `.` が
あることが必要である（`example.ac.jp` と `*.example.ac.jp` は一致する．
`evil-example.ac.jp` は一致しない．その名前では `example.ac.jp` の直前に `.` が
ないためである）．ワイルドカード target では，ベース名（`*.` の後の部分）が
サフィックス一覧と照合される．

## リポジトリの構成

```
cmd/
  acme-conductor/   コントロールプレーンのバイナリ (serve，Phase 2)．providers.go が同梱するランチャー型を登録する
  acme-runner/      データプレーンのバイナリ (reconcile，Phase 1)．providers.go が同梱する store 型を登録する
internal/
  conductor/            Conductor の配線: 設定，レジストリ，スケジューラ，ランチャー，API (Phase 2)
  conductor/api/        REST API ハンドラ，localhost-dev 認証器，ロールの強制，GUI のルート
  conductor/oidc/       OIDC ベアラートークン認証器: ディスカバリ，鍵セットのキャッシュ，JWS 検証 (Phase 5)
  conductor/oidc/oidctest/ テスト用のインプロセス OpenID プロバイダ．出荷するバイナリにはコンパイルされない
  conductor/ui/         埋め込みの GUI: index.html，app.js，app.css (Phase 5)
  conductor/config/     Conductor の設定の読み込みと検証．ランチャー型を知らない
  conductor/launchers/  合成層: Conductor のコアがランチャーを構築する際に通るランチャープロバイダのレジストリ
  conductor/launcher/localprocess/ ローカルプロセスのランチャー (開発とテスト)
  conductor/launcher/acajob/ Azure Container Apps Job ランチャー (Phase 4)．Conductor 唯一の Azure SDK import
  conductor/registry/   ドメインモデル (Target，CertificatePolicy，Run，AuditEvent) と Registry インタフェース
  conductor/scheduler/  期限到来の判断，target ごとの排他，run の実行
  conductor/sqlite/     Registry の SQLite 実装．マイグレーション付き
  conductor/fakerunner/ Conductor のテストで使う acme-runner のテストダブル．出荷するバイナリにはコンパイルされない
  conductor/migration/  インフラ定義のホスト一覧からの移行: Bicep パラメータ/TargetList の読み取り，差分，冪等な取り込み，shadow 比較 (Phase 6)
  exchange/         自ら起動する Runner にジョブを差し出し，1 つの Runner だけが取るためのディスク上の受け渡しプロトコル (Phase 4，ADR 0014)
  fslock/           Runner のディスク上の store が共有するアドバイザリファイルロック
  keygen/           両バイナリ共通の keygen サブコマンド: ジョブ署名鍵と Result 署名鍵 (Ed25519) の生成 (Phase 4，ADR 0015)
  policy/           FQDN の正規化とサフィックス照合 (internal/policy/fqdn.go)
  runner/           Runner の reconcile ループ，作業ディレクトリ/状態ディレクトリの扱い，Result の書き出し (Phase 1)
  runner/config/    Runner の設定の読み込みと検証 (Phase 1)．store 型を知らない
  runner/transport/ ジョブが Runner に届き Result が出ていく経路: Source コントラクトと 2 ファイル方式のトランスポート
  runner/transport/claim/ 共有ディレクトリ (交換用) のトランスポート．実行 ID はコマンドから与えられる
  runner/platform/azurecontainerapps/ Container Apps Job 実行の実行 ID．Runner がその基盤に言及する唯一の場所
  runner/stores/    合成層: Runner のコアが store を開く際に通る store プロバイダのレジストリ
  runner/lego/      lego の argv/env の構築，サブプロセス実行，出力の秘匿 (Phase 1)
  runner/fakelego/  Runner のテストで使う lego のテストダブル．出荷するバイナリにはコンパイルされない
  store/            Certificate Store の実装．コントラクト自体は pkg/store
  store/filesystem/ ファイルシステムを用いる Certificate Store (開発/テスト専用，Phase 1)
  store/keyvault/   Azure Key Vault の Certificate Store (Phase 3)．Runner 唯一の Azure SDK import
  strictjson/       セキュリティ上重要な設定とコントラクトの厳格な JSON デコード: 未知フィールド，重複キー，末尾データを拒否する
  version/          -ldflags で注入するビルド情報
pkg/api/v1alpha1/   バージョン付きの JobSpec/Result コントラクトと署名付きジョブエンベロープ (型，検証，厳格なデコード)
pkg/store/          Certificate Store コントラクト (Store，Bundle，Info) とすべての store が共有する証明書ヘルパー
pkg/launcher/       Job Launcher コントラクト (Launcher，Execution，Error/Reason)，ジョブ署名と Result 検証
                    — pkg/ は別モジュールのプロバイダアダプタが import するもの (pkg/contracts_test.go がそれを保つ)
schemas/v1alpha1/   Go コントラクトを写した JSON Schema．テストで同期を保つ
deploy/examples/    Conductor と Runner の設定例と JobSpec 文書の例
deploy/azure/       Container Apps デプロイ用の Bicep: 環境，ID，カスタムロール，Runner Job，Conductor アプリ (Phase 4)
docs/               この文書，脅威モデル，Conductor と Runner のガイド，ADR
Dockerfile.conductor  acme-conductor 用の distroless・非 root イメージ
Dockerfile.runner     acme-runner 用の distroless・非 root イメージ
Makefile            build / verify / image のターゲット
.github/workflows/   CI (フォーマット，vet，ビルド，テスト，race，govulncheck，コンテナのスモークテスト) とリリースワークフロー (SBOM と provenance 付きの GHCR イメージ，Phase 5)
```

`pkg/` には両バイナリから，そしてゆくゆくは JobSpec/Result コントラクトを話す外部
ツールからも import されることを意図したコードを置く．`internal/` にはこのモジュール
限りのコードを置く．

## 技術選定

- **Go**．REST API には標準の `net/http`（メソッドとパターンによる `ServeMux`）を使い，
  Web フレームワークは使わない（Phase 2）．
- **SQLite**（`modernc.org/sqlite`．純 Go なので `CGO_ENABLED=0` を保てる）を
  `Registry` インタフェースの背後に置き，Conductor の状態（Target，CertificatePolicy，
  Run，AuditEvent）にバージョン付きの明示的なマイグレーションを用いる．
  [ADR 0011](adr/0011-conductor-storage-and-run-model.md) を参照．PostgreSQL と
  複数レプリカの Conductor は当面明示的に対象外である（[非目標](#非目標)を参照）．
- GUI には **SPA フレームワークもビルド工程も使わない**（Phase 5）: バイナリに
  埋め込んだ 3 つの静的ファイル，DOM による描画，厳格な Content-Security-Policy，
  ブラウザ内でパブリッククライアントとして行う OIDC 認可コード + PKCE．API のトークン
  検証は JWT ライブラリから取らず，標準ライブラリの `crypto/rsa` と `crypto/ecdsa` の
  上にリポジトリ内で書かれている．受け入れるものが脅威モデルの列挙とちょうど一致する
  ようにするためである（[ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)）．
- **Runner イメージ**: マルチステージビルド，取得しチェックサム検証した固定バージョンの
  公式 `lego` バイナリ（Phase 1），distroless の静的ベースイメージ．
- **GHCR**（`ghcr.io/cits-nue/acme-conductor`，`ghcr.io/cits-nue/acme-runner`）が
  正式なコンテナレジストリである．バージョンタグを打つと，ダイジェスト固定のベース
  イメージから `linux/amd64` と `linux/arm64` 向けの両イメージが SBOM と SLSA provenance
  付きで公開される（[ADR 0017](adr/0017-release-pipeline.md)）．
- **設定**: 非シークレットの設定は環境変数または設定ファイルで行う．シークレットは
  設計上，Conductor の設定にはまったく含まれない（Conductor は DNS，Key Vault，
  長期有効なクラウド資格情報を持たない．[セキュリティ原則](#セキュリティ原則)を参照）．
- クラウド SDK（Azure，将来追加されるなら AWS/GCP）はランチャーと store アダプタの
  実装の内部にのみ置き，Conductor のコアには決して置かない．この境界は構造的である:
  アダプタは公開コントラクト `pkg/store` と `pkg/launcher` を実装し，コアは
  `internal/runner/stores` と `internal/conductor/launchers` のレジストリを通じてのみ
  それらに到達し，Runner のコアはいかなる基盤の環境も読まずに
  `internal/runner/transport` を通じてジョブを受け取る．2 つ目の基盤が現れるまでは
  単一の Go モジュールがすべてを持つ．`deploy/azure` は Azure アダプタの参照インフラで
  あり，それらと並べて残す（[ADR 0019](adr/0019-provider-boundary.md)）．

## セキュリティ原則

これらはすべての Phase を通じて成り立ち，[`docs/threat-model.md`](threat-model.md) で
具体的な対策に紐付けられている:

1. Conductor は証明書の秘密鍵を保存・取得・配布することが決してない．
2. Conductor は DNS の資格情報，Key Vault の資格情報，その他いかなる種類の長期有効な
   クラウド資格情報も持たない．
3. Runner は実行基盤のワークロード ID（Azure Managed Identity，AWS IAM Role，GCP
   Service Account）でクラウドサービスに認証する．設定に埋め込んだ静的シークレットは
   決して使わない．
4. 秘密鍵は Runner の一時領域で生成され，Certificate Store に直接格納された後，
   破棄される．Conductor を経由することは決してない．
5. Conductor の ID と Runner の ID は分離されている．Conductor には DNS の書き込み
   権限も Certificate Store の読み取り権限も与えない．
6. API の入力でコマンド，コンテナイメージ，リソース ID，資格情報，プロバイダ設定を
   指定することは決してできない．指定できるのは管理者が登録したバインディングの
   論理名だけである（[バインディングモデル](#バインディングモデル)を参照）．
7. FQDN ポリシーは，`Target`/`CertificatePolicy` を受け付ける際に Conductor が
   検証する．Runner は Conductor がすでに検査したことを信頼しない．Runner は受け取った
   `JobSpec` 文書を **検証** し（自己整合性．[検証と認可](#検証と認可)を参照），かつ
   自身の信頼された Runner 側ポリシーに照らして **認可** する．検証の段階はそれ自体では
   認可ではない．
8. 本番の ACME 認証局を自動テストから呼ぶことは決してない．

## 可観測性とログの規則

- 構造化 JSON ログ．常に UTC．
- 実行に関するすべてのログ行は `runId` と `targetId` を持つ．
- ログには資格情報，秘密鍵，ACME External Account Binding（EAB）の HMAC を決して
  含めない．脅威モデルのシークレット漏えいの項を参照．
- `/healthz` と `/readyz` は Phase 2 以降存在する（`readyz` はレジストリに ping する）．
  Prometheus の `/metrics` エンドポイントは後の Phase で続く．

## ロードマップ

**Phase 0 から 6** が現在実装済みである．Phase は厳密に順次進める．1 つの PR は
1 つの Phase の範囲を実装し，それ以上は実装しない
（[`CONTRIBUTING.md`](../CONTRIBUTING.md) を参照）．

| Phase | 範囲 |
|---|---|
| 0 | ブートストラップ: モジュール構成，JobSpec/Result コントラクト，CI． |
| 1 | **実装済み．** Runner + ファイルシステムの Certificate Store，固定バージョンの `lego` CLI 付き．[`docs/runner.md`](runner.md)，[ADR 0009](adr/0009-runner-execution-model.md)，[ADR 0010](adr/0010-pinned-lego-binary.md) を参照． |
| 2 | **実装済み．** Conductor MVP: SQLite レジストリ，REST API，ローカルプロセスランチャー，ローカルホスト限定の開発用認証．[`docs/conductor.md`](conductor.md)，[ADR 0011](adr/0011-conductor-storage-and-run-model.md)，[ADR 0012](adr/0012-localhost-only-dev-auth.md) を参照． |
| 3 | **実装済み．** Azure Key Vault の store アダプタ．基盤のマネージド ID（開発では SDK の `DefaultAzureCredential` チェーン）で認証する．[`docs/runner.md`](runner.md#certificate-store-azure-key-vault) と [ADR 0013](adr/0013-azure-key-vault-store-adapter.md) を参照．バインディングごとにパスワードなし PKCS #12 での取り込みも選べる（[ADR 0021](adr/0021-keyvault-pkcs12-content-type.md)）． |
| 4 | **実装済み．** Azure Container Apps Job ランチャー（Runner は自身のマネージド ID で動くスケジュール実行の Job として，Conductor が共有ボリュームに差し出すジョブを受け取る．Conductor は実行を開始できない）．分離された ID と最小権限のカスタムロールで Bicep によりプロビジョニングする．署名付き・期限付きのジョブエンベロープと Runner 側のリプレイ台帳，Runner が署名した Result．[`docs/conductor.md`](conductor.md#実行バインディング-azure-container-apps-job)，[`deploy/azure/README.md`](../deploy/azure/README.md)，[ADR 0014](adr/0014-azure-container-apps-job-launcher.md)，[ADR 0015](adr/0015-signed-job-envelope.md) を参照． |
| 5 | **実装済み．** 名前付きプリンシパルと admin/viewer ロールによる OIDC ベアラートークン認証，TLS リスナーまたは ingress 背後にあることの明示的な宣言，PKCE サインインを備えた最小限の静的 GUI，そして両イメージをダイジェスト固定のベースから SBOM と provenance 付きで GHCR に公開するリリースワークフロー．Container Apps のデプロイは HTTPS ingress を得て，管理用サイドカーを失う．[`docs/conductor.md`](conductor.md#認証)，[ADR 0016](adr/0016-oidc-bearer-auth-and-gui.md)，[ADR 0017](adr/0017-release-pipeline.md) を参照． |
| 6 | **実装済み．** 既存の cert-infra リポジトリからの移行ツール: ホスト一覧をその Bicep パラメータファイル（または TargetList 文書）から読み，レジストリと比較し（`added`/`changed`/`missing`/`unchanged`/`rejected`），冪等に取り込む（既定は dry-run．更新も削除も決して行わない）．`migration.targetSource` フラグ（`iac`/`shadow`/`registry`）により切り替えまで Conductor は発行を行わず，shadow モードでは比較を記録する．ロールバックはこのフラグである．[`docs/migration.md`](migration.md) と [ADR 0020](adr/0020-migration-from-cert-infra.md) を参照． |

## 非目標

将来の Phase または ADR が別途定めるまで，明示的に対象外とする:

- ACME プロトコルや DNS プロバイダ連携の再実装（`lego` がすでに行っている）．
- 独自の暗号．
- いかなる種類の秘密鍵配布 API．
- Kubernetes オペレータや CRD．
- 複数レプリカ / 高可用な Conductor．
- PostgreSQL（当面は SQLite がストアである）．
- AWS または GCP のプロバイダ（バインディングモデルはこれらを見越しており，プロバイダは
  今ではパッケージ 1 つと登録行 1 行である．[ADR 0019](adr/0019-provider-boundary.md)．
  まだ何も実装されていない）．
- Arc 管理下のホストへの証明書配布．
- あらゆる種類の自動 purge（[ADR 0008](adr/0008-no-purge-in-mvp.md) を参照）．
- 任意のスクリプトや発行後フック．
- 利用者が指定するコンテナイメージ．
- 動的なプラグインダウンロード．

## 関連文書

- [脅威モデル](threat-model.md)
- [Architecture Decision Records](adr/README.md)
