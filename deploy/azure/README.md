# Azure Container Apps へのデプロイ

`main.bicep` は Azure Container Apps 上に ACME Conductor の完全なデプロイを
プロビジョニングする．すなわち，環境の HTTPS ingress の背後で単一レプリカの
Container App として動き，API と GUI のすべての呼び出し元を OIDC ベアラー
トークンで認証する Conductor，Conductor が差し出したジョブを各実行が取っていく
*スケジュール実行の* Container Apps Job としての Runner（Conductor は実行を
開始できない．開始操作は Runner のイメージを差し替えられてしまうからである），
互いに重ならない権限を持つ 2 つのマネージド ID，そして 2 種類の署名付き交換用
文書が行き来するストレージである．これは脅威モデルが要求する IAM
（[`docs/threat-model.md`](../../docs/threat-model.md)，T10）をレビュー可能で
バージョン管理された形にしたものである．すべての権限付与は最小限のアクション
集合を持つカスタムロールであり，最も狭いスコープに割り当てられる．

ランチャーの動作は
[`docs/conductor.md`](../../docs/conductor.md#実行バインディング-azure-container-apps-job)
を，なぜこの形なのかは
[`docs/adr/0014-azure-container-apps-job-launcher.md`](../../docs/adr/0014-azure-container-apps-job-launcher.md)
を読むこと．**このテンプレートが検証されていない事項は末尾に列挙してある．
これに依存する前にそこを読むこと．** このディレクトリは Azure アダプタの
リファレンスインフラであり，アダプタとともにこのリポジトリに残る
（[ADR 0019](../../docs/adr/0019-provider-boundary.md)）．汎用のデプロイ
フレームワークではない．

## デプロイされるもの

| リソース | 目的 |
|---|---|
| `<prefix>-log` (Log Analytics) | 両バイナリのコンテナログ．Runner 自身のログは書き込まれる前に秘匿処理され，Conductor のログはシークレットを含まない． |
| `<prefix>-cae` (Container Apps environment) | アプリとジョブをホストする．Consumption プラン，VNet 統合なし． |
| `<prefix><hash>` (storage account) | 環境にマウントされる 3 つの Azure Files 共有: `conductor-state`（SQLite のレジストリ．`nobrl` でマウント），`runner-state`（ACME アカウントの状態．`/state`），`exchange`（署名付きジョブの入力と結果の出力）． |
| `<prefix>-id-conductor` (user-assigned identity) | Conductor の ID．Runner の Job に対してのみ **Conductor Job Execution Observer** カスタムロール（実行の読み取り・一覧・停止．開始は不可）を付与． |
| `<prefix>-id-runner` (user-assigned identity) | Runner の ID．チャレンジ用ゾーン（`dnsZoneNames` の各ゾーン）に **Runner DNS TXT Writer** カスタムロール，Key Vault に **Runner Key Vault Certificate Writer** カスタムロールを付与． |
| `<prefix>-runner` (Container Apps Job) | Runner イメージ．Runner の設定と結果署名用の秘密鍵（暗号化 EAB プロビジョニングを有効にした場合は provisioning 用の秘密鍵も）を `/etc/acme-runner/` 配下に，加えて `/exchange`，`/state`，一時的な `/work` をマウント．スケジュールトリガー（`runnerCronExpression`，毎分），実行ごとに 1 レプリカ（`parallelism: 1`．ランチャーのコントラクトは実行ごとに 1 つの run），リトライなし，固定コマンド `reconcile --exchange /exchange`． |
| `<prefix>-conductor` (Container App) | Conductor イメージ．設定とジョブ署名用の秘密鍵を `/etc/acme-conductor/` 配下に，加えて `/var/lib/acme-conductor` と `/mnt/exchange` をマウント．HTTPS 専用の ingress（既定で外部公開．必要に応じて送信元 CIDR で制限可）の背後に 1 レプリカ，`oidc` 認証，`/healthz` と `/readyz` での liveness/readiness プローブ． |
| 3 つのカスタムロール定義 (サブスクリプションスコープ) | **`main.bicep` ではなく `roles.bicep` が作る**．初回に一度だけ別にデプロイし，`main.bicep` はそれを割り当てるだけである（[ロール定義とデプロイの権限](#ロール定義とデプロイの権限)）． |

Conductor の ID は DNS，Key Vault，ストレージデータのいずれの権限も **持たない**．
Runner の ID は Job，アプリ，ストレージアカウントに対する権限を **持たない**．
どちらの ID もストレージアカウントキーを読めない．共有は環境がそのキーで
マウントし，キーはどちらのコンテナにも決して入らない．

## 前提条件

- このデプロイ用のリソースグループ，Runner が TXT レコードを書き込んでよい DNS
  ゾーン（1 つ以上．[複数の DNS ゾーン](#複数の-dns-ゾーン)），そして **RBAC** 権限モデル（`enableRbacAuthorization: true`）の
  Key Vault．後者 2 つは別のリソースグループにあってもよいが，デプロイと
  **同じサブスクリプションになければならない**．カスタムロールはその
  サブスクリプションを唯一の割り当て可能スコープとして定義されており，ロールは
  割り当て可能スコープの外には割り当てられないからである．必要な権限は，初回に
  一度だけのロール定義の作成と，毎回のデプロイとで分かれる
  （[ロール定義とデプロイの権限](#ロール定義とデプロイの権限)）．
  サブスクリプションをまたぐ配置は将来の拡張（サブスクリプションごとのロール
  定義）であり，パラメータにはなっていない．
- 3〜20 文字の小文字英字・数字・ハイフンからなる `namePrefix`．ストレージ
  アカウント名は，そこからハイフンを除いたものの先頭 11 文字に 13 文字の一意な
  サフィックスを付けて作られるため，受理されるどのプレフィックスからも 24 文字
  以内の有効な名前が得られる．
- ダイジェストで固定された両バイナリのコンテナイメージ．バージョン
  タグを打つと `ghcr.io/cits-nue/acme-conductor` と
  `ghcr.io/cits-nue/acme-runner` が `linux/amd64` と `linux/arm64` 向けに
  SBOM と SLSA provenance 付きで公開される
  （[ADR 0017](../../docs/adr/0017-release-pipeline.md)）．固定する前に
  リリースを検証し，そのダイジェストを読み取ること（ダイジェストはリリース
  実行のサマリにもある）:

  ```sh
  gh attestation verify oci://ghcr.io/cits-nue/acme-conductor:<version> --owner CITS-NUE
  gh attestation verify oci://ghcr.io/cits-nue/acme-runner:<version> --owner CITS-NUE
  docker buildx imagetools inspect ghcr.io/cits-nue/acme-conductor:<version>
  ```

  イメージはこのテンプレートと **同じツリーのリリース** から取ること．この
  テンプレートが両バイナリに渡す設定は現在の形式（store バインディングの
  `{type, config}` エンベロープなど）であり，それ以前のリリース（v0.5.0）の
  バイナリはこれを読めない．`main.bicepparam` の固定値のコメントがどの
  リリースかを示す．

  GHCR の公開イメージにはレジストリの資格情報は不要である．パッケージは初回
  リリース以降公開されている．GitHub が初回プッシュ時に作成するパッケージは
  リポジトリの可視性にかかわらず非公開なので，新しいパッケージ（名前を変えた
  イメージ，新しいバイナリ）を資格情報なしで pull できるようにするには，組織の
  オーナーが一度だけ公開に設定する必要がある．すべてのリリースは `latest` も
  タグ付けするが，これは便宜上存在するものであり，デプロイが固定する対象には
  決してならない．
- **OpenID Connect プロバイダ**と，Microsoft Entra ID の場合は 2 つのアプリ
  登録（下記の [ID](#id) を参照）．1 つは API *そのもの* を表すもの（その
  Application (client) ID が `oidcAudience`，そのアプリケーション ID URI が
  `oidcScopes` 内のスコープのプレフィックス，そのアプリロールが
  `oidcAdminRoles`/`oidcViewerRoles` の値），もう 1 つは GUI 用の *パブリック
  クライアント*（`oidcClientId`，シングルページアプリケーションのプラット
  フォーム，リダイレクト URI = `conductorGuiRedirectUri` 出力）．
- 署名鍵ペア 2 組．交換用共有の各方向に 1 組ずつ:

  ```sh
  acme-conductor keygen --private job-signing.pem --public job-signing.pub
  acme-runner keygen --private result-signing.pem --public result-signing.pub
  ```

  各コマンドは `keyId:` と `publicKey:`（公開鍵の 1 行形式）を出力する．秘密鍵
  ファイルはセキュアパラメータとして渡す（`jobSigningPrivateKeyPem` は
  Conductor 用にマウント，`resultSigningPrivateKeyPem` は Runner 用に
  マウント）．公開鍵は相手側に渡す（`jobSigningPublicKey` は Runner の設定へ，
  `resultSigningPublicKey` は Conductor の設定へ）．
- （EAB が必須の CA を使う場合のみ）暗号化 EAB プロビジョニング用の X25519
  鍵ペア（[ADR 0022](../../docs/adr/0022-encrypted-eab-provisioning-and-account-generations.md)）:

  ```sh
  acme-runner provisioning-keygen --private account-provisioning.pem --public account-provisioning.pub
  ```

  秘密鍵は `accountProvisioningPrivateKeyPem`（セキュアパラメータ．Runner の
  Job のシークレット `account-provisioning-key` として
  `/etc/acme-runner/account-provisioning.pem` にマウントされ，Runner の設定に
  `accountProvisioning.privateKeyFiles` として追加される），公開鍵は
  `accountProvisioningPublicKey`（Conductor の設定の
  `accountProvisioning.publicKey`）に渡す．**両方を渡すか，両方とも空にする．**
  あわせて，CA が EAB を要求する ACME binding の名前を
  `accountProvisioningBindings`（Conductor の設定の
  `accountProvisioning.bindings`．`acmeBindings` のいずれか）に渡す．
  機能を有効にするなら 1 個以上が必須で，無効なら空でなければならない．
  挙げた binding だけに GUI の投入フォームが出る．
  両方とも空（既定）なら機能は無効のままで，テンプレートの出力はこの機能の
  導入前と変わらない．片方だけを渡すと，デプロイは何も変更しないうちに
  失敗する（空の秘密鍵でシークレットを上書きすると，プロビジョニングの run が
  Runner 側で失敗するため）．出力された `keyId` は控えておく（デプロイ後の
  確認に使う）．鍵のローテーション（`privateKeyFiles` を 2 本にする）には，
  テンプレートはまだ対応していない．

## ロール定義とデプロイの権限

カスタムロールの定義（`roles.bicep`，サブスクリプションスコープ）と，それ以外の
すべて（`main.bicep`，リソースグループスコープ）は **別のデプロイ** である
（[ADR 0023](../../docs/adr/0023-separate-role-definitions-from-the-deployment.md)）．
ロール定義を作る権限（`Microsoft.Authorization/roleDefinitions/write`．`Owner`
または `User Access Administrator` にしか含まれず，多くの組織では PIM で
有効化する）が要るのは，初回と，ロール定義を変えるリリースだけである．
イメージの更新やパラメータの変更で `main.bicep` を再デプロイするときには要らない．

| 作業 | 必要な権限 | 頻度 |
|---|---|---|
| `roles.bicep` のデプロイ（`az deployment sub create`） | サブスクリプションの `roleDefinitions/write` と `Microsoft.Resources/deployments/*`（`Owner`，または `User Access Administrator` ＋ サブスクリプションの `Contributor` など） | 初回と，リリースノートがロール定義の変更を告げたときだけ |
| デプロイする者への条件付き委任の設定（下記） | 割り当て先スコープの `roleAssignments/write`（条件なし．`Owner` / `User Access Administrator`） | 初回だけ |
| `main.bicep` のデプロイ（`az deployment group create`） | デプロイ先 RG の `Contributor`，DNS ゾーンと Key Vault の RG での `Microsoft.Resources/deployments/*`（ロール割り当ては入れ子のデプロイとしてそれぞれの RG に作られる），そして下記の条件付き `Role Based Access Control Administrator` | 毎回．**常設の権限だけで足り，PIM は要らない** |

**1. ロール定義を作る（初回だけ）．** `roleNamePrefix` はテナント内で一意な
ロール名の接頭辞で，`main.bicep` にも同じ値を渡す（ロール ID はこの値から
決定的に計算される）:

```sh
az deployment sub create --location japaneast -n acme-roles \
  --template-file roles.bicep --parameters roleNamePrefix='ACME Conductor'
```

**2. デプロイする者に条件付きの委任を与える（初回だけ）．** `main.bicep` は毎回
3 つのロール割り当てを PUT するので，内容が同じでも `roleAssignments/write` が
要る．これを `Owner` や `User Access Administrator` で満たす代わりに，
[条件付きの委任](https://learn.microsoft.com/azure/role-based-access-control/delegate-role-assignments-overview)
で `Role Based Access Control Administrator` を与える．`roles.bicep` の出力
`deployerDelegationCondition` は，その割り当てを「この 3 つのロールを，
サービスプリンシパル（2 つのマネージド ID）にだけ」追加・削除できるように絞る
ABAC 条件である．ここまで絞れば，PIM ではなく常設の割り当てでよい:

```sh
COND=$(az deployment sub show -n acme-roles --query properties.outputs.deployerDelegationCondition.value -o tsv)
for scope in <デプロイ先 RG の ID> <DNS ゾーンの ID> <Key Vault の ID>; do
  az role assignment create --role "Role Based Access Control Administrator" \
    --assignee <デプロイする人・グループ・CI のサービスプリンシパル> --scope "$scope" \
    --condition "$COND" --condition-version 2.0
done
```

スコープは，ロールを割り当てる 3 か所（Runner の Job を含むデプロイ先 RG，
DNS ゾーン，Key Vault）である．条件がロールと割り当て先の種別を絞っているので，
サブスクリプションに 1 つだけ割り当ててもよい．「`Owner` などの特権ロール以外は
すべて許可」という条件付きの委任がすでにあるなら，それでも足りる．

**3. 以後のデプロイ．** 下の [デプロイ](#デプロイ) の手順は，上の表の常設の
権限だけで実行できる．`what-if` の結果にサブスクリプションスコープのリソースは
現れない．

ロール定義を変えるリリース（アクションの追加や削除）は，リリースノートでそう
告げる．そのときは先に `roles.bicep` を同じ `roleNamePrefix` で再デプロイし，
それから `main.bicep` をデプロイする．`roles.bicep` をデプロイしていない，
または別の `roleNamePrefix` で `main.bicep` をデプロイすると，ロール割り当てが
`RoleDefinitionDoesNotExist` で失敗する．

**以前のテンプレートからの移行．** 以前の `main.bicep` は同じロールを同じ名前
（GUID）で自分で作っていた．すでにデプロイ済みの環境では，ロール定義はその
まま残っており，`roles.bicep` を再デプロイする必要はない（同じ
`roleNamePrefix` で実行しても何も変わらない）．新しい `main.bicep` はそれを
参照するだけで，既存のロール定義を消すことも変えることもない．

## デプロイ

0. 初回なら，[ロール定義とデプロイの権限](#ロール定義とデプロイの権限) の
   手順 1 と 2 を済ませる．
1. Runner の設定を書く
   （[`deploy/examples/runner-config.aca.example.json`](../examples/runner-config.aca.example.json)
   が出発点になる）．`lego.stateDir` は `/state`，`lego.workDir` は `/work`
   のままにし，すべての DNS バインディングがマネージド ID で認証するようにする
   （後述）．`jobSigning.publicKeys` は `jobSigningPublicKey` パラメータから
   **テンプレートが追加する** ため，Runner は必要な鍵なしにはデプロイできない．
2. `main.bicepparam` を **このディレクトリ内に** コピーし（`runnerConfigJson`
   の `loadTextContent` はそのファイルからの相対パスで解決される），イメージ，
   バインディング名，ゾーン，Key Vault，公開鍵，OIDC の値を記入する．
3. 秘密鍵は環境変数から読まれる（`readEnvironmentVariable`）．両方を設定して
   デプロイする（暗号化 EAB プロビジョニングを使う場合は
   `ACME_ACCOUNT_PROVISIONING_PRIVATE_KEY_PEM` も設定し，パラメタファイルの
   `accountProvisioning*` の行を有効にする）:

   ```sh
   cd deploy/azure
   cp main.bicepparam my.bicepparam
   export ACME_JOB_SIGNING_PRIVATE_KEY_PEM="$(cat job-signing.pem)"
   export ACME_RESULT_SIGNING_PRIVATE_KEY_PEM="$(cat result-signing.pem)"
   az deployment group create --resource-group rg-acme \
     --template-file main.bicep --parameters my.bicepparam
   ```

   イメージをローカルでビルドする必要も，GHCR の資格情報も要らない．Container
   Apps は公開イメージをダイジェストでそのまま pull する．
4. Runner の最初の実行を確認する．Runner の設定はデプロイ時には検証されず，
   各実行の開始時に読み込まれる．誤り（たとえば予約済みの環境変数名．
   [`docs/runner.md`](../../docs/runner.md#dnsbindingsname) を参照）があっても
   デプロイは成功し，その後の実行が毎分 `Failed` になるだけである．
   ジョブがなくても実行は毎分動くので，1〜2 分待てば判定できる．待機中のジョブがなければ
   `no pending job; nothing to do` で `Succeeded` になるのが正常である:

   ```sh
   az containerapp job execution list -g rg-acme -n <prefix>-runner \
     --query "[0:3].{name:name,status:properties.status}" -o table
   az containerapp job logs show -g rg-acme -n <prefix>-runner \
     --execution <execution name> --container runner --format text
   ```

`conductorConfig` 出力は，テンプレートが導出した Conductor の設定
（サブスクリプション，リソースグループ，ジョブ名，Conductor の ID のクライアント
ID，交換用パス，OIDC の信頼設定）を示す．これが Conductor の実行時の設定である．
`conductorUrl` は API と GUI が応答する場所であり，`conductorGuiRedirectUri` は
GUI のパブリッククライアントに登録すべき値である（初回デプロイの後にはじめて
判明するので，これを登録するだけでよく，再デプロイは不要である — クライアント
登録はプロバイダ側にある）．

### ID

Conductor は OIDC の *リソースサーバ* である
（[ADR 0016](../../docs/adr/0016-oidc-bearer-auth-and-gui.md)）．プロバイダが
公開する鍵でトークンを検証し，クライアントシークレットを持たない．Microsoft
Entra ID の場合:

1. **API のアプリ登録**（`acme-conductor-api`）: `requestedAccessTokenVersion`
   を `2` に設定し（Conductor は v2 の issuer
   `https://login.microsoftonline.com/<tenant>/v2.0` を検査する
   → `oidcIssuer`），アプリケーション ID URI（既定の `api://<client-id>`，
   または検証済みドメインの URI）を設定し，クライアントが
   `<application ID URI>/.default` を要求できるようにスコープを 1 つ
   （`access`，管理者の同意）公開し，ユーザー／グループ向けの **アプリロール**
   を 2 つ，例えば `ACME.Admin` と `ACME.Viewer` を定義する
   （→ `oidcAdminRoles`，`oidcViewerRoles`）．エンタープライズアプリケーション
   上でユーザーまたはグループをロールに割り当てる．どちらのロールも持たない
   トークンは拒否される．

   **識別子は 2 つ，パラメータも 2 つ．** v2 アクセストークンの `aud` は，
   アプリケーション ID URI が何であれ，クライアントがどのスコープを要求したかに
   かかわらず，API 登録の **Application (client) ID**（GUID）である．
   アプリケーション ID URI はクライアントが要求するスコープの中にだけ現れる．
   したがって `oidcAudience` はクライアント ID（`1111…`）であり，`oidcScopes`
   は `['openid', 'profile', 'api://1111…/.default']`（そのような URI を持つ
   場合は `https://<verified domain>/<name>/.default`）である．URI を audience
   に設定すると，Conductor は正しく発行されたすべてのトークンを
   `401 token audience does not include this API` で拒否する．
2. **GUI のアプリ登録**（`acme-conductor-gui`）: プラットフォームは *シングル
   ページアプリケーション*，リダイレクト URI は `https://<app fqdn>/ui/`
   （`conductorGuiRedirectUri` 出力），クライアントシークレットなし，API の
   アクセス許可は `acme-conductor-api / access` に管理者の同意．その
   クライアント ID が `oidcClientId` であり，GUI はちょうど `oidcScopes` を
   要求する（クライアント ID を指定するときは必須．Conductor はこれを推測
   しない）．

端末から API を使うには，API のスコープに対するトークンを取得し，ベアラー
トークンとして提示する．プロバイダはクライアント ID を `aud` に書き込む:

```sh
token="$(az account get-access-token --scope api://11111111-1111-1111-1111-111111111111/.default --query accessToken -o tsv)"
curl -s -H "Authorization: Bearer $token" https://<app fqdn>/api/v1alpha1/targets
```

監査ログはトークンの `oid`（`oidcPrincipalClaim`）をアクターとして記録する．
これはユーザーのオブジェクト ID であり，`preferred_username` とは異なり，
ユーザーの名前が変わっても変化しない．ディスカバリ文書を公開し RS256/PS256/ES256
のトークンに署名するプロバイダなら，どれでも同じように動く．クレーム名は
設定可能である（`server.auth.oidc.principalClaim`，`rolesClaim`）．

### Job 内での Runner の ID

Runner はユーザー割り当て ID で Key Vault に認証する．テンプレートは
`config.credential: managed-identity` を持つすべての `azure-keyvault` store
バインディングの `config.managedIdentityClientId` をその ID のクライアント ID に
設定し（クライアント ID を指定しないマネージド ID 資格情報は，プラットフォームに
システム割り当て ID を求めるが，この Job はそれを持たない），`lego` のために
Job の環境に `AZURE_CLIENT_ID` を設定する．store バインディングは
`{type, config}` のエンベロープであり（[`docs/runner.md`](../../docs/runner.md)），
テンプレートが触れるのはプロバイダの `config` オブジェクトだけである．
エンベロープのルートに置かれたフィールドは Runner が未知のものとして拒否する．
`cmd/acme-runner/deploy_azure_test.go` は，テンプレートがこの設定例に加える
編集を Runner の設定ローダと store プロバイダのレジストリに通し，この形が
保たれていることを検査する．`lego` の `azuredns` プロバイダも同じ ID を
使うが，DNS バインディングは `AZURE_AUTH_METHOD` を **設定しない** こと．
`msi` を指定すると `lego` はクライアント ID なしの `ManagedIdentityCredential`
を作り，`AZURE_CLIENT_ID` を無視してシステム割り当て ID を求める（この Job には
ない）．未設定の `DefaultAzureCredential` 経路なら `AZURE_CLIENT_ID` が効く
（[`docs/runner.md`](../../docs/runner.md#dnsbindingsname)）．
Container Apps はコンテナの `IDENTITY_ENDPOINT` と `IDENTITY_HEADER` 変数を
通して ID を公開し，Runner は `lego` の環境を一から組み立てるので，
バインディングはちょうどこれらの名前を転送しなければならない:

```json
"passthroughEnv": ["AZURE_CLIENT_ID", "IDENTITY_ENDPOINT", "IDENTITY_HEADER"]
```

資格情報の値はどこにも現れない．`IDENTITY_HEADER` はローカルの ID エンドポイント
用のコンテナごとのトークンであり，他の passthrough の値と同様に Runner のログ
から秘匿される．

### 複数の DNS ゾーン

`dnsZoneNames` に並べたゾーンのそれぞれに，Runner の ID の **Runner DNS TXT
Writer** が割り当てられる．SAN 証明書の名前が複数のゾーンにまたがる場合や，
target ごとにチャレンジ用ゾーンが違う場合に使う
（[ADR 0024](../../docs/adr/0024-target-scoped-acme-accounts-and-san.md)）．

```bicep
param dnsZoneNames = ['example.ac.jp', 'example.jp']
param dnsZoneResourceGroup = 'rg-dns-example'
```

- ゾーンはすべて `dnsZoneResourceGroup` にあること（同じサブスクリプション内）．
- `lego` の `azuredns` プロバイダは `AZURE_ZONE_NAME` で 1 つのゾーンを指すので，
  Runner 設定にはゾーンごとに DNS バインディングを 1 つ書き，その名前を
  `dnsBindings` に並べる．
- ロール割り当ての名前はゾーンの ID から決まる．リストからゾーンを外しても，
  増分デプロイは既存の割り当てを **消さない**．不要になった割り当ては
  `az role assignment delete --assignee <runner principalId> --scope <zone id>`
  で外す．

**`dnsZoneName` からの移行．** 以前の単一ゾーンのパラメータ `dnsZoneName`
（文字列）は当面受け付け，`dnsZoneNames` に加えて扱う（重複は 1 つにまとまる）．
割り当ての名前は同じゾーンなら変わらないので，既存のパラメタファイルのまま
再デプロイしてもロール割り当ては失われない．`param dnsZoneName = 'x'` を
`param dnsZoneNames = ['x']` に書き換えれば移行は済む．どちらも空なら
デプロイは失敗する．`dnsZoneName` は将来のリリースで削除する．

## デプロイ後の運用

**API と GUI には `conductorUrl` で到達できる．** ingress はアプリの FQDN に
対するプラットフォームの証明書で HTTPS のみを受け付け（平文の HTTP は
リダイレクトされる），環境内の暗号化されたピア通信を通して Conductor のポートへ
転送する．Conductor は `server.behindTlsProxy: true` によってそのことを知らされ，
それを根拠にループバック以外の平文リスナーを受け入れる．`/api/` 配下のすべての
リクエストと GUI のすべての操作には，`oidcIssuer` が `oidcAudience` 向けに
発行した，admin または viewer ロールを持つベアラートークンが必要である．他に
入る方法はない．`/healthz` と `/readyz`（プローブ）および GUI の静的ファイルが，
認証不要な唯一のパスである．`ingressAllowedCidrs` は ingress にそもそも到達
できる相手を絞り，`ingressExternal: false` は ingress を環境の仮想ネットワーク
内にとどめる．どちらも認証の代わりにはならない．

管理は GUI（`https://<app fqdn>/ui/`）またはトークン付きの API で行う
（[ID](#id) を参照）．`oidc` モードではループバックのピアは信頼されないため，
レプリカへの `az containerapp exec` はもはや管理者セッションではない．

**バックアップ．** レジストリは `conductor-state` 共有上の `conductor.db` で
ある．共有のスナップショットを取るか，アプリをゼロにスケールした状態で
ファイルをコピーする．`runner-state` 共有は ACME アカウント鍵（証明書の鍵では
ない）を保持する．これもバックアップすること．`exchange` 共有には永続的なものは
何もない．

**イメージの更新．** `main.bicepparam` の 2 つのダイジェストを新しいリリースの
ものに替え（[前提条件](#前提条件) の検証をしてから），[デプロイ](#デプロイ) の
手順 3 を再実行する．テンプレートもそのリリースのツリーのものを使う．ロール定義を
変えるリリースでなければ，常設の権限だけで足りる（[ロール定義とデプロイの権限](#ロール定義とデプロイの権限)）．
Container Apps は，レジストリの更新を検知して自動で新しいイメージに入れ替える
ことはしない．イメージがダイジェストで固定されているのは，検証したものだけを
動かすためである．自動化するなら，ダイジェストを更新する PR（Renovate など）を
レビューしてマージし，CI がこの手順でデプロイする形がこの固定と両立する．

**ロールバック．** 以前のテンプレートとパラメータで `az deployment group create`
を実行するか，以前のイメージダイジェストを設定する．新しい Conductor の
スキーマは古いバイナリでは読めない．対応する `conductor.db` も復元すること
（[`docs/conductor.md`](../../docs/conductor.md#バックアップと復元とロールバック)）．

**署名鍵のローテーション．** まず検証側に新しい公開鍵を追加し（Runner の設定の
`jobSigning.publicKeys`，または Conductor の `resultSigningPublicKey` — どちらの
リストも複数の鍵を取れる），デプロイし，次に署名側を新しい秘密鍵に切り替え，
最後に古い公開鍵を取り除く．

**レイテンシ，スループット，空振りの実行．** run は次のスケジュール実行が
それを取ったときに始まる．つまり最大で `runnerCronExpression` の間隔（1 分）に
プラットフォームの起動レイテンシを加えた時間がかかる．各実行は 1 レプリカで動き
1 つのジョブを取るので，1 tick あたり始まる run は最大 1 つであり，run が
重なるのは連続する tick の実行が重なる範囲に限られる（想定であり，観測はして
いない — 後述）．何も待機していないあいだも，tick ごとにジョブを見つけられずに
即座に終了する実行が 1 回動く．これは `jobs/start/action` を保持しないことの
代償であり，それが問題になるならイベント駆動のトリガーが既知の後続課題である．

**残留した run ディレクトリ．** 実行の終了を確認できなかったとき — その状態が
読めず，停止も確認できなかったとき — Conductor は `exchange` 共有上の
`claimed/run-<runId>/` を残し（Runner がまだそこに書いているかもしれない），
「run directory kept」とログに記録する．実行が終了したことを確認したうえで
（`az containerapp job execution list`），そのようなディレクトリは手で削除
すること．

**`cert-infra` からの移行．** `migration` パラメータは Conductor 設定の
`migration` セクションそのものである
（[`docs/migration.md`](../../docs/migration.md)）．`targetSource` を `shadow`
にし，`cert-infra` の `infra/main.bicepparam` の `targetDomains` を
`source.fqdns` に貼り付けると，何も発行せず，その一覧を自身のレジストリと比較する
Conductor がデプロイされる．一覧は `acme-conductor migrate import --apply`
（または同じファイルから `--bicepparam`）で取り込む．Conductor に発行させるときは
`registry` に切り替え，ロールバックするには `iac` に戻す．Conductor は
`cert-infra` のデプロイに決して触れない．そのジョブを止めるのは操作者の作業で
ある．

## 実デプロイで確認したことと，まだ確認していないこと

このテンプレートはコンパイルが通り（`bicep build`，`bicep lint`，
`bicep build-params`．CI の `bicep` ジョブが実行する），その設定文書はバイナリが
使うのと同じ検証器（`internal/conductor/config`，`internal/runner/config`）と
store プロバイダのレジストリで読み込める（`cmd/acme-runner/deploy_azure_test.go`）．
CI はサブスクリプションにデプロイしない．

2026-09-25 に `v0.6.0` のイメージで staging のデプロイを行い（手順は
[`walkthrough.md`](walkthrough.md)），staging CA で 1 つの target の発行が
端から端まで通ることを確かめた．Conductor が交換用の共有にジョブを置き，
スケジュール実行の Runner の 1 つがそれを取り，署名を検証して発行し，Key Vault に
格納し，Conductor が実行の終了と署名付きの Result を受け取った．両方のログが
同じ `runId` でこの順に並ぶことで確認できる（手順 10）．これにより次のことは
観測済みである．

- **スケジュールと実行名．** 毎分の実行が始まり，`CONTAINER_APP_JOB_EXECUTION_NAME`
  が設定され，Conductor がその実行名をプラットフォームに照会して確認できる．
- **ジョブの受け渡し．** 共有上のディレクトリのリネームで，1 つの実行がジョブを
  取れる．
- **ロールのアクション名（読み取りと書き込み）．** Conductor の ID は実行の
  状態を読め，Runner の ID は DNS の TXT レコードを書き，Key Vault に証明書を
  取り込める．
- **`lego` のマネージド ID．** Container Apps の ID エンドポイント
  （`IDENTITY_ENDPOINT`/`IDENTITY_HEADER`）と `AZURE_CLIENT_ID` で，`azuredns`
  プロバイダが認証できる．
- **Azure Files (SMB) 上の SQLite．** `nobrl` でマウントしたレジストリが動き，
  Result は既定の `resultGraceSeconds`（30 秒）以内に共有上に現れる．
- **ingress．** API と GUI が HTTPS の ingress で応答し，GUI のリダイレクト
  URI にはプラットフォームが割り当てるアプリの FQDN を使える．
- **シークレットのサイズ．** 1 つの target 向けの Runner 設定は，ファイルとして
  マウントされるシークレットに収まる．

次のことはまだ観測していない．プラットフォームのリファレンスドキュメントに
基づく想定である．

- **同時に取り合うときのリネームの原子性．** 観測したのは 1 つの実行がジョブを
  取る場合だけである．2 つの実行が同じジョブを同時に取ろうとしたとき，SMB 上でも
  片方だけが成功すると想定している（サーバがリネームを実行する）．もし両方とも
  成功しうるなら，両方が同じジョブを実行し，Runner のリプレイ台帳が 2 つ目を
  拒否する．
- **実行の停止．** `Microsoft.App/jobs/stop/execution/action`（キャンセルと
  タイムアウトで使う）はまだ使われていない．名前が誤っていればデプロイが失敗する
  （ロール定義は検証される）ので，黙って通ることはない．
- **SMB 上の `flock`．** Conductor が取る所有権ロック（`<db>.lock`）の信頼性は，
  そのマウントでの `flock` の信頼性と同じにしかならない．アプリは単一リビジョン
  モードで 1 レプリカに固定されているが，リビジョン更新の際には一時的に 2 つの
  レプリカが重なりうる．ロックが効いていれば 2 つ目は起動を拒否し，効いて
  いなければそのまま起動すると想定している．NFS の Azure Files（VNet 統合
  環境）の方が堅牢であり，1 行の変更（`NfsAzureFile` ストレージタイプ）で
  済む．
- **Result 伝播の遅延の幅．** 今回は既定値で足りたが，SMB のキャッシュによっては
  `resultGraceSeconds` の調整が必要かもしれない．
- **ピア暗号化．** `peerTrafficConfiguration.encryption.enabled` が ingress から
  レプリカへのホップを暗号化することは，文書化されているが観測していない．
- **大きな設定．** 多数のバインディングを持つ Runner 設定は，プラットフォームの
  シークレット値の上限を超えるかもしれない．
- **複数の DNS ゾーン．** `dnsZoneNames` に 2 つ以上のゾーンを並べたデプロイは
  まだ行っていない．割り当ては 1 ゾーンの場合と同じモジュールをゾーンごとに
  繰り返すだけである．

新しい環境へのデプロイは，最初から最後まで見守ること．ステージング CA と
1 つの target から始める．
