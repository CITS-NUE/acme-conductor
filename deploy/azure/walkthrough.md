# Azure への導入の流れ（実施記録にもとづく手引き）

[`README.md`](README.md) はテンプレートの仕様書である．この文書は，実際に
1 つの組織のサブスクリプションへ staging 環境を立ち上げたときに実行した
コマンドを，**順番どおり** に並べ直したものである．何をどの順で決め，
誰がどの権限で何を実行し，どこでつまずいたかを示す．

値はすべて例である．テナント ID，サブスクリプション ID，オブジェクト ID は
`<...>` で伏せてある．組織ごとの実値は **リポジトリに入れない** ローカル
ファイル（後述の `<env>.bicepparam`）に置く．

生成 AI（Claude Code など）に作業を手伝わせる場合の指示の出し方は
[`ai-assisted-deploy.md`](ai-assisted-deploy.md) にまとめてある．

## 全体の流れ

```
 0. 事前調査（読み取りのみ）
 1. 命名とパラメタの決定               ← 人が決める
 2. 権限の確認と有効化（PIM）          ← 人が行う
 3. 署名鍵ペアの生成（ローカル）
 4. リソースグループと Key Vault の作成
 5. Entra ID のアプリ登録（API と GUI）
 6. Runner 設定とパラメタファイルの作成（ローカル）
 7. build-params と what-if（読み取りのみ）
 8. デプロイ
 9. デプロイ後の確認とリダイレクト URI の登録
10. 最初の target で発行テスト（staging CA）
11. 利用側への組み込み（本番 CA の証明書を実際のサービスで使う）  ← 利用側の管理者と行う
```

所要時間の目安は半日である．待ち時間のほとんどは，権限の有効化と
Container Apps 環境の作成（5〜10 分）が占める．

## 役割と必要な権限

| 作業 | 必要な権限 | 備考 |
|---|---|---|
| Azure リソースの作成（手順 4，8） | デプロイ先 RG の `Contributor` | |
| サブスクリプションスコープのネストしたデプロイ（手順 8） | サブスクリプションの `Microsoft.Resources/deployments/*`（サブスクリプションの `Contributor` や `Owner` に含まれる） | `main.bicep` はカスタムロールを `scope: subscription()` の module（`modules/roles.bicep`）で作るため，**RG の `Contributor` だけでは足りない**．`User Access Administrator` にも含まれない |
| カスタムロール定義の作成（手順 8） | サブスクリプションの `Microsoft.Authorization/roleDefinitions/write`（`Owner` または `User Access Administrator`） | `Contributor` と `Role Based Access Control Administrator` には **含まれない** |
| ロール割り当て（手順 8） | 割り当て先スコープ（Runner の Job，DNS ゾーン，Key Vault）の `Microsoft.Authorization/roleAssignments/write` | 条件（ABAC）付きの委任でもよい（#37 以降）．[手順 8](#8-デプロイ) を参照 |
| アプリ登録の作成（手順 5） | Entra の `Application Developer` 以上 | テナント設定で一般ユーザーのアプリ作成が禁止されている場合 |
| 管理者の同意，アプリロールの割り当て（手順 5） | Entra の `Application Administrator` / `Cloud Application Administrator` | 自テナントの API への委任許可の同意ならこれで足りる |

たとえば「RG の `Contributor`＋サブスクリプションの `User Access Administrator`」の
組み合わせは十分に見えるが，サブスクリプションスコープのネストしたデプロイを
開始できないため失敗する．実施した環境では，サブスクリプションの `Contributor`
（常設）と `User Access Administrator`（PIM で有効化）の組み合わせでこの要件を
満たした．

権限を確認するコマンドを示す（読み取りのみ）:

```sh
SUB=/subscriptions/<subscription-id>
# 実効権限（actions / notActions の集合）
az rest --method get --url "https://management.azure.com$SUB/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" \
  --query "value[].{actions:actions,notActions:notActions}" -o json
# 有効な割り当てと条件（PIM で有効化したものを含む）
az rest --method get --url "https://management.azure.com$SUB/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&\$filter=asTarget()" \
  --query "value[].properties.{role:expandedProperties.roleDefinition.displayName,scope:scope,end:endDateTime,cond:condition}" -o json
# PIM で有効化できるロール
az rest --method get --url "https://management.azure.com$SUB/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&\$filter=asTarget()" \
  --query "value[].properties.{role:expandedProperties.roleDefinition.displayName,scope:scope}" -o table
# Entra の有効なディレクトリロールと，一般ユーザーがアプリを作れるか
az rest --method get --url "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.directoryRole?\$select=displayName" --query "value[].displayName" -o tsv
az rest --method get --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy?\$select=defaultUserRolePermissions" \
  --query "defaultUserRolePermissions.allowedToCreateApps" -o tsv
```

## 0. 事前調査（読み取りのみ）

既存の資源と命名規約を把握する．特に `cert-infra` のような先行する証明書
基盤がある場合は，その DNS ゾーン，Key Vault，Job の環境変数を確認する．
これらがそのまま設定値の出発点になる．

```sh
az account show -o table
az group list --query "[].{name:name,loc:location}" -o table
az network dns zone list --query "[].{name:name,rg:resourceGroup}" -o table
az keyvault list --query "[].{name:name,rg:resourceGroup,rbac:properties.enableRbacAuthorization}" -o table
az containerapp job list --query "[].{name:name,rg:resourceGroup}" -o table
# 既存の証明書更新 Job の設定（ゾーン，RG，ACME の連絡先，対象ホスト）
az containerapp job show -n <existing-job> -g <rg> \
  --query "{env:properties.template.containers[0].env,cron:properties.configuration.scheduleTriggerConfig.cronExpression}" -o json
```

`_acme-challenge.<host>` がチャレンジ用ゾーンへ CNAME で委任済みなら，親ゾーン側
での作業は不要である（`lego` は既定で CNAME をたどる）．

## 1. 命名とパラメタの決定

**ここは人が決める．** 後から変えにくい名前が多い（ロール名はテナント内で
一意，バインディング名は target とポリシーから参照される）．

| 項目 | 例（staging） | 決め方 |
|---|---|---|
| サブスクリプション | DNS ゾーン・Key Vault と同じもの | カスタムロールはそのサブスクリプションにしか割り当てられない |
| リソースグループ | `rg-acme-staging`（`japaneast`） | 既存の本番 RG と分ける |
| `namePrefix` | `acme-stg` | `acme-stg-cae`，`acme-stg-conductor`，`acme-stg-runner`，`acme-stg-id-*` になる．3〜20 文字 |
| `roleNamePrefix` | `ACME Conductor Staging` | 将来の本番デプロイとロール名が衝突しないように環境名を入れる |
| Key Vault | 新規 `kv-acme-stg-<org>`（RBAC） | staging CA の証明書を本番の vault に混ぜない．名前はグローバルに一意で 24 文字以内 |
| DNS ゾーン | 既存のチャレンジ用ゾーン | Runner の ID に TXT 書き込みロールが付くだけで，ゾーン自体は変更しない |
| 最初の target | CNAME 委任が済んでいる 1 ホスト | 親ゾーン側の作業が要らないもの |
| バインディング名 | `letsencrypt-staging` / `azure-dns-<zone>` / `keyvault-staging` | 論理名．Runner 設定と Conductor 設定で一致させる |
| ACME の連絡先 | 組織の窓口アドレス | staging と本番でアカウントは別に作られる |
| OIDC | issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`，`oid`，`ACME.Admin` / `ACME.Viewer` | 手順 5 で作るアプリ登録の値 |
| アプリ登録名 | `acme-conductor-api` / `acme-conductor-gui` | 環境ごとに分けるなら `-stg` などを付ける |
| ingress | `ingressExternal: true`，`ingressAllowedCidrs: []` | 認証は OIDC が担う．CIDR は露出を絞るだけ |
| `migration` | 初回は `{}`（= `registry`） | まず 1 target を Conductor 自身で発行して端から端まで確かめる |

Key Vault 名が空いているかを確認する:

```sh
az rest --method post \
  --url "https://management.azure.com/subscriptions/<subscription-id>/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2022-07-01" \
  --body '{"name":"kv-acme-stg-<org>","type":"Microsoft.KeyVault/vaults"}'
```

## 2. 権限の確認と有効化

[役割と必要な権限](#役割と必要な権限) の表と確認コマンドで不足を洗い出す．
PIM の対象になっているロールは本人がポータルで有効化する．有効化には
期限があるので，**手順 5 と 8 の直前に** 行う．

## 3. 署名鍵ペアの生成

交換用共有の各方向に 1 組ずつ，Ed25519 鍵を用意する．秘密鍵は
**リポジトリの外** に置き，パーミッションを絞る．再デプロイのたびに環境変数で
渡すので，消さずに保管する．秘密鍵はファイルのまま置かず，操作者だけが読める
Key Vault などに保管し，デプロイの直前に環境変数へ読み込むとよい（例:
`export ACME_JOB_SIGNING_PRIVATE_KEY_PEM="$(az keyvault secret show --vault-name <vault> -n <name> --query value -o tsv)"`）．
環境変数が空のままデプロイすると，署名鍵のシークレットが空で上書きされ，run が
止まるので注意する．

リリースバイナリがあれば，それで生成するのが正規の方法である:

```sh
acme-conductor keygen --private job-signing.pem --public job-signing.pub
acme-runner keygen --private result-signing.pem --public result-signing.pub
```

Go もコンテナも手元にない場合は OpenSSL でも同じ形式になる．形式は
PKCS #8 の `PRIVATE KEY` PEM で，公開鍵は SubjectPublicKeyInfo の DER を base64 で
1 行にしたもの．詳しくは `pkg/api/v1alpha1/signedjob.go` を参照:

```sh
d=~/.acme-conductor/staging; mkdir -p "$d"; chmod 700 "$d"
for k in job-signing result-signing; do
  openssl genpkey -algorithm ed25519 -out "$d/$k.pem"; chmod 600 "$d/$k.pem"
  openssl pkey -in "$d/$k.pem" -pubout -outform DER | base64 > "$d/$k.pub.b64"
done
cat "$d"/*.pub.b64    # これが jobSigningPublicKey / resultSigningPublicKey
```

### 3-1. 暗号化 EAB プロビジョニング用の鍵（EAB が必須の CA を使う場合のみ）

UPKI など External Account Binding（EAB）が必須の CA を使う場合は，EAB を
GUI からブラウザ内で暗号化して投入するための X25519 鍵ペアも用意する
（[ADR 0022](../../docs/adr/0022-encrypted-eab-provisioning-and-account-generations.md)）．
Let's Encrypt だけなら不要で，次の手順のパラメタも空のままでよい．
この鍵は `acme-runner provisioning-keygen` で生成する:

```sh
acme-runner provisioning-keygen \
  --private "$d/account-provisioning.pem" --public "$d/account-provisioning.pub"
chmod 600 "$d/account-provisioning.pem"
# 出力の publicKey: が accountProvisioningPublicKey．keyId: は手順 9 の確認用に控える
```

署名鍵と同じく，秘密鍵は Key Vault などに保管し，デプロイの直前に環境変数
`ACME_ACCOUNT_PROVISIONING_PRIVATE_KEY_PEM` へ読み込む．テンプレートは
公開鍵と秘密鍵の **両方** が与えられたときだけこの機能を有効にし，片方だけの
ときはデプロイを何も変更しないうちに失敗させる．環境変数を設定し忘れた
再デプロイで，シークレットが空で上書きされることはない．

## 4. リソースグループと Key Vault の作成

```sh
az group create -n rg-acme-staging -l japaneast
az keyvault create -n kv-acme-stg-<org> -g rg-acme-staging -l japaneast --enable-rbac-authorization true
```

## 5. Entra ID のアプリ登録

[README の ID の節](README.md#id) を形にしたスクリプトである．API 側は
`requestedAccessTokenVersion: 2`，`access` スコープ，`ACME.Admin` /
`ACME.Viewer` のアプリロールを持つ．GUI 側は SPA で，シークレットを持たない．
実行者自身を `ACME.Admin` に割り当て，GUI から API への管理者の同意まで行う．
リダイレクト URI はデプロイ後に登録する（手順 9）．

```sh
#!/bin/zsh
set -euo pipefail
G=https://graph.microsoft.com/v1.0
API_NAME=acme-conductor-api GUI_NAME=acme-conductor-gui

# --- API ---
api=$(az ad app create --display-name $API_NAME --sign-in-audience AzureADMyOrg -o json)
apiAppId=$(jq -r .appId <<<"$api"); apiObj=$(jq -r .id <<<"$api")
scopeId=$(uuidgen | tr A-Z a-z); adminId=$(uuidgen | tr A-Z a-z); viewerId=$(uuidgen | tr A-Z a-z)
az rest --method patch --url "$G/applications/$apiObj" --headers Content-Type=application/json --body "$(jq -n \
  --arg uri "api://$apiAppId" --arg s "$scopeId" --arg a "$adminId" --arg v "$viewerId" '{
  identifierUris: [$uri],
  api: { requestedAccessTokenVersion: 2, oauth2PermissionScopes: [{
    id: $s, value: "access", type: "Admin", isEnabled: true,
    adminConsentDisplayName: "Access ACME Conductor", adminConsentDescription: "Call the ACME Conductor API on behalf of the signed-in user." }] },
  appRoles: [
    { id: $a, value: "ACME.Admin",  displayName: "ACME Admin",  description: "Administer ACME Conductor", allowedMemberTypes: ["User"], isEnabled: true },
    { id: $v, value: "ACME.Viewer", displayName: "ACME Viewer", description: "Read-only access to ACME Conductor", allowedMemberTypes: ["User"], isEnabled: true } ] }')"
apiSp=$(az ad sp create --id "$apiAppId" --query id -o tsv)
# 割り当てのないユーザーにはトークン自体を発行させない（任意．Conductor はロールのないトークンを拒否する）
az rest --method patch --url "$G/servicePrincipals/$apiSp" --headers Content-Type=application/json --body '{"appRoleAssignmentRequired": true}'
me=$(az ad signed-in-user show --query id -o tsv)
az rest --method post --url "$G/servicePrincipals/$apiSp/appRoleAssignedTo" --headers Content-Type=application/json \
  --body "$(jq -n --arg p "$me" --arg r "$apiSp" --arg a "$adminId" '{principalId:$p, resourceId:$r, appRoleId:$a}')" -o none

# --- GUI（SPA） ---
gui=$(az ad app create --display-name $GUI_NAME --sign-in-audience AzureADMyOrg -o json)
guiAppId=$(jq -r .appId <<<"$gui"); guiObj=$(jq -r .id <<<"$gui")
az rest --method patch --url "$G/applications/$guiObj" --headers Content-Type=application/json --body "$(jq -n \
  --arg api "$apiAppId" --arg s "$scopeId" '{ spa: { redirectUris: [] },
  requiredResourceAccess: [{ resourceAppId: $api, resourceAccess: [{ id: $s, type: "Scope" }] }] }')"
guiSp=$(az ad sp create --id "$guiAppId" --query id -o tsv)
# 管理者の同意（テナント全体）
az rest --method post --url "$G/oauth2PermissionGrants" --headers Content-Type=application/json \
  --body "$(jq -n --arg c "$guiSp" --arg r "$apiSp" '{clientId:$c, consentType:"AllPrincipals", resourceId:$r, scope:"access"}')" -o none

echo "oidcAudience=$apiAppId"
echo "oidcClientId=$guiAppId"
```

作成結果を確認する:

```sh
az ad app show --id <oidcAudience> \
  --query "{uri:identifierUris,v:api.requestedAccessTokenVersion,roles:appRoles[].value,scopes:api.oauth2PermissionScopes[].value}"
```

## 6. Runner 設定とパラメタファイルの作成

`main.bicepparam` と
[`runner-config.aca.example.json`](../examples/runner-config.aca.example.json)
をこのディレクトリにコピーして，環境名を付ける（例: `<env>.bicepparam`，
`<env>.runner-config.json`）．組織の実値が入るので，`.git/info/exclude` に
追加してコミット対象から外す:

```sh
cd deploy/azure
cp main.bicepparam staging.bicepparam
cp ../examples/runner-config.aca.example.json staging.runner-config.json
printf 'deploy/azure/staging.*\n' >> ../../.git/info/exclude
```

Runner 設定で書き換えるところ:

- `authorization.allowedDnsSuffixes`: 最初は **target そのもの**（完全一致も許可される）に絞る．
- `authorization.allowed*Bindings` と各バインディング名: 手順 1 で決めた名前にする．
- `acmeBindings.*.email`: 組織の連絡先にする．
- `dnsBindings.*.env`: `AZURE_ZONE_NAME`，`AZURE_RESOURCE_GROUP`，`AZURE_SUBSCRIPTION_ID` にチャレンジ用ゾーンの値を入れる．
  - `LEGO_*` は **書かない**．予約済みで，設定全体が拒否される．
  - `AZURE_AUTH_METHOD` も書かない（[README](README.md#job-内での-runner-の-id)）．
- `dnsBindings.*.passthroughEnv`: `["AZURE_CLIENT_ID", "IDENTITY_ENDPOINT", "IDENTITY_HEADER"]` のままにする．
- `storeBindings.*.config.vaultURL`: 新しい Key Vault の URL にする．`managedIdentityClientId` はテンプレートが上書きする．
- `jobSigning.publicKeys`: 空でよい（テンプレートが追加する）．

パラメタファイルで書き換えるところ:

```bicep
using 'main.bicep'
param namePrefix = 'acme-stg'
param roleNamePrefix = 'ACME Conductor Staging'
param tags = { environment: 'staging', system: 'acme-conductor' }
param conductorImage = 'ghcr.io/cits-nue/acme-conductor@sha256:<digest>'   // main.bicepparam の固定値
param runnerImage = 'ghcr.io/cits-nue/acme-runner@sha256:<digest>'
param acmeBindings = ['letsencrypt-staging']
param dnsBindings = ['azure-dns-<zone>']
param storeBindings = ['keyvault-staging']
param dnsZoneName = '<challenge zone>'
param dnsZoneResourceGroup = '<zone rg>'
param keyVaultName = 'kv-acme-stg-<org>'
param keyVaultResourceGroup = 'rg-acme-staging'
param jobSigningPublicKey = '<job-signing.pub.b64>'
param jobSigningPrivateKeyPem = readEnvironmentVariable('ACME_JOB_SIGNING_PRIVATE_KEY_PEM', '')
param resultSigningPublicKey = '<result-signing.pub.b64>'
param resultSigningPrivateKeyPem = readEnvironmentVariable('ACME_RESULT_SIGNING_PRIVATE_KEY_PEM', '')
// 手順 3-1 の鍵を作った場合のみ（3 行とも書くか，3 行とも書かない）
param accountProvisioningPublicKey = '<account-provisioning の publicKey>'
param accountProvisioningPrivateKeyPem = readEnvironmentVariable('ACME_ACCOUNT_PROVISIONING_PRIVATE_KEY_PEM', '')
param accountProvisioningBindings = ['<EAB を要求する CA の ACME binding>']  // acmeBindings のいずれか
param runnerConfigJson = loadTextContent('staging.runner-config.json')
param oidcIssuer = 'https://login.microsoftonline.com/<tenant-id>/v2.0'
param oidcAudience = '<oidcAudience>'
param oidcClientId = '<oidcClientId>'
param oidcScopes = ['openid', 'profile', 'api://<oidcAudience>/.default']
param oidcPrincipalClaim = 'oid'
param oidcAdminRoles = ['ACME.Admin']
param oidcViewerRoles = ['ACME.Viewer']
param ingressExternal = true
param ingressAllowedCidrs = []
```

## 7. build-params と what-if（読み取りのみ）

```sh
az bicep build-params --file staging.bicepparam --stdout > /dev/null && echo OK
export ACME_JOB_SIGNING_PRIVATE_KEY_PEM="$(cat ~/.acme-conductor/staging/job-signing.pem)"
export ACME_RESULT_SIGNING_PRIVATE_KEY_PEM="$(cat ~/.acme-conductor/staging/result-signing.pem)"
# 手順 3-1 の鍵を作った場合のみ
export ACME_ACCOUNT_PROVISIONING_PRIVATE_KEY_PEM="$(cat ~/.acme-conductor/staging/account-provisioning.pem)"
az deployment group what-if -g rg-acme-staging -n acme-stg \
  --template-file main.bicep --parameters staging.bicepparam --result-format ResourceIdOnly
```

新しい環境なら，すべて `+ Create` になる．内訳は，サブスクリプションスコープに
カスタムロール 3 つ，RG に 14 リソースと Job へのロール割り当て 1 つである．
既存の Key Vault は `* Ignore` になる．Runner の ID へのロール割り当て
2 つ（DNS ゾーンと Key Vault）は，ID の principalId がデプロイ中にしか
決まらないため `Unsupported` と表示される．これは正常である．**既存の本番
RG に対する変更は，DNS ゾーンへのロール割り当て 1 つだけ** であることを確認する．

## 8. デプロイ

```sh
az deployment group create -g rg-acme-staging -n acme-stg \
  --template-file main.bicep --parameters staging.bicepparam \
  --query "{state:properties.provisioningState,outputs:properties.outputs}" -o json
```

**ロール割り当て権限が ABAC 条件付きの場合**（「`Owner` などの特権ロールは
割り当て不可」という条件付きの `Role Based Access Control Administrator`
など）の注意．[#37](https://github.com/CITS-NUE/acme-conductor/pull/37) より前の
テンプレートでは，事前検証が次のエラーで失敗し，何も作成されずに止まる:

```
InvalidTemplateDeployment: Authorization failed for template resource '<guid>' of type
'Microsoft.Authorization/roleAssignments' ... does not have permission to perform action
'Microsoft.Authorization/roleAssignments/write' ...
```

原因は，ロール割り当ての `roleDefinitionId` が roles モジュールの出力で，
事前検証の時点では未確定なことにある．条件が参照するロール定義 ID が
わからないため，拒否される（[#34](https://github.com/CITS-NUE/acme-conductor/issues/34)）．
#37 以降のテンプレートはこの ID を事前検証の時点で確定させるので，既定の
検証レベルのままでデプロイできる．古いテンプレートでは，手順 7 の `what-if`
で差分を確認したうえで `--validation-level Template` を付けて実行する
（`ProviderNoRbac` では回避できない）．事前検証が省かれるので，途中で
失敗すると一部のリソースが作られた状態で止まる．同じコマンドを再実行すれば揃う．

出力のうち，`conductorUrl` と `conductorGuiRedirectUri` は次の手順で使う．

## 9. デプロイ後の確認

```sh
RG=rg-acme-staging P=acme-stg
U=$(az deployment group show -g $RG -n $P --query properties.outputs.conductorUrl.value -o tsv)
# Conductor: healthz/readyz は 200，トークンなしの API は 401 が正常
for p in healthz readyz api/v1alpha1/targets; do printf "%s: " $p; curl -s -o /dev/null -w "%{http_code}\n" "$U/$p"; done
# ロール割り当て: Runner に 2 つ（ゾーンと Key Vault），Conductor に 1 つ（Runner の Job）
for id in $P-id-runner $P-id-conductor; do
  az role assignment list --assignee "$(az identity show -g $RG -n $id --query principalId -o tsv)" --all \
    --query "[].{role:roleDefinitionId,scope:scope}" -o tsv
done
# Runner: 毎分実行され，ジョブがなければ Succeeded
az containerapp job execution list -g $RG -n $P-runner --query "[0:3].{name:name,status:properties.status}" -o table
az containerapp job logs show -g $RG -n $P-runner --execution <execution name> --container runner --format text
```

Runner の実行が毎分 `Failed` になる場合は，まずログを見る．ログに
`runner configuration could not be loaded` と出ていれば Runner 設定の誤りである．
直して手順 8 を再実行する．

暗号化 EAB プロビジョニングを有効にした場合は，Conductor が公開鍵を持っている
ことを確かめる．`GET /api/v1alpha1/account-provisioning/key` が `keyId` を返し，
それが手順 3-1 で控えた `keyId` と一致すればよい（未設定なら `404`
`not_configured`）．API にはトークンが要るので，GUI の EAB 投入画面
（タブ「EAB」）に表示される `keyId` で見るのが簡単である．
この比較は Conductor を経由しない控えと突き合わせて行う
（[`docs/conductor.md`](../../docs/conductor.md) の既知の制約を参照）．
出力の `conductorConfig` にも `accountProvisioning.publicKey` と
`accountProvisioning.bindings` が出る．

GUI のリダイレクト URI を登録する:

```sh
az rest --method patch --url "https://graph.microsoft.com/v1.0/applications(appId='<oidcClientId>')" \
  --headers Content-Type=application/json \
  --body '{"spa":{"redirectUris":["<conductorGuiRedirectUri>"]}}'
```

## 10. 最初の target で発行テスト（staging CA）

GUI（`<conductorUrl>/ui/`）に `ACME.Admin` でサインインし，次の順で登録する．

1. ポリシーを作る．`allowedDnsSuffixes` は target を覆うもの，`acmeBinding` は `letsencrypt-staging` にする．
2. target を 1 つ登録する．**その名前の `_acme-challenge` がチャレンジ用ゾーンへ
   委任済みであること** を先に確かめる．Runner の ID が書けるのはチャレンジ用
   ゾーンだけなので，委任のない名前（本番と分けるつもりで付けた `test.` 付きの
   名前など）は必ず失敗する:

   ```sh
   dig +short CNAME _acme-challenge.<target fqdn>   # チャレンジ用ゾーン内の名前が返ればよい
   ```

API で行う場合は [`docs/conductor.md`](../../docs/conductor.md#rest-api) を参照．
既存の証明書基盤と同じホストを扱う場合は，その定期実行の時間帯を避ける．

発行後に確認すること:

- target の画面で run が `succeeded` になり，証明書の概要が表示されている．
- Runner のログに発行と格納の記録がある．
- Key Vault に証明書オブジェクトができている（`az keyvault certificate list --vault-name kv-acme-stg-<org>`）．
  RBAC の Key Vault なので，確認する人にデータプレーンの読み取り権限（`Key Vault Reader`
  など）がなければ読めない．その場合は Runner のログの `reconcile succeeded` と
  `storeObjectRef` で代える．
- チャレンジ用ゾーンに `_acme-challenge` の TXT が残っていない
  （`az network dns record-set txt list -g <zone rg> -z <challenge zone>`）．

Conductor と Runner の間でジョブが受け渡されたことは，両方のログから確かめられる．
1 つの `runId` について，`job offered to the runner job`（conductor），
`signed job envelope verified`（runner），`job taken by an execution`（conductor．
`execution` に実行名が付く），`reconcile succeeded`（runner），`job execution ended`
（conductor．`status` が `Succeeded`）が並べばよい．Conductor のトークンは要らない:

```sh
WS=$(az containerapp env show -g $RG -n $P-cae \
  --query properties.appLogsConfiguration.logAnalyticsConfiguration.customerId -o tsv)
az monitor log-analytics query -w "$WS" -t P1D -o table --analytics-query '
ContainerAppConsoleLogs_CL
| where Log_s has_any ("job offered to the runner job", "job taken by an execution",
                       "signed job envelope verified", "reconcile succeeded", "job execution ended")
| project TimeGenerated, ContainerName_s, Log_s
| order by TimeGenerated asc'
```

run が `AcmeFailure lego exited with status 1` で失敗した場合，lego 自身のメッセージは
今のところ debug ログにしか出ず，Azure のテンプレートでは debug を有効にできない
（[#38](https://github.com/CITS-NUE/acme-conductor/issues/38)）．まず上の `dig` で
委任を確かめ，次に Runner のログで `fqdn` が意図した名前かを確かめる．失敗した
target は GUI で無効化しておく．有効なままだと再試行が続き，CA のレート制限を消費する．

## 11. 利用側への組み込み

Conductor は証明書を Key Vault に **格納するところまで** しか行わない．
それを実際のサービス（Application Gateway など）で使うには，次の 2 つが要る．

- 利用側の ID に読み取り権限を付ける
- 利用側の参照先を付け替える

どちらもテンプレートの外の作業であり，利用側の管理者と行う．
Runner の ID が持つのは証明書の書き込み権限だけで，誰に読ませるかは
利用側の判断である（[`docs/migration.md`](../../docs/migration.md)）．

**staging CA の証明書は，稼働中のサービスに決して付けない．** 信頼されない CA の
証明書なので，クライアントはエラーになる．この節は，本番 CA で発行した後の作業である．

### 11-1. 本番 CA で発行する

- Runner 設定の `acmeBindings` に本番 CA のバインディングを追加する（例: `letsencrypt-prod`）．
  このバインディングには `allowProductionCA: true` が **必要** である．ステージングと
  認識されないディレクトリは，これがないと拒否される
  （[`docs/runner.md`](../../docs/runner.md)）．
- あわせて `authorization.allowedAcmeBindings` とパラメタの `acmeBindings` にも追加し，
  再デプロイする（手順 8）．
- ポリシーの `acmeBinding` をそのバインディングにして，target の run が `succeeded` に
  なるのを待つ．

### 11-2. オブジェクトと利用側の要件を確かめる

run の画面の **Store object** が Key Vault の証明書名である．たとえば
`leaf-cerdad-naruto-u-ac-jp-0d438f060aa6c48a` のように，FQDN の `.` を `-` にし，
16 桁の接尾辞を付けたものになる．利用側が参照するのは，同名の **シークレット** の
バージョンなしの URI である:

```
https://<vault>.vault.azure.net/secrets/<Store object>
```

Conductor が証明書を格納する形式は，store バインディングの `contentType` で決まる．
既定は **PEM**（`application/x-pem-file`）で，`pkcs12` を指定すると **パスワードなしの PFX**
（`application/x-pkcs12`）になる．鍵は既定で **EC（P-256）** である．利用側がどの形式を
要求するかを先に確認し，target の `storeBinding` をそれに合うバインディングにする:

| 利用側 | 必要な形式 | 根拠 |
|---|---|---|
| Application Gateway v2 | **PFX（`pkcs12`）．PEM 不可** | PEM を参照すると更新が `ApplicationGatewaySslCertificateInvalidData` で失敗し，ゲートウェイが `Failed` のまま残る（leaf-infra の本番で確認．issue #41）．製品の文書も PFX のみとしている．PEM も有効とするトラブルシュート記事の記述は，実際の挙動と異なる．EC 鍵は PFX で提示の実績がある |
| App Service | PFX（`pkcs12`） | vault から PKCS #12 しか取り込まない |
| Azure Front Door，API Management | PFX（`pkcs12`）かつ RSA | ポリシーの `keyType` を `rsa2048` 以上にする（[`docs/runner.md`](../../docs/runner.md#certificate-store-azure-key-vault)） |
| シークレットを自分で読むアプリ，VM，コンテナ | PEM（既定） | PEM を読めればよい |

`pkcs12` のバインディングは，Runner の設定と Conductor の設定の両方に加える．既存の
target のバインディングを切り替えると，証明書がまだ有効でも次の run で再発行され，
同じ Store object に PFX の新しい版ができる．利用側を付け替える（11-4）のは，その版が
できた **後** にする．

### 11-3. 利用側の ID に読み取り権限を付ける

利用側は **自分の ID** で Key Vault のシークレットを読む．その ID に
`Key Vault Secrets User` を付ける．スコープは Key Vault 全体ではなく，
**シークレット単位** にするのが最小権限である．シークレット単位にするには，
先に証明書ができている必要がある．

まず，利用側の ID を確かめる（Application Gateway の例）:

```sh
az network application-gateway show -g <agw rg> -n <agw> --query identity -o json
# 既存の証明書の参照先と，その ID が持つ権限
az network application-gateway ssl-cert list -g <agw rg> --gateway-name <agw> --query "[].{name:name,kv:keyVaultSecretId}" -o table
az role assignment list --assignee <principalId> --all -o table
```

次に権限を付ける（ポータルでも CLI でもよい）:

```sh
KV=$(az keyvault show -n <vault> --query id -o tsv)
az role assignment create --role "Key Vault Secrets User" \
  --assignee-object-id <利用側 ID の principalId> --assignee-principal-type ServicePrincipal \
  --scope "$KV/secrets/<Store object>"
```

ポータルで行う場合は，Key Vault →「証明書」ではなく「シークレット」→ 該当の
シークレット →「アクセス制御 (IAM)」→「ロールの割り当ての追加」で
`Key Vault Secrets User` を選び，メンバーに利用側のマネージド ID を指定する．

割り当てる人には，そのスコープでの `roleAssignments/write` が要る．
`Key Vault Secrets User` は特権ロールではないので，条件付きの RBAC 委任でも
割り当てられる．Key Vault にファイアウォールを設定している場合は，利用側からの
ネットワーク到達性も確認する．

### 11-4. 参照先を付け替える（Application Gateway の例）

付け替える前に，戻せるように現在の参照先を控えておく（11-3 の `ssl-cert list`）．

```sh
az network application-gateway ssl-cert update -g <agw rg> --gateway-name <agw> -n <ssl cert name> \
  --key-vault-secret-id "https://<vault>.vault.azure.net/secrets/<Store object>"
```

- **バージョンなしの URI** にする．Application Gateway はおよそ 4 時間ごとに Key Vault を
  確認し，新しいバージョンを無停止で取り込む．Conductor の更新はこの経路で反映される．
  バージョンを含む URI では更新が反映されない．
- 更新の間，Application Gateway の `provisioningState` が `Updating` になる．
  `Failed` になった場合は，活動ログのエラーを確認する（権限，形式，到達性のいずれか）．

### 11-5. 確かめる

```sh
echo | openssl s_client -connect <fqdn>:443 -servername <fqdn> 2>/dev/null \
  | openssl x509 -noout -issuer -enddate -fingerprint -sha256
```

- 発行者が本番 CA であることを確認する．
- SHA-256 フィンガープリントが run の画面の **Fingerprint** と一致することを確認する
  （コロンの有無と大文字・小文字の違いは無視する）．

### 11-6. 戻し方と後片付け

- **戻す**: 11-4 で控えた元の `keyVaultSecretId` で，同じ `ssl-cert update` を実行する．
- **古い経路を止める**: 旧基盤（`cert-infra` など）の更新ジョブは，新しい経路で
  少なくとも 1 回の更新が反映されたことを確かめてから止める．
- **古い権限と証明書を片付ける**: 利用側の旧シークレットへの権限と，旧 Key Vault の証明書は，
  自動では消えない．不要になったら手で外す．

## 再デプロイ

パラメタや Runner 設定を変えたら，手順 7 の環境変数を設定して手順 8 のコマンドを
再実行する．内容が同じなら何度実行しても結果は変わらない．#37 より前のテンプレートで，
ABAC 条件付きの権限の場合は，毎回 `--validation-level Template` が要る．

## 片付け（staging を捨てるとき）

```sh
# 1. RG の外にある割り当て（DNS ゾーン上の Runner の ID）を先に外す．ID を消すと孤立した割り当てになる
RUNNER=$(az identity show -g rg-acme-staging -n acme-stg-id-runner --query principalId -o tsv)
az role assignment delete --assignee "$RUNNER" --scope <dns zone id>
# 2. RG ごと削除（アプリ，Job，ID，ストレージ，Key Vault）
az group delete -n rg-acme-staging
az keyvault purge -n kv-acme-stg-<org>            # 論理削除された vault を消す（同名で作り直すなら）
# 3. サブスクリプションのカスタムロールと Entra のアプリ登録
az role definition delete --name "ACME Conductor Staging Conductor Job Execution Observer"
az role definition delete --name "ACME Conductor Staging Runner DNS TXT Writer"
az role definition delete --name "ACME Conductor Staging Runner Key Vault Certificate Writer"
az ad app delete --id <oidcAudience>; az ad app delete --id <oidcClientId>
```

いずれも取り消せない操作である．実行前に対象を確認すること．

## つまずいた点の一覧

| 症状 | 原因 | 対処 |
|---|---|---|
| preflight で `roleAssignments/write` が拒否される | ABAC 条件付きの RBAC 委任で，`roleDefinitionId` が事前検証の時点で未確定（#34） | #37 以降のテンプレートを使う．古いものは `what-if` で確認後に `--validation-level Template` |
| デプロイ時にロール定義の作成で失敗する（想定） | `roleDefinitions/write` がない | PIM で `User Access Administrator` などを有効化する |
| サブスクリプションスコープの `roles` デプロイで失敗する（想定） | RG の `Contributor` だけで，サブスクリプションで `Microsoft.Resources/deployments/*` を持たない | サブスクリプションの `Contributor` などを用意する |
| アプリ登録を作れない | テナントで一般ユーザーのアプリ作成が禁止されている | Entra の `Application Developer` / `Application Administrator` を有効化する |
| デプロイは成功するが Runner が毎分 `Failed` になる | Runner 設定が読み込み時に拒否されている（例: `LEGO_DISABLE_CNAME_SUPPORT` は予約済み） | ログで理由を確認し，設定を直して再デプロイ |
| 鍵生成用の Go・コンテナがない | ― | OpenSSL で同じ形式の鍵を作る（手順 3） |
| what-if／デプロイが `accountProvisioningPrivateKeyPem and accountProvisioningPublicKey must be given together` で失敗する | provisioning 用の公開鍵と秘密鍵の片方だけが渡された（多くは環境変数 `ACME_ACCOUNT_PROVISIONING_PRIVATE_KEY_PEM` の設定忘れ） | 環境変数を設定する．機能を使わないなら `accountProvisioning*` の行をすべて消す（手順 3-1） |
| GUI で EAB を投入しようとすると公開鍵がないと言われる／API が `404 not_configured` | `accountProvisioningPublicKey` を渡していない | 手順 3-1 の鍵を渡して再デプロイする |
| what-if／デプロイが `accountProvisioningBindings must …` または `accountProvisioningBindings may only …` で失敗する | 有効化したのに `accountProvisioningBindings` が空，無効なのに値がある，または `acmeBindings` にない名前がある | EAB を要求する CA の binding（`acmeBindings` のいずれか）を挙げる．機能を使わないなら `accountProvisioning*` の行をすべて消す |
| GUI の EAB のページに，ある binding が出ない／API が `409 eab_not_required` | その binding が `accountProvisioningBindings` に挙がっていない | CA が EAB を要求するなら `accountProvisioningBindings` に加えて再デプロイする．要求しない CA（Let's Encrypt など）なら投入は不要 |
| 本番 CA のバインディングが Runner に拒否される（想定） | `allowProductionCA: true` がない | バインディングに追加する（手順 11-1） |
| 利用側（Application Gateway など）が証明書を読めない（想定） | 利用側の ID に `Key Vault Secrets User` がない，形式（PEM／EC）を受け付けない，ネットワークで届かない | 手順 11-2，11-3 |
| run が `AcmeFailure lego exited with status 1` で失敗し，理由がログにない | target の `_acme-challenge` がチャレンジ用ゾーンに委任されていない（lego の出力は debug のみ．#38） | 委任済みの名前を使うか，親ゾーンに CNAME を追加する（手順 10） |
