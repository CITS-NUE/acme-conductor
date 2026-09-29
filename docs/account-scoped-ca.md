# アカウントごとに発行範囲が決まる CA の運用ガイド（UPKI ACME を例に）

EAB（External Account Binding）を要求する CA の多くは，ACME アカウントごとに
発行できる名前の範囲を決めている．範囲の表し方は CA ごとに違い，組織単位で
事前検証したドメインの範囲（Sectigo，DigiCert，HARICA など）もあれば，申請時に
登録した FQDN の固定集合（UPKI ACME）もある．本書は，そうした CA を ACME
Conductor で運用する手順を，最も粒度の細かい UPKI ACME を例に説明する．

方針は [ADR 0024](adr/0024-target-scoped-acme-accounts-and-san.md) の通りである．
Conductor は CA ごとの発行範囲を写し持たず，事前検査もしない．範囲外の名前や
停止されたアカウントは CA がオーダーを拒否し，`AcmeFailure` として run に残る．
CA 専用の推奨値もコードには持たず，本書の設定例として置く．

設定項目そのものの説明は [`docs/conductor.md`](conductor.md) と
[`docs/runner.md`](runner.md) を参照．

## 目次

- [UPKI ACME の仕様](#upki-acme-の仕様)
- [対応関係: 申請 1 つ = アカウント 1 つ = target 1 つ](#対応関係-申請-1-つ--アカウント-1-つ--target-1-つ)
- [設定例](#設定例)
- [新しい申請を追加する](#新しい申請を追加する)
- [名前を変える](#名前を変える)
- [失敗の読み方](#失敗の読み方)
- [binding 全体のアカウントで運用する場合](#binding-全体のアカウントで運用する場合)
- [原典で確認すること](#原典で確認すること)

## UPKI ACME の仕様

本書が前提にする UPKI ACME の仕様を挙げる．出典は
[issue #53](https://github.com/CITS-NUE/acme-conductor/issues/53) の調査と，
UPKI ACME 移行支援サイトおよび UPKI マニュアルの公開情報（検索結果の抜粋）で
ある．原典の本文は未確認のものを含む．[原典で確認すること](#原典で確認すること)を
参照．

- 利用開始前に「ACME 利用情報作成申請」を登録担当者経由で提出し，審査後に
  EAB（Key ID と HMAC Key）が発行される．
- 1 つの EAB（= ACME アカウント）には，主体者 DN の CN となる **利用管理者
  FQDN が 1 つ** 固定され，CN を含めて **最大 8 個の FQDN** を dNSName として
  登録できる．
- オーダーに指定できる名前は，その申請で登録した利用管理者 FQDN と登録済みの
  dNSName だけである．**先頭には利用管理者 FQDN（CN）を指定する**．
- 登録した名前を変えるときは，変える内容で UPKI 側の手続きが分かれる．
  - CN（主体者 DN）の変更は，UPKI 側では新しい ACME アカウントの登録として
    扱われる．
  - dNSName などそれ以外の変更は，UPKI の「ACME アカウント更新」の手続きで
    行う．

  どちらの場合も，Conductor 側では手続きの結果受け取った EAB で ACME アカウントを
  登録し直す（[名前を変える](#名前を変える)）．
- 証明書の有効期間は **89 日** である．
- 発行できる鍵の種別は，EAB の発行時に指定した証明書プロファイルで決まる
  （RSA のプロファイルが多い）．
- EAB は ACME アカウントの登録時に使う資格情報で，登録後の発行・更新では
  使用しない．登録に使った EAB は再利用しない．
- ドメインの所有確認に 20 回失敗すると，翌日まで処理が制限される．

## 対応関係: 申請 1 つ = アカウント 1 つ = target 1 つ

UPKI の申請 1 つを，Conductor の target 1 つに対応させる．

| UPKI の申請 | Conductor |
|---|---|
| 利用管理者 FQDN（CN） | target の `fqdn`（主名．証明書の CN になり，`lego --domains` の先頭に渡る） |
| 登録した残りの dNSName（最大 7 個） | target の `additionalNames`（要求順に `--domains` に続く） |
| 発行された EAB | その target のアカウントの世代（`POST /acme-bindings/{binding}/targets/{id}/provisioning`） |
| ACME アカウント更新の手続きで受け取った EAB | 同じ target のアカウントの次の世代 |

これを実現するのが，ACME binding を `accountProvisioning.targetScopedBindings`
に挙げることである（[`docs/conductor.md`](conductor.md#accountprovisioning)）．
そうした binding では，Conductor はアカウントとその世代を binding 全体ではなく
target ごとに 1 つ持つ．binding は CA の接続情報（directory URL と email）を
表すだけの静的な設定のまま残り，UPKI の申請がいくつあっても binding は 1 つで
よい．申請を増やすのに設定変更も再デプロイも要らない．

target ごとのアカウントを持つ binding の target は，自分のアカウントしか使わない．
target に活性なアカウントも未着手の EAB もなければ，run は Runner を起動せずに
次の要約で失敗する（binding 全体のアカウントを代わりに使うことはない）．

```
acme binding "<binding>" keeps one account per target and this target has none yet: provision one with an EAB
```

登録した dNSName の一部だけの証明書を別の target として発行することは，本書では
扱わない．UPKI がそれを認めるかどうかが未確認であり（[原典で確認すること](#原典で確認すること)），
仮に認められても，1 つのアカウントを複数の target で共有する仕組みを Conductor は
持たない（ADR 0024 の「検討した代替案」）．登録した名前はすべて 1 つの target に
載せる．

## 設定例

### Runner

UPKI 用の ACME binding を 1 つ定義する．EAB は GUI から暗号化して投入するので，
`eab`（EAB を環境変数で渡すレガシーな経路）は書かない．アカウントの世代を使う
run では，`eab` が書いてあっても使われない
（[`docs/runner.md`](runner.md#accountprovisioning)）．

```json
{
  "authorization": {
    "allowedDnsSuffixes": ["example.ac.jp"],
    "allowWildcard": false,
    "allowedAcmeBindings": ["upki"],
    "allowedDnsBindings": ["azure-dns"],
    "allowedStoreBindings": ["keyvault"],
    "maxNames": 8
  },
  "acmeBindings": {
    "upki": {
      "directoryURL": "https://<UPKI ACME の directory URL>",
      "email": "pki-admin@example.ac.jp",
      "allowProductionCA": true
    }
  },
  "accountProvisioning": {
    "privateKeyFiles": ["/etc/acme-runner/account-provisioning.pem"]
  }
}
```

（`lego`，`dnsBindings`，`storeBindings` などは省略している．）

- `directoryURL` — UPKI の案内にある ACME の directory URL．ホスト名に
  `staging` や `test` などのラベルを含まない本番の CA なので，
  `allowProductionCA: true` が要る．
- `maxNames: 8` — UPKI の上限（CN を含めて 8 個）に合わせる．既定の `1` の
  ままでは，`additionalNames` を持つジョブを Runner が `PolicyViolation` で
  拒否する．これは CA の制約の写しではなく Runner 自身の上限なので，他の CA の
  binding と同じ Runner で動かすなら，すべての binding に効くことに注意する．
- `allowWildcard: false` — UPKI がワイルドカードを発行するかどうかは未確認で
  ある．確認できるまでは許さない．

### Conductor

```json
{
  "acmeBindings": ["upki"],
  "accountProvisioning": {
    "publicKey": "<acme-runner provisioning-keygen の publicKey>",
    "bindings": ["upki"],
    "targetScopedBindings": ["upki"]
  }
}
```

（`server`，`database`，`executionBindings` などは省略している．）

`bindings` に挙げると GUI に EAB の投入欄が出る．`targetScopedBindings` にも
挙げると，その欄は binding の EAB ページではなく各 target の詳細ページ
（「ACME account」の節）に出る．

### ポリシー

```json
{
  "allowedDnsSuffixes": ["example.ac.jp"],
  "allowWildcard": false,
  "acmeBinding": "upki",
  "renewBeforeDays": 30,
  "keyType": "rsa2048",
  "maxSANs": 8
}
```

- `keyType` — EAB を発行した証明書プロファイルの鍵種別に合わせる．RSA の
  プロファイルなら `rsa2048`（鍵長が指定されていればそれに合わせる）．
  プロファイルと合わない鍵種別では CA がオーダーを拒否する．
- `renewBeforeDays: 30` — 有効期間 89 日のうち，発行から約 59 日で更新に入る．
  更新が失敗し続けても，証明書が切れるまで 30 日ある．失敗した run は
  `scheduler.retryBackoffSeconds`（既定 5 分）から倍々に，
  `scheduler.maxRetryBackoffSeconds`（既定 6 時間）まで間隔を空けて再試行される．
- `maxSANs: 8` — CN を含めた名前の数の上限．Conductor は target の登録時に
  これを検査する．Runner の `maxNames` と両方を満たさなければ発行されない．
- `allowWildcard: false` — 上の Runner の設定と同じ理由．

UPKI の申請が部局ごとに違うサフィックスを持つなら，ポリシーを部局ごとに分けて
`allowedDnsSuffixes` を絞ってよい．binding は同じ `upki` を指す．

### Azure へのデプロイ

`deploy/azure` のテンプレートでは，Conductor の `accountProvisioning` を
パラメータで渡す．

```bicep
param accountProvisioningPublicKey = '<provisioning-keygen の publicKey>'
param accountProvisioningPrivateKeyPem = readEnvironmentVariable('ACME_ACCOUNT_PROVISIONING_PRIVATE_KEY_PEM', '')
param accountProvisioningBindings = ['upki']
param accountProvisioningTargetScopedBindings = ['upki']
```

`accountProvisioningTargetScopedBindings` が Conductor の設定の
`accountProvisioning.targetScopedBindings` になる（`accountProvisioningBindings` の
いずれかでなければデプロイが失敗する）．Runner の設定（`maxNames`，UPKI の
binding）は `runnerConfigJson` パラメータにそのまま書ける
（[`deploy/azure/README.md`](../deploy/azure/README.md)）．

名前が複数の DNS ゾーンにまたがるときは，各名前の `_acme-challenge` を
チャレンジ用ゾーンへ CNAME で委任する
（[`deploy/azure/README.md`](../deploy/azure/README.md#複数の-dns-ゾーン)）．
1 つでも委任が欠けていると，その名前の所有確認が失敗する．UPKI では所有確認の
失敗が 20 回で翌日まで制限されるので，名前を足す前に委任を確かめる．

## 新しい申請を追加する

UPKI の証明書を 1 つ（申請 1 つ = target 1 つ）追加するときの手順である．
UPKI の登録担当者が，UPKI 側（TSV と審査），DNS（委任），Conductor（ポリシー，
target，EAB）の作業をすべて 1 人で行うことを前提にする．Conductor を操作するのも
登録担当者だけで，証明書の利用者は Conductor に触れない．利用者から受け取るのは
名前と用途だけでよい．

審査には日数がかかることがあるので，審査を待つ間に手順 4 を済ませてよい．
Conductor の作業（手順 5 以降）は，EAB と委任の両方がそろってから行う．

| # | 作業 | 場所 |
|---|---|---|
| 1 | 名前を決め，前提を確かめる | ― |
| 2 | TSV を作る | [UPKI TSV 作成ツール](https://certs.nii.ac.jp/tsv-tool/) |
| 3 | TSV をアップロードし，審査を経て EAB を受け取る | [UPKI 証明書発行支援システム（登録担当者）](https://scia.secomtrust.net/upki-odcert/lra/SSLLogin.do) |
| 4 | `_acme-challenge` の CNAME を設定する | 親ゾーンの DNS |
| 5 | ポリシーを作る（初回，または条件が違うときだけ） | Conductor GUI |
| 6 | target を作る | Conductor GUI |
| 7 | EAB を投入し，発行を確かめる | Conductor GUI（target の詳細ページ） |

### 1. 名前を決め，前提を確かめる

- 利用管理者 FQDN（CN）を 1 つと，残りの dNSName（CN を含めて最大 8 個）を
  決める．この集合が，そのまま UPKI の申請と target の `fqdn`／`additionalNames`
  になる．後から名前を変えるには UPKI 側の手続きが要る（[名前を変える](#名前を変える)）．
- ワイルドカードは使わない（`allowWildcard: false`）．
- すべての名前が Runner の `authorization.allowedDnsSuffixes` のいずれかの下に
  あることを確かめる．外れていると，run は Runner で `PolicyViolation`
  （`fqdn is not under any allowed DNS suffix`）になる．Runner の設定は
  デプロイ時に決まり，登録担当者は GUI から変えられない．足りなければ，
  デプロイする者に Runner の設定の変更と再デプロイを頼む．
  名前ごとの制限は DNS の委任と UPKI の登録がかけるので，サフィックスは
  組織のドメイン（`example.ac.jp`）程度にまとめてよい．
- 名前の数が Runner の `maxNames` とポリシーの `maxSANs` を超えないことを
  確かめる（[設定例](#設定例)では両方 8）．

### 2. TSV を作る

[UPKI TSV 作成ツール](https://certs.nii.ac.jp/tsv-tool/) で，ACME 利用情報作成
申請の TSV を作る．利用管理者 FQDN には手順 1 の CN を，dNSName には残りの名前を
入れる．このとき選ぶ証明書プロファイルが，発行できる鍵の種別を決める．選んだ
プロファイル（RSA かどうか，鍵長）を控えておき，手順 5 のポリシーの `keyType` に
合わせる．

### 3. TSV をアップロードし，EAB を受け取る

[UPKI 証明書発行支援システムの登録担当者画面](https://scia.secomtrust.net/upki-odcert/lra/SSLLogin.do)
から TSV をアップロードする．審査が済むと EAB（Key ID と HMAC Key）が発行される．
EAB は登録担当者の手元から出さない．利用者やほかの担当者に渡さず，チャットや
チケットにも貼らない．Conductor のリポジトリにも Key Vault にも置かない
（手順 7 でブラウザ内で暗号化して投入する）．

### 4. `_acme-challenge` の CNAME を設定する

各名前の `_acme-challenge.<name>` を，チャレンジ用ゾーンの中の名前へ CNAME で
委任する（[`deploy/azure/README.md`](../deploy/azure/README.md#複数の-dns-ゾーン)）．
Runner が書き込めるのはチャレンジ用ゾーンだけなので，委任のない名前では
TXT を置けない．
登録担当者には，親ゾーンに CNAME を書く権限を持たせておく（Azure DNS なら，
親ゾーンの CNAME レコードの書き込み）．TXT を書く権限は要らない．

```
_acme-challenge.www.example.ac.jp.  IN CNAME  www.<チャレンジ用ゾーン>.
```

委任先の名前は，ほかの名前と重ならなければ何でもよい．チャレンジ用ゾーンの
中にレコードを事前に作る必要はない（TXT は run のたびに Runner が作って消す）．
設定したら，すべての名前について確かめる．

```sh
dig +short CNAME _acme-challenge.<name>   # チャレンジ用ゾーン内の名前が返ればよい
```

UPKI では所有確認に 20 回失敗すると翌日まで制限されるので，委任を確かめる前に
手順 7 に進まない．利用管理者 FQDN そのものが外部のサービス（ホスティングなど）
への CNAME でも，`_acme-challenge` は別の名前なので委任できる．

### 5. ポリシーを作る

UPKI 用のポリシーがまだないとき，または既存のものと条件（サフィックス，鍵種別）が
違うときだけ作る．内容は [設定例のポリシー](#ポリシー) の通りで，`acmeBinding` に
UPKI の binding を指定する．

`keyType` は手順 2 で控えたプロファイルに合わせる．RSA のプロファイルに
`rsa4096` を指定すると，チャレンジが通った後で CA に拒否され，run は
`AcmeFailure` で失敗する（実例は [失敗の読み方](#失敗の読み方)）．
既存のポリシーを流用するときも `keyType` を確かめる．ほかの CA 用に作った
ポリシーを付けたままにしない．

### 6. target を作る

`fqdn` に利用管理者 FQDN（CN），`additionalNames` に残りの dNSName を並べ，
`policyRef` に手順 5 のポリシーを指定する．**「Enabled」を外した無効の状態で
作る．**

有効のまま作ると，直後にスケジューラが最初の run を起こす．まだアカウントが
ないので，run は Runner を起動せずに上の要約の `AcmeFailure` で失敗する．
害はないが，失敗の記録が残る．

### 7. EAB を投入し，発行を確かめる

1. target の詳細ページの「ACME account」の節に，手順 3 の Key ID と HMAC Key を
   入力して投入する．ブラウザの中で Runner の公開鍵に封じられ，暗号文だけが
   Conductor に送られる．
2. target を有効にする（「Enabled」を付けて保存する）．有効にした時点で run が
   起き，保存された EAB を運ぶ．target を有効のまま作った場合は，EAB の投入と
   同時に run が起こる．手順 6 の失敗によるバックオフは待たない（投入より前の
   失敗だからである）．
3. その run が ACME アカウントを登録し（`newAccount` に EAB を使う），続けて
   証明書を発行する．run が `succeeded` になり，「ACME account」に世代 1 が
   `active` と表示され，Store（Key Vault など）に証明書が入っていれば完了である．
   以後の更新は EAB を使わず，登録したアカウントで行われる．

run が失敗したら [失敗の読み方](#失敗の読み方) で切り分ける．アカウントの登録が
済んでいれば（世代 1 が `active`），原因を直して GUI から run を起こし直すだけで
よく，EAB を投入し直す必要はない．

run を起こせなかった（target やポリシーが無効，実行中の run があるなど）ときも
EAB は記録され，ページの上部にその理由が出る．run に添付されていない未着手の
EAB は，次の tick でスケジューラが run を起こす理由になる．

## 名前を変える

UPKI 上の手続き（ACME アカウント更新か，新しい ACME アカウントの登録か）と，
Conductor 上の操作は別のものである．Conductor は，どちらの手続きで受け取った
EAB も，target のアカウントの新しい世代として登録する．登録した EAB は再利用
しないので，同じアカウントの情報を UPKI 側で更新した場合でも，Conductor では
新しい世代（新しいアカウント鍵での `newAccount`）になり，旧世代は `retired` に
なる．

### dNSName を足す・減らす（CN は変えない）

1. UPKI で ACME アカウント更新の手続きを行い，新しい名前の集合に対応した EAB を
   受け取る．
2. **先に** target の `additionalNames` を新しい集合に編集する．target の
   リビジョンが上がるので，すぐに run が起こる．この run はまだ旧アカウントを
   使うので，旧アカウントに登録されていない名前があれば CA が拒否して
   `AcmeFailure` で失敗する．格納済みの証明書はそのまま残るので，サービスは
   止まらない．
3. 続けて，その target に新しい EAB を投入する．新しい世代を運ぶ run が起こり，
   新しいアカウントを登録して，新しい名前の集合で証明書を発行する．
   手順 2 の run がまだ動いていれば，投入の時点では run を起こせないが，その run
   が終わった次の tick でスケジューラが起こす．手順 2 の run は EAB より前に
   要求されたものなので，その失敗のバックオフは待たない．
4. 新しい世代が `active` になると，旧世代は `retired` になる．

順序を逆にする（先に EAB を投入する）と，EAB を運ぶ run は旧い名前の集合で
発行しようとする．アカウントの登録は成功して新しい世代は `active` になるが，
旧い名前が新しいアカウントの範囲に含まれていなければ発行は失敗し，その失敗は
EAB より後のものなので，名前を編集した後の run はバックオフを待つことになる．
待たずに進めるには `POST /targets/{id}/runs`（GUI の run の要求）を使う．

Conductor は target の編集と EAB の投入を 1 つの操作に結び付けない
（ADR 0024）．どちらの順序でも最後は収束するが，上の順序なら失敗は手順 2 の
1 回だけで済み，バックオフも待たない．その 1 回も残したくなければ，手順 2 の
前に target を無効にし，名前を編集して EAB を投入してから有効にする．有効に
した時点で run が起き，保存された EAB を運ぶ．

### CN（利用管理者 FQDN）を変える

target の `fqdn` は作成後に変えられない（Store のオブジェクト名もこれから
決まる）．CN（主体者 DN）の変更は UPKI 側では新しい ACME アカウントの登録と
して扱われ，Conductor 側では新しい target を作ることになる．

1. UPKI で新しい CN の ACME アカウントを申請し，EAB を受け取る．
2. 旧 target を無効にする（`POST /targets/{id}/disable`）．旧い CN の証明書を
   更新し続けないためである．
3. 新しい CN の target を作り，[新しい申請を追加する](#新しい申請を追加する)の
   手順 4 から進める（新しい名前の委任を確かめてから）．
4. 証明書の利用側（Key Vault の参照など）を，新しい target の Store の
   オブジェクトに切り替える．

1 つの名前は 1 つの target にしか属せず，無効にした target も名前を持った
ままである（target を削除する API はない）．新しい target に旧 target の
`additionalNames` にあった名前を載せるなら，先に旧 target の
`additionalNames` からその名前を外す（無効にしてから編集すれば run は
起きない）．旧 target の `fqdn` だった名前は新しい target に載せられない．

## 失敗の読み方

UPKI 固有の失敗を，Conductor は専用の状態で扱わない．どれも `AcmeFailure`
として run に残り，既存のバックオフで再試行される．

| 状況 | run に残るもの |
|---|---|
| target にアカウントがない（EAB 未投入） | `AcmeFailure`．要約は `acme binding "…" keeps one account per target and this target has none yet: provision one with an EAB`．Runner は起動しない． |
| 名前が Runner の `allowedDnsSuffixes` の下にない | `PolicyViolation`．要約は `runner authorization policy rejected the job: fqdn is not under any allowed DNS suffix`．lego は起動しない．Runner の設定を直して再デプロイする． |
| 登録されていない名前，CN が先頭にない | CA がオーダーを拒否し，`AcmeFailure`（`lego exited with status <n>`）． |
| 鍵種別がプロファイルと違う | 同上．チャレンジが通った後で拒否されるので，lego は数十秒動いてから失敗する． |
| CA 側で停止されたアカウント | 同上． |
| DNS-01 の所有確認に失敗（委任の漏れなど） | 同上．委任がなければ TXT を置けないので，lego は数秒で失敗する． |
| EAB が無効（打ち間違い，すでに使われた） | EAB を運んだ run の `AcmeFailure`．その世代は `failed` になり，番号は再利用されない．新しい EAB を次の世代として投入し直す． |

`lego` の失敗理由（CA の応答）は，いまのところ `Result.error.summary` にも
info ログにも残らない．理由を run から読めるようにするのは
[issue #38](https://github.com/CITS-NUE/acme-conductor/issues/38) で扱う．
それまでは，上の表のどれに当たるかを，直前に行った操作（名前の編集，EAB の
投入，DNS の変更）と，次の手がかりから切り分ける．

- **lego の所要時間**．Runner の info ログの `lego finished` に `durationMs` が
  出る．数秒なら，チャレンジより前（委任の漏れで TXT を置けない，オーダーの
  拒否）で失敗している．数十秒なら，TXT を置いてチャレンジまで進んだ後
  （鍵種別の不一致など，検証や発行の段階）で失敗している．
- **アカウントの世代**．EAB を運んだ run が失敗しても，世代が `active` に
  なっていれば，アカウントの登録（EAB）は成功している．EAB を投入し直さず，
  原因を直して run を起こし直す．
- **チャレンジ用ゾーンの操作記録**．Azure DNS なら，チャレンジ用ゾーンの
  アクティビティログに `TXT/write` があるかで，lego が TXT を置けたかが分かる．
- **委任**．`dig +short CNAME _acme-challenge.<name>`．

実例（2026-09 の導入時）: 次の 3 つが順に起きた．

1. 名前が Runner の `allowedDnsSuffixes` の下になく，`PolicyViolation` になった．
2. 委任がなく，lego が約 2 秒で失敗した．
3. ポリシーの `keyType` が `rsa4096` のままで，lego が約 40 秒で失敗した．
   TXT は置けていて，世代 1 は `active` になっていた．`rsa2048` にして run を
   起こし直すと発行できた．

## binding 全体のアカウントで運用する場合

`targetScopedBindings` を使えない（`acme.account.scope` を知らない古い Runner を
使い続けるなど）ときは，UPKI のアカウント 1 つにつき **binding 1 つ・
ポリシー 1 つ・target 1 つ** を静的に並べる（ADR 0024 の暫定運用）．

- Runner の `acmeBindings` に `upki-<名前>` のような binding を申請ごとに
  定義する（directory URL と email は同じでよい）．`authorization.allowedAcmeBindings`
  にも加える．
- Conductor の `acmeBindings` と `accountProvisioning.bindings` に同じ名前を
  加える．`targetScopedBindings` には挙げない．Azure では `acmeBindings` と
  `accountProvisioningBindings` パラメータ，`runnerConfigJson` を更新して
  再デプロイする．
- binding ごとにポリシーを 1 つ作り（`acmeBinding` にその binding），その下に
  target を **1 つだけ** 置く．2 つ目の target を置くと，binding の EAB を運ぶ
  run がどちらの target で起こるかを操作者が選べず，範囲外の名前で登録と発行を
  試みることがある．
- EAB は GUI の「EAB」ページから binding ごとに投入する．投入と同時に，その
  binding を使う target の run が起こる（手動で run を起こす必要はない）．
- SAN（`additionalNames`）も使える．Runner の `maxNames` とポリシーの `maxSANs`
  は上の設定例と同じにする．

申請を増やすたびに設定変更と再デプロイが要ること以外は，名前の変更の手順も
失敗の読み方も上と同じである．後で `targetScopedBindings` に移るときは，
新しい binding を target ごとのアカウントで作り，target のポリシーをそちらに
付け替えて EAB を投入し直す（binding 全体のアカウントの世代は target ごとの
アカウントには引き継がれない）．

## 原典で確認すること

次は issue #53 で要確認とされた事項である．この環境からは
`certs.nii.ac.jp` と UPKI マニュアルの本文を取得できず，公開情報の抜粋で
確認できたものだけを上に反映した．原典で確認できたら，設定例と本書を更新する．

| 事項 | 現状 | 本書での扱い |
|---|---|---|
| ワイルドカードの可否 | 未確認 | `allowWildcard: false` |
| 鍵種別 | EAB 発行時の証明書プロファイルで決まる（RSA が多い）．RSA のプロファイルで `rsa4096` は拒否され，`rsa2048` で発行できた（2026-09，実運用で確認） | `keyType: rsa2048`．プロファイルに合わせる |
| EAB の有効期限 | 未確認 | 期限がないことを前提にしない．受け取った EAB はそのまま投入する |
| EAB の再利用 | 登録時に使う資格情報で，登録後の発行・更新では使わない．登録に使った EAB は再利用しない | 1 つの EAB は 1 つの世代の登録にだけ使う．certbot などからの移行でも，Conductor のアカウントには新しい EAB を受け取る |
| CN を先頭に置く必要 | 必要 | Runner は `fqdn` を先頭の `--domains` に渡す |
| 登録名の一部ずつ別の証明書を発行してよいか | 未確認 | 行わない（登録名はすべて 1 つの target に載せる） |
| アカウント登録時の email の扱い | 未確認 | binding の `email` に組織の連絡先を書く |
| レート制限 | ドメインの所有確認 20 回の失敗で翌日まで制限．それ以外は未確認 | 名前を足す前に DNS-01 の委任を確かめる |
