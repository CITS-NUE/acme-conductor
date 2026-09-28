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
- [名前を変える（再申請）](#名前を変える再申請)
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
- 名前の集合を変える（dNSName の追加・削除，CN の変更）には再申請が要り，
  新しい EAB で新しいアカウントを登録し直す．CN を変えると旧アカウントは
  停止され，旧アカウントを使い続ける設定は更新のたびに失敗する．
- 証明書の有効期間は **89 日** である．
- 発行できる鍵の種別は，EAB の発行時に指定した証明書プロファイルで決まる
  （RSA のプロファイルが多い）．
- EAB に有効期限は基本的にない．
- ドメインの所有確認に 20 回失敗すると，翌日まで処理が制限される．

## 対応関係: 申請 1 つ = アカウント 1 つ = target 1 つ

UPKI の申請 1 つを，Conductor の target 1 つに対応させる．

| UPKI の申請 | Conductor |
|---|---|
| 利用管理者 FQDN（CN） | target の `fqdn`（主名．証明書の CN になり，`lego --domains` の先頭に渡る） |
| 登録した残りの dNSName（最大 7 個） | target の `additionalNames`（要求順に `--domains` に続く） |
| 発行された EAB | その target のアカウントの世代（`POST /acme-bindings/{binding}/targets/{id}/provisioning`） |
| 再申請で発行された新しい EAB | 同じ target のアカウントの次の世代 |

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

`deploy/azure` のテンプレートはまだ `targetScopedBindings` を Conductor の設定に
渡さない（パラメータがない）．Azure で target ごとのアカウントを使うには，
テンプレートの対応を待つか，それまでは
[binding 全体のアカウントで運用する](#binding-全体のアカウントで運用する場合)．
Runner の設定（`maxNames`，UPKI の binding）は `runnerConfigJson` パラメータに
そのまま書ける．

名前が複数の DNS ゾーンにまたがるときは，各名前の `_acme-challenge` を
チャレンジ用ゾーンへ CNAME で委任する
（[`deploy/azure/README.md`](../deploy/azure/README.md#複数の-dns-ゾーン)）．
1 つでも委任が欠けていると，その名前の所有確認が失敗する．UPKI では所有確認の
失敗が 20 回で翌日まで制限されるので，名前を足す前に委任を確かめる．

## 新しい申請を追加する

1. UPKI に ACME 利用情報作成申請を出し，EAB（Key ID と HMAC Key）を受け取る．
   申請する名前は，これから作る target の `fqdn` と `additionalNames` そのもので
   ある．
2. 各名前の DNS-01 チャレンジが通ることを確かめる（委任しているなら
   `dig +short CNAME _acme-challenge.<name>`）．
3. target を作る．`fqdn` に利用管理者 FQDN（CN），`additionalNames` に残りの
   dNSName を並べ，`policyRef` に UPKI のポリシーを指定する．
   作った直後にスケジューラが最初の run を起こすが，まだアカウントがないので，
   Runner を起動せずに上の要約の `AcmeFailure` で失敗する．これは想定通りで
   ある．
4. target の詳細ページの「ACME account」の節から EAB を投入する（Key ID と
   HMAC Key を入力する．ブラウザの中で Runner の公開鍵に封じられ，暗号文だけが
   Conductor に送られる）．投入と同時に，その target の run が 1 つ起こる．
   手順 3 の失敗によるバックオフは待たない（投入より前の失敗だからである）．
5. その run が ACME アカウントを登録し（`newAccount` に EAB を使う），続けて
   証明書を発行する．run が成功し，target の「ACME account」に世代 1 が
   `active` として表示されれば完了である．以後の更新は EAB を使わず，登録した
   アカウントで行われる．

手順 4 で run を起こせなかった（target やポリシーが無効，実行中の run がある
など）ときも EAB は記録され，ページの上部にその理由が出る．run に添付されて
いない未着手の EAB は，次の tick でスケジューラが run を起こす理由になる．

## 名前を変える（再申請）

### dNSName を足す・減らす（CN は変えない）

1. UPKI に再申請し，新しい名前の集合で新しい EAB を受け取る．
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
（ADR 0024）．どちらの順序でも最後は収束するが，上の順序なら余分な失敗が
残らない．

### CN（利用管理者 FQDN）を変える

target の `fqdn` は作成後に変えられない（Store のオブジェクト名もこれから
決まる）．CN を変える再申請は，新しい target を作ることになる．

1. UPKI に再申請し，新しい EAB を受け取る．
2. 旧 target を無効にする（`POST /targets/{id}/disable`）．旧アカウントは CA 側で
   停止されるので，旧 target の更新は以後すべて失敗するためである．
3. 新しい CN の target を作り，[新しい申請を追加する](#新しい申請を追加する)の
   手順 3 から進める．
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
| 登録されていない名前，CN が先頭にない，鍵種別がプロファイルと違う | CA がオーダーを拒否し，`AcmeFailure`（`lego exited with status <n>`）． |
| CA 側で停止されたアカウント | 同上． |
| DNS-01 の所有確認に失敗（委任の漏れなど） | 同上． |
| EAB が無効（打ち間違い，すでに使われた） | EAB を運んだ run の `AcmeFailure`．その世代は `failed` になり，番号は再利用されない．新しい EAB を次の世代として投入し直す． |

`lego` の失敗理由（CA の応答）は，いまのところ `Result.error.summary` にも
info ログにも残らない．理由を run から読めるようにするのは
[issue #38](https://github.com/CITS-NUE/acme-conductor/issues/38) で扱う．
それまでは，上の表のどれに当たるかを，直前に行った操作（名前の編集，EAB の
投入，DNS の変更）から切り分ける．

## binding 全体のアカウントで運用する場合

`targetScopedBindings` を使えない（Azure のテンプレートがまだ対応していない
など）ときは，UPKI のアカウント 1 つにつき **binding 1 つ・ポリシー 1 つ・
target 1 つ** を静的に並べる（ADR 0024 の暫定運用）．

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
| 鍵種別 | EAB 発行時の証明書プロファイルで決まる（RSA が多い）．RSA の鍵長は未確認 | `keyType: rsa2048`．プロファイルに合わせる |
| EAB の有効期限 | 基本的にない | 投入を急ぐ必要はない |
| EAB の再利用 | CN を変えなければ同じ EAB を使い続けられる，との記述と，別のサーバにアカウントを移すには再発行を依頼する，との記述がある | Conductor ではアカウント鍵が新しくなるので，certbot などからの移行では新しい EAB を受け取る前提とする |
| CN を先頭に置く必要 | 必要 | Runner は `fqdn` を先頭の `--domains` に渡す |
| 登録名の一部ずつ別の証明書を発行してよいか | 未確認 | 行わない（登録名はすべて 1 つの target に載せる） |
| アカウント登録時の email の扱い | 未確認 | binding の `email` に組織の連絡先を書く |
| レート制限 | ドメインの所有確認 20 回の失敗で翌日まで制限．それ以外は未確認 | 名前を足す前に DNS-01 の委任を確かめる |
