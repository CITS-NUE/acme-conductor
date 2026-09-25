# 0021: Key Vault store のコンテンツタイプ — パスワードなし PKCS #12 での取り込みを選べるようにする

- ステータス: 採択
- 日付: 2026-09-25

## 背景

[ADR 0013](0013-azure-key-vault-store-adapter.md) は，Key Vault store の取り込みを
PEM（`application/x-pem-file`）だけに絞った．PKCS #12 が必要な利用者は，実際の
target が現れたときに扱うことにしていた．そのとき主な利用先と見込んでいた
Application Gateway については，PEM も受け付けると考えていた．

2026-09-25，leaf-infra の本番デプロイで，Application Gateway `agw-leaf-prod` の
証明書の参照先を Conductor が PEM で格納した証明書
（`kv-acme-prod-nue` / `leaf-cerdad-naruto-u-ac-jp-0d438f060aa6c48a`）に切り替えた．
その更新は `ApplicationGatewaySslCertificateInvalidData` で失敗し，ゲートウェイは
`provisioningState: Failed` のまま残った．同じテンプレートでも，参照先が PFX の
ときは成功していた．製品の文書
（[TLS termination with Key Vault certificates](https://learn.microsoft.com/azure/application-gateway/key-vault-certs#certificate-settings-in-key-vault)）も，
Application Gateway が受け付けるのは PFX だけだとしている．PEM も有効とする記述は
トラブルシュート記事にしかなく，実際の挙動はそれと食い違った．

こうして PFX を要求する具体的な target が現れた．App Service，Front Door，
API Management の組み込み Key Vault 連携も PFX を要求する（issue #41）．

使い捨ての vault で行った実験（issue #41）から，Key Vault の取り込みについて
次のことが分かっている．

- `application/x-pkcs12` のポリシーで PEM を渡すと拒否される．Key Vault は PEM を
  PFX に変換しない．
- 暗号化も MAC もないパスワードなしの PFX，AES-256 と SHA-256 の MAC を使う
  空パスワードの PFX，legacy 形式の空パスワードの PFX は，どれも取り込める．
- どれを入力しても，取り出されるシークレットは Key Vault が組み直した同じ形式に
  なる（空パスワード，`pbeWithSHA1And3-KeyTripleDES-CBC`，SHA-1 の MAC）．
  これは Application Gateway の文書が最も互換性が高いとする形式である．
- 同じ証明書名のまま，版ごとに PEM と PFX を切り替えられる．

## 決定

- **`azure-keyvault` バインディングの config に `contentType: "pem" | "pkcs12"` を
  加える．** 既定は `pem` とし，既存のバインディングの振る舞いは変えない．同じ
  vault を指すバインディングを 2 つ用意し，target の `storeBinding` で選ぶ．
  新しい概念は増えない．バインディング名が違っても，オブジェクト名は FQDN から
  導くので，同じ証明書名に新しい版が重なる．それ以外の値と，パスワードのフィールドは設定で拒否する
  （config は strict）．
- **`pkcs12` では，Runner がパスワードなし（暗号化なし・MAC なし）の PKCS #12 を
  作り，base64 で `application/x-pkcs12` として取り込む．** エンコーダは
  `software.sslmate.com/src/go-pkcs12` の `Passwordless` とする（依存が 1 つ増える）．
  - 利用者が受け取る形式は Key Vault が組み直すので，Runner 側の暗号方式は互換性に
    影響しない．そのため，パスワードを必要としない形式を選ぶ．
  - パスワードはどこにも存在しない．ADR 0013 の「システムに PFX パスワードは
    存在しない」と，脅威モデル T6 の前提は保たれる．PFX のバイト列は取り込みの
    間だけメモリ上にあり，PEM 文書と同じ扱いになる．エンコードした後，バッファは
    消去する．
  - `pem` の取り込みの内容は変えない（リーフ + チェーン + PKCS #8 の鍵）．
- **格納形式がバインディングと異なる証明書は，Runner が再発行する．** 鍵種別の
  不一致（ポリシーの `keyType` の変更）と同じ扱いである．
  - `store.Info` に `Stale` を加える．Key Vault の `Current` は，`certificates/get` が
    返すポリシーの `secret_props.contentType` をバインディングの設定と比べ，
    異なれば `Stale` を立てる．必要な権限は増えない．
  - 再 Put ではなく再発行にするのは，Runner が秘密鍵を読み戻さないからである
    （`secrets/get` を持たない．ADR 0013）．
  - vault がコンテンツタイプを報告しないときは `Stale` にしない．立ててしまうと，
    run のたびに再発行が繰り返されるおそれがある．同じ理由で，取り込みの応答が
    バインディングと異なるコンテンツタイプを報告したときは，`Put` を失敗させる．
  - `Stale` の概念を持たない store は，常に `false` のままでよい（`pkg/store` への
    後方互換な追加）．
- **鍵種別はポリシーで選ぶ．** Front Door と API Management には RSA が必要だが，
  それはすでにポリシーの `keyType`（`rsa2048` など）で選べる．Application Gateway は
  EC P-256 のままでよい（本番の Application Gateway で，EC 鍵の証明書を PFX で
  格納して提示した実績がある）．

## 結果

- Application Gateway，App Service，Front Door，API Management の組み込み
  Key Vault 連携が，Conductor の証明書を使えるようになる．Front Door と
  API Management は，RSA の鍵種別を選んだ場合に限る．
- `pkcs12` のバインディングを増やすには，Runner の設定（`storeBindings`）と
  Conductor の設定（target が選べるバインディング名）の両方に加える．
- `pkcs12` のバインディングに切り替えた target は，次の run で証明書が再発行され，
  同じ証明書名に PFX の新しい版ができる．切り替えるたびに ACME の
  発行が 1 回増えるので，多数の target を一度に切り替えるときは，CA のレート
  制限に注意する．
- ADR 0013 の「コンテンツタイプは PEM のみ」は，この ADR で置き換える．それ以外の
  決定（公開部分だけを読むこと，書き込み後の検証，認証，オブジェクト名，
  エラーの文言）は変わらない．
- 本物の vault での取り込みは，issue #41 の実験で確かめた範囲に限られる．
  テストは偽物の vault に対して行う（原則 8）．偽物は，パスワードなしで読めない
  PFX と，PKCS #12 として読めない PEM を拒否する．
