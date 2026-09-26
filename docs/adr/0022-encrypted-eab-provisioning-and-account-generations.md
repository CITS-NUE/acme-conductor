# 0022: 暗号化された EAB プロビジョニングと ACME アカウントの世代

- ステータス: 採択
- 日付: 2026-09-25

## 背景

一部の ACME CA（プライベート CA，学内の CA 連携）は External Account Binding
（EAB，`kid` と HMAC 鍵）を要求する．EAB は ACME の `newAccount` にちょうど 1 度
提示すれば済む **起動用の資格情報** であり，Runner がいったんアカウントを登録
すれば，通常の発行・更新はその登録済みアカウント鍵で行われ，EAB を二度と必要
としない．したがってこれは，`DnsBinding`／Store バインディングの資格情報が
run のたびに使われる継続的な資格情報とは性質が異なる．

これまで EAB は `docs/runner.md` の `acmeBindings.<name>.eab` の通り，Runner の
設定が名指す環境変数（`kidEnv`／`hmacEnv`）でのみ渡せた．すなわち，Runner の
プロセス環境に恒久的に置くか，実行基盤のシークレットストアに置くしかない．
これは「一度きりの起動用資格情報」に対して「常駐する長期シークレット」という
不釣り合いな運用コストを課す．操作者が GUI から EAB を **投入** し，それが
1 回の登録実行のためだけに存在してから消える経路が必要だった．

もう 1 つの制約は，[ADR 0005](0005-conductor-never-touches-secrets.md) が定める
「Conductor は決してシークレットに触れない」である．Conductor の GUI から EAB を
受け取る以上，Conductor のプロセスやデータベースに平文が一瞬でも存在しては
ならない．決めるべきだったのは，ブラウザから Runner までの間，平文が
どこにも留まらない具体的な暗号方式，Conductor が保存してよいものの形，そして
「このアカウント世代は登録済みか」を Runner がどう判断し，取り違えや再送を
どう防ぐかである．

## 決定

- **EAB は起動専用の資格情報であり，通常の発行・更新には使われない．** EAB が
  意味を持つのは ACME の `newAccount`（アカウント登録）だけである．登録された
  アカウントの以後の発行・更新は，そのアカウント鍵で行われる ACME オーダーで
  あり，EAB を必要としない．したがって Runner は，登録済みのアカウント世代を
  使う run では EAB を一切 `lego` に渡さない（`acmeBindings.<name>.eab` に
  設定されていても）．プロビジョニング payload を運ぶ run だけが EAB を運ぶ．
- **目的別に鍵を分ける．署名鍵と暗号化鍵は決して同じ鍵にしない．** 既存の
  ジョブ／Result 署名（[ADR 0015](0015-signed-job-envelope.md)）は Ed25519 で
  「誰が作ったか」を証明する．EAB の機密性を守るにはそれとは別の性質，すなわち
  「誰が読めるか」を制限する暗号化が要る．この 2 つの目的を 1 つの鍵に
  重ねると，署名鍵の想定される使い方（署名検証）とかけ離れた使い方（復号）を
  同じ鍵素材に許すことになり，鍵の危殆化の影響範囲が両方の目的にまたがる．
  そこで Runner は署名用の Ed25519 鍵に加えて，**account-provisioning 用の
  X25519 鍵ペア**を持つ．`ParseProvisioningPrivateKey`／
  `ParseProvisioningPublicKey`（`pkg/api/v1alpha1/provisioning.go`）は Go の型
  （`*ecdh.PrivateKey`／`*ecdh.PublicKey`）が一致しない鍵を無条件に拒否するので，
  署名鍵を暗号化関数に渡すことも，暗号化鍵を署名関数に渡すことも，コード上
  ありえない．
- **方式は byte-exact に固定し，ブラウザの WebCrypto と Go の両方で同一に
  再現できるようにする．** 版識別子
  `ProvisioningVersion = "x25519-hkdf-sha256-a256gcm/v1"` の下で:

  1. Runner の X25519 公開鍵 `R` に対し，毎回新しい一時鍵ペア `eph` を生成する．
  2. `shared := ECDH(eph.private, R)`．
  3. `salt := eph.public.Bytes() || R.Bytes()`（64 バイト，一時鍵を先に置く固定順）．
  4. `info := "acme-conductor.cits-nue.github.io/v1alpha1 account-provisioning"`
     （目的の名前と契約バージョンだけを含む固定文字列．他の目的では二度と
     使わない）．
  5. `key := HKDF-SHA256(secret=shared, salt, info, 32)`（AES-256 鍵）．
  6. `nonce` は 12 バイトの乱数．
  7. `aad := ProvisioningAAD(version, keyId, binding, generation)` —
     `"acme-conductor.cits-nue.github.io/v1alpha1\naccount-provisioning\n` +
     `version=<version>\nkeyId=<keyId>\nbinding=<binding>\n` +
     `generation=<generation>"`．
  8. `plaintext` は厳密に 2 フィールドの JSON
     `{"kid":"<kid>","hmac":"<hmac>"}`．他のフィールドは一切許さない．
  9. `ciphertext := AES-256-GCM.Seal(key, nonce, plaintext, aad)`（タグは
     ciphertext の末尾に付く．WebCrypto の `encrypt` と同じ並び）．

  `SealedProvisioning` はこの手順の出力（`version`，`keyId`，
  `ephemeralPublicKey`，`nonce`，`ciphertext`，すべて base64url 無パディング）
  だけを運ぶ．開く側（`SealedProvisioning.Open`）はすべてをこの手順の逆で
  再計算し，AAD に自分自身の binding／generation／version／keyId を差し込んで
  検証するので，運ばれてきた AAD をそのまま信用することはない．鍵 ID
  （`ProvisioningKeyID`）は，署名鍵の `KeyID` と同じ導出（生の公開鍵の
  SHA-256 の先頭 16 桁の 16 進）を X25519 の生公開鍵に適用したものであり，
  どちらの鍵種別も同じ考え方で識別できる．
- **EAB を受け付ける binding は操作者が明示する．** Conductor は ACME binding
  を名前でしか知らず（binding が指す CA の directory は Runner の設定にしか
  ない），その CA が EAB を要求するかどうかを自分では判断できない．そこで
  Conductor の設定 `accountProvisioning.bindings`（1 個以上，いずれも
  `acmeBindings` に列挙済み）に EAB を要求する CA の binding を挙げ，それ
  以外の binding は GUI に投入フォームを出さず，API も
  `409 eab_not_required` で要求を拒否する．EAB が要らない CA（Let's
  Encrypt など）の binding に無意味な EAB を投入させたり，ダミー値の投入を
  誘ったりしないためである．これは真偽の属性であってシークレットではない
  ので，[ADR 0005](0005-conductor-never-touches-secrets.md) には反しない．
  リストから外した binding に残った未着手の要求は，従来通りキャンセルできる．
- **Conductor が保存し取り扱えるのは暗号文とメタデータだけである．**
  Conductor の `acme_accounts` テーブル（`internal/conductor/sqlite`）は
  `sealed_payload` に `SealedProvisioning` の JSON をそのまま持つが，これは
  暗号文であって EAB の `kid`／`hmac` そのものではない．Conductor は
  Runner の秘密鍵を持たないので，これを復号する手段を持たない．行が終端
  状態（`active`／`retired`／`failed`／`cancelled`）に達した時点で
  `sealed_payload` は `NULL` に落とされ，暗号文でさえ必要以上に残らない．
  これは [ADR 0005](0005-conductor-never-touches-secrets.md) の延長である:
  そこでの決定は Conductor が秘密鍵・証明書本体・クラウド資格情報を持たない
  ことだったが，本 ADR はそこに「Conductor が持つのは，自分には開けない
  暗号文だけである」という形を加える．API レスポンス（`ACMEAccountResource`）
  も監査イベントも `sealed_payload` を運ばない．
- **暗号化された payload は署名付き `JobSpec` の内側を運ばれる．署名と暗号化は
  別の仕事をする．** `ACMEAccountRef.Provisioning`（`*SealedProvisioning`）は
  `JobSpec.acme.account` の一部としてシリアライズされ，ジョブ全体が
  [ADR 0015](0015-signed-job-envelope.md) の署名付きエンベロープで包まれる
  デプロイでは，その署名の対象に含まれる．署名は完全性とリプレイ耐性
  （エンベロープが改変されていないこと，同じ run が二度実行されないこと）を
  与えるが，中身を読めるかどうかには関与しない．暗号化はその逆に，機密性
  （EAB の平文を Runner の秘密鍵を持つ者以外の誰にも見せないこと）だけを
  与え，改ざんからは（AEAD のタグが破れて拒否される限りにおいて）守るが，
  リプレイからは守らない．交換用ボリュームやジョブレジストリを読める者
  （侵害された交換用ストレージ，ログに落ちた JobSpec の写し）は暗号文しか
  見えない．
- **アカウントは世代で管理し，状態は `stateDir/acme-accounts/<binding>/<generation>`
  に置く．** `spec.acme.account` が無ければレガシーな，世代のない
  アカウント状態（`stateDir` そのもの）であり，これまでの挙動を一切変えない．
  世代を指定すると，Runner はその世代専用のディレクトリを使う．すべての
  パス構成要素は `Lstat` で実ディレクトリであることを確認し（シンボリック
  リンクは決して辿らない），binding 名とジェネレーション番号はどちらも
  コントラクトがすでに検証済みの，構文的に閉じた値である．
- **プロビジョニング run は必ず `lego` を起動する．** `lego` がアカウントを
  登録するのは `run` サブコマンドの内側だけであり，証明書が最新で noop に
  なる早期リターンの経路では登録が起きない．そのため，プロビジョニング
  payload を運ぶ run は，証明書がすでに要件を満たしていても noop の早期
  リターンを飛ばして必ず `lego run` を実行する．その結果，このひと続きの
  run はアカウントの登録と，対象の証明書 1 枚の発行または更新を同時に行う
  ことになる —— 登録専用の別コマンドは存在しない．
- **登録の判定は，`lego` が実際に書く `account.json` の形から行う．**
  `accountRegistered`（`internal/runner/account.go`）は
  `accounts/<host>/<email>/account.json` を走査し，`registration.uri` が
  空でない文字列であるものが 1 つでもあれば登録済みとみなす．ファイルの
  存在だけでは判定しない．失敗した，または中断した登録試行がこのファイルを
  部分的に残しうるからである．
- **世代の活性化は，一致する `registered` の Result を得たときだけ行われる．
  失敗や不明な結果はその世代番号を燃やし，旧世代を活性のままにする．**
  Runner は，`lego` の実行後にその世代のディレクトリが登録済みになっている
  ときにだけ状態を公開し（登録に至らなかった試みは何も公開しない），その
  公開が成功して読み直した状態に登録済みのアカウントがあるときにだけ
  `registered` と報告する．公開に失敗すれば，登録自体は成功していても
  `failed` である．
  Conductor 側では `CompleteACMEAccountProvisioning` が，`Result` の
  `accountProvisioning` が要求した binding／generation と一致し，かつ
  `status: registered` であるときにだけ，その世代を `active` にし
  （直前の `active` 世代は `retired` に落とす）．`failed` の報告，別の
  binding／世代を指す結果，または run そのものが結果を返さずに終わった場合
  （クラッシュ，タイムアウト）は，その世代を `failed` にする ——
  **その世代番号は二度と再利用されない**．`accountProvisioning` を持たない
  結果（Runner が payload を開く段階に達しなかった）だけは添付を外し，
  次の run が同じ世代を再び運ぶ．いずれの場合も，直前に活性
  だった世代は活性のままである．したがって一度アクティブなアカウントが
  確立していれば，プロビジョニングの試みが失敗しても発行・更新が止まる
  ことはない．
- **リプレイ対策は 3 層である．** (1) 署名付きジョブのリプレイ台帳
  （[ADR 0015](0015-signed-job-envelope.md)）が，同じ run（したがって同じ
  暗号化 payload）の再実行そのものを拒否する．(2) Runner は，対象の世代が
  すでに登録済みであれば，プロビジョニングを一切試みずに拒否する
  （`acme account generation <g> of binding "<b>" is already provisioned`，
  `InvalidJobSpec`）．登録済みの状態は変更されない．(3) AAD が
  `keyId`／`binding`／`generation`／`version` を暗号文に縛り付けているので，
  ある世代向けに封じた payload を別の世代や別の binding へ黙って転用する
  ことはできない —— AEAD の検証がその場で失敗する．
- **1 つの未着手のプロビジョニング要求は，ちょうど 1 つの run にだけ添付
  される．** `ClaimACMEAccountProvisioning` は binding ごとに未着手（`run_id`
  が `NULL`）のプロビジョニング行をアトミックに 1 つの `runId` へ結び付ける．
  同じ binding を使う複数の target が同時に期限を迎えても，暗号化された
  payload を運ぶのはその 1 回の run だけであり，他は（世代がすでに活性なら）
  世代なしの EAB なしの通常の run になる．run が Runner に到達する前に失敗
  すれば `ReleaseACMEAccountProvisioning` が付着を外し，次の機会にやり直せる
  ようにする．
- **鍵の生成・読み込み・ローテーション．** `acme-runner provisioning-keygen
  --private FILE --public FILE` が X25519 鍵ペアを生成する（既存の `keygen`
  と同じ安全なファイル書き込み: 既存ファイルは決して上書きしない，秘密鍵は
  `0600`）．表示される `keyId:` と `publicKey:` を Conductor の
  `accountProvisioning.publicKey` に貼り付ける．Runner 側の
  `accountProvisioning.privateKeyFiles`（1〜8 個）は，プロビジョニング
  payload を運ぶジョブが来たときにだけ遅延して読み込まれ，通常の発行・
  更新の run では一切ディスクに触れない．ローテーションは：(1) 新しい鍵
  ペアを生成し，Runner の `privateKeyFiles` に新しい秘密鍵ファイルを追加
  （旧鍵はまだ残す），(2) Conductor の `accountProvisioning.publicKey` を
  新しい公開鍵に切り替え，(3) 旧鍵に封じられた，未着手のプロビジョニング
  要求が残っていればキャンセルするか（`DELETE …/provisioning/{generation}`）
  再投入させ，実行中の（旧鍵に封じられて添付済みの）要求は完了するまで
  待つ，(4) 十分な移行期間の後，旧秘密鍵ファイルを `privateKeyFiles` から
  取り除く．どの時点でも Runner は複数の鍵を同時に保持でき，payload は
  自身の `keyId` で選ぶので，切り替えの窓の間も両方の鍵が有効である．
- **残存リスク: 侵害された Conductor は偽の公開鍵を提示できる．** GUI は
  `GET /account-provisioning/key` が返す `publicKey`／`keyId` を信じて
  ブラウザ内で封をする．Conductor 自体が侵害されていれば，これを攻撃者の
  鍵に差し替え，操作者に投入させた EAB を横取りできる —— ちょうど
  [脅威モデル](../threat-model.md) の T15 が GUI について述べる `/ui/config`
  の残存リスクと同じ形である．これを打ち消すには，GUI が表示する `keyId`
  を，`acme-runner provisioning-keygen` が生成時に出力した `keyId` と，
  Conductor を経由しない経路（運用者の手元の記録，別の端末での実行結果）で
  比較することを運用手順として要求する．一致しなければ投入を止める．
  これはコードでは強制できない，運用上の統制である．
- **Go の文字列はその場でゼロ化できない．** `ProvisioningEAB.Open` が返す
  `KID`／`HMAC` は Go の文字列であり，Go の文字列は不変でヒープ上のどこに
  何個コピーが残るかを保証できないため，確実な意味でのゼロ化はできない．
  Runner はこれを軽減として，復号した値を `lego.Build` に渡した直後に
  ローカル変数をゼロ値の構造体で上書きし（`eab = v1alpha1.ProvisioningEAB{}`），
  `ProvisioningEAB` に `String`／`GoString`／`LogValue` を実装して，誤って
  `%v`／`%+v`／構造化ログに渡っても値そのものは決して現れないようにする．
  これは **最善努力** であり，ガベージコレクタや OS のページングによる
  コピー全部の破棄を保証するものではない．同じ限界はすでに証明書の秘密鍵
  （`[]byte`，`zero()` で上書き可能）よりも弱いことを明記しておく．

## 検討した代替案

- **EAB を Key Vault や環境変数に恒久的に置く（現状のまま）．** 却下．
  EAB は 1 回の `newAccount` にしか使わない起動用の資格情報であり，それを
  継続的な資格情報と同じ運用コスト（シークレットストアへの投入，ローテー
  ション手順，アクセス監査）で扱うのは不釣り合いである．
- **Conductor 側で暗号化する（Conductor がいったん平文を受け取り，Runner の
  公開鍵で包んでから送る）．** 却下．[ADR 0005](0005-conductor-never-touches-secrets.md)
  に反する．Conductor のプロセスメモリやログに，たとえ一瞬でも EAB の平文が
  存在してしまう．封をブラウザの中で終わらせることで，Conductor に届く
  ものは最初から暗号文だけになる．
- **`JobSpec` 全体を暗号化する．** 却下．`JobSpec` の残りのフィールド
  （FQDN，binding 名，ポリシースナップショット）は秘密ではなく，監査や
  デバッグのために平文で読めることに価値がある．暗号化を EAB の 1 フィールド
  に絞ることで，署名検証や監査ログの記録など，文書の残りの部分に対する
  既存の取り扱いを何も変えなくてよい．
- **X25519 の代わりに RSA-OAEP を使う．** 却下．鍵と暗号文が大きく（コントラクトの
  上限が余分に必要），ブラウザの WebCrypto でも X25519 の方が扱いやすい．
  X25519 は鍵が固定 32 バイトで，`crypto/ecdh` と WebCrypto の両方が標準で
  対応する．
- **Go 実装の登録専用 ACME クライアントを別に書く（`lego` を経由しない
  newAccount）．** 却下．「独自の暗号を書かない／実装しない」という既存の
  方針（[`docs/architecture.md`](../architecture.md#非目標)）に反するだけ
  でなく，`lego` が書くアカウント状態の正確な形式（`account.json` の
  レイアウト，鍵の保存形式）を別実装で再現・追従する必要が生じ，`lego` の
  バージョンが上がるたびに食い違いのリスクを負う．登録も通常の発行と
  同じ `lego run` の内側で起こるようにすれば，Runner が知るべき `lego` の
  ふるまいは 1 つのままである．

## 結果

- 操作者は GUI から EAB を投入できるようになり，それを Runner のプロセス
  環境や実行基盤のシークレットストアに恒久的に置く必要がなくなる．
  Conductor のデータベース，API レスポンス，監査ログ，ログ出力のいずれにも
  EAB の平文が現れないことは，専用のテスト（`internal/conductor/api` の
  マーカー文字列アサーション，`provisioning_test.go`）で検査される．
- 1 つの binding について，同時に活性なアカウントは常に高々 1 つであり，
  新しい世代のプロビジョニングが失敗しても発行・更新は旧世代のアカウントで
  引き続き動く．プロビジョニングの失敗は「アカウントを失う」ことには
  ならず，「新しい世代を得られない」ことにしかならない．
- 通常の発行・更新の run は，世代を指定していても EAB を一切運ばない．
  EAB が `lego` に渡るのは，プロビジョニング payload を運ぶその 1 回の
  run だけである．
- 侵害された Conductor は，依然として偽の公開鍵を提示して EAB を横取り
  できる残存リスクを持つ．これはコードでは閉じられておらず，`keyId` を
  帯外で比較する運用手順に依存する．署名がそうであるように（ADR 0015），
  暗号化も生成者・提示者自身の侵害には対処しない．
- Runner の `accountProvisioning.privateKeyFiles` と Conductor の
  `accountProvisioning.publicKey` は，`jobSigning`／`resultSigning` と同じ
  形のローテーション手順（新しい鍵を先に加え，設定を切り替え，古い鍵を
  後で外す）に従う．
