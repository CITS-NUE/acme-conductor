# 0024: target 単位の ACME アカウントと SAN 証明書

- ステータス: 提案（issue #53 の方針案．未採択）
- 日付: 2026-09-28

## 背景

issue #53 は，UPKI ACME の次の仕様が現行モデルと噛み合わないことを
洗い出した．1 つの ACME アカウント（EAB）で発行できるのは，申請時に登録した
FQDN の集合（CN を含めて最大 8 個）だけである．集合を変えるには再申請して
新しい EAB でアカウントを登録し直す必要がある．

EAB を要求する CA では，アカウントごとに発行できる名前の範囲が決まっている
のが一般的である（Sectigo，DigiCert，HARICA などは組織単位で事前検証した
ドメインの範囲）．範囲外の名前は CA がオーダーを拒否する．UPKI はこの範囲を
FQDN の固定集合で持つ，最も粒度の細かい例である．

現行実装は Let's Encrypt 型で，次を前提にしている．

- ACME binding はポリシー単位で共有され（`policies.acme_binding`），
  アカウントの世代（[ADR 0022](0022-encrypted-eab-provisioning-and-account-generations.md)）
  も binding 単位である．binding ごとに活性なアカウントは高々 1 つ．
- binding は Runner / Conductor の設定と Bicep パラメータに静的に並ぶ．
- target = 1 FQDN = 単一名の証明書（`MaxSANs` は 1 固定，`lego --domains` は 1 回）．
- プロビジョニング payload は，binding を共有する target のうち最初に期限が
  来たものの run に添付される．

このため，アカウントごとに発行範囲が狭い CA では次の問題が起きる．

1. アカウントを分けるには binding を分けるしかなく，アカウントを増やすたびに
   設定変更と再デプロイが要る（#52，[ADR 0023](0023-separate-role-definitions-from-the-deployment.md)）．
2. SAN（複数名）証明書を出せない．
3. プロビジョニング payload がどの target の run に添付されるか決まらない．
   その target の名前がアカウントの範囲外なら，登録と同時の発行が失敗して
   世代番号が燃える．
4. payload は期限が来た target の run にしか添付されないので，EAB の投入から
   登録まで次の更新期限まで待たされる．EAB に有効期限がある CA では失効しうる．

## 方針

**UPKI に対応するが，UPKI 専用の仕組みは作らない．** CA ごとの発行範囲
（登録名の集合，CN の位置，名前の数の上限）を Conductor が写し持って事前検査
することはしない．範囲外の名前は CA がオーダーを拒否し，既存の `AcmeFailure`
として run に残る．Conductor が持つのは，どの CA にも意味のある汎用の仕組み
だけである．

## 決定（案）

### 1. アカウントのスコープを binding ごとに選べるようにする

- Conductor の設定 `accountProvisioning.targetScopedBindings` に，アカウントを
  target ごとに持つ binding を列挙する（#57 の実装で，binding ごとの
  `accountScope: binding | target` をこのリストの形にした）．挙げなかった
  binding は従来どおり binding 全体で 1 つのアカウントを持ち，挙動も既存
  データも変わらない．挙げられるのは `accountProvisioning.bindings`（EAB を
  投入できる binding）に列挙された binding だけである．
- `target` スコープでは，アカウントの世代を target ごとに持つ．
  `acme_accounts` に `scope`（`binding` スコープでは `''`，`target` スコープでは
  target ID）を加え，主キーを `(binding, scope, generation)`，「活性 1 つ」
  「保留 1 つ」の一意インデックスを `(binding, scope)` 単位にする．世代番号の
  扱い（単調増加，失敗した番号は再利用しない，新世代の失敗中も旧世代は活性の
  まま）は ADR 0022 をそのまま引き継ぐ．
- これにより，アカウントを増やすのは GUI / API から EAB を投入するだけになり，
  設定変更と再デプロイは要らない（問題 1）．binding は CA の接続情報
  （directory URL，email）だけを表す静的な設定のまま残る．
- プロビジョニング payload はその target の run にしか添付されないので，
  問題 3 は構造的に起きない．
- target ごとのアカウントを持つ binding の target は，自分のアカウントしか
  使わない．活性なアカウントも未着手の要求もなければ，run は Runner を起動
  せずに `AcmeFailure` で失敗する．binding 全体のアカウントを代わりに使うと，
  CA がその target の名前を発行させないアカウントで発行を試みることになる
  からである．
- コントラクト（v1alpha1 への追加のみ．[ADR 0004](0004-versioned-jobspec-result-contract.md)）:
  `ACMEAccountRef.scope`（省略可．指定されたら `target.id` と一致しなければ
  `Validate` で拒否）．Runner の状態ディレクトリは
  `stateDir/acme-accounts/<binding>/targets/<scope>/<generation>`（scope なしは
  現行のパスのまま．`targets` は数字でないので，target の id がどんな形でも
  binding 全体の世代のディレクトリと衝突しない）．
- 暗号化 payload の AAD に scope を含める．`ProvisioningVersion` に
  `x25519-hkdf-sha256-a256gcm/v2` を追加し，AAD に `scope=<scope>` 行を加える
  （鍵導出と暗号方式は v1 と同じ）．v1 は binding スコープ専用として残し，
  scope 付きの run で v1 の payload を受け取ったら拒否する．ある target 向けに
  封じた EAB を別の target のアカウント登録に転用できないようにするためで
  ある．

UPKI では「UPKI の申請 1 つ = アカウント 1 つ = target 1 つ（CN を主名，
残りを SAN とする証明書 1 枚）」として運用する．部署ごとにアカウントを
分ける Sectigo 型の運用にも同じ仕組みが使える．

### 2. SAN 証明書に対応する（v1alpha1 への追加のみ）

- `TargetRef.additionalNames`（`[]string`，省略可）を追加する．主名 `fqdn` が
  CN になり，`lego --domains` には主名 → 追加名の順に渡す．旧 Runner は厳密
  デコードで未知フィールドを拒否するので，SAN 付きジョブを単一名で黙って
  発行することはない（fail closed）．
- 名前の数の上限は CA に合わせず，ポリシーの `maxSANs`（主名を含む）で
  操作者が決める．コントラクトの上限は 100（Let's Encrypt の上限）とする．
  `maxSANs` は `PolicySpec` のスナップショットにも載せる．
- 全名前に，正規化・サフィックス照合・ワイルドカード判定
  （[ADR 0006](0006-ascii-only-fqdn-in-v1alpha1.md)）と正規化後の重複禁止を
  `Validate` と Runner の `RunnerAuthorizationPolicy.Authorize` の両方で適用する．
  Runner の認可に `maxNames`（既定 1）を加え，Runner 側で明示的に許さない限り
  SAN を受け付けない．これは CA の制約の写しではなく，Runner 自身の信頼境界
  である．
- レジストリ: 名前の一意性を target をまたいで保証するため
  `target_names(name PRIMARY KEY, target_id)` を設ける（`targets.fqdn UNIQUE`
  だけでは，ある名前が別 target の SAN に入る重複を防げない）．名前集合の
  変更は target の `revision` を上げる．
- Runner: 既存証明書の SAN 集合が要求と一致するときだけ noop とし，不一致なら
  再発行する．
- Store のオブジェクト名は主名由来のまま（`store.ObjectName`）．
- DNS-01: 各名前にチャレンジが要る．Azure では `dnsZoneName` を配列
  `dnsZoneNames` に広げ，ロール割り当てを各ゾーンに付ける．
- 移行（[ADR 0020](0020-migration-from-cert-infra.md)）: cert-infra の定義に
  SAN があれば `additionalNames` として取り込む．

### 3. EAB を投入したらすぐ run を起こす

- EAB を投入（新しい世代を保留）したら，その世代を使う run を期限と無関係に
  1 つ enqueue する．`target` スコープではその target の run，`binding`
  スコープではその binding を使う target のうち 1 つの run である．
  プロビジョニング run は ADR 0022 の通り noop を飛ばして必ず `lego run` する．
- これで EAB の投入から登録までの待ちがなくなり（問題 4），EAB が短期間で
  失効する CA（Google Trust Services など）でも使える．
- 名前集合を変えるとき（UPKI の再申請など）は，target の編集と新 EAB の投入を
  別々の操作として行えばよい．両者を 1 トランザクションで結び付ける仕組みは
  作らない．順序を誤れば CA がオーダーを拒否し，run に残る．

### 4. やらないこと

- **アカウントごとの発行範囲を Conductor に登録して事前検査すること．**
  CA ごとに範囲の表し方（FQDN の固定集合，ドメイン単位，組織単位）が違い，
  CA が確実に拒否してくれるものを写し持っても，食い違いの元が増えるだけで
  ある．
- **CA 側で停止されたアカウントを専用の状態で扱うこと．** 停止されたアカウント
  での失敗は，他の ACME の失敗と同じく `AcmeFailure` として run に残り，既存の
  バックオフで再試行間隔が伸びる．失敗理由を run から読めるようにするのは
  #38 で扱う．
- **CA 専用の推奨ポリシーをコードに持つこと．** UPKI 向けの設定例（鍵種別，
  `renewBeforeDays`，`maxSANs` など）は運用ドキュメントに書く．

## 暫定運用（実装が揃うまで）

UPKI のアカウント 1 つにつき binding 1 つ・ポリシー 1 つ・target 1 つを
静的に並べ，申請する名前は利用管理者 FQDN 1 つだけ（SAN なし）にする．
EAB を投入したら手動で run を起こす．

## 実装の分割

1. #56 SAN 対応（コントラクト `additionalNames`，JSON Schema，`target_names`，
   ポリシー `maxSANs`，Runner の認可・`lego` 引数・noop 判定，GUI，移行）．
2. #57 target スコープのアカウント（`targetScopedBindings`，`acme_accounts.scope`，
   `ACMEAccountRef.scope`，provisioning v2 AAD，Runner の状態パス，GUI）．
3. #59 EAB 投入時の即時 run．
4. #58 Azure の複数 DNS ゾーン（`dnsZoneNames`）．1 と並行可．
5. #60 UPKI を例にした運用ドキュメント（申請内容と target の対応，設定例）．

1 と 2 は独立しており，どちらからでも着手できる．

## 検討した代替案

- **binding と account を分離し，account を独立したエンティティにして複数の
  target を束ねる．** 現時点では `target` スコープと実質同じで，API・GUI・
  認可の面が増えるだけである．1 つのアカウントを複数の target で共有したい
  需要が出れば，`scope` を target ID から account ID に一般化して移れる
  （`scope` は文字列の列なので，スキーマは変えずに意味を広げられる）．
- **アカウントごとに binding を静的に並べ続ける．** アカウントを増やすたびに
  再デプロイが要り，台数の多い機関ではスケールしない．暫定運用としてのみ使う．
- **アカウントの世代に登録名の集合を持たせ，Conductor が事前検査する．**
  上記「やらないこと」の通り，UPKI 特化であり採らない．
- **SAN のために `v1alpha2` を切る．** 不要．追加は省略可能フィールドで済み，
  旧 Runner は厳密デコードで安全側に倒れる．

## 結果

- Let's Encrypt など `binding` スコープの挙動と既存データは変わらない．
- アカウントごとに発行範囲が決まる CA（UPKI を含む）で，アカウントを
  再デプロイなしで増やせるようになる．
- SAN 証明書をどの CA でも発行できるようになる．
- 範囲外の名前は CA の拒否で検出されるので，誤りに気付くのは run の失敗
  （`AcmeFailure`）の時点になる．事前検査はしない．
- コントラクトは追加のみで済むが，`ProvisioningVersion` v2 と，
  `target_names` テーブルの追加・`acme_accounts` の主キー変更というスキーマ
  マイグレーションが要る．
