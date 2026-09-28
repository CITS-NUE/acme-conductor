# 0024: 名前集合に縛られた ACME アカウント（UPKI）と SAN 証明書

- ステータス: 提案（issue #53 の方針案．未採択）
- 日付: 2026-09-28

## 背景

issue #53 の通り，UPKI ACME では 1 つの ACME アカウント（EAB）が「利用管理者
FQDN（CN）1 つ + dNSName 最大 8 個（CN を含む）」という **名前集合に縛られる**．
オーダーに書けるのはその集合の名前だけで，集合を変えるには再申請 → 新 EAB →
新アカウント登録が要り，旧アカウントは CA 側で停止される．

現行実装は Let's Encrypt 型で，次を前提にしている．

- ACME binding はポリシー単位で共有され（`policies.acme_binding`），1 つの
  binding のアカウントで任意の FQDN を発行できる．
- アカウントの世代（[ADR 0022](0022-encrypted-eab-provisioning-and-account-generations.md)）
  は binding 単位で，世代は「どの名前のために登録されたか」を持たない．
- target = 1 FQDN = 単一名の証明書（`MaxSANs` は 1 固定，`lego --domains` は 1 回）．
- プロビジョニング payload は，binding を共有する target のうち最初に期限が
  来たものの run に添付される．

このため UPKI では (1) 登録外の名前の target を事前に弾けない，(2) SAN
証明書を出せない，(3) 名前集合の変更（= アカウントの作り直し）と target の
変更を同期できず，旧アカウント停止後に更新が失敗し続ける，(4) 添付先の
target が登録名に含まれないと世代番号が燃える，という問題がある．

## 決定（案）

### 1. アカウントのスコープを binding ごとに選べるようにし，UPKI は「target スコープ」にする

issue の選択肢のうち **(A) 1 アカウント = 1 target** を採る．

- Conductor の設定で binding ごとに `accountScope: binding | target` を持つ
  （既定 `binding` = 現行の挙動．Let's Encrypt などは何も変わらない）．
  `target` は `accountProvisioning.bindings` に列挙された binding にだけ
  許す（EAB なしで target スコープにする意味はない）．
- `acme_accounts` に `scope`（`binding` スコープでは `''`，`target` スコープでは
  target ID）を加え，主キーを `(binding, scope, generation)`，
  「活性 1 つ」「保留 1 つ」の一意インデックスを `(binding, scope)` 単位にする．
  世代番号は `(binding, scope)` ごとに単調増加し，再利用しない（ADR 0022 の
  規則をそのまま引き継ぐ）．
- **各世代に，登録した名前集合 `names` を持たせる．** EAB 投入時に操作者が
  申請 TSV と同じ内容（CN を先頭に，正規化済み，最大 8 個）を入力する．
  名前は秘密ではないので平文で保存してよい（[ADR 0005](0005-conductor-never-touches-secrets.md)
  に反しない）．
- Conductor は **target の名前集合 ⊆ 活性世代の `names`**，かつ
  **target の主名（CN）= `names` の先頭** を，target の登録・変更時と
  run 生成時の両方で検査し，満たさなければ run を作らない
  （`PolicyViolation`）．これで問題 (1) を CA に投げる前に弾ける．
- target スコープではプロビジョニング payload はその target の run にしか
  添付されないので，問題 (4)（添付先の取り違えによる世代番号の焼失）は
  構造的に起きなくなる．
- コントラクト（v1alpha1 への追加のみ．[ADR 0004](0004-versioned-jobspec-result-contract.md)）:
  `ACMEAccountRef.scope`（省略可．target スコープでは `target.id` と一致しなければ
  `Validate` で拒否）．Runner の状態ディレクトリは
  `stateDir/acme-accounts/<binding>/<scope>/<generation>`（scope なしは現行の
  パスのまま）．
- 暗号化 payload の AAD に scope を含めるため，
  `ProvisioningVersion` に `x25519-hkdf-sha256-a256gcm/v2`（AAD に
  `scope=<scope>` 行を加えるだけ．鍵導出・暗号は v1 と同じ）を追加する．
  v1 は binding スコープ専用として残し，target スコープで v1 の payload を
  受け取ったら拒否する．これで，ある target 向けに封じた EAB を別 target の
  アカウント登録に転用できない．

**(B) を採らない理由．** UPKI の申請単位（CN + dNSName）は実質「証明書 1 枚」
であり，account を独立したエンティティにしても target と 1:1 になるだけで，
API・GUI・認可の面が増える．ただし「1 アカウントで登録名の部分集合ごとに別の
証明書を出してよい」ことが原典で確認でき，実需があれば，scope を target ID から
account ID に一般化する（`scope` は文字列の列なので，スキーマは変えずに意味を
広げられる）．

**(C) を採らない理由．** binding は Runner / Conductor の設定と Bicep パラメータに
静的に並ぶので，ホストを増やすたびに設定変更と再デプロイが要る（#52，
[ADR 0023](0023-separate-role-definitions-from-the-deployment.md)）．台数の
多い機関ではスケールしない．ただし (A) の実装までの **暫定運用** としては
使える（後述）．

### 2. SAN 証明書に対応する（v1alpha1 への追加のみ）

- `TargetRef.additionalNames`（`[]string`，省略可，最大 7 個 → 主名と合わせて
  最大 8 個）を追加する．主名 `fqdn` が CN になる．上限は UPKI に合わせて
  8 とし，必要になれば上げる（上限を上げるのは以前の有効な文書を拒否しない
  ので追加のみの変更である）．旧 Runner は厳密デコードで未知フィールドを
  拒否するので，SAN 付きジョブを単一名で黙って発行することはない（fail closed）．
- 全名前に，正規化・サフィックス照合・ワイルドカード判定
  （[ADR 0006](0006-ascii-only-fqdn-in-v1alpha1.md)）と正規化後の重複禁止を
  `Validate` と Runner の `RunnerAuthorizationPolicy.Authorize` の両方で適用する．
  Runner の認可に `maxNames`（既定 1）を加え，Runner 側で明示的に許さない限り
  SAN を受け付けない．
- ポリシーの `maxSANs` を 1..8 に開放し，`PolicySpec` のスナップショットにも
  載せる．
- レジストリ: 名前の一意性を target をまたいで保証するため
  `target_names(name PRIMARY KEY, target_id)` を設ける（`targets.fqdn UNIQUE`
  だけでは，ある名前が別 target の SAN に入る重複を防げない）．名前集合の
  変更は target の `revision` を上げる．
- Runner: `lego --domains` を主名 → 追加名の順に渡す．noop 判定は既存証明書の
  SAN 集合が要求と一致するときだけ noop とし，不一致なら再発行する．
- Store のオブジェクト名は主名由来のまま（`store.ObjectName`）．
- DNS-01: 各名前にチャレンジが要る．当面は「全名前が DNS binding の扱える
  ゾーンに入ること」を target 登録時に検査し，Azure は `dnsZoneName` を
  配列 `dnsZoneNames` に広げてロール割り当てを各ゾーンに付ける．
- 移行（[ADR 0020](0020-migration-from-cert-infra.md)）: cert-infra の定義に
  SAN があれば `additionalNames` として取り込む．

### 3. 名前集合の変更（再申請）ワークフロー

UPKI では「名前集合の変更」と「アカウントの作り直し」が常に同時に起きるので，
Conductor でも 1 つの操作として扱う．

1. 操作者は再申請で得た新 EAB を投入するとき，同じ要求に **新しい登録名
   `names`** と **target の新しい名前集合**（`names` の部分集合，先頭が CN）を
   入れる．両方とも新世代の保留行に保存し，target 本体はまだ変えない．
2. 投入と同時に，その target の run を期限と無関係に 1 つ enqueue する
   （プロビジョニング run は ADR 0022 の通り noop を飛ばして必ず `lego run`
   する）．EAB に有効期限があっても，次の更新期限まで待たずに済む．
3. その run の `JobSpec` は保留中の新しい名前集合で作る．Result が
   `registered` かつ発行成功なら，**新世代の活性化・旧世代の `retired` 化・
   target の名前集合と `revision` の更新を 1 トランザクションで** 行う．
4. 失敗なら ADR 0022 の通り世代番号を燃やし，target は旧名前集合・旧世代の
   まま残す．ただし UPKI では旧アカウントがすでに停止されている可能性が
   あるので，下記 4 の検知で操作者に再投入を促す．

これにより ADR 0022 の「新世代の登録に失敗しても旧世代で更新は続く」は
**binding スコープでだけ成り立つ保証** と位置付け直し，target スコープでは
「失敗は明示的な要対応状態として見える」ことを保証とする．

### 4. 停止されたアカウントを検知して，更新の空回りを止める

- Runner は `lego` の出力から ACME の `unauthorized` / `accountDoesNotExist`
  系のエラーを識別し，新しい `ErrorCode` `AcmeAccountUnusable`（列挙への追加）
  で報告する（`lego` の失敗理由を残す #38 と同じ仕組みに乗せる）．
- Conductor はこれを受けたら，その世代を `suspended`（新しい状態）にし，
  target を「アカウント要再登録」として GUI に出し，通常のバックオフによる
  再試行を止める（CA を叩き続けない）．新世代の投入で解除される．

### 5. UPKI 用ポリシーの推奨値（原典確認後に確定）

- `keyType`: ECDSA の可否が確認できるまでは `rsa2048`．
- `allowWildcard`: `false`（可否未確認）．
- `renewBeforeDays`: 30（有効期間 89 日の約 1/3）．
- `maxSANs`: 8．

## 暫定運用（実装が揃うまで）

(C) で運用する: UPKI のアカウント 1 つにつき binding 1 つ・ポリシー 1 つ・
target 1 つを静的に並べ，**申請する名前は利用管理者 FQDN 1 つだけ**（SAN なし）
にする．SAN が必要な証明書と台数の多い機関は，実装が揃うまで対象外とする．
名前を変えるときは，新 EAB を投入してから旧アカウントの停止を依頼する順序を
守り，投入後に手動で run を起こす．

## 実装の分割（別 issue 案）

依存順に並べる．0 は他のすべての前提．

0. UPKI 原典での仕様確認（ワイルドカード，鍵種別，EAB の有効期限と再利用，
   CN を先頭に置く必要，部分集合ごとの発行可否，email の扱い，レート制限）．
1. SAN 対応（コントラクト `additionalNames`，JSON Schema，`target_names`，
   ポリシー `maxSANs`，Runner の認可・`lego` 引数・noop 判定，GUI，移行）．
2. target スコープのアカウント（`accountScope`，`acme_accounts.scope` と
   `names`，`ACMEAccountRef.scope`，provisioning v2 AAD，Runner の状態パス，
   名前集合の検査）．
3. 名前集合変更ワークフロー（保留中の名前集合，投入時の即時 run，
   原子的な切り替え）．
4. 停止アカウントの検知（`AcmeAccountUnusable`，`suspended`，再試行停止．#38 と合わせる）．
5. Azure の複数 DNS ゾーン（`dnsZoneNames`）．1 と並行可．
6. UPKI 向けの運用ドキュメントと推奨ポリシー．

## 検討した代替案

- **(B) binding と account を分離し，account が名前集合を持って複数 target を
  束ねる．** 上記の通り，現時点では (A) と実質同じで面だけが増える．
  `scope` の一般化で後から移れる．
- **(C) 1 binding = 1 アカウントを静的に並べる．** 暫定運用としてのみ使う．
- **SAN のために `v1alpha2` を切る．** 不要．追加は省略可能フィールドで済み，
  旧 Runner は厳密デコードで安全側に倒れる．
- **Conductor が CA に問い合わせて登録名を知る．** ACME にアカウントの
  許可名を返す仕組みはなく，Conductor は CA と直接話さない（ADR 0005）．
  操作者の入力を正とし，食い違いは CA の拒否（`AcmeFailure`）で検出される．

## 結果

- Let's Encrypt などの binding スコープの挙動と既存データは変わらない．
- UPKI では，登録外の名前・9 個目以降の名前・CN の取り違えを Conductor が
  CA に投げる前に拒否できる．
- 名前集合の変更が 1 つの操作になり，即時 run で EAB 投入から登録までの
  待ちがなくなる．失敗時は旧状態に戻り，停止されたアカウントは空回りせず
  要対応として見える．
- コントラクトは追加のみで済むが，`ProvisioningVersion` v2 と
  `target_names` テーブル・`acme_accounts` の主キー変更というスキーマ
  マイグレーションが要る．
