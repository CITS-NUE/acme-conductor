# 0029: 退役の前に証明書を ACME で失効させる

- ステータス: 採択
- 日付: 2026-11-27

## 背景

[ADR 0026](0026-retire-targets.md) の退役は Conductor のレジストリだけを変え，
CA 側には何もしない．保存済みの証明書は期限まで有効なまま残る．ところが UPKI
（[`docs/upki-guide.md`](../upki-guide.md)）は，使わなくなったサーバ証明書の失効を
求めており，期限が近づくと「更新するか，失効させるか」の通知を利用管理者に送る．
運用を止めたホストの証明書が有効なまま残ることは，鍵が漏れたときの影響範囲を
期限まで広げておくことでもある．

UPKI のマニュアルでは，ACME で発行した証明書は ACME クライアントから失効させる
（`certbot revoke` に当たる revokeCert）のが本来の手順で，登録担当者を通す
TSV による失効申請は，クライアントから失効できないとき（サーバの廃止，
アカウント情報の喪失，アカウントの停止後）の代わりの手段である．また，ACME
アカウントの停止申請をした後はクライアントから失効できないので，順序は
「失効 → アカウントの停止」でなければならない．

この ACME クライアントは Runner（lego）であり，ACME アカウントの鍵は Runner の
状態にしかない（[ADR 0005](0005-conductor-never-touches-secrets.md)，
[ADR 0022](0022-encrypted-eab-provisioning-and-account-generations.md)）．
したがって失効も Runner が行うしかない．

## 決定

**失効 run** を加える．Conductor が依頼し，Runner が自分の ACME アカウントで
revokeCert を送る．

- **JobSpec**: `operation: "revoke"` と `revocation: {reason, fingerprintSha256}`
  を加える．`operation` がなければこれまでどおりの reconcile である．
  `revocation` は `operation: "revoke"` のときだけ，かつ必ず持つ．
  `reason` は RFC 5280 の CRLReason のうち UPKI の失効理由と対応する
  0（unspecified），1（keyCompromise），3（affiliationChanged），
  4（superseded），5（cessationOfOperation）に限る．`fingerprintSha256` は
  失効させる証明書の SHA-256 指紋である．失効 run はアカウントの
  プロビジョニングを伴わない（`acme.account.provisioning` があれば不正）．
  これらのフィールドを知らない Runner は厳格なデコードで JobSpec ごと拒むので，
  古い Runner が失効 run を発行 run と取り違えることはない．
- **Runner**:
  - ACME バインディングが `allowRevocation: true` のときだけ失効 run を受け付ける
    （既定は false．`PolicyViolation`）．Conductor が侵害されても，運用者が
    Runner の設定で許していないかぎり失効は起きない（セキュリティ原則 7）．
  - 認可（Runner の認可ポリシー）は reconcile と同じである．
  - Store から今の証明書を読み，その指紋が `revocation.fingerprintSha256` と
    一致するときだけ失効させる．一致しなければ失効させずに `InvalidJobSpec` で
    失敗する．Conductor が知らない新しい証明書を巻き添えにしないためである．
  - 証明書の公開部分を作業ディレクトリに置き，reconcile と同じアカウント
    （同じ世代，EAB なし）で `lego … revoke --reason N --keep` を実行する．
    DNS の設定と資格情報は lego に渡さない．Store は変えない（失効した証明書は
    Store に残る）．
  - CA が `alreadyRevoked` を返したときは失効済みとして成功にする．
  - 成功した Result は `action: "revoked"` と，失効させた証明書の指紋・期限・
    Store のオブジェクト名を持つ．
- **Conductor**:
  - `POST /api/v1alpha1/targets/{id}/revoke-certificate`（admin のみ．本文
    `{"revision": N, "reason": 5}`．`reason` の既定は 5）で失効 run を作る．
    前提は，退役していない（`target_retired`），無効である（`target_enabled`），
    実行中の run がない（`run_active`），最後に成功した run の証明書があり
    （`no_certificate`），それが失効済みでなく（`certificate_revoked`），
    期限が切れていない（`certificate_expired`）こと．指紋はその証明書のものを
    Conductor が入れる．
  - スケジューラは失効 run に限り，無効な target でも実行する．プロビジョニングの
    要求は取らず，target のアクティブな世代を使う（なければ `AcmeFailure` で
    失敗し，GUI は TSV による失効申請を案内する）．DNS 委任の確認はしない．
    失効 run は計画（自動の run）では作らず，失敗しても再試行しない．
  - 最後に成功した run が失効 run なら，その target の証明書は「失効済み」と
    表示する．失効済みの target は有効にできない（`409 certificate_revoked`）．
    Store に残る失効済みの証明書を Runner は「まだ有効」と判断してしまうので，
    有効に戻すと失効した証明書を使い続けることになるからである．同じ名前を
    もう一度管理するときは，退役させて新しい target を作る．
  - 失効は退役の前提にはしない（ACME 以外の CA，期限切れの証明書，Runner が
    失効を許していない場合がある）．GUI が「無効化 → 失効 → 退役」の順を案内する．
- **ACME アカウントの停止は扱わない．** UPKI では登録担当者が停止申請（TSV）を
  出す．Conductor には EAB の kid がない（暗号文しか見ない）ので，GUI は手順と
  TSV ツールへの案内だけを出す．

## 結果

- ACME で発行した証明書を，UPKI が想定する手順（クライアントからの失効）で
  運用から外せる．TSV による失効申請が要るのは，Runner から失効できない場合
  だけになる．
- 新たに，CA 側で取り消しのきかない操作を Conductor の署名付きジョブで起こせる
  ようになる．侵害された Conductor が起こせることは，`allowRevocation` を許した
  バインディングで，Runner の認可ポリシーの範囲の名前の，今 Store にある証明書を
  失効させることである．これは可用性への攻撃（その名前のサービスの TLS が
  使えなくなる）で，鍵や証明書が漏れることはない．Conductor の侵害は
  reconcile の範囲でも同じ名前の証明書を再発行させられるので，影響の種類は
  変わらないが，失効は元に戻せない．そのため Runner 側の明示的な許可を要する．
- 失効には発行したアカウントを使う．target のアカウントの世代が発行後に
  入れ替わっていると（古い世代は Runner の状態に残るが，Conductor は
  アクティブな世代しか指定しない），CA が失効を拒むことがある．その場合は
  TSV による失効申請で対応する．
- CA によっては一部の失効理由を受け付けない．その場合 run は CA の
  エラーのまま `AcmeFailure` で失敗し，自動で別の理由を試すことはしない．
- スキーマ（バージョン 10）: `runs` に `operation`，`revocation_reason`，
  `revocation_fingerprint_sha256` を加える．既存の行は `reconcile` である．
