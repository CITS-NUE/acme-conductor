# 0027: Conductor が公開 DNS で _acme-challenge の委任を確かめる

- ステータス: 採択
- 日付: 2026-09-30

## 背景

DNS-01 のチャレンジ用レコードは，各名前の `_acme-challenge.<名前>` を CNAME で
チャレンジ用ゾーンに委任して置く（[`deploy/azure/README.md`](../../deploy/azure/README.md#複数の-dns-ゾーン)）．
Runner が書き込めるのはチャレンジ用ゾーンだけなので，委任が 1 つでも欠けていれば
その run は失敗する（[#75](https://github.com/CITS-NUE/acme-conductor/pull/75) 以降は
`DnsFailure`）．CNAME は target を登録する人とは別の人（学内 DNS の担当者）が
置くことが多く，これまでは run を起こすまで漏れに気づけなかった
（[#66](https://github.com/CITS-NUE/acme-conductor/issues/66)）．

確かめること自体は，運用者が手で打っている `dig +short CNAME _acme-challenge.<名前>`
と同じである．ただし，CNAME の行き先が正しいかを判断するには委任先のゾーン名が
要る．これまで Conductor は DNS バインディングを名前でしか知らず，ゾーン名は
Runner の設定（`AZURE_ZONE_NAME`）にしかなかった．

## 決定

- **Conductor が公開 DNS を引いて確かめる．** target の各名前（`fqdn` と
  `additionalNames`．ワイルドカードは基底名）について `_acme-challenge.<名前>` の
  CNAME をたどり（最大 8 段），結果を `ok`（チャレンジ用ゾーンの中．名前自体が
  ゾーンの中にある場合も含む），`present`（CNAME はあるが，ゾーンが未設定で行き先を
  確かめていない），`missing`，`mismatch`，`error` のいずれかにする．リゾルバは
  システムのもの（`net.DefaultResolver`）を使い，結果は 5 分だけメモリに持つ．
  資格情報は使わず，何も書き込まない．
- **委任先のゾーン名を Conductor の設定にも持たせる．** `dnsChallengeZones` は
  DNS バインディング名からチャレンジ用ゾーンへの対応である．エントリのない
  バインディングは CNAME の有無だけを確かめる．Azure のテンプレートは，
  Runner に書き込みを許すゾーン（`dnsZoneName`）をすべてのバインディングに入れる．
- **このゾーン名は Runner に渡さない．** `dnsChallengeZones` は `JobSpec` に載らず，
  Conductor の中だけで使う．Runner はこれまでどおり，自身の設定と ID の権限だけで
  書き込み先を決める．
- **確認の結果で run を止めない．** API（`GET /targets/{id}/dns-delegation`），
  GUI の target の詳細ページ，run を起こす際のスケジューラのログ（warn）に
  出すだけである．

## 結果

- 同じゾーン名を Conductor と Runner がそれぞれ持つ．これは許可する DNS
  サフィックス（Conductor の発行ポリシーと Runner の `allowedDnsSuffixes`）と
  同じ形で，セキュリティ原則 7 のとおり，Runner は Conductor の見立てを信用しない．
  両者がずれて起きうる最悪のことは，確認の表示が誤ることだけで，Runner の
  書き込み先は変わらない．Conductor が侵害されても得られるのは，公開 DNS から
  誰でも引けるゾーン名だけである．
- 確認の誤り（リゾルバの障害，スプリット DNS で Conductor と CA の見え方が違う
  場合）で更新が止まることはない．run を止めないことの代償は，委任の漏れた
  run が起きてしまうことだが，その run は数秒で `DnsFailure` になり，要約が理由を
  示す．
- Conductor から公開 DNS への問い合わせ（外向きの UDP/TCP 53）が新たに生じる．
  問い合わせる名前は登録済みの target から決まる `_acme-challenge.<名前>` だけで
  ある．
- システムのリゾルバはネガティブキャッシュを持つので，CNAME を追加した直後は
  しばらく `missing` と見えることがある．GUI はその旨を表示する．権威サーバーへ
  直接問い合わせる形は，必要になったときに検討する．
