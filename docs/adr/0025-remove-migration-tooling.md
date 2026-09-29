# 0025: 移行ツールを削除する

- ステータス: 採択（[ADR 0020](0020-migration-from-cert-infra.md) を廃止する）
- 日付: 2026-09-29

## 背景

[ADR 0020](0020-migration-from-cert-infra.md) の移行ツールは，最初のデプロイの
ホスト一覧を，一斉切り替えの日を設けずに Conductor のレジストリへ移すために
作った．インフラ定義（Bicep パラメータファイルなど）からの一覧の読み取り，
レジストリとの差分と shadow 比較，冪等な取り込み，そして発行を止めておく
target-source フラグ（`iac` / `shadow` / `registry`）である．

予定していた移行はすべて完了し，Conductor は以後つねにレジストリから発行する．
一方でこの機能は，使い道がなくなった後も次のコストを払わせている．

- 設定の面: `migration` セクション（`targetSource`，`source`，`profile`，
  `compareIntervalSeconds`）と，それに対応する Bicep パラメータ．
- `.bicepparam` を読むためのファイルリーダ．文字列リテラルだけを受け付ける
  制限付きの構文解析であり，入力チャネルとしての攻撃面
  （[脅威モデル](../threat-model.md) T16）でもあった．
- スケジューラと API の発行ゲート（発行が止まっているときに計画・開始・
  run の要求を拒否する分岐）．
- GUI の移行ページとその表示文字列，CLI の `migrate` サブコマンド，
  移行 API，およびそれらのテスト．

この機能の利用者は最初のデプロイだけであり，ほかにはいない．新しいデプロイは
API または GUI で target を登録する（一覧があるなら，スクリプトから
`POST /targets` を繰り返せばよい）．

## 決定

移行ツールを削除する．

- パッケージ `internal/conductor/migration`，`acme-conductor migrate`，
  移行 API（`/migration`，`/migration/diff`，`/migration/import`），GUI の
  移行ページ，shadow 比較のループ，スケジューラと API の発行ゲートを削除する．
  Conductor は無条件に発行する．
- 設定に `migration` キーが残っている場合は，起動時の読み込みを
  `migration was removed (docs/adr/0025): delete the "migration" section` で
  失敗させる．黙って無視しない: `targetSource` が `iac` のままのデプロイが，
  セクションを無視されたことで突然発行を始めてはならないからである．値が何で
  あっても（`null` を含めて）拒否する．
- Bicep の `migration` パラメータを削除する．
- SQLite のスキーマは変えない（破壊的な変更はしない）．

## 結果

- 運用者は，アップグレードの前に，デプロイのパラメータから `migration`
  セクション（Bicep なら `param migration`）を削除しなければならない．
  削除しないと，Conductor は起動せず，Bicep はコンパイルに失敗する．
  `targetSource` が `registry` だったデプロイは，それ以外に変わることはない．
- 取り込みや shadow 比較が記録した監査イベント（`target.imported`，
  `migration.compared`）はデータベースに残る．監査 API と GUI は action を
  文字列のまま表示するので，読み出しに影響しない．
- 歴史的な記録は [ADR 0020](0020-migration-from-cert-infra.md) に残す．本文は
  変えず，ステータスだけを廃止にした．
- 設定の面，リーダ，ゲート，GUI ページ，テストがなくなり，保守と攻撃面が減る．
  脅威モデルの T16（入力チャネルとしての移行一覧）は対象がなくなった．
- 別の既存環境から移す必要が将来生じたら，そのときの要件に合わせて，
  この規模のツールではなく API を使うスクリプトから始める．
