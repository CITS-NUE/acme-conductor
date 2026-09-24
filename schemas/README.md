# ACME Conductor の JSON Schema

このディレクトリには，Go の `pkg/api/v1alpha1` で定義されたワイヤコントラクトを
記述する JSON Schema（draft 2020-12）文書を置く．`JobSpec`
（`jobspec.schema.json`），`Result`（`result.schema.json`），そして Phase 4
以降は署名付きジョブエンベロープ（`signedjob.schema.json`）であり，その
`payload` は base64url エンコードされた `JobSpec` 文書である．

## バージョンポリシー

- `v1alpha1` はプレリリースのコントラクトバージョンである．Phase 1 が出荷され
  コントラクトが `v1` に達するまでは，いつでも **非互換な** 変更（フィールドの
  改名や削除，検証の厳格化や緩和，新しい必須フィールド）が入りうる．
- Phase 1 の出荷後は，バージョン内の変更（たとえば `v1alpha1` のさらなる改訂，
  および `v1` 以降のすべてのバージョン）は **追加のみ** でなければならない．
  新しい任意フィールドと新しい列挙値は問題ない．フィールドの削除や改名，
  既存の制約をそれまで有効だった文書を拒否するように狭めることは，新しい
  バージョンを必要とする．
- 破壊的変更は常に新しい `kind`/`apiVersion` の組と新しいスキーマファイル
  （たとえば `v1alpha2`）を意味し，出荷済みスキーマをその場で編集することは
  決してない．

## Go の検証が正である

これらのスキーマは，`pkg/api/v1alpha1/validate.go` と
`internal/policy/fqdn.go` が強制する規則の **ベストエフォートな，人間とツールが
読める近似** である．Go のコードが正（source of truth）であり，スキーマより
厳密に厳しい．特に，以下は Go だけが検査し，JSON Schema は検査しない:

- FQDN の正規化（値はすでに正準形でなければならない）．
- ラベル境界でのサフィックス照合（`evil-example.ac.jp` は，生の文字列としては
  サフィックスに一致するものの，`example.ac.jp` の配下ではない）．
- すべて数字のトップレベルラベルと `xn--`（IDNA）ラベルの拒否．
- ワイルドカード FQDN には `policy.allowWildcard` が必要であるという
  フィールド横断の規則．
- `policy.allowedDnsSuffixes` における（正規化後の）厳密な重複検出
  （JSON Schema の `uniqueItems` は，すでにバイト単位で同一な文字列の重複しか
  捕捉しない）．
- `Result` における `finishedAt >= startedAt` の順序規則．
- `expiresAt` に対するゼロ値の `time.Time` の拒否．
- `error.summary` などの自由テキストフィールドにおける，印字不能文字
  （制御文字，Unicode の行・段落区切り，双方向・書式文字）と既知のシークレット
  マーカー（PEM ヘッダ，ベアラートークン，`password=`，`sig=` など）の拒否．
  ヘッダ形および key=value 形のマーカー（`bearer `，`basic `，
  `authorization:`，`password=`，`sig=`，および類似のもの）は大文字小文字を
  区別せずに照合し，大文字小文字が書式の一部であるトークン接頭辞マーカー
  （`eyJ`，`AKIA`，`ghp_`，...）は厳密に照合する．
  このマーカー検査はベストエフォートの多層防御ヒューリスティックであり，
  シークレット検出器ではない．任意のシークレットや未知の書式を認識することは
  できず，それだけで自由テキストフィールドに生の外部出力を入れても安全に
  なるわけではない．本当の統制は，Runner が生の外部出力を Result に決して
  コピーしないことである．`error.summary` は Runner が所有するテンプレート
  から生成しなければならない．
- 署名付きエンベロープの `protected` ヘッダ内のすべて（固定の `alg`，`kid` の
  書式，有効期間，ノンス），署名そのもの，および `payload` の `JobSpec` としての
  デコード．スキーマは `protected`，`payload`，`signature` を不透明な
  base64url 文字列として見る（`TestSignedJobFixtures`，独自の
  `schema-accepts.txt` を持つ）．
- 厳密なデコード: 未知のフィールド，重複する JSON オブジェクトキー，文書の後ろに
  続く末尾データは，特定の JSON Schema バリデータ実装が
  `additionalProperties` や不正な JSON に対して何を強制するかにかかわらず，
  `pkg/api/v1alpha1/decode.go` により常に拒否される．

JSON Schema に失敗する文書が Go に受理されることは決して期待されない．逆は
保証されない．上記の規則は JSON Schema では表現できないため，Go は拒否するが
スキーマは受理する無効な文書が存在する．「スキーマを通った」をそれだけで
「有効」と決して扱ってはならない．

## 同期テスト

`pkg/api/v1alpha1/schema_test.go` は，スキーマと Go のコードが乖離しないように
保つ:

- `pkg/api/v1alpha1/testdata/jobspec/valid/` と `testdata/result/valid/` 配下の
  すべてのフィクスチャは，JSON Schema と
  `v1alpha1.DecodeJobSpec` / `v1alpha1.DecodeResult` の両方を通らなければならない．
- `.../invalid/` 配下のすべてのフィクスチャは Go のデコードに拒否されなければ
  ならず，隣にある対応する `schema-accepts.txt` 許可リストに載っている
  **場合を除き**，JSON Schema にも拒否されなければならない．この許可リストは，
  スキーマ単体なら受理するにもかかわらず（上記の一覧の）どの Go 固有の意味規則が
  そのフィクスチャを無効にしているかを，ファイルごとに正確に記録する．
  許可リストに載ったフィクスチャが実際にはスキーマに受理され *ない* 場合
  （古くなった許可リスト項目），テストは失敗する．
- `TestSchemaInvariants` は 3 つのスキーマ文書すべてを走査し，すべての `object`
  ノードが `additionalProperties: false` を設定していること，シークレット・
  コマンド・イメージ参照・クラウドリソース識別子を運びうるように見える
  プロパティ名がないこと，`apiVersion`/`kind` が `const` で固定されていることを
  表明する．
- さらに別のテストが，スキーマの `keyType` と `error.code` の列挙が
  `v1alpha1.KeyTypes` と `v1alpha1.ErrorCodes` の集合と正確に一致することを
  表明する．

実行方法:

```sh
go test ./pkg/api/v1alpha1/...
```
