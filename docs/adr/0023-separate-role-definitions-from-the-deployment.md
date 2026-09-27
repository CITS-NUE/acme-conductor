# 0023: カスタムロールの定義をデプロイから分け，再デプロイを常設の権限だけで行えるようにする

- ステータス: 採択
- 日付: 2026-09-27

## 背景

[ADR 0014](0014-azure-container-apps-job-launcher.md) は，2 つのマネージド ID に
組み込みロールではなく最小のアクションだけを持つカスタムロールを割り当てると
決めた．これまで `deploy/azure/main.bicep` は，そのロール定義をサブスクリプション
スコープの module（`modules/roles.bicep`）として毎回のデプロイで作っていた．

そのため，イメージのダイジェストを替えるだけの再デプロイでも，毎回次の権限が
要った（issue #52）．

- サブスクリプションの `Microsoft.Authorization/roleDefinitions/write`．`Owner` か
  `User Access Administrator` にしか含まれず，多くの組織では PIM で一時的に
  有効化する．
- サブスクリプションの `Microsoft.Resources/deployments/*`（サブスクリプション
  スコープの入れ子のデプロイ）．

ロール定義の中身はリリース間でほとんど変わらない．それにもかかわらず，
イメージを更新するたびに特権の有効化を求めるのは釣り合わない．

## 決定

- **ロール定義は `deploy/azure/roles.bicep` として単独でデプロイする．**
  サブスクリプションスコープのテンプレートで，`az deployment sub create` で
  初回と，ロール定義を変えるリリースのときだけ実行する．
- **`main.bicep` はロール定義を書かない．** 割り当てに使うロール ID は，
  これまでどおり `modules/role-ids.bicep` の名前（`roleNamePrefix` とロールの
  キーから `guid()` で決まる）から計算する．ID は決定的なので，`main.bicep` は
  `roles.bicep` の出力を必要としない．これは事前検証の時点で ID が確定して
  いることを求める ABAC 条件付きの委任（issue #34）とも両立する．`main.bicep`
  のデプロイはリソースグループスコープのものだけになる．
- **ロール割り当ては `main.bicep` に残す．** 割り当て先のマネージド ID と同じ
  テンプレートにあることで，ID を作り直したときに割り当てが追従する．
  ARM は割り当てを毎回 PUT するので，再デプロイにも `roleAssignments/write` が
  要る．これは
  [条件付きの委任](https://learn.microsoft.com/azure/role-based-access-control/delegate-role-assignments-overview)
  で満たす．`roles.bicep` は，`Role Based Access Control Administrator` を
  「この 3 つのロールだけを，サービスプリンシパルにだけ」追加・削除できるように
  絞る ABAC 条件を出力 `deployerDelegationCondition` として返す．ここまで絞った
  権限は，PIM ではなく常設で与えてよい．
- **ロール定義を変えるリリースはリリースノートでそう告げる．** そのときは
  `roles.bicep` を同じ `roleNamePrefix` で先に再デプロイする．

## 検討した代替案

- **`main.bicep` に `deployRoleDefinitions` のようなスイッチを設ける．** 却下．
  既定値をどちらにしても，片方の利用者はパラメータを覚えておく必要がある．
  サブスクリプションスコープのリソースと RG スコープのリソースが同じ
  テンプレートに残るので，`main.bicep` のデプロイに必要な権限が既定値次第で
  変わり，読み取りにくい．
- **ロール割り当ても初回のデプロイに移す．** 却下．割り当ては Runner と
  Conductor の ID の `principalId` に依存するので，ID の作成も初回側に移す
  必要がある．Job や DNS ゾーン，Key Vault へのスコープも初回側で知る必要があり，
  テンプレートの分け目が不自然になる．
- **イメージの更新を `az containerapp update --image` などで Bicep の外で行う．**
  却下（標準の手順としては）．Bicep の宣言と実際の状態がずれ，次のフルデプロイで
  古いダイジェストに戻りうる．
- **レジストリの更新を検知して自動でイメージを入れ替える．** 却下．Container
  Apps にはその機能がなく，あったとしても，検証したダイジェストだけを動かすと
  いう [ADR 0017](0017-release-pipeline.md) の固定と両立しない．

## 結果

- 初回のロール定義の作成と条件付き委任の設定を除き，`main.bicep` のデプロイ
  （イメージの更新を含む）は，デプロイ先 RG の `Contributor`，DNS ゾーンと
  Key Vault の RG での `Microsoft.Resources/deployments/*`，条件付きの
  `Role Based Access Control Administrator` という常設の権限だけで行える．
  `what-if` にサブスクリプションスコープのリソースは現れない．
- 既存の環境は，以前の `main.bicep` が同じ名前（GUID）で作ったロール定義を
  そのまま使う．移行のためにロール定義を作り直す必要はない．
- `roles.bicep` をデプロイしていない，または別の `roleNamePrefix` で
  `main.bicep` をデプロイすると，ロール割り当てが `RoleDefinitionDoesNotExist`
  で失敗する．黙って誤った権限になることはない．
- 手順が 1 つ増える．初回のデプロイでは `roles.bicep` と条件付き委任の設定を
  先に行う必要がある（`deploy/azure/README.md`，`deploy/azure/walkthrough.md`）．
