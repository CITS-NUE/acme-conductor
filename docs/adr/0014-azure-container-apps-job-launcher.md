# 0014: Azure Container Apps Job ランチャー

- ステータス: 採択（以下で述べる管理用サイドカーは Phase 5 で OIDC ingress に置き換えられた，[ADR 0016](0016-oidc-bearer-auth-and-gui.md)）
- 日付: 2026-09-22

## 背景

Phase 4 は Conductor に最初のプラットフォームランチャーを与える．Runner は
Azure Container Apps Job として，run ごとに 1 つの実行（execution）として，自身の
マネージド ID の下で動く．したがって Conductor の環境にはもはや DNS や Store の
資格情報が存在しない（Phase 2 のローカルランチャーの `passthroughEnv` という
残存事項，脅威モデル T10）．`launcher.Launcher` インターフェースはランチャーが
何をするかを定める．すなわち `JobSpec` に対する execution を得ること，
プラットフォーム id を報告すること，`Result` を待つことである．しかし，その
プラットフォーム上で 2 つの文書がどのように境界を越えるか，Conductor の ID に
何を許可しなければならないか（そして決定的なのは，何を許可してはならないか），
run をどう制限し停止するか，インフラをどうプロビジョニングするかは開かれた
ままであった．

## 決定

- **仕事を自ら取りに来るスケジュール実行の Job．Conductor が execution を開始
  することは決してない．** Job（イメージ，ID，ボリューム，シークレット，Runner の
  設定，固定コマンド `reconcile --exchange /exchange`）は Bicep（`deploy/azure`）
  で宣言され，Conductor が触れることは決してない．そのトリガーはスケジュール
  （毎分．プラットフォームが提供する最小間隔）である．各 execution は Conductor が
  交換用共有に差し出した最も古いジョブを取るか，何もなければ直ちに終了する．
  プラットフォームの *start* 操作はトリガーとして却下された．それは Job の
  コンテナのイメージ・コマンド・環境を置き換えられる execution テンプレートを
  受け付けるからである．`Microsoft.App/jobs/start/action` を持つ ID は Job の
  マネージド ID の下で任意のイメージを実行できるので，Conductor の ID が侵害
  されれば，ランチャーのコードが何を控えていようと Runner の DNS と Key Vault の
  権限へ昇格していたであろう．したがって Conductor の ID はそれを持たない．
  Conductor が選ぶのは Runner が *どの run* を実行するかであり，*Runner が何で
  あるか* はインフラで固定されている．
- **1 つの run は 1 つの execution，レプリカは 1 つ．** プラットフォームの
  `parallelism` は 1 つの execution *内の* レプリカ数である．レプリカは execution
  名を共有し，停止と判定は execution 単位なので，別々の run を取ったレプリカは
  それらの run を結びつけてしまう．Job は `parallelism` と
  `replicaCompletionCount` を 1 に固定する．並行性は，連続するスケジュール tick
  の execution が重なることで得られる．
- **文書は両方のコンテナがマウントするファイル共有を，claim プロトコルで
  行き来する**（`internal/exchange`）．Conductor は署名付きジョブを
  `staging/run-<runId>/` の下に書き，そのディレクトリを 1 回のリネームで
  `pending/` に移す．Runner は `claimed/` へリネームすることでそれを取るので，
  複数の execution のうちちょうど 1 つが勝つ．Runner は claim したディレクトリに
  自身の execution 名（`CONTAINER_APP_JOB_EXECUTION_NAME`）を記録し，処理を行い，
  ジョブの隣に `result.json` を書く．Conductor はそのマーカーから execution を
  知り，それがこの Job の execution であることをプラットフォームに確認し，
  監視し，終了したらディレクトリを削除する．`claimTimeoutSeconds` 以内にどの
  execution もジョブを取らなければ，Conductor は同じリネームでそれを引き揚げる．
  したがってジョブは取られるか引き揚げられるかのどちらかであり，両方になる
  ことは決してない．ジョブが取られた後，Conductor がその背後の Runner を見捨てる
  ことは決してない．記録された execution 名はプラットフォームに確認され
  （プラットフォームが知らない名前なら run を終え，プラットフォームに問い合わせ
  できない場合は終えず，execution は未確認のまま監視される），run ディレクトリは
  execution の終了が確認されたときにのみ削除される．そうでなければ保持され
  報告されるので，まだ処理中かもしれない Runner はその result のパスを失わない．
  共有には証明書の素材も資格情報もなく，これらの文書だけがある．これは
  Conductor が所有するトランスポートではない（ストレージキーやマウントを持つ
  者は誰でも書ける）ので，両方向を認証する．ジョブは **署名付きエンベロープ**
  であり，Result は Runner の公開鍵で検証できる **署名付き Result** でなければ
  ならない（[ADR 0015](0015-signed-job-envelope.md)）．ランチャーは署名者と
  検証者なしに構築されることを拒否し，設定は `jobSigning` と `resultSigning`
  のない `azure-container-apps-job` バインディングを拒否する．Result はさらに，
  差し出された run と target を指し，プラットフォーム自身の判定と一致しなければ
  ならない（`Succeeded` で終了した execution に `failed` の Result，あるいはその
  逆は，不一致であって result ではない）．
- **3 つの権限を，1 つのリソースに．** Conductor の ID には，Runner の Job
  のみに対する `Microsoft.App/jobs/execution/read`，`jobs/executions/read`，
  `jobs/stop/execution/action` を持つカスタムロールが付与される．すなわち
  execution を 1 つ読む，一覧する，1 つ停止する，である．execution を開始
  できず，Job を変更できず，そのシークレットを読めず，DNS・Key Vault・
  ストレージのデータ権限は何も持たない．Runner の ID には，チャレンジゾーンに
  対する DNS ゾーン/TXT の 4 つのアクションを持つカスタムロールと，vault に
  対する `certificates/read` と `certificates/import/action` を持つカスタム
  ロール（[ADR 0013](0013-azure-key-vault-store-adapter.md)）が付与され，Job・
  アプリ・ストレージアカウントに対しては何も付与されない．ロールは組み込み
  ではなくカスタムとし，各付与が明示的でレビュー可能な一覧になるようにする．
  ロールはデプロイ先のサブスクリプション内でのみ割り当て可能なので，Phase 4
  ではゾーンと vault はそのサブスクリプションに置かなければならない．
- **ポーリング，タイムアウト，停止．** Conductor は execution の状態を
  終端になるまでポーリングする（`pollIntervalSeconds`，10 秒）．一時的な読み取り
  エラーは上限まで再試行する．終端状態に至らずにポーリングが終わったとき，
  すなわち run のコンテキストが終了したとき（操作者のキャンセル，シャットダウン，
  バインディングの `timeoutSeconds`），または状態を読めなくなったときは，run
  ディレクトリを削除する前にプラットフォームを通じて execution を停止する．
  まだ動いているかもしれず，result のパスを失った Runner は誰にも観測されずに
  完了してしまうからである．その後 execution を限られた猶予の間ポーリングし，
  Runner が書けた Result（通常は `Cancelled`）を報告する．Job 自身の
  `replicaTimeout` は Conductor のものより下にある 2 つ目の上限である．
  `replicaRetryLimit` はゼロである．再試行されたレプリカは同じ署名付きジョブを
  再び提示し，Runner のリプレイ台帳に拒否されるからである．
- **エラーは固定の文言．** ARM のエラーは `<op>: HTTP <status> (<code>)` となり，
  トランスポートの失敗はその種別，それ以外は最も内側のエラーの Go の型名と
  なる．応答ボディがラップされることは決してない．run レコードが得るのは
  ローカルランチャーと同様に Conductor 自身の要約だけである．
- **Conductor は同じ環境で，ingress なしで動く．** その API は `localhost-dev`
  認証（[ADR 0012](0012-localhost-only-dev-auth.md)）のままで，レプリカの
  ループバックからのみ到達できる．同じレプリカ内の任意の管理用サイドカー
  （`curl` を備えたシェル．`az containerapp exec` で到達する）が Phase 5 までの
  操作者の入口である．誰がそれをできるかは Container App に対する Azure RBAC が
  制御する．
- **テストは偽物のプラットフォームに対して走る．** ランチャーが使う 2 つの REST
  操作のプロセス内の偽物が，プラットフォームのスケジュールがそうするように
  独自の周期で claim モードの偽物の Runner の execution を開始する．したがって
  交換の全体，すなわち署名付きジョブの差し出し，取得，execution の確認，
  署名付き Result の返却，キャンセル時の停止，タイムアウト，ポーリングの失敗，
  不一致と改竄の検出，エラーの文言が，Azure サブスクリプションなしにディスク上で
  検証される（原則 8）．Azure SDK は `internal/conductor/launcher/acajob` に
  閉じ込める．

## 検討した代替案

- **Runner の引数だけを置き換える execution テンプレートで，Conductor から各
  execution を開始する**（この Phase の最初の草案）．レビューで却下．抑制は
  コードにあって権限にはない．`jobs/start/action` は保持者に任意のテンプレートの
  提出を許し，プラットフォームはこの権限を持つ ID が「execution テンプレートを
  使って Job のシークレットを参照し ... コンテナで利用可能に設定されたマネージド
  ID を使う」ことができると文書化している．侵害された Conductor のプロセスや
  ID は，Runner の ID の下で攻撃者のイメージを実行するだろう．スケジュール
  トリガーは，最大 1 分の開始遅延と引き換えにこの権限を完全に取り除く．
- **スケジュールの代わりにイベント駆動の Job（キュースケーラー）．** Phase 4
  では採らない．キューと，それに対する Conductor のデータプレーン権限
  （エンキュー用）およびスケーラーまたは Runner の権限（読み取りと削除用），
  そして 2 つ目のパッケージにキュー SDK のコードが必要になる．スケジュールなら
  cron 式 1 つだけで同じ性質（固定テンプレート，start 権限なし）が得られる．
  1 分周期やアイドルの execution がコストになれば，自然な次の一手として残る．
- **Conductor に代わって固定テンプレートで Job を開始するブローカー（Function
  や Logic App）．** 却下．独自の ID とレビューすべきコードを持ち，設計が
  取り除こうとしているまさにその権限を保持する，もう 1 つのコンポーネントで
  ある．
- **JobSpec を execution の環境変数や引数で渡し，Result を blob ストレージや
  キューで返す．** Phase 4 では却下．どのみち戻りの経路は必要であり，blob や
  キューは両方の ID に 2 つ目の Azure データプレーン権限と Runner 側の SDK コード
  を加えるのに対し，共有なら Runner のファイルベースのコントラクトを変えずに
  済む．エンベロープは共有の弱点（他者が書ける）を両方向で明示的かつ検出可能に
  する．
- **Result を届けるための Runner から Conductor の API へのコールバック．**
  却下．Conductor は Phase 5 まで認証されネットワークから到達可能な API を持たず，
  コールバックは Runner を Conductor の稼働に依存させることになり，それは
  アーキテクチャが禁じている．
- **run ごとに Conductor が Job を作成または更新する．** 却下．`jobs/write` が
  必要になり，侵害された Conductor はそれで Runner のイメージ・ID・マウントを
  変更できる．まさに T10 が扱う昇格である．
- **組み込みロール（Container Apps Jobs Operator，DNS Zone Contributor，
  Key Vault Certificates Officer）．** 却下．いずれも必要よりはるかに多くを
  付与する（`jobs/*/action` ワイルドカードによる start と `listSecrets`，
  すべてのレコード種別，証明書の削除と purge）．カスタムロールはデプロイ担当者が
  作成を許可されている必要があるサブスクリプションレベルのリソースであり，
  それは受け入れる．

## 結果

- このデプロイ形態では Conductor の環境は Runner の資格情報を一切持たず，その
  ID は Runner Job に Bicep で宣言された Runner イメージ以外を実行させることが
  できない．T10 の Phase 2 の残存事項はこれについては閉じられ，Conductor の
  侵害はどの run を実行するかの選択に限定される（T1）．
- run はキューに入ってから最大 1 分とプラットフォームの開始遅延の後に開始し，
  tick あたり最大 1 つの run であり，何も保留されていない間はプラットフォームが
  tick ごとに短いアイドルの execution を 1 つ動かす．スケジューラの
  `maxConcurrentRuns` が，同時に execution を待つか保持する run の数を制限する．
- execution の終了が確認できなかったとき，run ディレクトリは run より長く残り
  得る．運用ガイドがその見分け方と削除方法を述べる．
- 両方の署名鍵は操作者が所有するシークレットである．Conductor のジョブ署名鍵と
  Runner の Result 署名鍵で，それぞれ自身のバイナリのためだけにマウントされる．
  ローテーションは検証側で追加的に行う．
- 本物のプラットフォームに対するランチャーの振る舞い（スケジュールの周期と
  tick をまたぐ execution の重なり，SMB 共有上のリネームの原子性，ロールの
  アクション名，SMB 共有上の SQLite と `flock`，Result の伝播遅延）はリファ
  レンスドキュメントから文書化されており，CI ではなく最初の本物のデプロイで
  のみ検証される．`deploy/azure/README.md` が各項目を列挙する．
- Phase 5 までの管理は `az containerapp exec` でサイドカーに入ることである．
  監査ログは依然としてすべての呼び出し元を `localhost-dev` として記録する．
- run のキャンセルにはプラットフォーム呼び出しが伴うようになった．プラット
  フォームが停止に応じなければ，停止の猶予の後に Result なしで
  `Timeout`/`Cancelled` として終わり，Job の `replicaTimeout` がいずれにせよ
  execution を終わらせる．
