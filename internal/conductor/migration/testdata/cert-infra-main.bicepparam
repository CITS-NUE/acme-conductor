// Mirrors the shape of cert-infra's infra/main.bicepparam (the migration
// source this package is written for): the same statements, comment
// styles and the commented-out hosts, with example names.
using './main.bicep'

param location = 'japaneast'
param dnsZoneName = 'cert.example.ac.jp'
param keyVaultName = 'kv-cert-example'
// CI では GitHub Variables の ACME_EMAIL が環境変数として渡る（ガイド §9）．
// 未設定なら決定済みの値にフォールバックするので，ローカルからの az deployment は
// これまでどおり引数なしで流せる．
param acmeEmail = readEnvironmentVariable('ACME_EMAIL', 'itc@example.ac.jp')

param targetDomains = [
  'leaf.cerdad.example.ac.jp'
  // 'aries.example.ac.jp'
  // 'ann.example.ac.jp'
]

// container/ のイメージを ACR に push したら差し替える．
// タグは build-image.yml がコミット SHA で打つ．
param containerImage = 'crcertexample.azurecr.io/cert-renew:ebf65553ec7e95a28562c9d1e7b31a762ceac602'

// 空なら lego の既定 CA（Let's Encrypt 本番）を使う．ディレクトリ URL の指定は要らない．
// 検証で staging に戻すときは下の行を有効にする．そのときも lego-state を
// 作り直すこと（staging と本番では ACME アカウントも証明書も別物．ランブック §7）．
// param acmeServer = 'https://acme-staging-v02.api.letsencrypt.org/directory'

// --- 監視（ガイド §5） ---
// 通知先の既定は ACME アカウントと同じ情報基盤センターの共有アドレス．
// 既存の通知基盤に寄せる場合は webhook を足す（両方指定してもよい）．
// param alertEmail = 'itc@example.ac.jp'
// param alertWebhookUri = 'https://example.ac.jp/alerts'

// false にするとワークスペースを作らず，ジョブ失敗の検知はメトリック
// アラートだけの best-effort に落ちる．有効期限の監視には影響しない．
// param enableLogAnalytics = false
