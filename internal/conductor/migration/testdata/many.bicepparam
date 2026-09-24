using './main.bicep'
/* a block comment
   spanning lines, mentioning param targetDomains = ['not.this.one'] */
param location = 'japaneast'
param acmeEmail = readEnvironmentVariable('ACME_EMAIL', 'itc@example.ac.jp')
param description = 'the param targetDomains = [ inside a string is not a statement'
param targetDomains = [
  'WWW.Example.AC.JP.' // upper case and a trailing dot: normalized
  'api.example.ac.jp', 'ftp.example.ac.jp' /* two on one line */
  // 'commented.example.ac.jp'
  'it\'s.example.ac.jp'
]
param containerImage = 'cr.example.azurecr.io/cert-renew:abc'
