// Example parameters for deploy/azure/main.bicep. Copy, edit, deploy:
//
//   az deployment group create --resource-group rg-acme \
//     --template-file main.bicep --parameters main.bicepparam \
//     --parameters jobSigningPrivateKeyPem=@job-signing.pem
//
// The runner configuration below is deploy/examples/runner-config.aca.example.json
// with the paths this template mounts (/state, /work, /usr/local/bin/lego).
using 'main.bicep'

param namePrefix = 'acme'
param conductorImage = 'ghcr.io/cits-nue/acme-conductor@sha256:0000000000000000000000000000000000000000000000000000000000000000'
param runnerImage = 'ghcr.io/cits-nue/acme-runner@sha256:0000000000000000000000000000000000000000000000000000000000000000'

param acmeBindings = ['letsencrypt-staging']
param dnsBindings = ['azure-dns-staging']
param storeBindings = ['keyvault-staging']

param dnsZoneName = 'example.ac.jp'
param dnsZoneResourceGroup = 'rg-dns-example'
param keyVaultName = 'kv-acme-staging'
param keyVaultResourceGroup = 'rg-acme'

// From `acme-conductor keygen --private job-signing.pem --public job-signing.pub`
// (the "publicKey:" line of its output).
param jobSigningPublicKey = 'MCowBQYDK2VwAyEAXwYpAPJZlUf8sscb1XL7N9EJXgCWGHQnj6+tELbUZms='
param jobSigningPrivateKeyPem = readEnvironmentVariable('ACME_JOB_SIGNING_PRIVATE_KEY_PEM', '')

param runnerConfigJson = loadTextContent('../examples/runner-config.aca.example.json')
