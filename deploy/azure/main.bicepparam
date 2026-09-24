// Example parameters for deploy/azure/main.bicep. Copy, edit, deploy:
//
//   az deployment group create --resource-group rg-acme \
//     --template-file main.bicep --parameters main.bicepparam \
//     --parameters jobSigningPrivateKeyPem=@job-signing.pem \
//     --parameters resultSigningPrivateKeyPem=@result-signing.pem
//
// The runner configuration below is deploy/examples/runner-config.aca.example.json
// with the paths this template mounts (/state, /work, /usr/local/bin/lego).
using 'main.bicep'

param namePrefix = 'acme'
// v0.5.0 (https://github.com/CITS-NUE/acme-conductor/actions/runs/35945554057);
// verify before trusting: gh attestation verify oci://<image>:0.5.0 --owner CITS-NUE
param conductorImage = 'ghcr.io/cits-nue/acme-conductor@sha256:97198bc1d338ec0ce9748120b4b2b9645b881c40b58d40920f11781fa4558ed3'
param runnerImage = 'ghcr.io/cits-nue/acme-runner@sha256:760a2e9f906b4b85ec5fe92c34e2f13c1fdf61abef2ea48504de70e511c1a6d2'

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

// From `acme-runner keygen --private result-signing.pem --public result-signing.pub`.
param resultSigningPublicKey = 'MCowBQYDK2VwAyEA65N/M3oDE8dU2aAKvMDf19gGaRxk3W3gRWTKAj2DPOM='
param resultSigningPrivateKeyPem = readEnvironmentVariable('ACME_RESULT_SIGNING_PRIVATE_KEY_PEM', '')

param runnerConfigJson = loadTextContent('../examples/runner-config.aca.example.json')

// OIDC: an Entra ID tenant; the API app registration's Application
// (client) ID as audience (what a v2 access token carries in aud); the
// scope the GUI requests, built from the API's application ID URI (here
// the default api://<client-id>); the GUI's SPA app registration as
// client; the app roles that grant each API role; and oid as the actor
// identity (docs/conductor.md, "Authentication").
param oidcIssuer = 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0'
param oidcAudience = '11111111-1111-1111-1111-111111111111'
param oidcClientId = '22222222-2222-2222-2222-222222222222'
param oidcScopes = ['openid', 'profile', 'api://11111111-1111-1111-1111-111111111111/.default']
param oidcPrincipalClaim = 'oid'
param oidcAdminRoles = ['ACME.Admin']
param oidcViewerRoles = ['ACME.Viewer']
param ingressExternal = true
param ingressAllowedCidrs = []

// Migration from the existing cert-infra deployment (docs/migration.md):
// start in shadow mode with its targetDomains pasted here, import the
// list with `acme-conductor migrate import --apply`, and switch
// targetSource to 'registry' when the Conductor is to issue. A rollback
// is 'iac' (the Conductor issues nothing; the Container Apps Job of
// cert-infra keeps renewing).
// param migration = {
//   targetSource: 'shadow'
//   source: { fqdns: ['leaf.cerdad.example.ac.jp'] }
//   profile: { policyRef: '<policy id>', executionBinding: 'azure', dnsBinding: 'azure-dns-staging', storeBinding: 'keyvault-staging', owner: 'cert-infra migration' }
// }
