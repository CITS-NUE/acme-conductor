// Example parameters for deploy/azure/main.bicep. Copy it next to
// main.bicep (loadTextContent below resolves relative to this file), fill
// in the deployment-specific values, and deploy:
//
//   cp main.bicepparam my.bicepparam
//   export ACME_JOB_SIGNING_PRIVATE_KEY_PEM="$(cat job-signing.pem)"
//   export ACME_RESULT_SIGNING_PRIVATE_KEY_PEM="$(cat result-signing.pem)"
//   export ACME_ACCOUNT_PROVISIONING_PRIVATE_KEY_PEM="$(cat account-provisioning.pem)"  # optional
//   az deployment group create --resource-group rg-acme \
//     --template-file main.bicep --parameters my.bicepparam
//
// The runner configuration below is deploy/examples/runner-config.aca.example.json
// with the paths this template mounts (/state, /work, /usr/local/bin/lego).
// The template adds jobSigning.publicKeys from jobSigningPublicKey and the
// Runner identity's client ID to the config of every managed-identity Key
// Vault store binding (cmd/acme-runner/deploy_azure_test.go checks that
// what it emits loads).
using 'main.bicep'

param namePrefix = 'acme'
// Pin both images by digest to one release. The digests below are v0.6.0
// (https://github.com/CITS-NUE/acme-conductor/actions/runs/36006087963),
// the first release that emits and accepts the {type, config} binding
// format this template produces. Verify before trusting, and read the
// multi-arch index (linux/amd64, linux/arm64, plus the attestation
// manifests) to confirm the digest:
//   gh attestation verify oci://ghcr.io/cits-nue/acme-conductor:0.6.0 --owner CITS-NUE
//   gh attestation verify oci://ghcr.io/cits-nue/acme-runner:0.6.0 --owner CITS-NUE
//   docker buildx imagetools inspect ghcr.io/cits-nue/acme-conductor:0.6.0
//   docker buildx imagetools inspect ghcr.io/cits-nue/acme-runner:0.6.0
param conductorImage = 'ghcr.io/cits-nue/acme-conductor@sha256:fbdef0b8731a22847294fd057656551e7ecb4d130e47c4ca638a590a1235f1fd'
param runnerImage = 'ghcr.io/cits-nue/acme-runner@sha256:fec1410b1c631d4d74738e8b814c8cede06038da51a3cac6fd3c95d3b0e64e60'

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

// Encrypted EAB provisioning (docs/adr/0022), for a CA that requires
// External Account Binding: from
// `acme-runner provisioning-keygen --private account-provisioning.pem --public account-provisioning.pub`
// (the "publicKey:" line of its output). Give both or neither; both empty
// (the default) leaves the feature disabled, and one without the other
// fails the deployment before anything changes.
// param accountProvisioningPublicKey = '<publicKey from provisioning-keygen>'
// param accountProvisioningPrivateKeyPem = readEnvironmentVariable('ACME_ACCOUNT_PROVISIONING_PRIVATE_KEY_PEM', '')

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
