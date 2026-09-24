// Names of the custom role definitions, in one place.
//
// modules/roles.bicep creates the definitions under these names and
// main.bicep assigns them by the IDs built from the same names. main.bicep
// must not take the IDs from the roles module's outputs: a module output
// is unknown at preflight, and a role assignment whose roleDefinitionId is
// unknown then cannot be checked against an ABAC condition on
// @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] (the
// usual "may assign anything but Owner / User Access Administrator"
// delegation). ARM rejects such a deployment in preflight, even with
// --validation-level ProviderNoRbac (issue #34). A known ID passes, even
// before the definition exists.

@export()
@description('Keys of the three custom roles; each is hashed into its definition name.')
var roleKeys = {
  conductorJobObserver: 'acme-conductor-job-observer'
  runnerDnsTxtWriter: 'acme-runner-dns-txt-writer'
  runnerKeyVaultCertificateWriter: 'acme-runner-keyvault-certificate-writer'
}

@export()
@description('Name (GUID) of a custom role definition: subscriptionId is subscription().id, roleKey one of roleKeys.')
func roleDefinitionName(subscriptionId string, roleNamePrefix string, roleKey string) string =>
  guid(subscriptionId, roleNamePrefix, roleKey)
