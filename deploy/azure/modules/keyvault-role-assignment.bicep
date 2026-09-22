// Grants the Runner identity the Key Vault certificate writer role on one
// vault. The vault must use the RBAC permission model
// (enableRbacAuthorization: true); access policies are not managed here.
// main.bicep deploys this module at the vault's resource group scope.
targetScope = 'resourceGroup'

@description('Name of the existing Key Vault the Runner stores certificates in.')
param keyVaultName string

@description('Principal ID of the Runner user-assigned identity.')
param runnerPrincipalId string

@description('Resource ID of the Runner Key Vault Certificate Writer role definition.')
param roleDefinitionId string

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, runnerPrincipalId, roleDefinitionId)
  scope: vault
  properties: {
    principalId: runnerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}
