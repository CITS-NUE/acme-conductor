// Grants the Runner identity the DNS TXT writer role on one DNS zone. The
// zone may live in another resource group or subscription; main.bicep
// deploys this module at the zone's resource group scope.
targetScope = 'resourceGroup'

@description('Name of the existing DNS zone (the challenge zone).')
param dnsZoneName string

@description('Principal ID of the Runner user-assigned identity.')
param runnerPrincipalId string

@description('Resource ID of the Runner DNS TXT Writer role definition.')
param roleDefinitionId string

resource zone 'Microsoft.Network/dnsZones@2023-07-01-preview' existing = {
  name: dnsZoneName
}

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(zone.id, runnerPrincipalId, roleDefinitionId)
  scope: zone
  properties: {
    principalId: runnerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}
