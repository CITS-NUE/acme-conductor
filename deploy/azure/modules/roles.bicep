// Custom role definitions for ACME Conductor (subscription scope).
//
// Each role is the smallest set of actions one identity needs; the point
// of declaring them here rather than granting built-in roles is that the
// exact grant is a reviewable, versioned artifact (docs/threat-model.md,
// T10). Role definitions are subscription-level resources, so this module
// is deployed at subscription scope by main.bicep; their assignable scope
// is that subscription, which is why the DNS zone and the Key Vault must
// live in the same subscription as the deployment (Phase 4).
targetScope = 'subscription'

import { roleDefinitionName, roleKeys } from 'role-ids.bicep'

@description('Prefix for the role names, so several deployments in one tenant do not collide (role names are tenant-unique).')
@minLength(1)
@maxLength(40)
param roleNamePrefix string

// The Conductor's identity may read an execution of the Runner Job, list
// its executions and stop an execution. It may NOT start one:
// Microsoft.App/jobs/start/action accepts an execution template that
// replaces the image, command and environment of the Job's containers, so
// a holder of it can run any image under the Runner's managed identity
// (docs/adr/0014, threat model T1/T10). Executions are started by the
// Job's own schedule instead. It may not change the Job either, and it
// holds no DNS, Key Vault or storage data permission at all.
resource conductorJobObserver 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: roleDefinitionName(subscription().id, roleNamePrefix, roleKeys.conductorJobObserver)
  properties: {
    roleName: '${roleNamePrefix} Conductor Job Execution Observer'
    description: 'Read, list and stop executions of the ACME Runner Container Apps Job. No start (its execution template could replace the image) and no write access to the Job.'
    type: 'CustomRole'
    assignableScopes: [
      subscription().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.App/jobs/execution/read'
          'Microsoft.App/jobs/executions/read'
          'Microsoft.App/jobs/stop/execution/action'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

// The Runner's identity may read the DNS zone and manage TXT record sets
// in it (what lego's azuredns provider does for a DNS-01 challenge) and
// nothing else in DNS.
resource runnerDnsTxtWriter 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: roleDefinitionName(subscription().id, roleNamePrefix, roleKeys.runnerDnsTxtWriter)
  properties: {
    roleName: '${roleNamePrefix} Runner DNS TXT Writer'
    description: 'Read a DNS zone and create, read and delete TXT record sets in it (ACME DNS-01 challenges).'
    type: 'CustomRole'
    assignableScopes: [
      subscription().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.Network/dnsZones/read'
          'Microsoft.Network/dnsZones/TXT/read'
          'Microsoft.Network/dnsZones/TXT/write'
          'Microsoft.Network/dnsZones/TXT/delete'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

// The Runner's identity may read a certificate's public part and import a
// certificate into the vault (docs/adr/0013). It may never read a secret
// (the private key of any certificate), delete, purge or recover.
resource runnerKeyVaultCertificateWriter 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: roleDefinitionName(subscription().id, roleNamePrefix, roleKeys.runnerKeyVaultCertificateWriter)
  properties: {
    roleName: '${roleNamePrefix} Runner Key Vault Certificate Writer'
    description: 'Read certificates (public part) and import certificates into a Key Vault. No secrets/get, no delete or purge.'
    type: 'CustomRole'
    assignableScopes: [
      subscription().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/certificates/read'
          'Microsoft.KeyVault/vaults/certificates/import/action'
        ]
        notDataActions: []
      }
    ]
  }
}

output conductorJobObserverRoleId string = conductorJobObserver.id
output runnerDnsTxtWriterRoleId string = runnerDnsTxtWriter.id
output runnerKeyVaultCertificateWriterRoleId string = runnerKeyVaultCertificateWriter.id
