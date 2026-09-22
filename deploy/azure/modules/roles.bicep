// Custom role definitions for ACME Conductor (subscription scope).
//
// Each role is the smallest set of actions one identity needs; the point
// of declaring them here rather than granting built-in roles is that the
// exact grant is a reviewable, versioned artifact (docs/threat-model.md,
// T10). Role definitions are subscription-level resources, so this module
// is deployed at subscription scope by main.bicep.
targetScope = 'subscription'

@description('Prefix for the role names, so several deployments in one tenant do not collide (role names are tenant-unique).')
@minLength(1)
@maxLength(40)
param roleNamePrefix string

// The Conductor's identity may read the Runner Job, start an execution of
// it, read an execution's status and stop an execution. It may not change
// the Job (image, identity, volumes, secrets) and holds no DNS, Key Vault
// or storage data permission at all.
resource conductorJobStarter 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, roleNamePrefix, 'acme-conductor-job-starter')
  properties: {
    roleName: '${roleNamePrefix} Conductor Job Starter'
    description: 'Start, observe and stop executions of the ACME Runner Container Apps Job. No write access to the Job itself.'
    type: 'CustomRole'
    assignableScopes: [
      subscription().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.App/jobs/read'
          'Microsoft.App/jobs/start/action'
          'Microsoft.App/jobs/stop/action'
          'Microsoft.App/jobs/executions/read'
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
  name: guid(subscription().id, roleNamePrefix, 'acme-runner-dns-txt-writer')
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
  name: guid(subscription().id, roleNamePrefix, 'acme-runner-keyvault-certificate-writer')
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

output conductorJobStarterRoleId string = conductorJobStarter.id
output runnerDnsTxtWriterRoleId string = runnerDnsTxtWriter.id
output runnerKeyVaultCertificateWriterRoleId string = runnerKeyVaultCertificateWriter.id
