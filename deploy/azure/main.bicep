// ACME Conductor on Azure Container Apps.
//
// Deploys, in one resource group:
//   - a Container Apps environment with a Log Analytics workspace;
//   - a storage account with three file shares mounted into the
//     environment: conductor-state (the SQLite registry), runner-state
//     (ACME account state) and exchange (signed jobs in, results out);
//   - two user-assigned identities, one per binary, with disjoint grants
//     (docs/threat-model.md, T10): the Conductor's may observe and stop
//     executions of the Runner Job and nothing else — never start one,
//     since the start operation's execution template could replace the
//     Runner's image (docs/adr/0014); the Runner's may write TXT records
//     in one DNS zone and import certificates into one Key Vault, and
//     nothing else;
//   - the Runner as a scheduled Container Apps Job whose executions take
//     the jobs the Conductor offers on the exchange share;
//   - the Conductor as a single-replica Container App behind the
//     environment's HTTPS ingress, authenticating API and GUI callers
//     with OIDC bearer tokens (docs/adr/0016); the platform terminates
//     TLS and the hop from ingress to replica is encrypted.
//
// Nothing here is a secret except the two signing private keys (the
// Conductor's job-signing key, the Runner's result-signing key), each a
// secure parameter stored as a secret and mounted as a file for its own
// binary.
// No DNS or Key Vault credential exists anywhere: both are the Runner's
// managed identity. See deploy/azure/README.md for what this template does
// not verify and how to operate the result.
targetScope = 'resourceGroup'

import { roleDefinitionName, roleKeys } from 'modules/role-ids.bicep'

// --- parameters --------------------------------------------------------------

@description('Azure region for every resource.')
param location string = resourceGroup().location

@description('Name prefix for the resources created here: lower-case letters, digits and hyphens. The storage account name is the first 11 characters of the prefix without hyphens plus a 13-character unique suffix, so it always fits the 24-character limit.')
@minLength(3)
@maxLength(20)
param namePrefix string = 'acme'

@description('Prefix for the custom role names (tenant-unique).')
param roleNamePrefix string = 'ACME Conductor'

@description('Conductor container image, pinned by digest for anything but development.')
param conductorImage string

@description('Runner container image, pinned by digest for anything but development.')
param runnerImage string

@description('The Runner configuration document (RunnerConfig JSON) as authored by the operator. jobSigning.publicKeys is added from jobSigningPublicKey; the paths must match the mounts below (lego.stateDir /state, lego.workDir /work).')
param runnerConfigJson string

@description('The Ed25519 job-signing private key, PEM (PKCS #8), from `acme-conductor keygen`. Stored as a Container App secret and mounted as a file for the Conductor only.')
@secure()
param jobSigningPrivateKeyPem string

@description('The matching public key (PEM or one-line base64), placed into the Runner configuration as jobSigning.publicKeys[0].')
param jobSigningPublicKey string

@description('The Ed25519 result-signing private key, PEM (PKCS #8), from `acme-runner keygen`. Stored as a Container Apps Job secret and mounted as a file for the Runner only.')
@secure()
param resultSigningPrivateKeyPem string

@description('The matching public key (PEM or one-line base64), placed into the Conductor configuration as resultSigning.publicKeys[0].')
param resultSigningPublicKey string

@description('Logical ACME binding names the Conductor registers (must match the Runner configuration).')
param acmeBindings array

@description('Logical DNS binding names the Conductor registers (must match the Runner configuration).')
param dnsBindings array

@description('Logical store binding names the Conductor registers (must match the Runner configuration).')
param storeBindings array

@description('Name of the DNS zone the Runner completes challenges in.')
param dnsZoneName string

@description('Resource group of the DNS zone. The zone must be in this subscription (the custom roles are assignable in this subscription only).')
param dnsZoneResourceGroup string

@description('Name of the Key Vault the Runner stores certificates in (RBAC permission model).')
param keyVaultName string

@description('Resource group of the Key Vault. The vault must be in this subscription (the custom roles are assignable in this subscription only).')
param keyVaultResourceGroup string

@description('Maximum seconds one Runner execution may run before the platform stops it. Keep it above the Runner lego.timeoutSeconds and below the Conductor timeoutSeconds.')
@minValue(60)
@maxValue(86400)
param runnerReplicaTimeoutSeconds int = 1500

@description('Conductor-side timeout for one execution (seconds); must exceed runnerReplicaTimeoutSeconds.')
@minValue(60)
@maxValue(86400)
param conductorLaunchTimeoutSeconds int = 1800

@description('How long a signed job stays acceptable after issue (seconds). It has to cover the schedule cadence plus the platform start latency, and must be at least claimTimeoutSeconds.')
@minValue(60)
@maxValue(86400)
param jobSigningValiditySeconds int = 900

@description('How long the Conductor waits for a scheduled execution to take an offered job before it withdraws it (seconds). At most jobSigningValiditySeconds.')
@minValue(60)
@maxValue(86400)
param claimTimeoutSeconds int = 300

@description('Cron schedule on which the platform starts Runner executions; each execution takes one offered job or exits at once. Every minute is the finest schedule Container Apps supports and bounds the start latency of a run.')
param runnerCronExpression string = '* * * * *'


@description('OIDC issuer of the API\'s tokens, e.g. https://login.microsoftonline.com/<tenant-id>/v2.0 for Microsoft Entra ID (v2 tokens).')
param oidcIssuer string

@description('Audience every access token must carry, as the provider writes it into the aud claim. Entra ID v2 access tokens carry the API app registration\'s Application (client) ID, a GUID, never its application ID URI. Used for verification only; nothing is derived from it.')
param oidcAudience string

@description('Client ID of the public client (SPA) the GUI signs in as; empty means the GUI cannot sign in. Its redirect URI is the conductorGuiRedirectUri output.')
param oidcClientId string = ''

@description('Scopes the GUI requests at sign-in; required when oidcClientId is set (the Conductor refuses to start otherwise) and never derived from oidcAudience. Entra ID: openid, profile and <API application ID URI>/.default, e.g. api://<api-client-id>/.default.')
param oidcScopes array = []

@description('Token claim recorded as the audit-log actor and requestedBy: a stable identifier of the subject, not a display name. oid for Entra ID (sub is pairwise per client there); sub for most other providers.')
param oidcPrincipalClaim string = 'oid'

@description('Values of the token roles claim that grant the admin role (every operation).')
param oidcAdminRoles array

@description('Values of the token roles claim that grant the viewer role (read only).')
param oidcViewerRoles array = []

@description('Whether the Conductor ingress is reachable from outside the environment. false keeps it internal to the environment\'s virtual network.')
param ingressExternal bool = true

@description('CIDR ranges allowed to reach the ingress; empty allows every source. Authentication does not depend on this list, it only narrows the exposure.')
param ingressAllowedCidrs array = []

@description('Scheduler settings copied into the Conductor configuration.')
param schedulerTickSeconds int = 60
param schedulerMaxConcurrentRuns int = 2

@description('The migration section of the Conductor configuration, verbatim (docs/migration.md): the targetSource flag (registry, shadow or iac), the infrastructure host list (source.fqdns can be pasted from the existing cert-infra targetDomains parameter) and the import profile. Empty means target source registry and no list.')
param migration object = {}

@description('Tags applied to every resource.')
param tags object = {}

// --- names -------------------------------------------------------------------

var environmentName = '${namePrefix}-cae'
var workspaceName = '${namePrefix}-log'
// Storage account names: 3-24 lower-case alphanumerics, globally unique.
var storageAccountName = toLower('${take(replace(namePrefix, '-', ''), 11)}${uniqueString(resourceGroup().id)}')
var conductorIdentityName = '${namePrefix}-id-conductor'
var runnerIdentityName = '${namePrefix}-id-runner'
var runnerJobName = '${namePrefix}-runner'
var conductorAppName = '${namePrefix}-conductor'

var shareConductorState = 'conductor-state'
var shareRunnerState = 'runner-state'
var shareExchange = 'exchange'

// --- roles (subscription scope) ----------------------------------------------

// The role definition IDs are built here from the same names the roles
// module uses, not taken from its outputs, so that they are known at
// preflight (see modules/role-ids.bicep). The grants below depend on the
// module explicitly instead.
var conductorJobObserverRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionName(subscription().id, roleNamePrefix, roleKeys.conductorJobObserver))
var runnerDnsTxtWriterRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionName(subscription().id, roleNamePrefix, roleKeys.runnerDnsTxtWriter))
var runnerKeyVaultCertificateWriterRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionName(subscription().id, roleNamePrefix, roleKeys.runnerKeyVaultCertificateWriter))

module roles 'modules/roles.bicep' = {
  name: '${deployment().name}-roles'
  scope: subscription()
  params: {
    roleNamePrefix: roleNamePrefix
  }
}

// --- identities --------------------------------------------------------------

resource conductorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: conductorIdentityName
  location: location
  tags: tags
}

resource runnerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: runnerIdentityName
  location: location
  tags: tags
}

// --- logging and environment -------------------------------------------------

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: workspace.properties.customerId
        sharedKey: workspace.listKeys().primarySharedKey
      }
    }
    // The ingress terminates TLS; this encrypts the hop from the ingress
    // to the Conductor replica, which otherwise carries bearer tokens in
    // the clear inside the environment (server.behindTlsProxy below).
    peerTrafficConfiguration: {
      encryption: {
        enabled: true
      }
    }
    zoneRedundant: false
  }
}

// --- storage: three file shares ---------------------------------------------

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    // The Container Apps environment mounts Azure Files with the account
    // key (that is how environment storages work); the key never reaches
    // either binary.
    allowSharedKeyAccess: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource conductorStateShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  parent: fileService
  name: shareConductorState
  properties: {
    shareQuota: 5
  }
}

resource runnerStateShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  parent: fileService
  name: shareRunnerState
  properties: {
    shareQuota: 1
  }
}

resource exchangeShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  parent: fileService
  name: shareExchange
  properties: {
    shareQuota: 1
  }
}

resource conductorStateStorage 'Microsoft.App/managedEnvironments/storages@2024-03-01' = {
  parent: environment
  name: shareConductorState
  properties: {
    azureFile: {
      accountName: storage.name
      accountKey: storage.listKeys().keys[0].value
      shareName: conductorStateShare.name
      accessMode: 'ReadWrite'
    }
  }
}

resource runnerStateStorage 'Microsoft.App/managedEnvironments/storages@2024-03-01' = {
  parent: environment
  name: shareRunnerState
  properties: {
    azureFile: {
      accountName: storage.name
      accountKey: storage.listKeys().keys[0].value
      shareName: runnerStateShare.name
      accessMode: 'ReadWrite'
    }
  }
}

resource exchangeStorage 'Microsoft.App/managedEnvironments/storages@2024-03-01' = {
  parent: environment
  name: shareExchange
  properties: {
    azureFile: {
      accountName: storage.name
      accountKey: storage.listKeys().keys[0].value
      shareName: exchangeShare.name
      accessMode: 'ReadWrite'
    }
  }
}

// --- the Runner: a scheduled Job -------------------------------------------

// The operator's Runner configuration plus the Conductor's public key (so
// the Runner cannot be deployed without the key it needs to verify jobs),
// the path of its own result-signing key, and the client ID of the
// Runner's user-assigned identity on every Key Vault store binding that
// authenticates with a managed identity: the Job carries a user-assigned
// identity only, and a managed-identity credential that names no client
// ID asks for the system-assigned one, which this Job does not have.
//
// A store binding is a {type, config} envelope (docs/runner.md): the
// Runner's configuration knows no store type, and everything a provider
// reads — here the Key Vault adapter's credential and
// managedIdentityClientId — lives in its config object. The template
// therefore reads the credential from, and merges the client ID into,
// binding.config, and leaves the envelope itself as the operator wrote
// it; a field added at the binding root would be refused by the Runner
// as unknown. cmd/acme-runner's TestAzureTemplateRunnerConfigLoads holds
// this expression and the example configuration to that shape.
var runnerConfigInput = json(runnerConfigJson)
var runnerStoreBindings = toObject(
  items(runnerConfigInput.storeBindings),
  b => b.key,
  b => (b.value.type == 'azure-keyvault' && (b.value.config.?credential ?? 'default') == 'managed-identity')
    ? union(b.value, {
        config: union(b.value.config, { managedIdentityClientId: runnerIdentity.properties.clientId })
      })
    : b.value
)
var runnerConfig = union(runnerConfigInput, {
  jobSigning: {
    publicKeys: [
      jobSigningPublicKey
    ]
  }
  resultSigning: {
    privateKeyFile: '/etc/acme-runner/result-signing.pem'
  }
  storeBindings: runnerStoreBindings
})

resource runnerJob 'Microsoft.App/jobs@2024-03-01' = {
  name: runnerJobName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${runnerIdentity.id}': {}
    }
  }
  properties: {
    environmentId: environment.id
    configuration: {
      // Scheduled, never started by the Conductor: the start operation's
      // execution template could replace the image, so no identity of
      // this deployment holds jobs/start/action (docs/adr/0014). Each
      // execution takes the oldest job the Conductor offered on the
      // exchange share, or exits at once when there is none.
      triggerType: 'Schedule'
      replicaTimeout: runnerReplicaTimeoutSeconds
      // A retried replica would present the same signed job again; the
      // Runner refuses it (replay ledger) and the retry only burns time.
      replicaRetryLimit: 0
      scheduleTriggerConfig: {
        cronExpression: runnerCronExpression
        // parallelism is replicas *per execution*, and the launcher's
        // contract is one run per execution (stop and verdict are per
        // execution): several replicas of one execution would share an
        // execution name while taking different runs. Concurrency comes
        // from executions of successive ticks overlapping.
        parallelism: 1
        replicaCompletionCount: 1
      }
      secrets: [
        {
          name: 'runner-config'
          // Not a secret (it holds no credential, docs/runner.md); a
          // Container Apps secret is simply how a file is mounted.
          #disable-next-line use-secure-value-for-secure-inputs
          value: string(runnerConfig)
        }
        {
          name: 'result-signing-key'
          value: resultSigningPrivateKeyPem
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'runner'
          image: runnerImage
          // Claim mode: take one offered job from the exchange share
          // (docs/runner.md). The arguments are fixed here; nothing about
          // an execution is chosen by the Conductor.
          args: [
            'reconcile'
            '--exchange'
            '/exchange'
          ]
          env: [
            {
              name: 'ACME_RUNNER_CONFIG'
              value: '/etc/acme-runner/config.json'
            }
            {
              // The user-assigned identity the Runner authenticates with
              // (Key Vault store and lego azuredns via AZURE_CLIENT_ID).
              name: 'AZURE_CLIENT_ID'
              value: runnerIdentity.properties.clientId
            }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          volumeMounts: [
            {
              volumeName: 'runner-config'
              mountPath: '/etc/acme-runner'
            }
            {
              volumeName: 'exchange'
              mountPath: '/exchange'
            }
            {
              volumeName: 'runner-state'
              mountPath: '/state'
            }
            {
              volumeName: 'work'
              mountPath: '/work'
            }
          ]
        }
      ]
      volumes: [
        {
          name: 'runner-config'
          storageType: 'Secret'
          secrets: [
            {
              secretRef: 'runner-config'
              path: 'config.json'
            }
            {
              secretRef: 'result-signing-key'
              path: 'result-signing.pem'
            }
          ]
        }
        {
          name: 'exchange'
          storageType: 'AzureFile'
          storageName: exchangeStorage.name
        }
        {
          name: 'runner-state'
          storageType: 'AzureFile'
          storageName: runnerStateStorage.name
        }
        {
          // The certificate private key exists here, transiently, for the
          // duration of one run; the volume dies with the replica.
          name: 'work'
          storageType: 'EmptyDir'
        }
      ]
    }
  }
}

// --- the Conductor: a single-replica app behind the HTTPS ingress ------------

var conductorConfig = union(conductorConfigBase, empty(migration) ? {} : { migration: migration })

var conductorConfigBase = {
  apiVersion: 'acme-conductor.cits-nue.github.io/v1alpha1'
  kind: 'ConductorConfig'
  server: {
    listen: '0.0.0.0:8080'
    auth: {
      mode: 'oidc'
      oidc: union(
        {
          issuer: oidcIssuer
          audience: oidcAudience
          clientId: oidcClientId
          principalClaim: oidcPrincipalClaim
          roles: {
            admin: oidcAdminRoles
            viewer: oidcViewerRoles
          }
        },
        empty(oidcScopes) ? {} : { scopes: oidcScopes }
      )
    }
    // TLS is terminated by the environment ingress, the only route to
    // the port; peer traffic encryption covers the hop behind it.
    behindTlsProxy: true
    shutdownGraceSeconds: conductorLaunchTimeoutSeconds
  }
  database: {
    path: '/var/lib/acme-conductor/conductor.db'
  }
  scheduler: {
    tickSeconds: schedulerTickSeconds
    maxConcurrentRuns: schedulerMaxConcurrentRuns
  }
  jobSigning: {
    privateKeyFile: '/etc/acme-conductor/job-signing.pem'
    validitySeconds: jobSigningValiditySeconds
  }
  resultSigning: {
    publicKeys: [
      resultSigningPublicKey
    ]
  }
  executionBindings: {
    azure: {
      type: 'azure-container-apps-job'
      config: {
        subscriptionId: subscription().subscriptionId
        resourceGroup: resourceGroup().name
        jobName: runnerJob.name
        credential: 'managed-identity'
        managedIdentityClientId: conductorIdentity.properties.clientId
        exchangeDir: '/mnt/exchange'
        claimTimeoutSeconds: claimTimeoutSeconds
        timeoutSeconds: conductorLaunchTimeoutSeconds
      }
    }
  }
  acmeBindings: acmeBindings
  dnsBindings: dnsBindings
  storeBindings: storeBindings
}

var conductorContainer = {
  name: 'conductor'
  image: conductorImage
  args: [
    'serve'
  ]
  env: [
    {
      name: 'ACME_CONDUCTOR_CONFIG'
      value: '/etc/acme-conductor/config.json'
    }
  ]
  resources: {
    cpu: json('0.25')
    memory: '0.5Gi'
  }
  probes: [
    {
      type: 'Liveness'
      httpGet: {
        path: '/healthz'
        port: 8080
      }
      periodSeconds: 30
    }
    {
      type: 'Readiness'
      httpGet: {
        path: '/readyz'
        port: 8080
      }
      periodSeconds: 10
    }
  ]
  volumeMounts: [
    {
      volumeName: 'conductor-config'
      mountPath: '/etc/acme-conductor'
    }
    {
      volumeName: 'conductor-state'
      mountPath: '/var/lib/acme-conductor'
    }
    {
      volumeName: 'exchange'
      mountPath: '/mnt/exchange'
    }
  ]
}

// Source restrictions on the ingress, when any are given.
var ingressRestrictions = [for (cidr, i) in ingressAllowedCidrs: {
  name: 'allow-${i}'
  ipAddressRange: cidr
  action: 'Allow'
}]

resource conductorApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: conductorAppName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${conductorIdentity.id}': {}
    }
  }
  properties: {
    environmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      // HTTPS only: the platform redirects plain HTTP and terminates TLS
      // with its own certificate for the app's FQDN. Nothing but a valid
      // bearer token is accepted behind it (docs/adr/0016).
      ingress: {
        external: ingressExternal
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
        ipSecurityRestrictions: ingressRestrictions
      }
      secrets: [
        {
          name: 'conductor-config'
          // Not a secret either; mounted as a file like the Runner's.
          #disable-next-line use-secure-value-for-secure-inputs
          value: string(conductorConfig)
        }
        {
          name: 'job-signing-key'
          value: jobSigningPrivateKeyPem
        }
      ]
    }
    template: {
      containers: [conductorContainer]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
      volumes: [
        {
          name: 'conductor-config'
          storageType: 'Secret'
          secrets: [
            {
              secretRef: 'conductor-config'
              path: 'config.json'
            }
            {
              secretRef: 'job-signing-key'
              path: 'job-signing.pem'
            }
          ]
        }
        {
          name: 'conductor-state'
          storageType: 'AzureFile'
          storageName: conductorStateStorage.name
          // SQLite on SMB needs byte-range locks disabled; see README.
          mountOptions: 'nobrl'
        }
        {
          name: 'exchange'
          storageType: 'AzureFile'
          storageName: exchangeStorage.name
        }
      ]
    }
  }
}

// --- grants ------------------------------------------------------------------

// Conductor identity -> observe and stop executions of this Job only
// (never start one; see modules/roles.bicep).
resource conductorObservesRunner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(runnerJob.id, conductorIdentity.id, 'job-observer')
  scope: runnerJob
  properties: {
    principalId: conductorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: conductorJobObserverRoleId
  }
  dependsOn: [
    roles
  ]
}

// Runner identity -> TXT records in the challenge zone.
module runnerDns 'modules/dns-role-assignment.bicep' = {
  name: '${deployment().name}-dns'
  scope: resourceGroup(dnsZoneResourceGroup)
  params: {
    dnsZoneName: dnsZoneName
    runnerPrincipalId: runnerIdentity.properties.principalId
    roleDefinitionId: runnerDnsTxtWriterRoleId
  }
  dependsOn: [
    roles
  ]
}

// Runner identity -> import certificates into the vault.
module runnerKeyVault 'modules/keyvault-role-assignment.bicep' = {
  name: '${deployment().name}-keyvault'
  scope: resourceGroup(keyVaultResourceGroup)
  params: {
    keyVaultName: keyVaultName
    runnerPrincipalId: runnerIdentity.properties.principalId
    roleDefinitionId: runnerKeyVaultCertificateWriterRoleId
  }
  dependsOn: [
    roles
  ]
}

// --- outputs -----------------------------------------------------------------

output environmentName string = environment.name
output runnerJobName string = runnerJob.name
output conductorAppName string = conductorApp.name
output conductorIdentityClientId string = conductorIdentity.properties.clientId
output runnerIdentityClientId string = runnerIdentity.properties.clientId
output storageAccountName string = storage.name
@description('Where the API and the GUI answer.')
output conductorUrl string = 'https://${conductorApp.properties.configuration.ingress.fqdn}'
@description('The redirect URI to register on the GUI\'s public client (SPA platform).')
output conductorGuiRedirectUri string = 'https://${conductorApp.properties.configuration.ingress.fqdn}/ui/'
@description('The Conductor configuration as deployed, for review.')
output conductorConfig object = conductorConfig
