// ACME Conductor on Azure Container Apps (Phase 4).
//
// Deploys, in one resource group:
//   - a Container Apps environment with a Log Analytics workspace;
//   - a storage account with three file shares mounted into the
//     environment: conductor-state (the SQLite registry), runner-state
//     (ACME account state) and exchange (signed jobs in, results out);
//   - two user-assigned identities, one per binary, with disjoint grants
//     (docs/threat-model.md, T10): the Conductor's may start, observe and
//     stop executions of the Runner Job and nothing else; the Runner's may
//     write TXT records in one DNS zone and import certificates into one
//     Key Vault, and nothing else;
//   - the Runner as a manually triggered Container Apps Job (one execution
//     per run, started by the Conductor);
//   - the Conductor as a single-replica Container App without ingress.
//
// Nothing here is a secret except the job-signing private key, which is a
// secure parameter stored as a Container App secret and mounted as a file.
// No DNS or Key Vault credential exists anywhere: both are the Runner's
// managed identity. See deploy/azure/README.md for what this template does
// not verify and how to operate the result.
targetScope = 'resourceGroup'

// --- parameters --------------------------------------------------------------

@description('Azure region for every resource.')
param location string = resourceGroup().location

@description('Name prefix for the resources created here (letters, digits, hyphens).')
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

@description('Logical ACME binding names the Conductor registers (must match the Runner configuration).')
param acmeBindings array

@description('Logical DNS binding names the Conductor registers (must match the Runner configuration).')
param dnsBindings array

@description('Logical store binding names the Conductor registers (must match the Runner configuration).')
param storeBindings array

@description('Name of the DNS zone the Runner completes challenges in.')
param dnsZoneName string

@description('Resource group of the DNS zone.')
param dnsZoneResourceGroup string

@description('Subscription of the DNS zone (defaults to this one).')
param dnsZoneSubscriptionId string = subscription().subscriptionId

@description('Name of the Key Vault the Runner stores certificates in (RBAC permission model).')
param keyVaultName string

@description('Resource group of the Key Vault.')
param keyVaultResourceGroup string

@description('Subscription of the Key Vault (defaults to this one).')
param keyVaultSubscriptionId string = subscription().subscriptionId

@description('Maximum seconds one Runner execution may run before the platform stops it. Keep it above the Runner lego.timeoutSeconds and below the Conductor timeoutSeconds.')
@minValue(60)
@maxValue(86400)
param runnerReplicaTimeoutSeconds int = 1500

@description('Conductor-side timeout for one execution (seconds); must exceed runnerReplicaTimeoutSeconds.')
@minValue(60)
@maxValue(86400)
param conductorLaunchTimeoutSeconds int = 1800

@description('How long a signed job stays acceptable after issue (seconds). It only has to cover the platform start latency.')
@minValue(60)
@maxValue(86400)
param jobSigningValiditySeconds int = 900

@description('Optional image for an administration sidecar in the Conductor replica (a shell with curl reaches the loopback-only API through `az containerapp exec`). Empty deploys no sidecar. Pin by digest.')
param adminSidecarImage string = ''

@description('Scheduler settings copied into the Conductor configuration.')
param schedulerTickSeconds int = 60
param schedulerMaxConcurrentRuns int = 2

@description('Tags applied to every resource.')
param tags object = {}

// --- names -------------------------------------------------------------------

var environmentName = '${namePrefix}-cae'
var workspaceName = '${namePrefix}-log'
// Storage account names: 3-24 lower-case alphanumerics, globally unique.
var storageAccountName = toLower(replace('${namePrefix}${uniqueString(resourceGroup().id)}', '-', ''))
var conductorIdentityName = '${namePrefix}-id-conductor'
var runnerIdentityName = '${namePrefix}-id-runner'
var runnerJobName = '${namePrefix}-runner'
var conductorAppName = '${namePrefix}-conductor'

var shareConductorState = 'conductor-state'
var shareRunnerState = 'runner-state'
var shareExchange = 'exchange'

// --- roles (subscription scope) ----------------------------------------------

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

// --- the Runner: a manually triggered Job ------------------------------------

// The operator's Runner configuration plus the Conductor's public key, so
// the Runner cannot be deployed without the key it needs to verify jobs.
var runnerConfig = union(json(runnerConfigJson), {
  jobSigning: {
    publicKeys: [
      jobSigningPublicKey
    ]
  }
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
      triggerType: 'Manual'
      replicaTimeout: runnerReplicaTimeoutSeconds
      // A retried replica would present the same signed job again; the
      // Runner refuses it (replay ledger) and the retry only burns time.
      replicaRetryLimit: 0
      manualTriggerConfig: {
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
      ]
    }
    template: {
      containers: [
        {
          name: 'runner'
          image: runnerImage
          // The Conductor supplies the arguments of each execution
          // (reconcile --job ... --result ...); these defaults make a
          // stray manual start fail fast instead of doing anything.
          args: [
            '--version'
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

// --- the Conductor: a single-replica app without ingress ---------------------

var conductorConfig = {
  apiVersion: 'acme-conductor.cits-nue.github.io/v1alpha1'
  kind: 'ConductorConfig'
  server: {
    listen: '127.0.0.1:8080'
    auth: {
      mode: 'localhost-dev'
    }
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
  executionBindings: {
    azure: {
      type: 'azure-container-apps-job'
      azureContainerAppsJob: {
        subscriptionId: subscription().subscriptionId
        resourceGroup: resourceGroup().name
        jobName: runnerJob.name
        credential: 'managed-identity'
        managedIdentityClientId: conductorIdentity.properties.clientId
        containerName: 'runner'
        exchangeDir: '/mnt/exchange'
        runnerExchangeDir: '/exchange'
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

// An optional sidecar in the same replica: it shares the loopback
// interface with the Conductor, so a shell obtained with
// `az containerapp exec --container admin` is a loopback peer of the API
// and therefore an administrator under localhost-dev (docs/adr/0012).
// Access to that command is what RBAC on the Container App gates.
var adminContainer = {
  name: 'admin'
  image: adminSidecarImage
  command: [
    'sleep'
    'infinity'
  ]
  resources: {
    cpu: json('0.25')
    memory: '0.5Gi'
  }
}

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
      // No ingress: the API listens on the replica's loopback only.
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
      containers: empty(adminSidecarImage) ? [conductorContainer] : [conductorContainer, adminContainer]
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

// Conductor identity -> start/observe/stop executions of this Job only.
resource conductorStartsRunner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(runnerJob.id, conductorIdentity.id, 'job-starter')
  scope: runnerJob
  properties: {
    principalId: conductorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roles.outputs.conductorJobStarterRoleId
  }
}

// Runner identity -> TXT records in the challenge zone.
module runnerDns 'modules/dns-role-assignment.bicep' = {
  name: '${deployment().name}-dns'
  scope: resourceGroup(dnsZoneSubscriptionId, dnsZoneResourceGroup)
  params: {
    dnsZoneName: dnsZoneName
    runnerPrincipalId: runnerIdentity.properties.principalId
    roleDefinitionId: roles.outputs.runnerDnsTxtWriterRoleId
  }
}

// Runner identity -> import certificates into the vault.
module runnerKeyVault 'modules/keyvault-role-assignment.bicep' = {
  name: '${deployment().name}-keyvault'
  scope: resourceGroup(keyVaultSubscriptionId, keyVaultResourceGroup)
  params: {
    keyVaultName: keyVaultName
    runnerPrincipalId: runnerIdentity.properties.principalId
    roleDefinitionId: roles.outputs.runnerKeyVaultCertificateWriterRoleId
  }
}

// --- outputs -----------------------------------------------------------------

output environmentName string = environment.name
output runnerJobName string = runnerJob.name
output conductorAppName string = conductorApp.name
output conductorIdentityClientId string = conductorIdentity.properties.clientId
output runnerIdentityClientId string = runnerIdentity.properties.clientId
output storageAccountName string = storage.name
@description('The Conductor configuration as deployed, for review.')
output conductorConfig object = conductorConfig
