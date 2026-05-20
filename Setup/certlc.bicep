/* 

CERTLC - Bicep file for deploying the required resources for the CERTLC solution.

Validate with: az deployment group validate --resource-group <existing resource group> -parameters .\parameters.dev.bicepparam
What-if: az deployment group what-if --resource-group <existing resource group> -parameters .\parameters.dev.bicepparam
Deploy with: az deployment group create --resource-group <existing resource group> -parameters .\parameters.dev.bicepparam

*/

metadata name = 'CertLC Infrastructure'
metadata description = 'Azure infrastructure deployment for Certificate Lifecycle Management solution with automated certificate enrollment, renewal, and monitoring'

targetScope = 'resourceGroup'

@description('The Azure region where resources will be deployed. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('The resource ID of the subnet for private endpoint connections. Format: /subscriptions/{subscriptionId}/resourceGroups/{rgName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}')
param peSubnetId string

@description('The resource ID of the subnet for the function app VNet integration. Must be delegated to Microsoft.App/environments for Flex Consumption plans. Format: /subscriptions/{subscriptionId}/resourceGroups/{rgName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}')
param fnSubnetId string

@description('The subscription ID where existing Private DNS Zones are located (for privatelink zones). Format: GUID')
param dnsZonesSubscriptionId string

@description('The resource group name containing existing Private DNS Zones (e.g., privatelink.blob.core.windows.net, privatelink.vaultcore.azure.net)')
param dnsZonesResourceGroupName string

@description('The name of the storage account to create. Must be globally unique, 3-24 characters, lowercase letters and numbers only. Used for function app storage and certificate lifecycle queue.')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('The name of the function app to create. Must be globally unique, 2-60 characters, alphanumerics and hyphens. Hosts the queue processor and automation triggers.')
@minLength(2)
@maxLength(60)
param functionAppName string

@description('The name of the Log Analytics workspace for centralized logging and monitoring. Stores diagnostic logs, custom certificate statistics, and application telemetry.')
param logAnalyticsWorkspaceName string

@description('Retention in days for the Log Analytics workspace and the certlc_CL custom table. Range 30-730. Default 30 (lab-friendly).')
@minValue(30)
@maxValue(730)
param logAnalyticsRetentionInDays int = 30

@description('The name of the Application Insights instance for function app monitoring and performance tracking.')
param applicationInsightsName string

@description('The name of the Automation Account to create. 6-50 characters, alphanumerics and hyphens. Executes certificate lifecycle runbooks on hybrid workers.')
@minLength(6)
@maxLength(50)
param automationAccountName string

@description('The name of the hybrid runbook worker group. On-premises workers must be registered to this group to execute certificate operations.')
param hybridWorkerGroupName string

@description('The name of the runbook to invoke for certificate lifecycle operations. Must match the runbook name deployed to the Automation Account.')
param runbookName string

@description('The name of the custom PowerShell 7.6 runtime environment to create on the Automation Account and use for the runbooks. Note: runtime environment names cannot contain dots.')
param runtimeEnvironmentName string = 'certlc-PowerShell-7-6'

@description('The name of the Key Vault to create. Must be globally unique, 3-24 characters, alphanumerics and hyphens. Stores and manages certificates with automated lifecycle tracking.')
@minLength(3)
@maxLength(24)
param keyVaultName string

@description('Soft-delete retention in days for the Key Vault. Allowed range 7-90. Default 7 (lab-friendly minimum); use 90 for production.')
@minValue(7)
@maxValue(90)
param keyVaultSoftDeleteRetentionInDays int = 7

@description('The name of the Data Collection Endpoint (DCE) to create. Ingestion endpoint for custom certificate statistics logs sent from automation runbooks.')
param dataCollectionEndpointName string

@description('The name of the Data Collection Rule (DCR) to create. Defines transformation and routing of certificate statistics to Log Analytics custom table.')
param dataCollectionRuleName string

@description('The Certificate Authority name for certificate enrollment. Format: CA_SERVER\\\\CA_NAME (e.g., PKI-CA01\\\\ContosoRootCA). Used by runbooks for ADCS operations.')
param automationAccountVarCA string

@description('The root folder path on hybrid workers where PFX certificates are stored. Format: UNC path or local path (e.g., \\\\\\\\fileserver\\\\certs or C:\\\\\\\\Certificates).')
param automationAccountVarPfxRootFolder string

@description('The SMTP From email address for certificate expiration notifications (e.g., certlc@contoso.com).')
param automationAccountVarSmtpFrom string

@description('The SMTP server hostname or IP address for sending email notifications (e.g., smtp.office365.com or smtp.gmail.com).')
param automationAccountVarSmtpServer string

@description('The SMTP username for authentication to the mail server. Required if the SMTP server requires authentication.')
param automationAccountVarSmtpUser string

@description('The SMTP password for authentication. Stored encrypted in Automation Account variables.')
@secure()
param automationAccountVarSmtpPassword string

@description('The start time for the certlcstats schedule. Defaults to 15 minutes from deployment time.')
param scheduleStartTime string = dateTimeAdd(utcNow('u'), 'PT15M')

/*************/
/* VARIABLES */
/*************/

// Common tags for all resources
var commonTags = {
  solution: 'CertLC'
  purpose: 'Certificate Lifecycle Management'
}

// Azure built-in role definition IDs
var roleDefinitions = {
  storageQueueDataReader: '19e7f393-937e-4f77-808e-94535e297925'
  storageQueueDataMessageSender: 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'
  keyVaultCertificatesOfficer: 'a4417e6f-fecd-4de8-b567-7b0420556985'
  keyVaultSecretsOfficer: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
  reader: 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
  monitoringMetricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
  storageBlobDataOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  storageBlobDataContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  storageQueueDataMessageProcessor: '8a0f0c08-91a1-4084-bc3d-661d67233fed'
  storageQueueDataContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  automationOperator: 'd3881f73-407a-4167-8283-e981cbba0404'
}

/**********************/
/* EXISTING RESOURCES */
/**********************/

// References to existing Private DNS Zones in their subscription
resource blobDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

resource keyVaultDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.vaultcore.azure.net'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

resource queueDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.queue.${environment().suffixes.storage}'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

resource webAppDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.azurewebsites.net'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

resource automationAccountDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.azure-automation.net'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

/*****************/
/* NEW RESOURCES */
/*****************/

// Storage Account
resource storageAccount 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    defaultToOAuthAuthentication: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    allowCrossTenantReplication: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
    publicNetworkAccess: 'Disabled'
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        queue: {
          enabled: true
        }
      }
    }
  }
  resource blobServices 'blobServices' = {
    name: 'default'
    properties: {}
    resource deadLetterContainer 'containers' = {
      name: 'eventgrid-deadletter'
      properties: {}
    }
  }
  resource queueServices 'queueServices' = {
    name: 'default'
    properties: {}
    resource queues 'queues' = {
      name: 'certlc'
      properties: {}
    }
  }

  tags: commonTags
}

// Private endpoints for the storage account (blob + queue).
// Declared here (before the function app) so the function app can depend on them: the function app
// reaches storage via private link, so it must not start before its PEs and DNS records are ready.
var storagePeDefs = [
  { peName: 'pe-blob-${storageAccountName}',  plsConnName: 'pls-${storageAccountName}', groupId: 'blob',  nicName: 'nic-pe-${storageAccountName}',       dnsKey: 'blob' }
  { peName: 'pe-queue-${storageAccountName}', plsConnName: 'pls-${storageAccountName}', groupId: 'queue', nicName: 'nic-pe-queue-${storageAccountName}', dnsKey: 'queue' }
]

resource storagePrivateEndpoints 'Microsoft.Network/privateEndpoints@2024-10-01' = [for d in storagePeDefs: {
  name: d.peName
  location: location
  properties: {
    subnet: { id: peSubnetId }
    privateLinkServiceConnections: [
      {
        name: d.plsConnName
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [ d.groupId ]
        }
      }
    ]
    customNetworkInterfaceName: d.nicName
  }
  tags: commonTags
}]

resource storagePrivateEndpointDnsGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = [for (d, i) in storagePeDefs: {
  parent: storagePrivateEndpoints[i]
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: d.dnsKey == 'blob' ? blobDnsZone.id : queueDnsZone.id
        }
      }
    ]
  }
}]

// Log Analytics Workspace
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: logAnalyticsWorkspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: logAnalyticsRetentionInDays
    features: {
      disableLocalAuth: true
    }
  }
  tags: commonTags
}

// Data Collection Endpoint
resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = {
  name: dataCollectionEndpointName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
  tags: commonTags
}

// Schema of the certlc_CL custom table data columns (shared between the LAW custom table and the DCR stream).
// The LAW table additionally prepends a TimeGenerated column (the DCR computes it via transformKql).
var certlcDataColumns = [
  { name: 'Thumbprint', type: 'string' }
  { name: 'Name',       type: 'string' }
  { name: 'Created',    type: 'datetime' }
  { name: 'Expires',    type: 'datetime' }
  { name: 'Subject',    type: 'string' }
  { name: 'Template',   type: 'string' }
  { name: 'DNSNames',   type: 'string' }
]

// Custom Table for Certificate Statistics
resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2025-02-01' = {
  name: 'certlc_CL'
  parent: logAnalyticsWorkspace
  properties: {
    retentionInDays: logAnalyticsRetentionInDays
    schema: {
      name: 'certlc_CL'
      columns: concat(
        [ { name: 'TimeGenerated', type: 'datetime' } ],
        certlcDataColumns
      )
    }
  }
}

// Data Collection Rule for Certificate Statistics
resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: dataCollectionRuleName
  location: location
  properties: {
    dataCollectionEndpointId: dataCollectionEndpoint.id
    streamDeclarations: {
      'Custom-certlc_CL': {
        columns: certlcDataColumns
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspace.id
          name: 'clv2ws1'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-certlc_CL'
        ]
        destinations: [
          'clv2ws1'
        ]
        transformKql: 'source | extend Created = todatetime(Created), Expires = todatetime(Expires) | extend TimeGenerated = now()'
        outputStream: 'Custom-certlc_CL'
      }
    ]
  }
  dependsOn: [
    customTable  // the DCR must be created after the custom table
  ]
  tags: commonTags
}

// Application Insights
// IMPORTANT: Deploy AFTER all Log Analytics operations are complete to avoid "Workspace not active" errors
resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspace.id
    DisableLocalAuth: true
  }
  dependsOn: [
    // Wait until the customTable (the last LAW child to provision) exists. By then the workspace backend is
    // fully ready, which avoids the "Workspace not active" race that App Insights would otherwise hit on first
    // deployment. (logAnalyticsWorkspace itself is already an implicit dep via WorkspaceResourceId.)
    customTable
  ]
  tags: commonTags
}

// Flexible Consumption Plan for the function app
resource flexServicePlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: 'asp-${functionAppName}'
  location: location
  kind: 'functionapp'
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  properties: {
    reserved: true
  }
  tags: commonTags
}

// Function App
resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: flexServicePlan.id
    httpsOnly: true
    clientAffinityEnabled: false
    keyVaultReferenceIdentity: 'SystemAssigned'
    virtualNetworkSubnetId: fnSubnetId
    publicNetworkAccess: 'Disabled'
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageAccount.properties.primaryEndpoints.blob}azure-webjobs-hosts'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 100
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'powerShell'
        version: '7.4'
      }
    }
  }
  resource appSettings 'config' = {
    name: 'appsettings'
    properties: {
      AutomationAccountName: automationAccount.name
      HybridWorkerGroupName: hybridWorkerGroupName
      RunbookName: runbookName
      ResourceGroupName: resourceGroup().name
      AzureWebJobsStorage__credential: 'managedidentity'
      AzureWebJobsStorage__blobServiceUri: storageAccount.properties.primaryEndpoints.blob
      AzureWebJobsStorage__queueServiceUri: storageAccount.properties.primaryEndpoints.queue
      APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'Authorization=AAD'
      APPLICATIONINSIGHTS_CONNECTION_STRING: applicationInsights.properties.ConnectionString
    }
  }
  dependsOn: [
    storagePrivateEndpoints // create the function only after the PEs for the storage account are ready
  ]
  tags: commonTags
}

// Automation Account with its managed identity
resource automationAccount 'Microsoft.Automation/automationAccounts@2024-10-23' = {
  name: automationAccountName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publicNetworkAccess: false
    // Local auth must remain enabled so that webhooks invoked via key in the URL query string keep working
    // (callers cannot use AAD). Do NOT set this to true unless all webhook callers have been migrated to AAD.
    disableLocalAuth: false
    sku: {
      name: 'Basic'
    }
  }
  tags: commonTags

  // Custom runtime environment based on PowerShell 7.6 with Az module preloaded
  resource runtimeEnv 'runtimeEnvironments@2024-10-23' = {
    name: runtimeEnvironmentName
    location: location
    properties: {
      runtime: {
        language: 'PowerShell'
        version: '7.6'
      }
      defaultPackages: {
        Az: '15.1.0'
        'Azure CLI': '2.77.0'
      }
    }
    tags: commonTags
  }

  // Runbook: certlc
  resource runbookCertLC 'runbooks@2024-10-23' = {
    name: 'certlc'
    location: location
    properties: {
      runbookType: 'PowerShell'
      logProgress: false
      logVerbose: false
      description: 'Certificate lifecycle management runbook for enrollment, renewal, and revocation'
      runtimeEnvironment: runtimeEnv.name
    }
    tags: commonTags
  }
  
  // Runbook: certlcstats
  resource runbookCertLCStats 'runbooks@2024-10-23' = {
    name: 'certlcstats'
    location: location
    properties: {
      runbookType: 'PowerShell'
      logProgress: false
      logVerbose: false
      description: 'Certificate statistics collection runbook for monitoring and reporting'
      runtimeEnvironment: runtimeEnv.name
    }
    tags: commonTags
  }

  // Schedule for certlcstats runbook - runs every hour
  // Note: Schedule is created but NOT linked to runbook initially (disabled state)
  // To enable: Link the schedule to the runbook in Azure Portal or via Azure CLI
  resource scheduleCertLCStats 'schedules@2024-10-23' = {
    name: 'schedule-certlcstats-hourly'
    properties: {
      description: 'Runs certlcstats runbook every hour to collect certificate statistics (manually link to enable)'
      startTime: scheduleStartTime
      frequency: 'Hour'
      interval: 1
      timeZone: 'UTC'
    }
  }

  // Uncomment to automatically link schedule to runbook (enables automatic execution on hybrid worker group)
  // resource jobScheduleCertLCStats 'jobSchedules@2024-10-23' = {
  //   name: guid(automationAccount.id, 'certlcstats-schedule')
  //   properties: {
  //     runbook: {
  //       name: runbookCertLCStats.name
  //     }
  //     schedule: {
  //       name: scheduleCertLCStats.name
  //     }
  //     runOn: hybridWorkerGroupName  // Execute on hybrid worker group (not Azure sandbox)
  //   }
  // }
}

// Automation Account variables (loop). Values are JSON-string-encoded:
// wrapped in double-quotes and with any backslashes escaped (replace is a no-op for values without backslashes).
// Note: the [for] iteratee must be calculable at the start of deployment (BCP178), so it lists only literal
// variable names; the actual values (some of which reference runtime resource properties) are looked up via
// the automationAccountVariableValues map inside the loop body.
var automationAccountVariableValues = {
  'certlc-ca':                 automationAccountVarCA
  'certlc-pfxrootfolder':      automationAccountVarPfxRootFolder
  'certlc-smtpfrom':           automationAccountVarSmtpFrom
  'certlc-smtpserver':         automationAccountVarSmtpServer
  'certlc-smtpuser':           automationAccountVarSmtpUser
  'certlc-smtppassword':       automationAccountVarSmtpPassword
  'certlc-stats-keyvault':     keyVault.name
  'certlc-stats-immutableid':  dataCollectionRule.properties.immutableId
  'certlc-stats-streamname':   'Custom-certlc_CL'
  'certlc-stats-ingestionurl': dataCollectionEndpoint.properties.logsIngestion.endpoint
}
var automationAccountVariableNames = [
  'certlc-ca'
  'certlc-pfxrootfolder'
  'certlc-smtpfrom'
  'certlc-smtpserver'
  'certlc-smtpuser'
  'certlc-smtppassword'
  'certlc-stats-keyvault'
  'certlc-stats-immutableid'
  'certlc-stats-streamname'
  'certlc-stats-ingestionurl'
]

resource automationAccountVariables 'Microsoft.Automation/automationAccounts/variables@2024-10-23' = [for n in automationAccountVariableNames: {
  parent: automationAccount
  name: n
  properties: {
    value: '"${replace(automationAccountVariableValues[n], '\\', '\\\\')}"'
    isEncrypted: true
  }
}]

// Hybrid Worker Group
resource hybridWorkerGroup 'Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups@2024-10-23' = {
  name: hybridWorkerGroupName
  parent: automationAccount
  properties: {
    // Hybrid worker group properties - workers will be added separately
  }
}

// Diagnostic Settings for Automation Account
resource automationAccountDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-${automationAccountName}'
  scope: automationAccount
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'JobLogs'
        enabled: true
      }
      {
        category: 'JobStreams'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// KeyVault
resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableSoftDelete: true
    softDeleteRetentionInDays: keyVaultSoftDeleteRetentionInDays
    enablePurgeProtection: true
    enableRbacAuthorization: true
    publicNetworkAccess: 'Disabled'
  }
  tags: commonTags
}

// Private endpoints for the application-tier resources: Function App, Automation Account (Webhook + DSCAndHybridWorker), Key Vault.
// Declared here (after the Key Vault) so all target resources are already in scope.
var appPeDefs = [
  { peName: 'pe-sites-${functionAppName}',                    plsConnName: 'pls-${functionAppName}',                          groupId: 'sites',              nicName: 'nic-pe-${functionAppName}',                          targetKey: 'function', dnsKey: 'webapp' }
  { peName: 'pe-webhook-${automationAccountName}',            plsConnName: 'pls-${automationAccountName}',                    groupId: 'Webhook',            nicName: 'nic-pe-webhook-${automationAccountName}',            targetKey: 'aa',       dnsKey: 'aa' }
  { peName: 'pe-dscandhybridworker-${automationAccountName}', plsConnName: 'pls-dscandhybridworker-${automationAccountName}', groupId: 'DSCAndHybridWorker', nicName: 'nic-pe-dscandhybridworker-${automationAccountName}', targetKey: 'aa',       dnsKey: 'aa' }
  { peName: 'pe-vault-${keyVaultName}',                       plsConnName: 'pls-${keyVaultName}',                             groupId: 'vault',              nicName: 'nic-pe-${keyVaultName}',                             targetKey: 'kv',       dnsKey: 'kv' }
]

// Lookup maps (resource ids are calculable at start; DNS zone ids likewise). Looked up inside the loop body.
var appPeTargetIds = {
  function: functionApp.id
  aa: automationAccount.id
  kv: keyVault.id
}
var appPeDnsZoneIds = {
  webapp: webAppDnsZone.id
  aa: automationAccountDnsZone.id
  kv: keyVaultDnsZone.id
}

resource appPrivateEndpoints 'Microsoft.Network/privateEndpoints@2024-10-01' = [for d in appPeDefs: {
  name: d.peName
  location: location
  properties: {
    subnet: { id: peSubnetId }
    privateLinkServiceConnections: [
      {
        name: d.plsConnName
        properties: {
          privateLinkServiceId: appPeTargetIds[d.targetKey]
          groupIds: [ d.groupId ]
        }
      }
    ]
    customNetworkInterfaceName: d.nicName
  }
  tags: commonTags
}]

resource appPrivateEndpointDnsGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = [for (d, i) in appPeDefs: {
  parent: appPrivateEndpoints[i]
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: appPeDnsZoneIds[d.dnsKey]
        }
      }
    ]
  }
}]

// Diagnostic Settings for Key Vault
resource keyVaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-${keyVaultName}'
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
      }
      {
        category: 'AzurePolicyEvaluationDetails'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// Event Grid System Topic for the KeyVault
resource keyVaultEventGridSystemTopic 'Microsoft.EventGrid/systemTopics@2025-02-15' = {
  name: 'egst-${keyVaultName}'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    source: keyVault.id
    topicType: 'Microsoft.KeyVault.Vaults'
  }
  tags: commonTags
}

// Event Grid subscription for the KeyVault to the queue
// This subscription filters only the CertificateNearExpiry events and sends them to the storage queue
resource keyVaultEventGridSubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2025-02-15' = {
  parent: keyVaultEventGridSystemTopic
  name: 'egs-${keyVaultEventGridSystemTopic.name}'
  properties: {
    destination: {
      endpointType: 'StorageQueue'
      properties: {
        resourceId: storageAccount.id
        queueName: 'certlc'
        queueMessageTimeToLiveInSeconds: 86400 // 1 day
      }
    }
    eventDeliverySchema: 'CloudEventSchemaV1_0'
    filter: {
      includedEventTypes: [
        'Microsoft.KeyVault.CertificateNearExpiry'
      ]
      isSubjectCaseSensitive: false
    }
    retryPolicy: {
      maxDeliveryAttempts: 30
      eventTimeToLiveInMinutes: 1440 // 1 day
    }
    deadLetterWithResourceIdentity: {
      identity: {
        type: 'SystemAssigned'
      }
      deadLetterDestination: {
        endpointType: 'StorageBlob'
        properties: {
          resourceId: storageAccount.id
          blobContainerName: 'eventgrid-deadletter'
        }
      }
    }
  }
  dependsOn: [
    storageRoleAssignments // ensure all storage role grants (incl. Storage Blob Data Contributor for dead-letter) are in place before EG validates destinations
  ]
}

// Azure Monitor Workbook for Certificate Statistics
resource workbookCertLCStats 'Microsoft.Insights/workbooks@2023-06-01' = {
  name: guid(resourceGroup().id, 'certlcstats')
  location: location
  kind: 'shared'
  properties: {
    displayName: 'certlcstats'
    serializedData: '{"version":"Notebook/1.0","items":[],"styleSettings":{},"$schema":"https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"}'
    category: 'workbook'
    sourceId: logAnalyticsWorkspace.id
  }
  dependsOn: [
    applicationInsights  // Wait for App Insights to ensure workspace is fully active
  ]
  tags: commonTags
}

// Role Assignments (grouped by scope so each loop has a constant scope, as required by Bicep)
// Note: variable arrays used in [for] cannot contain runtime resource references (BCP178), so principals are
// referenced by literal key here and resolved inside the loop body via the principalIds map below.
var principalIds = {
  eg: keyVaultEventGridSystemTopic.identity.principalId
  aa: automationAccount.identity.principalId
  fa: functionApp.identity.principalId
}

// On Storage Account: EG (read/send queue, dead-letter blob) + Function App (blob owner, queue processor, queue contributor)
var storageRoleAssignmentDefs = [
  { key: 'eventGridStorageQueueDataReader',             roleId: roleDefinitions.storageQueueDataReader,           principalKey: 'eg', description: 'EventGrid SystemTopic -> Storage Queue Data Reader -> Storage Account' }
  { key: 'eventGridStorageQueueDataMessageSender',      roleId: roleDefinitions.storageQueueDataMessageSender,    principalKey: 'eg', description: 'EventGrid SystemTopic -> Storage Queue Data Message Sender -> Storage Account' }
  { key: 'eventGridStorageBlobDataContributor',         roleId: roleDefinitions.storageBlobDataContributor,       principalKey: 'eg', description: 'EventGrid SystemTopic -> Storage Blob Data Contributor -> Storage Account (for dead-letter)' }
  { key: 'functionAppStorageBlobDataOwner',             roleId: roleDefinitions.storageBlobDataOwner,             principalKey: 'fa', description: 'Function App -> Storage Blob Data Owner -> Storage Account' }
  { key: 'functionAppStorageQueueDataMessageProcessor', roleId: roleDefinitions.storageQueueDataMessageProcessor, principalKey: 'fa', description: 'Function App -> Storage Queue Data Message Processor -> Storage Account' }
  { key: 'functionAppStorageQueueDataContributor',      roleId: roleDefinitions.storageQueueDataContributor,      principalKey: 'fa', description: 'Function App -> Storage Queue Data Contributor -> Storage Account' }
]
resource storageRoleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for d in storageRoleAssignmentDefs: {
  scope: storageAccount
  name: guid(subscription().id, resourceGroup().id, d.key)
  properties: {
    description: d.description
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', d.roleId)
    principalId: principalIds[d.principalKey]
    principalType: 'ServicePrincipal'
  }
}]

// On Key Vault: Automation Account (certificates officer, secrets officer)
var keyVaultRoleAssignmentDefs = [
  { key: 'automationAccountKeyVaultCertificatesOfficer', roleId: roleDefinitions.keyVaultCertificatesOfficer, principalKey: 'aa', description: 'Automation Account -> Key Vault Certificates Officer -> Key Vault' }
  { key: 'automationAccountKeyVaultSecretsOfficer',      roleId: roleDefinitions.keyVaultSecretsOfficer,      principalKey: 'aa', description: 'Automation Account -> Key Vault Secrets Officer -> Key Vault' }
]
resource keyVaultRoleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for d in keyVaultRoleAssignmentDefs: {
  scope: keyVault
  name: guid(subscription().id, resourceGroup().id, d.key)
  properties: {
    description: d.description
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', d.roleId)
    principalId: principalIds[d.principalKey]
    principalType: 'ServicePrincipal'
  }
}]

// On Automation Account: AA self-reader (needed by hybrid workers to read AA variables) + Function App (reader, automation operator)
var automationAccountRoleAssignmentDefs = [
  { key: 'automationAccountReader',            roleId: roleDefinitions.reader,             principalKey: 'aa', description: 'Automation Account -> Reader -> Automation Account (self; required for hybrid workers to read AA variables)' }
  { key: 'functionAppAutomationAccountReader', roleId: roleDefinitions.reader,             principalKey: 'fa', description: 'Function App -> Reader -> Automation Account' }
  { key: 'functionAppAutomationOperator',      roleId: roleDefinitions.automationOperator, principalKey: 'fa', description: 'Function App -> Automation Operator -> Automation Account' }
]
resource automationAccountRoleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for d in automationAccountRoleAssignmentDefs: {
  scope: automationAccount
  name: guid(subscription().id, resourceGroup().id, d.key)
  properties: {
    description: d.description
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', d.roleId)
    principalId: principalIds[d.principalKey]
    principalType: 'ServicePrincipal'
  }
}]

// Singletons (one-of-a-kind scope; no benefit from a loop)

// On Data Collection Rule: Automation Account (Monitoring Metrics Publisher) to allow AA to write custom logs
resource automationAccountMonitoringMetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'automationAccountMonitoringMetricsPublisher')
  scope: dataCollectionRule
  properties: {
    description: 'Automation Account -> Monitoring Metrics Publisher -> DCR'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitions.monitoringMetricsPublisher)
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// On Application Insights: Function App (Monitoring Metrics Publisher) to instrument the Function App
resource functionAppMonitoringMetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'functionAppMonitoringMetricsPublisher')
  scope: applicationInsights
  properties: {
    description: 'Function App -> Monitoring Metrics Publisher -> Application Insights'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitions.monitoringMetricsPublisher)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Output all resource IDs and important properties
output storageAccountId string = storageAccount.id
output storageAccountQueueUri string = storageAccount.properties.primaryEndpoints.queue
output automationAccountId string = automationAccount.id
output keyVaultId string = keyVault.id
output functionAppId string = functionApp.id
output logAnalyticsWorkspaceId string = logAnalyticsWorkspace.id
output applicationInsightsId string = applicationInsights.id
output dceIngestionEndpoint string = dataCollectionEndpoint.properties.logsIngestion.endpoint
@secure()
output dataCollectionRuleImmutableId string = dataCollectionRule.properties.immutableId
