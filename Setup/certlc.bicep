/* 

CERTLC - Bicep file for deploying the required resources for the CERTLC solution.

Validate with: az deployment group validate --resource-group <existing resource group> -parameters .\parameters.dev.bicepparam
What-if: az deployment group what-if --resource-group <existing resource group> -parameters .\parameters.dev.bicepparam
Deploy with: az deployment group create --resource-group <existing resource group> -parameters .\parameters.dev.bicepparam

*/

targetScope = 'resourceGroup'

@description('The ID of the subnet to use for the private endpoint connections')
param peSubnetId string

@description('The ID of the subnet to use for the function app - for Flex functions, it must be delegated to Microsoft.App/environments')
param fnSubnetId string

@description('Subscription ID where the Private DNS Zones are located')
param dnsZonesSubscriptionId string

@description('Resource Group name where the Private DNS Zones are located')
param dnsZonesResourceGroupName string

@description('The name of the storage account to create')
param storageAccountName string

@description('The name of the function app to create')
param functionAppName string

@description('The name of the log analytics workspace to create')
param logAnalyticsWorkspaceName string

@description('The name of the application insights to create')
param applicationInsightsName string

@description('The name of the automation account to create')
param automationAccountName string

@description('The name of the hybrid worker group to create')
param hybridWorkerGroupName string

@description('The name of the KeyVault to create')
param keyVaultName string

@description('The name of the Data Collection Endpoint (DCE) to create')
param dataCollectionEndpointName string

@description('The name of the Data Collection Rule (DCR) to create')
param dataCollectionRuleName string

@description('The name of the CA to use (for the automation account variable)')
param automationAccountVarCA string

@description('The name of the folder to use (for the automation account variable)')
param automationAccountVarPfxRootFolder string

@description('The SMTP From address to use (for the automation account variable)')
param automationAccountVarSmtpFrom string

@description('The SMTP Server to use (for the automation account variable)')
param automationAccountVarSmtpServer string

@description('The SMTP User to use (for the automation account variable)')
param automationAccountVarSmtpUser string

@description('The SMTP Password to use (for the automation account variable)')
@secure()
param automationAccountVarSmtpPassword string

/**********************/
/* EXISTING RESOURCES */
/**********************/

// References to existing Private DNS Zones in their subscription
resource blobDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' existing = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

resource keyVaultDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' existing = {
  name: 'privatelink.vaultcore.azure.net'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

resource queueDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' existing = {
  name: 'privatelink.queue.${environment().suffixes.storage}'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

resource webAppDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' existing = {
  name: 'privatelink.azurewebsites.net'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

resource automationAccountDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' existing = {
  name: 'privatelink.azure-automation.net'
  scope: resourceGroup(dnsZonesSubscriptionId, dnsZonesResourceGroupName)
}

/*****************/
/* NEW RESOURCES */
/*****************/

// Storage Account
resource storageAccount 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageAccountName
  location: resourceGroup().location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    defaultToOAuthAuthentication: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
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
  }
  resource queueServices 'queueServices' = {
    name: 'default'
    properties: {}
    resource queues 'queues' = {
      name: 'certlc'
      properties: {}
    }
  }

  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private endpoint for the storage account - blob
resource storageAccountBlobPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: 'pe-blob-${storageAccountName}'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: peSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'pls-${storageAccountName}'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
    customNetworkInterfaceName: 'nic-pe-${storageAccountName}'
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private DNS Zone Group for the storage account - blob
resource storageAccountBlobPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: storageAccountBlobPrivateEndpoint
  name: 'pdzg-${storageAccountBlobPrivateEndpoint.name}'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'pdzc-${storageAccountBlobPrivateEndpoint.name}'
        properties: {
          privateDnsZoneId: blobDnsZone.id
        }
      }
    ]
  }
}

// Private endpoint for the storage account - queue
resource storageAccountQueuePrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: 'pe-queue-${storageAccountName}'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: peSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'pls-${storageAccountName}'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [
            'queue'
          ]
        }
      }
    ]
    customNetworkInterfaceName: 'nic-pe-queue-${storageAccountName}'
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private DNS Zone Group for the storage account - queue
resource storageAccountQueuePrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: storageAccountQueuePrivateEndpoint
  name: 'pdzg-${storageAccountQueuePrivateEndpoint.name}'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'pdzc-${storageAccountQueuePrivateEndpoint.name}'
        properties: {
          privateDnsZoneId: queueDnsZone.id
        }
      }
    ]
  }
}

// Log Analytics Workspace
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsWorkspaceName
  location: resourceGroup().location
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// Custom Table for Certificate Statistics
resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  name: 'certlc_CL'
  parent: logAnalyticsWorkspace
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'certlc_CL'
      columns: [
        {
          name: 'TimeGenerated'
          type: 'datetime'
          description: 'The time the log was generated'
        }
        {
          name: 'Thumbprint'
          type: 'string'
          description: 'Certificate thumbprint'
        }
        {
          name: 'Name'
          type: 'string'
          description: 'Certificate name in Key Vault'
        }
        {
          name: 'Created'
          type: 'datetime'
          description: 'Certificate creation date'
        }
        {
          name: 'Expires'
          type: 'datetime'
          description: 'Certificate expiration date'
        }
        {
          name: 'Subject'
          type: 'string'
          description: 'Certificate subject'
        }
        {
          name: 'Template'
          type: 'string'
          description: 'Certificate template used'
        }
        {
          name: 'DNSNames'
          type: 'string'
          description: 'Certificate DNS names (SAN)'
        }
      ]
    }
  }
}

// Data Collection Rule for Certificate Statistics
resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dataCollectionRuleName
  location: resourceGroup().location
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
  properties: {
    dataCollectionEndpointId: dataCollectionEndpoint.id
    streamDeclarations: {
      'Custom-certlc_CL': {
        columns: [
          {
            name: 'Thumbprint'
            type: 'string'
          }
          {
            name: 'Name'
            type: 'string'
          }
          {
            name: 'Created'
            type: 'datetime'
          }
          {
            name: 'Expires'
            type: 'datetime'
          }
          {
            name: 'Subject'
            type: 'string'
          }
          {
            name: 'Template'
            type: 'string'
          }
          {
            name: 'DNSNames'
            type: 'string'
          }
        ]
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
    customTable     // the DCR must be created after the custom table
  ]
}

// Application Insights
resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: resourceGroup().location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspace.id
    DisableLocalAuth: true
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Flexible Consumption Plan for the function app
resource flexServicePlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: 'plan-${functionAppName}'
  location: resourceGroup().location
  kind: 'functionapp'
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  properties: {
    reserved: true
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Function App
resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: functionAppName
  location: resourceGroup().location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: flexServicePlan.id
    httpsOnly: true
    virtualNetworkSubnetId: fnSubnetId
    publicNetworkAccess: 'Disabled'
    siteConfig: {
      minTlsVersion: '1.2'
      vnetRouteAllEnabled: false
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
      ResourceGroupName: resourceGroup().name
      AzureWebJobsStorage__credential: 'managedidentity'
      AzureWebJobsStorage__blobServiceUri: storageAccount.properties.primaryEndpoints.blob
      AzureWebJobsStorage__queueServiceUri: storageAccount.properties.primaryEndpoints.queue
      APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'Authorization=AAD'
      APPLICATIONINSIGHTS_CONNECTION_STRING: applicationInsights.properties.ConnectionString
    }
  }
  dependsOn: [
    storageAccountBlobPrivateDnsZoneGroup // create the function only after the PEs for the storage account are ready
    storageAccountQueuePrivateDnsZoneGroup
  ]
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private endpoint for the function app
resource functionAppPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: 'pe-sites-${functionAppName}'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: peSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'pls-${functionAppName}'
        properties: {
          privateLinkServiceId: functionApp.id
          groupIds: [
            'sites'
          ]
        }
      }
    ]
    customNetworkInterfaceName: 'nic-pe-${functionAppName}'
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private DNS Zone Group for the function app
resource functionAppPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: functionAppPrivateEndpoint
  name: 'pdzg-${functionAppPrivateEndpoint.name}'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'pdzc-${functionAppPrivateEndpoint.name}'
        properties: {
          privateDnsZoneId: webAppDnsZone.id
        }
      }
    ]
  }
}

// Data Collection Endpoint
resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dataCollectionEndpointName
  location: resourceGroup().location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Automation Account with its managed identity
resource automationAccount 'Microsoft.Automation/automationAccounts@2024-10-23' = {
  name: automationAccountName
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publicNetworkAccess: false
    sku: {
      name: 'Basic'
    }
  }
  // variables
  resource automationAccountVariables 'variables@2024-10-23' = {
    name: 'certlc-ca'
    properties: {
      value: '"${replace(automationAccountVarCA, '\\', '\\\\')}"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesPfxRootFolder 'variables@2024-10-23' = {
    name: 'certlc-pfx-root-folder'
    properties: {
      value: '"${replace(automationAccountVarPfxRootFolder, '\\', '\\\\')}"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesSmtpFrom 'variables@2024-10-23' = {
    name: 'certlc-smtpfrom'
    properties: {
      value: '"${replace(automationAccountVarSmtpFrom, '\\', '\\\\')}"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesSmtpServer 'variables@2024-10-23' = {
    name: 'certlc-smtpserver'
    properties: {
      value: '"${replace(automationAccountVarSmtpServer, '\\', '\\\\')}"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesSmtpUser 'variables@2024-10-23' = {
    name: 'certlc-smtpuser'
    properties: {
      value: '"${replace(automationAccountVarSmtpUser, '\\', '\\\\')}"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesSmtpPassword 'variables@2024-10-23' = {
    name: 'certlc-smtppassword'
    properties: {
      value: '"${replace(automationAccountVarSmtpPassword, '\\', '\\\\')}"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesKeyVault 'variables@2024-10-23' = {
    name: 'certlc-stats-keyvault'
    properties: {
      value: '"${keyVault.name}"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesImmutableId 'variables@2024-10-23' = {
    name: 'certlc-stats-immutableid'
    properties: {
      value: '"${dataCollectionRule.properties.immutableId}"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesStreamName 'variables@2024-10-23' = {
    name: 'certlc-stats-streamname'
    properties: {
      value: '"Custom-certlc_CL"'
      isEncrypted: true
    }
  }
  resource automationAccountVariablesIngestionUrl 'variables@2024-10-23' = {
    name: 'certlc-stats-ingestionurl'
    properties: {
      value: '"${dataCollectionEndpoint.properties.logsIngestion.endpoint}"'
      isEncrypted: true
    }
  }
}

// Hybrid Worker Group
resource hybridWorkerGroup 'Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups@2023-11-01' = {
  name: hybridWorkerGroupName
  parent: automationAccount
  properties: {
    // Hybrid worker group properties - workers will be added separately
  }
}

// Private endpoint for the Automation Account - Webhook
resource automationAccountPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: 'pe-webhook-${automationAccountName}'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: peSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'pls-${automationAccountName}'
        properties: {
          privateLinkServiceId: automationAccount.id
          groupIds: [
            'Webhook'
          ]
        }
      }
    ]
    customNetworkInterfaceName: 'nic-pe-webhook-${automationAccountName}'
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private DNS Zone Group for the Automation Account - Webhook
resource automationAccountPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: automationAccountPrivateEndpoint
  name: 'pdzg-${automationAccountPrivateEndpoint.name}'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'pdzc-${automationAccountPrivateEndpoint.name}'
        properties: {
          privateDnsZoneId: automationAccountDnsZone.id
        }
      }
    ]
  }
}

// Private endpoint for the Automation Account - DSCAndHybridWorker
resource automationAccountPrivateEndpointDSCAndHybridWorker 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: 'pe-dscandhybridworker-${automationAccountName}'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: peSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'pls-dscandhybridworker-${automationAccountName}'
        properties: {
          privateLinkServiceId: automationAccount.id
          groupIds: [
            'DSCAndHybridWorker'
          ]
        }
      }
    ]
    customNetworkInterfaceName: 'nic-pe-dscandhybridworker-${automationAccountName}'
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private DNS Zone Group for the Automation Account - DSCAndHybridWorker
resource automationAccountPrivateDnsZoneGroupDSCAndHybridWorker 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: automationAccountPrivateEndpointDSCAndHybridWorker
  name: 'pdzg-dscandhybridworker-${automationAccountPrivateEndpointDSCAndHybridWorker.name}'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'pdzc-dscandhybridworker-${automationAccountPrivateEndpointDSCAndHybridWorker.name}'
        properties: {
          privateDnsZoneId: automationAccountDnsZone.id
        }
      }
    ]
  }
}

// KeyVault
resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  name: keyVaultName
  location: resourceGroup().location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enableRbacAuthorization: true
    publicNetworkAccess: 'Disabled'
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private endpoint for the KeyVault
resource keyVaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: 'pe-vault-${keyVaultName}'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: peSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'pls-${keyVaultName}'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
    customNetworkInterfaceName: 'nic-pe-${keyVaultName}'
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
}

// Private DNS Zone Group for the KeyVault
resource keyVaultPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: keyVaultPrivateEndpoint
  name: 'pdzg-${keyVaultPrivateEndpoint.name}'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'pdzc-${keyVaultPrivateEndpoint.name}'
        properties: {
          privateDnsZoneId: keyVaultDnsZone.id
        }
      }
    ]
  }
}

// Event Grid System Topic for the KeyVault
resource keyVaultEventGridSystemTopic 'Microsoft.EventGrid/systemTopics@2025-02-15' = {
  name: 'egst-${keyVaultName}'
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    source: keyVault.id
    topicType: 'Microsoft.KeyVault.Vaults'
  }
  tags: {
    solution: 'CertLC'
    purpose: 'Certificate Lifecycle Management'
  }
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
  }
}

// Role Assignment: Grant the Event Grid System Topic the "Storage Queue Data Reader" role on the Storage Account
// this role allows Event Grid to read messages from the queue
resource eventGridStorageQueueDataReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'eventGridStorageQueueDataReader')
  scope: storageAccount
  properties: {
    description: 'EventGrid SystemTopic -> Storage Queue Data Reader -> Storage Account'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '19e7f393-937e-4f77-808e-94535e297925'
    ) // Storage Queue Data Reader
    principalId: keyVaultEventGridSystemTopic.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Event Grid System Topic the "Storage Queue Data Message Sender" role on the Storage Account
// this role allows Event Grid to send messages to the queue
resource eventGridStorageQueueDataMessageSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'eventGridStorageQueueDataMessageSender')
  scope: storageAccount
  properties: {
    description: 'EventGrid SystemTopic -> Storage Queue Data Message Sender -> Storage Account'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'
    ) // Storage Queue Data Message Sender
    principalId: keyVaultEventGridSystemTopic.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Automation Account the "Key Vault Certificates Officer" role on the KeyVault
// this role allows the automation account to create and manage certificates in the KeyVault
resource automationAccountKeyVaultCertificatesOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'automationAccountKeyVaultCertificatesOfficer')
  scope: keyVault
  properties: {
    description: 'Automation Account -> Key Vault Certificates Officer -> Key Vault'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'a4417e6f-fecd-4de8-b567-7b0420556985'
    ) // Key Vault Certificates Officer
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Automation Account the "Key Vault Secrets Officer" role on the KeyVault
// this role allows the automation account to create and manage secrets (private keys of the certificates) in the KeyVault
resource automationAccountKeyVaultSecretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'automationAccountKeyVaultSecretsOfficer')
  scope: keyVault
  properties: {
    description: 'Automation Account -> Key Vault Secrets Officer -> Key Vault'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
    ) // Key Vault Secrets Officer
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Automation Account the "Reader" role on the Automation Account
// This may seem strange, but it is required for the hybrid worker (that uses the automation account's identity) to read the automation account variables
resource automationAccountReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'automationAccountReader')
  scope: automationAccount
  properties: {
    description: 'Automation Account -> Reader -> Automation Account (self)'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'acdd72a7-3385-48ef-bd42-f606fba81ae7'
    ) // Reader Role
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Automation Account the "Monitoring Metrics Publisher" role on the DCR
// (this is to allow the automation account to write custom logs to the DCR)
resource automationAccountMonitoringMetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'automationAccountMonitoringMetricsPublisher')
  scope: dataCollectionRule
  properties: {
    description: 'Automation Account -> Monitoring Metrics Publisher -> DCR'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '3913510d-42f4-4e42-8a64-420c390055eb'
    ) // Monitoring Metrics Publisher
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Function App the "Storage Blob Data Owner" role on the Storage Account
resource functionAppStorageBlobDataOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'functionAppStorageBlobDataOwner')
  scope: storageAccount
  properties: {
    description: 'Function App -> Storage Blob Data Owner -> Storage Account'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
    ) // Storage Blob Data Owner
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Function App the "Storage Queue Data Message Processor" role on the Storage Account
resource functionAppStorageQueueDataMessageProcessor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'functionAppStorageQueueDataMessageProcessor')
  scope: storageAccount
  properties: {
    description: 'Function App -> Storage Queue Data Message Processor -> Storage Account'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '8a0f0c08-91a1-4084-bc3d-661d67233fed'
    ) // Storage Queue Data Message Processor
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Function App the "Storage Queue Data Contributor" role on the Storage Account
resource functionAppStorageQueueDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'functionAppStorageQueueDataContributor')
  scope: storageAccount
  properties: {
    description: 'Function App -> Storage Queue Data Contributor -> Storage Account'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
    ) // Storage Queue Data Contributor
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Function App the "Reader" role on the Automation Account
// (this is to allow the function app to read automation account information and trigger runbooks)
resource functionAppAutomationAccountReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'functionAppAutomationAccountReader')
  scope: automationAccount
  properties: {
    description: 'Function App -> Reader -> Automation Account'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'acdd72a7-3385-48ef-bd42-f606fba81ae7'
    ) // Reader
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Function App the "Automation Operator" role on the Automation Account
// (this is to allow the function app to start runbook jobs)
resource functionAppAutomationOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'functionAppAutomationOperator')
  scope: automationAccount
  properties: {
    description: 'Function App -> Automation Operator -> Automation Account'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'd3881f73-407a-4167-8283-e981cbba0404'
    ) // Automation Operator
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role Assignment: Grant the Function App the "Monitoring Metrics Publisher" role on the Application Insights instance
// (this is to instrument the function app with App Insights)
resource functionAppMonitoringMetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'functionAppMonitoringMetricsPublisher')
  scope: applicationInsights
  properties: {
    description: 'Function App -> Monitoring Metrics Publisher -> Application Insights'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '3913510d-42f4-4e42-8a64-420c390055eb'
    ) // Monitoring Metrics Publisher
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output logAnalyticsWorkspaceId string = logAnalyticsWorkspace.id
output customTableName string = customTable.name
output dataCollectionRuleId string = dataCollectionRule.id
output dataCollectionRuleImmutableId string = dataCollectionRule.properties.immutableId
output dataCollectionEndpointId string = dataCollectionEndpoint.id
output keyVaultName string = keyVault.name
output automationAccountName string = automationAccount.name
output functionAppName string = functionApp.name

// Role Assignment GUID Mappings (for troubleshooting)
output roleAssignmentGuids object = {
  eventGridToStorageQueueDataReader: eventGridStorageQueueDataReader.name
  eventGridToStorageQueueDataMessageSender: eventGridStorageQueueDataMessageSender.name
  automationAccountToKeyVaultCertificatesOfficer: automationAccountKeyVaultCertificatesOfficer.name
  automationAccountToKeyVaultSecretsOfficer: automationAccountKeyVaultSecretsOfficer.name
  automationAccountToAutomationAccountReader: automationAccountReader.name
  automationAccountToDCRMonitoringMetricsPublisher: automationAccountMonitoringMetricsPublisher.name
  functionAppToStorageBlobDataOwner: functionAppStorageBlobDataOwner.name
  functionAppToStorageQueueDataContributor: functionAppStorageQueueDataContributor.name
  functionAppToStorageQueueDataMessageProcessor: functionAppStorageQueueDataMessageProcessor.name
  functionAppToAutomationAccountReader: functionAppAutomationAccountReader.name
  functionAppToAutomationOperator: functionAppAutomationOperator.name
  functionAppToAppInsightsMonitoringMetricsPublisher: functionAppMonitoringMetricsPublisher.name
}
