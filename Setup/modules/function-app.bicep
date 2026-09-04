// Deploys the Flex Consumption plan, PowerShell Function App, settings, and private endpoint.
targetScope = 'resourceGroup'

param location string
param functionAppName string
param functionSubnetId string
param deploymentContainerUri string
param storageBlobEndpoint string
param storageQueueEndpoint string
param applicationInsightsConnectionString string
param automationAccountName string
param hybridWorkerGroupName string
param runbookName string
param peSubnetId string
param privateDnsZoneId string
param tags object

// Flex Consumption provides the Linux PowerShell 7.6 hosting plan.
resource flexServicePlan 'Microsoft.Web/serverfarms@2025-03-01' = {
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
  tags: tags
}

// Managed identity is used for host storage, Application Insights, and Automation access.
resource functionApp 'Microsoft.Web/sites@2025-03-01' = {
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
    virtualNetworkSubnetId: functionSubnetId
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
          value: deploymentContainerUri
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
        version: '7.6'
      }
    }
  }
  resource appSettings 'config' = {
    name: 'appsettings'
    properties: {
      AutomationAccountName: automationAccountName
      HybridWorkerGroupName: hybridWorkerGroupName
      RunbookName: runbookName
      ResourceGroupName: resourceGroup().name
      RunbookPollingTimeoutMinutes: '25'
      AzureWebJobsStorage__credential: 'managedidentity'
      AzureWebJobsStorage__blobServiceUri: storageBlobEndpoint
      AzureWebJobsStorage__queueServiceUri: storageQueueEndpoint
      APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'Authorization=AAD'
      APPLICATIONINSIGHTS_CONNECTION_STRING: applicationInsightsConnectionString
    }
  }
  tags: tags
}

// Keeping the endpoint here means consumers of module outputs wait for private access to be ready.
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2025-07-01' = {
  name: 'pe-sites-${functionAppName}'
  location: location
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
  tags: tags
}

resource privateEndpointDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-07-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}

// Integrations and workbook modules consume only the app identity and resource ID.
output id string = functionApp.id
output principalId string = functionApp.identity.principalId