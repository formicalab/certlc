// Deploys private Function host storage, lifecycle queues, and both storage private endpoints.
targetScope = 'resourceGroup'

param location string
param storageAccountName string
param peSubnetId string
param blobDnsZoneId string
param queueDnsZoneId string
param tags object

// The account uses managed identity authentication only; shared keys and public networking are disabled.
resource storageAccount 'Microsoft.Storage/storageAccounts@2026-04-01' = {
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
    resource deploymentContainer 'containers' = {
      name: 'azure-webjobs-hosts'
      properties: {}
    }
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
  tags: tags
}

// Blob and queue require separate private endpoints and DNS zones.
var privateEndpointDefinitions = [
  { peName: 'pe-blob-${storageAccountName}',  plsConnName: 'pls-${storageAccountName}', groupId: 'blob',  nicName: 'nic-pe-${storageAccountName}',       dnsZoneId: blobDnsZoneId }
  { peName: 'pe-queue-${storageAccountName}', plsConnName: 'pls-${storageAccountName}', groupId: 'queue', nicName: 'nic-pe-queue-${storageAccountName}', dnsZoneId: queueDnsZoneId }
]

resource privateEndpoints 'Microsoft.Network/privateEndpoints@2025-07-01' = [for definition in privateEndpointDefinitions: {
  name: definition.peName
  location: location
  properties: {
    subnet: { id: peSubnetId }
    privateLinkServiceConnections: [
      {
        name: definition.plsConnName
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [ definition.groupId ]
        }
      }
    ]
    customNetworkInterfaceName: definition.nicName
  }
  tags: tags
}]

resource privateEndpointDnsGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-07-01' = [for (definition, index) in privateEndpointDefinitions: {
  parent: privateEndpoints[index]
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: definition.dnsZoneId
        }
      }
    ]
  }
}]

// Consumers use these outputs for identity-based Function host configuration and Event Grid delivery.
output storageAccountId string = storageAccount.id
output blobEndpoint string = storageAccount.properties.primaryEndpoints.blob
output queueEndpoint string = storageAccount.properties.primaryEndpoints.queue
output deploymentContainerUri string = '${storageAccount.properties.primaryEndpoints.blob}${storageAccount::blobServices::deploymentContainer.name}'