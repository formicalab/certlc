// Connects CertLC services through Event Grid and least-privilege cross-service RBAC.
targetScope = 'resourceGroup'

param location string
param storageAccountName string
param storageAccountId string
param keyVaultName string
param keyVaultId string
param automationAccountName string
param automationPrincipalId string
param functionAppPrincipalId string
param dataCollectionRuleName string
param applicationInsightsName string
param tags object

// Built-in role IDs are centralized here because this module owns every cross-service assignment.
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

// Existing references provide constant extension-resource scopes for the RBAC loops.
resource storageAccount 'Microsoft.Storage/storageAccounts@2026-04-01' existing = {
  name: storageAccountName
}

resource keyVault 'Microsoft.KeyVault/vaults@2026-02-01' existing = {
  name: keyVaultName
}

resource automationAccount 'Microsoft.Automation/automationAccounts@2024-10-23' existing = {
  name: automationAccountName
}

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: dataCollectionRuleName
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' existing = {
  name: applicationInsightsName
}

// The system topic identity delivers near-expiry events and writes failed deliveries to blob storage.
resource eventGridSystemTopic 'Microsoft.EventGrid/systemTopics@2025-02-15' = {
  name: 'egst-${keyVaultName}'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    source: keyVaultId
    topicType: 'Microsoft.KeyVault.Vaults'
  }
  tags: tags
}

// Resolve runtime principal IDs by literal keys so loop collections remain deployment-start safe.
var principalIds = {
  eg: eventGridSystemTopic.identity.principalId
  aa: automationPrincipalId
  fa: functionAppPrincipalId
}

// Storage permissions cover Event Grid queue/dead-letter delivery and Function host queue processing.
var storageRoleAssignmentDefinitions = [
  { key: 'eventGridStorageQueueDataReader',             roleId: roleDefinitions.storageQueueDataReader,           principalKey: 'eg', description: 'EventGrid SystemTopic -> Storage Queue Data Reader -> Storage Account' }
  { key: 'eventGridStorageQueueDataMessageSender',      roleId: roleDefinitions.storageQueueDataMessageSender,    principalKey: 'eg', description: 'EventGrid SystemTopic -> Storage Queue Data Message Sender -> Storage Account' }
  { key: 'eventGridStorageBlobDataContributor',         roleId: roleDefinitions.storageBlobDataContributor,       principalKey: 'eg', description: 'EventGrid SystemTopic -> Storage Blob Data Contributor -> Storage Account (for dead-letter)' }
  { key: 'functionAppStorageBlobDataOwner',             roleId: roleDefinitions.storageBlobDataOwner,             principalKey: 'fa', description: 'Function App -> Storage Blob Data Owner -> Storage Account' }
  { key: 'functionAppStorageQueueDataMessageProcessor', roleId: roleDefinitions.storageQueueDataMessageProcessor, principalKey: 'fa', description: 'Function App -> Storage Queue Data Message Processor -> Storage Account' }
  { key: 'functionAppStorageQueueDataContributor',      roleId: roleDefinitions.storageQueueDataContributor,      principalKey: 'fa', description: 'Function App -> Storage Queue Data Contributor -> Storage Account' }
]

resource storageRoleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for definition in storageRoleAssignmentDefinitions: {
  scope: storageAccount
  name: guid(subscription().id, resourceGroup().id, definition.key)
  properties: {
    description: definition.description
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', definition.roleId)
    principalId: principalIds[definition.principalKey]
    principalType: 'ServicePrincipal'
  }
}]

// Automation manages Key Vault certificates and the notification secrets stored with them.
var keyVaultRoleAssignmentDefinitions = [
  { key: 'automationAccountKeyVaultCertificatesOfficer', roleId: roleDefinitions.keyVaultCertificatesOfficer, principalKey: 'aa', description: 'Automation Account -> Key Vault Certificates Officer -> Key Vault' }
  { key: 'automationAccountKeyVaultSecretsOfficer',      roleId: roleDefinitions.keyVaultSecretsOfficer,      principalKey: 'aa', description: 'Automation Account -> Key Vault Secrets Officer -> Key Vault' }
]

resource keyVaultRoleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for definition in keyVaultRoleAssignmentDefinitions: {
  scope: keyVault
  name: guid(subscription().id, resourceGroup().id, definition.key)
  properties: {
    description: definition.description
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', definition.roleId)
    principalId: principalIds[definition.principalKey]
    principalType: 'ServicePrincipal'
  }
}]

// The Function starts and reads Automation jobs; the Automation identity reads its own assets.
var automationRoleAssignmentDefinitions = [
  { key: 'automationAccountReader',            roleId: roleDefinitions.reader,             principalKey: 'aa', description: 'Automation Account -> Reader -> Automation Account (self; required for hybrid workers to read AA variables)' }
  { key: 'functionAppAutomationAccountReader', roleId: roleDefinitions.reader,             principalKey: 'fa', description: 'Function App -> Reader -> Automation Account' }
  { key: 'functionAppAutomationOperator',      roleId: roleDefinitions.automationOperator, principalKey: 'fa', description: 'Function App -> Automation Operator -> Automation Account' }
]

resource automationRoleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for definition in automationRoleAssignmentDefinitions: {
  scope: automationAccount
  name: guid(subscription().id, resourceGroup().id, definition.key)
  properties: {
    description: definition.description
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', definition.roleId)
    principalId: principalIds[definition.principalKey]
    principalType: 'ServicePrincipal'
  }
}]

// Monitoring publisher roles allow custom log ingestion and identity-authenticated telemetry.
resource automationMonitoringMetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'automationAccountMonitoringMetricsPublisher')
  scope: dataCollectionRule
  properties: {
    description: 'Automation Account -> Monitoring Metrics Publisher -> DCR'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitions.monitoringMetricsPublisher)
    principalId: automationPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource functionMonitoringMetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'functionAppMonitoringMetricsPublisher')
  scope: applicationInsights
  properties: {
    description: 'Function App -> Monitoring Metrics Publisher -> Application Insights'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitions.monitoringMetricsPublisher)
    principalId: functionAppPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Create delivery only after Event Grid has access to both queue and dead-letter destinations.
resource eventGridSubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2025-02-15' = {
  parent: eventGridSystemTopic
  name: 'egs-${eventGridSystemTopic.name}'
  properties: {
    destination: {
      endpointType: 'StorageQueue'
      properties: {
        resourceId: storageAccountId
        queueName: 'certlc'
        queueMessageTimeToLiveInSeconds: 86400
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
      eventTimeToLiveInMinutes: 1440
    }
    deadLetterWithResourceIdentity: {
      identity: {
        type: 'SystemAssigned'
      }
      deadLetterDestination: {
        endpointType: 'StorageBlob'
        properties: {
          resourceId: storageAccountId
          blobContainerName: 'eventgrid-deadletter'
        }
      }
    }
  }
  dependsOn: [
    storageRoleAssignments
  ]
}

// The final alerting stage consumes these outputs to target the exact Event Grid resources.
output eventGridSystemTopicId string = eventGridSystemTopic.id
output eventGridSubscriptionName string = eventGridSubscription.name