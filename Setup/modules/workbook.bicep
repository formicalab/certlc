// Publishes the CertLC workbook after replacing repository placeholders with deployed resource IDs.
targetScope = 'resourceGroup'

param location string
param logAnalyticsWorkspaceId string
param automationAccountId string
param runbookName string
param functionAppId string
param eventGridSystemTopicId string
param eventGridSourceId string
param queueStorageAccountId string
param tags object

// Keep the tokenized workbook file authoritative instead of duplicating its JSON in Bicep.
var workbookTemplate = loadJsonContent('../../Workbooks/certlcstats.workbook')
var workbookReplacements = {
  __LOG_ANALYTICS_WORKSPACE_ID__: logAnalyticsWorkspaceId
  __AUTOMATION_ACCOUNT_ID__: automationAccountId
  __MAIN_RUNBOOK_ID__: '${automationAccountId}/runbooks/${runbookName}'
  __STATS_RUNBOOK_ID__: '${automationAccountId}/runbooks/certlcstats'
  __FUNCTION_APP_ID__: functionAppId
  __EVENT_GRID_TOPIC_ID__: eventGridSystemTopicId
  __EVENT_GRID_SOURCE_ID__: eventGridSourceId
  __QUEUE_STORAGE_ACCOUNT_ID__: queueStorageAccountId
  __QUEUE_SERVICE_ID__: '${queueStorageAccountId}/queueServices/default'
}

// ARM replace() cannot process the full workbook string once it exceeds 128 KiB.
var workbookItems = map(workbookTemplate.items, item => json(reduce(
  items(workbookReplacements),
  string(item),
  (content, replacement) => replace(content, replacement.key, replacement.value)
)))
var workbookMetadata = json(reduce(
  items(workbookReplacements),
  string(shallowMerge([workbookTemplate, { items: [] }])),
  (content, replacement) => replace(content, replacement.key, replacement.value)
))
// A shallow merge preserves item order and duplicates instead of merging/deduplicating arrays.
var workbookContent = string(shallowMerge([workbookMetadata, { items: workbookItems }]))

// The deterministic name updates the same shared workbook on every deployment.
resource workbook 'Microsoft.Insights/workbooks@2023-06-01' = {
  name: guid(resourceGroup().id, 'certlcstats')
  location: location
  kind: 'shared'
  properties: {
    displayName: 'certlcstats'
    serializedData: workbookContent
    category: 'workbook'
    sourceId: logAnalyticsWorkspaceId
  }
  tags: union(tags, {
    'hidden-title': 'certlcstats'
  })
}