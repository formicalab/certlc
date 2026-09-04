// Publishes the CertLC workbook after replacing repository placeholders with deployed resource IDs.
targetScope = 'resourceGroup'

param location string
param logAnalyticsWorkspaceId string
param automationAccountId string
param runbookName string
param functionAppId string
param tags object

// Keep the tokenized workbook file authoritative instead of duplicating its JSON in Bicep.
var workbookTemplate = loadTextContent('../../Workbooks/certlcstats.workbook')
var workbookWithWorkspace = replace(workbookTemplate, '__LOG_ANALYTICS_WORKSPACE_ID__', logAnalyticsWorkspaceId)
var workbookWithAutomation = replace(workbookWithWorkspace, '__AUTOMATION_ACCOUNT_ID__', automationAccountId)
var workbookWithMainRunbook = replace(workbookWithAutomation, '__MAIN_RUNBOOK_ID__', '${automationAccountId}/runbooks/${runbookName}')
var workbookWithStatsRunbook = replace(workbookWithMainRunbook, '__STATS_RUNBOOK_ID__', '${automationAccountId}/runbooks/certlcstats')
var workbookContent = replace(workbookWithStatsRunbook, '__FUNCTION_APP_ID__', functionAppId)

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