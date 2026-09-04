// Deploys the dedicated CertLC Action Group and proactive operational alerts after all monitored resources exist.
targetScope = 'resourceGroup'

param location string
param actionGroupName string
param alertEmailReceivers array
param storageAccountName string
param automationAccountId string
param runbookName string
param eventGridSystemTopicId string
param eventGridSubscriptionName string
param logAnalyticsWorkspaceId string
param tags object

// Email receivers are deployment-specific; an empty array still creates alerts visible in Azure Monitor.
module actionGroup 'br/public:avm/res/insights/action-group:0.8.0' = {
  name: 'certlc-alert-action-group'
  params: {
    name: actionGroupName
    groupShortName: 'CertLC'
    emailReceivers: alertEmailReceivers
    location: 'global'
    tags: tags
    enableTelemetry: false
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2026-04-01' existing = {
  name: storageAccountName
}

resource queueService 'Microsoft.Storage/storageAccounts/queueServices@2026-04-01' existing = {
  parent: storageAccount
  name: 'default'
}

// Resource-specific Queue logs expose StorageQueueLogs, allowing the poison queue to be distinguished by URI.
resource queueDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-${storageAccountName}-queue-alerts'
  scope: queueService
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      {
        category: 'StorageWrite'
        enabled: true
      }
    ]
  }
}

var eventGridMetricAlertDefinitions = [
  {
    key: 'dead-lettered'
    description: 'CertLC Event Grid events were dead-lettered.'
    metricName: 'DeadLetteredCount'
    threshold: 0
    severity: 1
    windowSize: 'PT5M'
  }
  {
    key: 'dropped'
    description: 'CertLC Event Grid events were dropped.'
    metricName: 'DroppedEventCount'
    threshold: 0
    severity: 1
    windowSize: 'PT5M'
  }
  {
    key: 'delivery-failures'
    description: 'CertLC Event Grid delivery attempts repeatedly failed.'
    metricName: 'DeliveryAttemptFailCount'
    threshold: 5
    severity: 3
    windowSize: 'PT15M'
  }
]

module eventGridMetricAlerts 'br/public:avm/res/insights/metric-alert:0.4.1' = [for definition in eventGridMetricAlertDefinitions: {
  name: 'certlc-eventgrid-${definition.key}-alert'
  params: {
    name: 'alert-certlc-eventgrid-${definition.key}'
    alertDescription: definition.description
    scopes: [ eventGridSystemTopicId ]
    actions: [ actionGroup.outputs.resourceId ]
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allof: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'EventSubscriptionName'
              operator: 'Include'
              values: [ eventGridSubscriptionName ]
            }
          ]
          metricName: definition.metricName
          metricNamespace: 'Microsoft.EventGrid/systemTopics'
          name: definition.key
          operator: 'GreaterThan'
          threshold: definition.threshold
          timeAggregation: 'Total'
        }
      ]
    }
    evaluationFrequency: 'PT5M'
    windowSize: definition.windowSize
    severity: definition.severity
    autoMitigate: true
    location: 'global'
    tags: tags
    enableTelemetry: false
  }
}]

var poisonQueueQuery = '''
StorageQueueLogs
| where TimeGenerated > ago(10m)
| where Uri has "/certlc-poison/messages"
| where OperationName =~ "PutMessage"
'''

var automationFailureQuery = join([
  'AzureDiagnostics'
  '| where _ResourceId =~ "${automationAccountId}"'
  '| where Category == "JobLogs"'
  '| where RunbookName_s in~ ("${runbookName}", "certlcstats")'
  '| summarize arg_max(TimeGenerated, ResultType) by JobId_g'
  '| where ResultType in~ ("Failed", "Stopped", "Suspended")'
], '\n')

var staleStatisticsQuery = join([
  'AzureDiagnostics'
  '| where _ResourceId =~ "${automationAccountId}"'
  '| where Category == "JobLogs"'
  '| where RunbookName_s =~ "certlcstats"'
  '| where ResultType =~ "Completed"'
  '| summarize LastSuccess = max(TimeGenerated)'
  '| extend AggregatedValue = iff(isnull(LastSuccess) or LastSuccess < ago(2h), 1, 0)'
  '| where AggregatedValue > 0'
], '\n')

var scheduledQueryAlertDefinitions = [
  {
    key: 'poison-message'
    displayName: 'CertLC poison message created'
    description: 'A message was written to the certlc-poison queue after Function retry exhaustion.'
    query: poisonQueueQuery
    severity: 1
    evaluationFrequency: 'PT5M'
    windowSize: 'PT10M'
    metricMeasureColumn: ''
    timeAggregation: 'Count'
  }
  {
    key: 'automation-failure'
    displayName: 'CertLC Automation job failed'
    description: 'A CertLC lifecycle or statistics runbook ended in a failed, stopped, or suspended state.'
    query: automationFailureQuery
    severity: 2
    evaluationFrequency: 'PT5M'
    windowSize: 'PT10M'
    metricMeasureColumn: ''
    timeAggregation: 'Count'
  }
  {
    key: 'statistics-stale'
    displayName: 'CertLC statistics are stale'
    description: 'The certlcstats runbook has not completed successfully within two hours.'
    query: staleStatisticsQuery
    severity: 2
    evaluationFrequency: 'PT15M'
    windowSize: 'PT2H'
    metricMeasureColumn: 'AggregatedValue'
    timeAggregation: 'Maximum'
  }
]

module scheduledQueryAlerts 'br/public:avm/res/insights/scheduled-query-rule:0.6.0' = [for definition in scheduledQueryAlertDefinitions: {
  name: 'certlc-${definition.key}-alert'
  params: {
    name: 'alert-certlc-${definition.key}'
    alertDisplayName: definition.displayName
    alertDescription: definition.description
    location: location
    scopes: [ logAnalyticsWorkspaceId ]
    actions: {
      actionGroupResourceIds: [ actionGroup.outputs.resourceId ]
    }
    criterias: {
      allOf: [
        union(
          {
            dimensions: []
            operator: 'GreaterThan'
            query: definition.query
            threshold: 0
            timeAggregation: definition.timeAggregation
          },
          empty(definition.metricMeasureColumn) ? {} : {
            metricMeasureColumn: definition.metricMeasureColumn
          }
        )
      ]
    }
    evaluationFrequency: definition.evaluationFrequency
    windowSize: definition.windowSize
    severity: definition.severity
    autoMitigate: true
    // Fresh workspaces may not expose these tables until their first diagnostic record arrives.
    skipQueryValidation: true
    tags: tags
    enableTelemetry: false
  }
  dependsOn: [
    queueDiagnostics
  ]
}]

output actionGroupId string = actionGroup.outputs.resourceId