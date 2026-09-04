// Deploys the shared Log Analytics, custom certificate statistics ingestion, and Application Insights stack.
targetScope = 'resourceGroup'

param location string
param logAnalyticsWorkspaceName string
param logAnalyticsRetentionInDays int
param applicationInsightsName string
param dataCollectionEndpointName string
param dataCollectionRuleName string
param tags object

// Log Analytics is the common destination for platform diagnostics and certificate snapshots.
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
  tags: tags
}

// The DCE accepts custom certlcstats payloads routed by the DCR below.
resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = {
  name: dataCollectionEndpointName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
  tags: tags
}

// Keep the table and stream declarations aligned through one shared column definition.
var certlcDataColumns = [
  { name: 'SnapshotId', type: 'string' }
  { name: 'Thumbprint', type: 'string' }
  { name: 'Name',       type: 'string' }
  { name: 'Created',    type: 'datetime' }
  { name: 'Expires',    type: 'datetime' }
  { name: 'Subject',    type: 'string' }
  { name: 'Template',   type: 'string' }
  { name: 'DNSNames',   type: 'string' }
]

resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2025-07-01' = {
  name: 'certlcstats_CL'
  parent: logAnalyticsWorkspace
  properties: {
    retentionInDays: logAnalyticsRetentionInDays
    schema: {
      name: 'certlcstats_CL'
      columns: concat(
        [ { name: 'TimeGenerated', type: 'datetime' } ],
        certlcDataColumns
      )
    }
  }
}

// Create the destination table before the DCR references its custom stream.
resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: dataCollectionRuleName
  location: location
  properties: {
    dataCollectionEndpointId: dataCollectionEndpoint.id
    streamDeclarations: {
      'Custom-certlcstats_CL': {
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
          'Custom-certlcstats_CL'
        ]
        destinations: [
          'clv2ws1'
        ]
        transformKql: 'source | extend Created = todatetime(Created), Expires = todatetime(Expires) | extend TimeGenerated = now()'
        outputStream: 'Custom-certlcstats_CL'
      }
    ]
  }
  dependsOn: [
    customTable
  ]
  tags: tags
}

// Waiting for the table avoids the initial "Workspace not active" provisioning race.
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
    customTable
  ]
  tags: tags
}

// Runtime-generated ingestion values configure Automation; resource IDs connect other modules.
output logAnalyticsWorkspaceId string = logAnalyticsWorkspace.id
output dataCollectionEndpointId string = dataCollectionEndpoint.id
output dataCollectionRuleId string = dataCollectionRule.id
output applicationInsightsId string = applicationInsights.id
output applicationInsightsConnectionString string = applicationInsights.properties.ConnectionString
output dceIngestionEndpoint string = dataCollectionEndpoint.properties.logsIngestion.endpoint
output dataCollectionRuleImmutableId string = dataCollectionRule.properties.immutableId