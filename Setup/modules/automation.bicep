// Deploys the Automation runtime, runbooks, configuration, private connectivity, and diagnostics.
targetScope = 'resourceGroup'

param location string
param automationAccountName string
param hybridWorkerGroupName string
param runbookName string
param runtimeEnvironmentName string
param scheduleStartTime string
param enableStatsSchedule bool
param ca string
param pfxRootFolder string
param smtpFrom string
param smtpServer string
param smtpUser string
@secure()
param smtpPassword string
param keyVaultName string
param dataCollectionRuleImmutableId string
param dataCollectionEndpointIngestionUrl string
param logAnalyticsWorkspaceId string
param peSubnetId string
param privateDnsZoneId string
param tags object

// The account identity executes lifecycle operations and is authorized by the integrations module.
resource automationAccount 'Microsoft.Automation/automationAccounts@2024-10-23' = {
  name: automationAccountName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publicNetworkAccess: false
    // Webhooks use a key in the URL and cannot authenticate with Microsoft Entra ID.
    disableLocalAuth: false
    sku: {
      name: 'Basic'
    }
  }
  tags: tags

  resource runtimeEnvironment 'runtimeEnvironments@2024-10-23' = {
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
    tags: tags
  }

  resource runbookCertLC 'runbooks@2024-10-23' = {
    name: runbookName
    location: location
    properties: {
      runbookType: 'PowerShell'
      logProgress: false
      logVerbose: false
      description: 'Certificate lifecycle management runbook for enrollment, renewal, and revocation'
      runtimeEnvironment: runtimeEnvironment.name
    }
    tags: tags
  }

  resource runbookCertLCStats 'runbooks@2024-10-23' = {
    name: 'certlcstats'
    location: location
    properties: {
      runbookType: 'PowerShell'
      logProgress: false
      logVerbose: false
      description: 'Certificate statistics collection runbook for monitoring and reporting'
      runtimeEnvironment: runtimeEnvironment.name
    }
    tags: tags
  }

  // Keep the schedule resource available even when an environment disables its runbook link.
  resource scheduleCertLCStats 'schedules@2024-10-23' = {
    name: 'schedule-certlcstats-hourly'
    properties: {
      description: 'Runs certlcstats every hour to collect certificate statistics'
      startTime: scheduleStartTime
      frequency: 'Hour'
      interval: 1
      timeZone: 'UTC'
    }
  }

  resource jobScheduleCertLCStats 'jobSchedules@2024-10-23' = if (enableStatsSchedule) {
    name: guid(automationAccount.id, 'certlcstats-schedule')
    properties: {
      runbook: {
        name: runbookCertLCStats.name
      }
      schedule: {
        name: scheduleCertLCStats.name
      }
      runOn: hybridWorkerGroup.name
    }
  }
}

// Values are JSON-string encoded because the Automation variables API expects quoted string payloads.
var variableValues = {
  'certlc-ca':                 ca
  'certlc-pfxrootfolder':      pfxRootFolder
  'certlc-smtpfrom':           smtpFrom
  'certlc-smtpserver':         smtpServer
  'certlc-smtpuser':           smtpUser
  'certlc-smtppassword':       smtpPassword
  'certlc-stats-keyvault':     keyVaultName
  'certlc-stats-immutableid':  dataCollectionRuleImmutableId
  'certlc-stats-streamname':   'Custom-certlcstats_CL'
  'certlc-stats-ingestionurl': dataCollectionEndpointIngestionUrl
}

var variableNames = [
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

resource variables 'Microsoft.Automation/automationAccounts/variables@2024-10-23' = [for variableName in variableNames: {
  parent: automationAccount
  name: variableName
  properties: {
    value: substring(string([variableValues[variableName]]), 1, max(0, length(string([variableValues[variableName]])) - 2))
    isEncrypted: true
  }
}]

resource hybridWorkerGroup 'Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups@2024-10-23' = {
  name: hybridWorkerGroupName
  parent: automationAccount
  properties: {}
}

// Automation exposes separate private-link group IDs for webhooks and Hybrid Worker traffic.
var privateEndpointDefinitions = [
  { peName: 'pe-webhook-${automationAccountName}',            plsConnName: 'pls-${automationAccountName}',                    groupId: 'Webhook',            nicName: 'nic-pe-webhook-${automationAccountName}' }
  { peName: 'pe-dscandhybridworker-${automationAccountName}', plsConnName: 'pls-dscandhybridworker-${automationAccountName}', groupId: 'DSCAndHybridWorker', nicName: 'nic-pe-dscandhybridworker-${automationAccountName}' }
]

resource privateEndpoints 'Microsoft.Network/privateEndpoints@2025-07-01' = [for definition in privateEndpointDefinitions: {
  name: definition.peName
  location: location
  properties: {
    subnet: {
      id: peSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: definition.plsConnName
        properties: {
          privateLinkServiceId: automationAccount.id
          groupIds: [
            definition.groupId
          ]
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
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}]

// Forward job status and streams so workbook queries can correlate lifecycle failures.
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-${automationAccountName}'
  scope: automationAccount
  properties: {
    workspaceId: logAnalyticsWorkspaceId
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

// Downstream modules use these outputs for app settings, endpoints, and RBAC.
output id string = automationAccount.id
output name string = automationAccount.name
output principalId string = automationAccount.identity.principalId