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

@description('Retention in days for the Log Analytics workspace and the certlcstats_CL custom table. Range 30-730. Default 30 (lab-friendly).')
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

@description('Deploy the dedicated CertLC Action Group and proactive operational alerts. Defaults to false.')
param enableAlerts bool = false

@description('The name of the dedicated CertLC Azure Monitor Action Group.')
param actionGroupName string = 'ag-${logAnalyticsWorkspaceName}'

@description('Email receivers for the CertLC Action Group. Each object requires name and emailAddress; useCommonAlertSchema defaults to true when specified.')
param alertEmailReceivers array = []

/*************/
/* VARIABLES */
/*************/

// Common tags for all resources
var commonTags = {
  solution: 'CertLC'
  purpose: 'Certificate Lifecycle Management'
}

/*****************/
/* NEW RESOURCES */
/*****************/

module storage './modules/storage.bicep' = {
  name: 'certlc-storage'
  params: {
    location: location
    storageAccountName: storageAccountName
    peSubnetId: peSubnetId
    blobDnsZoneId: resourceId(dnsZonesSubscriptionId, dnsZonesResourceGroupName, 'Microsoft.Network/privateDnsZones', 'privatelink.blob.${environment().suffixes.storage}')
    queueDnsZoneId: resourceId(dnsZonesSubscriptionId, dnsZonesResourceGroupName, 'Microsoft.Network/privateDnsZones', 'privatelink.queue.${environment().suffixes.storage}')
    tags: commonTags
  }
}

module observability './modules/observability.bicep' = {
  name: 'certlc-observability'
  params: {
    location: location
    logAnalyticsWorkspaceName: logAnalyticsWorkspaceName
    logAnalyticsRetentionInDays: logAnalyticsRetentionInDays
    applicationInsightsName: applicationInsightsName
    dataCollectionEndpointName: dataCollectionEndpointName
    dataCollectionRuleName: dataCollectionRuleName
    tags: commonTags
  }
}

module functionApp './modules/function-app.bicep' = {
  name: 'certlc-function-app'
  params: {
    location: location
    functionAppName: functionAppName
    functionSubnetId: fnSubnetId
    deploymentContainerUri: storage.outputs.deploymentContainerUri
    storageBlobEndpoint: storage.outputs.blobEndpoint
    storageQueueEndpoint: storage.outputs.queueEndpoint
    applicationInsightsConnectionString: observability.outputs.applicationInsightsConnectionString
    automationAccountName: automation.outputs.name
    hybridWorkerGroupName: hybridWorkerGroupName
    runbookName: runbookName
    peSubnetId: peSubnetId
    privateDnsZoneId: resourceId(dnsZonesSubscriptionId, dnsZonesResourceGroupName, 'Microsoft.Network/privateDnsZones', 'privatelink.azurewebsites.net')
    tags: commonTags
  }
}

module automation './modules/automation.bicep' = {
  name: 'certlc-automation'
  params: {
    location: location
    automationAccountName: automationAccountName
    hybridWorkerGroupName: hybridWorkerGroupName
    runbookName: runbookName
    runtimeEnvironmentName: runtimeEnvironmentName
    scheduleStartTime: scheduleStartTime
    ca: automationAccountVarCA
    pfxRootFolder: automationAccountVarPfxRootFolder
    smtpFrom: automationAccountVarSmtpFrom
    smtpServer: automationAccountVarSmtpServer
    smtpUser: automationAccountVarSmtpUser
    smtpPassword: automationAccountVarSmtpPassword
    keyVaultName: keyVault.outputs.name
    dataCollectionRuleImmutableId: observability.outputs.dataCollectionRuleImmutableId
    dataCollectionEndpointIngestionUrl: observability.outputs.dceIngestionEndpoint
    logAnalyticsWorkspaceId: observability.outputs.logAnalyticsWorkspaceId
    peSubnetId: peSubnetId
    privateDnsZoneId: resourceId(dnsZonesSubscriptionId, dnsZonesResourceGroupName, 'Microsoft.Network/privateDnsZones', 'privatelink.azure-automation.net')
    tags: commonTags
  }
}

module keyVault './modules/key-vault.bicep' = {
  name: 'certlc-key-vault'
  params: {
    location: location
    keyVaultName: keyVaultName
    softDeleteRetentionInDays: keyVaultSoftDeleteRetentionInDays
    logAnalyticsWorkspaceId: observability.outputs.logAnalyticsWorkspaceId
    peSubnetId: peSubnetId
    privateDnsZoneId: resourceId(dnsZonesSubscriptionId, dnsZonesResourceGroupName, 'Microsoft.Network/privateDnsZones', 'privatelink.vaultcore.azure.net')
    tags: commonTags
  }
}

module integrations './modules/integrations.bicep' = {
  name: 'certlc-integrations'
  params: {
    location: location
    storageAccountName: storageAccountName
    storageAccountId: storage.outputs.storageAccountId
    keyVaultName: keyVaultName
    keyVaultId: keyVault.outputs.id
    automationAccountName: automationAccountName
    automationPrincipalId: automation.outputs.principalId
    functionAppPrincipalId: functionApp.outputs.principalId
    dataCollectionRuleName: dataCollectionRuleName
    applicationInsightsName: applicationInsightsName
    tags: commonTags
  }
}

module workbook './modules/workbook.bicep' = {
  name: 'certlc-workbook'
  params: {
    location: location
    logAnalyticsWorkspaceId: observability.outputs.logAnalyticsWorkspaceId
    automationAccountId: automation.outputs.id
    runbookName: runbookName
    functionAppId: functionApp.outputs.id
    tags: commonTags
  }
}

// Alerts deploy last because they target resources owned by several upstream modules.
module alerts './modules/alerts.bicep' = if (enableAlerts) {
  name: 'certlc-alerts'
  params: {
    location: location
    actionGroupName: actionGroupName
    alertEmailReceivers: alertEmailReceivers
    storageAccountName: storageAccountName
    automationAccountId: automation.outputs.id
    runbookName: runbookName
    eventGridSystemTopicId: integrations.outputs.eventGridSystemTopicId
    eventGridSubscriptionName: integrations.outputs.eventGridSubscriptionName
    logAnalyticsWorkspaceId: observability.outputs.logAnalyticsWorkspaceId
    tags: commonTags
  }
}

// Output all resource IDs and important properties
output storageAccountId string = storage.outputs.storageAccountId
output storageAccountQueueUri string = storage.outputs.queueEndpoint
output automationAccountId string = automation.outputs.id
output keyVaultId string = keyVault.outputs.id
output functionAppId string = functionApp.outputs.id
output logAnalyticsWorkspaceId string = observability.outputs.logAnalyticsWorkspaceId
output applicationInsightsId string = observability.outputs.applicationInsightsId
output dceIngestionEndpoint string = observability.outputs.dceIngestionEndpoint
output dataCollectionRuleImmutableId string = observability.outputs.dataCollectionRuleImmutableId
