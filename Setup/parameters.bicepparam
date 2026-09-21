using './certlc.bicep'

// Network Configuration
param peSubnetId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-network-contoso/providers/Microsoft.Network/virtualNetworks/vnet-workloads-contoso/subnets/snet-private-endpoints'
param fnSubnetId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-network-contoso/providers/Microsoft.Network/virtualNetworks/vnet-workloads-contoso/subnets/snet-functions'

// DNS Configuration
param dnsZonesSubscriptionId = '00000000-0000-0000-0000-000000000000'
param dnsZonesResourceGroupName = 'rg-dns-contoso'

// Resource Names
param storageAccountName = 'certlcstorage001'
param functionAppName = 'func-certlc-contoso'
param logAnalyticsWorkspaceName = 'log-certlc-contoso'
param applicationInsightsName = 'appi-certlc-contoso'
param automationAccountName = 'aa-certlc-contoso'
param hybridWorkerGroupName = 'hwg-certlc-contoso'
param runbookName = 'certlc'
param runtimeEnvironmentName = 'certlc-PowerShell-7-6'
param keyVaultName = 'kv-certlc-contoso'
param dataCollectionEndpointName = 'dce-certlc-contoso'
param dataCollectionRuleName = 'dcr-certlcstats-contoso'
param actionGroupName = 'ag-certlc-contoso'

// Alerting Configuration
param enableAlerts = true
param enableStatsSchedule = true
param alertEmailReceivers = [
  {
    name: 'CertLC operators'
    emailAddress: 'certlc-operations@contoso.com'
    useCommonAlertSchema: true
  }
]

// Automation account variables
param automationAccountVarCA = 'ca01.contoso.com\\Contoso-Issuing-CA'
param automationAccountVarPfxRootFolder = 'C:\\CertLC\\PFX'
param automationAccountVarSmtpFrom = 'certlc@contoso.com'
param automationAccountVarSmtpServer = 'smtp.contoso.com'
param automationAccountVarSmtpUser = 'certlc-smtp-user'
param automationAccountVarSmtpPassword = '<replace-with-smtp-password>'
