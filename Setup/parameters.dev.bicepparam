using './certlc.bicep'

// Network Configuration
param peSubnetId = '/subscriptions/4a570962-701a-475e-bf5b-8dc76ec748ff/resourceGroups/rg-shared-itn-001/providers/Microsoft.Network/virtualNetworks/vnet-shared-itn-001/subnets/snet-pe-shared-itn-002'
param fnSubnetId = '/subscriptions/4a570962-701a-475e-bf5b-8dc76ec748ff/resourceGroups/rg-shared-itn-001/providers/Microsoft.Network/virtualNetworks/vnet-shared-itn-001/subnets/snet-fn-shared-itn-001'

// DNS Configuration
param dnsZonesSubscriptionId = 'c4e6c176-bf9c-4e8c-87b2-ebdceea7085f'
param dnsZonesResourceGroupName = 'rg-vhub-itn-001'

// Resource Names
param storageAccountName = 'flazstcertlcitn001'
param functionAppName = 'flazfn-certlc-itn-001'
param logAnalyticsWorkspaceName = 'log-certlc-itn-001'
param applicationInsightsName = 'appi-certlc-itn-001'
param automationAccountName = 'aa-certlc-itn-001'
param hybridWorkerGroupName = 'hwg-certlc-itn-001'
param keyVaultName = 'flazkv-certlc-itn-001'
param dataCollectionEndpointName = 'dce-certlc-itn-001'
param dataCollectionRuleName = 'dcr-certlc-itn-001'

// Automation account variables
param automationAccountVarCA = 'flazdc03.formicalab.casa\\SubCA' // Name of the CA to use (for the automation account variable)
param automationAccountVarPfxRootFolder = 'C:\\PFX_Repo' // Name of the folder to use (for the automation account variable)
param automationAccountVarSmtpFrom = 'certlc@formicalab.casa' // SMTP From address to use (for the automation account variable)
param automationAccountVarSmtpServer = 'mail.smtp2go.com' // SMTP Server to use (for the automation account variable)
param automationAccountVarSmtpUser = 'certlc@formicalab.casa' // SMTP User to use (for the automation account variable)
param automationAccountVarSmtpPassword = 'YourSMTPPasswordHere' // SMTP Password to use (for the automation account variable)
