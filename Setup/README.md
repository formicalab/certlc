# Certificate Lifecycle Management (CertLC)
## Setup

This directory contains the Bicep infrastructure-as-code templates for deploying all Azure resources required by the CertLC solution.

## Prerequisites

Before deploying, ensure you have:

1. **Resource Group**: Created in the target Azure region
2. **Virtual Network and Subnets**:
   - Subnet for Private Endpoints
   - Subnet delegated to `Microsoft.App/environments` for Function App VNet integration
3. **Private DNS Zones**: Pre-existing Private DNS Zones for all required services (can be in a different subscription/resource group)
   - `privatelink.blob.core.windows.net`
   - `privatelink.queue.core.windows.net`
   - `privatelink.azurewebsites.net`
   - `privatelink.azure-automation.net`
   - `privatelink.vaultcore.azure.net`
4. **Hybrid Worker VM**: A Windows VM (on-premises or Azure) with access to the Enterprise CA

### Required RBAC Permissions

The identity deploying this Bicep template requires the following Azure role assignments:

#### On the Deployment Resource Group (where CertLC resources will be created):
- **Owner** role (or Contributor + User Access Administrator)
  - Required to create resources and assign RBAC roles to managed identities
  - The template creates 12 role assignments for managed identities across various resources

#### On the Private DNS Zones Resource Group (if zones are in a different subscription/resource group):
- **Private DNS Zone Contributor** role
  - Required to create DNS A records in private DNS zones when private endpoints are deployed
  - The template creates 6 private endpoints, each with a DNS zone group that registers A records
  - This role must be assigned on the resource group containing the private DNS zones, or individually on each DNS zone

**Example Azure CLI commands to grant required permissions:**

```powershell
# Grant Owner role on the deployment resource group
az role assignment create `
  --assignee <user-or-service-principal-id> `
  --role "Owner" `
  --resource-group <certlc-resource-group>

# Grant Private DNS Zone Contributor on the DNS zones resource group (if different subscription/RG)
az role assignment create `
  --assignee <user-or-service-principal-id> `
  --role "Private DNS Zone Contributor" `
  --scope "/subscriptions/<dns-zones-subscription-id>/resourceGroups/<dns-zones-resource-group>"
```

**Note**: If using a service principal for automated deployments, ensure it has these permissions before running the deployment.

## Deployment

1. Edit the parameter file with the required values
2. Deploy the infrastructure using the Bicep template and parameter file:

```powershell
az deployment group create `
  --resource-group <your-resource-group> `
  --parameters .\parameters.dev.bicepparam
```

## Resources Created

The Bicep template creates and configures the following Azure resources:

### Core Infrastructure

#### 1. **Storage Account**
- **Type**: Standard LRS with hierarchical namespace disabled
- **Purpose**: Hosts the `certlc` queue for event-driven certificate lifecycle operations. It is also used by the Azure Function
- **Configuration**: 
  - Public network access disabled
  - Default to Azure AD authentication
  - Blob and Queue services enabled
- **Private Endpoints**:
  - Blob service endpoint
  - Queue service endpoint

#### 2. **Log Analytics Workspace**
- **Type**: PerGB2018 pricing tier
- **Purpose**: Centralized logging and analytics for all CertLC components
- **Configuration**: 30-day retention period
- **Used by**: Application Insights, Azure Monitor, and custom tables for certificate statistics

#### 3. **Application Insights**
- **Type**: Web application monitoring
- **Purpose**: Application performance monitoring and diagnostics for the Function App
- **Configuration**: Linked to Log Analytics Workspace

#### 4. **Custom Table** (`certlc_CL`)
- **Type**: Custom table in Log Analytics Workspace
- **Purpose**: Stores certificate statistics updated by the `certlcstats.ps1` runbook
- **Configuration**: 30-day retention, Analytics plan
- **Schema**: 8 columns including TimeGenerated, Thumbprint, Name, Created, Expires, Subject, Template, DNSNames

#### 5. **Data Collection Endpoint (DCE)**
- **Purpose**: Ingestion endpoint for custom logs and metrics
- **Configuration**: Public network access enabled (can be disabled after configuring private endpoints)
- **Used by**: Data Collection Rule for certificate statistics ingestion

#### 6. **Data Collection Rule (DCR)**
- **Purpose**: Defines data transformation and routing for custom certificate statistics
- **Configuration**:
  - Stream declaration: `Custom-certlc_CL`
  - KQL transformation: Converts string dates to datetime and adds TimeGenerated
  - Destination: Log Analytics Workspace custom table (`certlc_CL`)
- **Used by**: Automation Account runbook to publish certificate statistics

### Compute Resources

#### 7. **Function App (Flex Consumption Plan)**
- **Type**: Azure Functions on Flex Consumption plan
- **Purpose**: Event-driven processing of certificate lifecycle events from the queue
- **Configuration**:
  - Integrated with VNet via delegated subnet
  - Connected to Storage Account and Application Insights using its system assigned managed identity for authentication
  - Runtime: PowerShell 7.4
- **Private Endpoint**: Secured with private endpoint for site access

#### 8. **Automation Account**
- **Type**: Basic SKU with System-Assigned Managed Identity
- **Purpose**: Orchestrates certificate operations with the Enterprise CA and Key Vault (runbook `certlc.ps1`); collects statistics about certificates in the KeyVault (runbook `certlcstats.ps1`)
- **Configuration**:
  - Public network access disabled
  - PowerShell 7.2 runtime environment configured
  - Includes encrypted variables used by the runbooks (CA name, PFX root folder, SMTP settings, Key Vault name, DCR details)
  - Two placeholder runbooks created: `certlc` and `certlcstats` (code must be uploaded post-deployment)
  - Hybrid Worker Group for on-premises CA communication
  - Hourly schedule prepared for `certlcstats` runbook (disabled by default, requires manual activation)
  - Diagnostic settings enabled: JobLogs, JobStreams, AllMetrics sent to Log Analytics
- **Private Endpoints**:
  - Webhook endpoint (for Function App to trigger runbooks)
  - DSC and Hybrid Worker endpoint (for hybrid worker communication)

#### 9. **Hybrid Worker Group**
- **Type**: Azure Automation Hybrid Runbook Worker Group
- **Purpose**: Enables the automation account to execute runbooks on on-premises or Azure VMs with access to the Enterprise CA
- **Note**: Worker machines must be registered separately after deployment

### Security Resources

#### 10. **Key Vault**
- **Type**: Standard tier with RBAC authorization
- **Purpose**: Secure storage for certificates and secrets
- **Configuration**:
  - Public network access disabled
  - Soft delete enabled (7-day retention)
  - RBAC authorization mode
  - Diagnostic settings enabled: AuditEvent, AzurePolicyEvaluationDetails, AllMetrics sent to Log Analytics
- **Private Endpoint**: Secured with private endpoint for vault access

### Event Processing

#### 11. **Event Grid System Topic**
- **Type**: System Topic for Key Vault events
- **Purpose**: Captures certificate lifecycle events from Key Vault
- **Configuration**:
  - Uses system-assigned managed identity
  - Connected to Key Vault as event source
  - Topic type: `Microsoft.KeyVault.Vaults`

#### 12. **Event Grid Event Subscription**
- **Type**: Event subscription with Storage Queue destination
- **Purpose**: Routes certificate expiry events to the Storage Queue for processing
- **Configuration**:
  - Filters for `Microsoft.KeyVault.CertificateNearExpiry` events only
  - Delivers to `certlc` queue in Storage Account
  - Uses CloudEvents v1.0 schema
  - Message TTL: 1 day (86400 seconds)
  - Retry policy: 30 attempts over 1 day (1440 minutes)

### Networking

#### 13. **Private Endpoints** (6 total)
All PaaS resources are secured with private endpoints to disable public access:
- Storage Account Blob endpoint
- Storage Account Queue endpoint
- Function App site endpoint
- Automation Account webhook endpoint
- Automation Account DSC/Hybrid Worker endpoint
- Key Vault endpoint

Each private endpoint is linked to existing Private DNS Zones (they can be in another subscription/resource group) for name resolution.

#### 14. **Azure Monitor Workbook**
- **Type**: Shared workbook for certificate statistics visualization
- **Purpose**: Provides a dashboard for monitoring certificate lifecycle and statistics
- **Configuration**:
  - Name: `certlcstats`
  - Initially empty (queries and visualizations can be added post-deployment)
  - Linked to Log Analytics Workspace as data source
  - Depends on Application Insights to ensure workspace stability

#### 15. **Private DNS Zone Groups** (6 total)
Each private endpoint has an associated DNS zone group that links to the appropriate Private DNS Zones:
- `privatelink.blob.core.windows.net`
- `privatelink.queue.core.windows.net`
- `privatelink.azurewebsites.net`
- `privatelink.azure-automation.net`
- `privatelink.vaultcore.azure.net`

### Identity and Access Management

#### 16. **Role Assignments** (12 total)

**Automation Account Managed Identity** (4 assignments):
- `Key Vault Certificates Officer` on Key Vault - For certificate requests
- `Key Vault Secrets Officer` on Key Vault - For PFX export
- `Reader` on Automation Account (self) - For runbook access to automation variables
- `Monitoring Metrics Publisher` on Data Collection Rule (DCR) - For publishing certificate statistics to custom table

**Function App Managed Identity** (6 assignments):
- `Storage Blob Data Owner` on Storage Account - For function runtime storage
- `Storage Queue Data Contributor` on Storage Account - For queue binding
- `Storage Queue Data Message Processor` on Storage Account - For processing queue messages
- `Reader` on Automation Account - For reading automation account information
- `Automation Operator` on Automation Account - For starting runbook jobs
- `Monitoring Metrics Publisher` on Application Insights - For telemetry and monitoring

**Event Grid System Topic Managed Identity** (2 assignments):
- `Storage Queue Data Reader` on Storage Account - For reading queue metadata
- `Storage Queue Data Message Sender` on Storage Account - For sending certificate expiry events to queue

## Parameters

The deployment requires the following parameters (configured in `parameters.dev.bicepparam`):

| Parameter | Description |
|-----------|-------------|
| `peSubnetId` | Resource ID of the subnet for private endpoints |
| `fnSubnetId` | Resource ID of the subnet for Function App VNet integration (must be delegated to Microsoft.App/environments) |
| `dnsZonesSubscriptionId` | Subscription ID where Private DNS Zones are located |
| `dnsZonesResourceGroupName` | Resource group name where Private DNS Zones are located |
| `storageAccountName` | Name for the Storage Account |
| `functionAppName` | Name for the Function App |
| `logAnalyticsWorkspaceName` | Name for the Log Analytics Workspace |
| `applicationInsightsName` | Name for the Application Insights instance |
| `automationAccountName` | Name for the Automation Account |
| `hybridWorkerGroupName` | Name for the Hybrid Worker Group |
| `keyVaultName` | Name for the Key Vault |
| `dataCollectionEndpointName` | Name for the Data Collection Endpoint |
| `dataCollectionRuleName` | Name for the Data Collection Rule |
| `automationAccountVarCA` | Certificate Authority name (CA_SERVER\\CA_NAME) |
| `automationAccountVarPfxRootFolder` | Root folder path for PFX certificates |
| `automationAccountVarSmtpFrom` | SMTP From email address |
| `automationAccountVarSmtpServer` | SMTP server hostname or IP |
| `automationAccountVarSmtpUser` | SMTP username for authentication |
| `automationAccountVarSmtpPassword` | SMTP password (encrypted in Automation Account) |
| `scheduleStartTime` | Start time for certlcstats schedule (defaults to 15 minutes after deployment) |

## Post-Deployment Steps

After deploying the infrastructure, complete these additional steps:

1. **Register Hybrid Workers**: Add the hybrid worker VM(s) to the Hybrid Worker Group
2. **Upload Runbook Code**: 
   - Upload the actual PowerShell code for `certlc.ps1` runbook (placeholder created during deployment)
   - Upload the actual PowerShell code for `certlcstats.ps1` runbook (placeholder created during deployment)
3. **Enable Certificate Statistics Collection** (Optional):
   - The hourly schedule for `certlcstats` runbook is created but NOT linked
   - To enable automatic statistics collection:
     - Option A: Uncomment the `jobScheduleCertLCStats` resource in `certlc.bicep` and redeploy
     - Option B: Manually link the schedule `schedule-certlcstats-hourly` to the `certlcstats` runbook in Azure Portal
     - Option C: Use Azure CLI: `az automation job-schedule create`
   - The schedule will run the runbook every hour on the hybrid worker group
4. **Deploy Function App Code**: Deploy the PowerShell function code to the Function App
5. **Grant CA Permissions**: Assign the hybrid worker's computer account Enroll permissions on the CA templates
6. **Customize Workbook** (Optional): Add queries and visualizations to the `certlcstats` workbook for certificate monitoring
7. **Test End-to-End**: 
   - **Create a test certificate** using the utility scripts in the `Utilities` folder:
     - `testnewcert.ps1` - Request a new certificate enrollment
     - `testrenewcert.ps1` - Request certificate renewal
     - `testrevocationcert.ps1` - Request certificate revocation
   - These scripts can send requests via Storage Queue, Automation Webhook, or direct runbook invocation
   - **Monitor the workflow**:
     1. Verify the message appears in the Storage Queue (`certlc` queue)
     2. Check Function App logs in Application Insights to confirm queue message processing
     3. Verify the Function App triggers the `certlc` runbook in the Automation Account
     4. Monitor the runbook job execution logs in the Automation Account
     5. Verify certificate operations complete successfully in Key Vault
     6. For certificate near-expiry events, verify Event Grid captures the event and delivers to the queue
   - **Verify statistics collection**:
     - Run the `certlcstats` runbook manually or wait for the schedule (if enabled)
     - Query the custom table in Log Analytics: `certlc_CL | order by TimeGenerated desc`
     - Verify certificate data appears with correct fields (Thumbprint, Name, Expires, Subject, etc.)

## Security Notes

The solution follows a secure-by-default architecture:
- All PaaS resources use private endpoints with public access disabled
- All authentication uses managed identities (no service accounts or passwords)
- Sensitive parameters (like SMTP password) are marked with `@secure()` decorator
- Sensitive outputs (like DCR immutable ID) are protected with `@secure()` decorator
- All resources are tagged with `solution: 'CertLC'` for easy identification
- Role-based access control (RBAC) follows the principle of least privilege
- Automation Account variables for sensitive data are encrypted
- Key Vault uses RBAC authorization and soft delete protection
- Diagnostic settings enabled on critical resources (Automation Account, Key Vault) for audit logging

## Files

- `certlc.bicep` - Main Bicep template
- `parameters.dev.bicepparam` - Bicep parameter file
- `README.md` - This file