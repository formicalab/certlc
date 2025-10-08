# Certificate Lifecycle Management (CertLC)
## Setup

This directory contains the Bicep infrastructure-as-code templates for deploying all Azure resources required by the CertLC solution.

## Deployment

Deploy the infrastructure using the Bicep template and parameter file:

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
- **Purpose**: Hosts the `certlc` queue for event-driven certificate lifecycle operations
- **Configuration**: 
  - Public network access disabled
  - Default to Azure AD authentication
  - Blob, Queue, File, and Table services enabled
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
- **Purpose**: Stores certificate statistics and metadata for monitoring and reporting
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
  - Uses managed identity for authentication
  - Connected to Storage Account and Application Insights
  - Runtime: PowerShell 7.4
- **Private Endpoint**: Secured with private endpoint for site access

#### 8. **Automation Account**
- **Type**: Basic SKU with System-Assigned Managed Identity
- **Purpose**: Orchestrates certificate operations with the Enterprise CA and Key Vault
- **Configuration**:
  - Public network access disabled
  - Includes 10 encrypted variables (CA name, PFX root folder, SMTP settings, Key Vault name, DCR details)
  - Hybrid Worker Group for on-premises CA communication
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

Each private endpoint is linked to existing Private DNS Zones (in another subscription/resource group) for name resolution.

#### 14. **Private DNS Zone Groups** (6 total)
Each private endpoint has an associated DNS zone group that links to the appropriate Private DNS Zones:
- `privatelink.blob.core.windows.net`
- `privatelink.queue.core.windows.net`
- `privatelink.azurewebsites.net`
- `privatelink.azure-automation.net`
- `privatelink.vaultcore.azure.net`

### Identity and Access Management

#### 15. **Role Assignments** (12 total)

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

## Prerequisites

Before deploying, ensure you have:

1. **Resource Group**: Created in the target Azure region
2. **Virtual Network and Subnets**:
   - Subnet for Private Endpoints
   - Subnet delegated to `Microsoft.App/environments` for Function App VNet integration
3. **Private DNS Zones**: Pre-existing Private DNS Zones for all required services (can be in a different subscription)
4. **Hybrid Worker VM**: A Windows VM (on-premises or Azure) with access to the Enterprise CA

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

## Post-Deployment Steps

After deploying the infrastructure, complete these additional steps:

1. **Register Hybrid Workers**: Add the hybrid worker VM(s) to the Hybrid Worker Group
2. **Deploy Runbooks**: Upload `certlc.ps1` and `certlcstats.ps1` to the Automation Account
3. **Configure Automation Variables**: Set required variables in the Automation Account
4. **Deploy Function App Code**: Deploy the PowerShell function code to the Function App
5. **Create Custom Table**: Set up the custom table in Log Analytics for certificate statistics
6. **Grant CA Permissions**: Assign the hybrid worker's computer account Enroll permissions on the CA templates
7. **Deploy Workbook**: Import the Azure Monitor workbook for certificate monitoring

## Architecture

The solution follows a secure-by-default architecture:
- All PaaS resources use private endpoints with public access disabled
- All authentication uses managed identities (no service accounts or passwords)
- All resources are tagged with `solution: 'CertLC'` for easy identification
- Role-based access control (RBAC) follows the principle of least privilege

## Files

- `certlc.bicep` - Main Bicep template
- `parameters.dev.bicepparam` - Bicep parameter file
- `README.md` - This file