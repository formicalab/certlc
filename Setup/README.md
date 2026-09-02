# CertLC Setup Guide

This directory contains the Bicep infrastructure-as-code templates for deploying all Azure resources required by the CertLC solution.

For a complete solution overview, architecture, and feature description, see the [main README](../README.md).

## Prerequisites

Before deploying, ensure you have:

1. **Resource Group**: Created in the target Azure region
2. **Virtual Network and Subnets**:
  - Subnet for the 6 Private Endpoints created by this template: Storage blob and queue, Function App, Automation webhook, Automation `DSCAndHybridWorker`, and Key Vault. Each endpoint consumes one IP address; use at least `/28` (16 total addresses minus 5 reserved by Azure, leaving 11 usable) to accommodate all 6 endpoints, and choose a larger subnet if future endpoints are expected.
    - Subnet delegated to `Microsoft.App/environments` for Function App VNet integration; Flex Consumption requires a minimum size of `/27` (32 total addresses minus 5 reserved by Azure, leaving 27 usable IP addresses)
3. **Private DNS Zones**: Pre-existing Private DNS Zones for all required services (can be in a different subscription/resource group)
   - `privatelink.blob.core.windows.net`
   - `privatelink.queue.core.windows.net`
   - `privatelink.azurewebsites.net`
   - `privatelink.azure-automation.net`
   - `privatelink.vaultcore.azure.net`
4. **Hybrid Worker VM**: A Windows Azure VM configured as an extension-based Hybrid Runbook Worker and registered in the configured worker group. Azure Arc-enabled and non-Azure machines have not been tested and are not supported by this solution. The VM requires:
    - At least 2 CPU cores and 4 GB of RAM
    - A system-assigned managed identity; enable it before adding the VM to the Hybrid Worker Group
    - PowerShell 7.6 installed and available to the Hybrid Worker
    - Az PowerShell 15.1.0 available to PowerShell 7.6, including `Az.Accounts`, `Az.KeyVault`, `Az.Storage`, and `Az.Resources`, as required by the runbooks
    - Domain membership (or an equivalent trust and identity configuration) with DNS, Kerberos, and LDAP connectivity to Active Directory; the runbooks query certificate templates through LDAP and resolve domain principals used to protect exported PFX files
    - RPC connectivity to the issuing Enterprise CA for certificate enrollment and revocation: TCP 135 for the RPC endpoint mapper and the dynamic RPC port range configured on the CA (TCP 49152-65535 by default on current Windows Server versions)
    - Routed HTTPS access on TCP 443, with working private DNS resolution, to the Key Vault private endpoint and the Automation Account `DSCAndHybridWorker` private endpoint
    - Outbound HTTPS access on TCP 443 to Microsoft Entra ID/Azure Resource Manager for managed-identity authentication and to the Azure Monitor data collection endpoint used by `certlcstats.ps1` (the template currently exposes this endpoint through public network access)
    - Read/write/create-folder and ACL permissions on the configured PFX root path; if it is a UNC path, network and SMB access (TCP 445) to the file server are required
    - Network access to the configured SMTP server and port when email notifications are enabled
5. **Deployment VM**: Prepare a dedicated Windows VM in advance for both the Bicep infrastructure deployment and the subsequent bridge Function App publishing. Install and verify the following tools on this VM:
  - **Azure CLI**: Install Azure CLI with Windows Package Manager by running `winget install -e --id Microsoft.AzureCLI`, or use the [64-bit MSI installer](https://aka.ms/installazurecliwindowsx64). Open a new PowerShell session after installation and verify it with `az version`.
  - **Azure CLI-managed Bicep CLI**: Install Bicep through Azure CLI by running `az bicep install`; a separate standalone Bicep installation is not required. Verify it with `az bicep version`. Use `az bicep upgrade` to update it when required.
  - **Azure Functions Core Tools**: Install Core Tools v4 by following the [official installation guidance](https://learn.microsoft.com/azure/azure-functions/functions-run-local#install-the-azure-functions-core-tools). On Windows, use either the 64-bit MSI (recommended for command-line use and does not require Node.js) or npm (`npm install -g azure-functions-core-tools@4 --unsafe-perm true`), which requires Node.js and npm. Use one installation method only to avoid PATH and version conflicts. Verify the installed version with `func --version` and confirm it is 4.14 or later before publishing.
  - **Azure management connectivity**: Allow outbound HTTPS on TCP 443 from the deployment VM to Microsoft Entra ID and Azure management endpoints so Azure CLI can authenticate, validate the template, and deploy resources.
  - **PowerShell Gallery connectivity**: Allow outbound HTTPS on TCP 443 to PowerShell Gallery so the Function modules can be downloaded with `Save-Module`. If direct access is not permitted, stage the required modules on the VM through the customer's approved offline software-distribution process before publishing.
  - **Azure authentication**: Before validating or deploying the Bicep template, authenticate Azure CLI and explicitly select the target subscription. Verify the selected account and subscription before continuing:

    ```powershell
    az login
    az account set --subscription <subscription-id>
    az account show --query "{Subscription:name, SubscriptionId:id, TenantId:tenantId, User:user.name}" --output table
    ```

6. **Azure Resource Providers**: Ensure the resource providers used by the template are registered in the deployment subscription. The identity performing registration requires `Microsoft.Resources/subscriptions/providers/register/action` at subscription scope. If the private DNS zones are hosted in another subscription, ensure `Microsoft.Network` is also registered there.

    ```powershell
    @(
      'Microsoft.Automation'
      'Microsoft.EventGrid'
      'Microsoft.Insights'
      'Microsoft.KeyVault'
      'Microsoft.Network'
      'Microsoft.OperationalInsights'
      'Microsoft.Storage'
      'Microsoft.Web'
    ) | ForEach-Object {
      az provider register --namespace $_ --wait
      az provider show --namespace $_ --query "{Namespace:namespace, State:registrationState}" --output table
    }
    ```

### Required RBAC Permissions

The identity deploying this Bicep template requires the following Azure role assignments:

#### On the Deployment Resource Group (where CertLC resources will be created):
- **Owner** role (or Contributor + User Access Administrator)
  - Required to create resources and assign RBAC roles to managed identities
  - The template creates 13 role assignments for managed identities across various resources

#### On the Private DNS Zones Resource Group (if zones are in a different subscription/resource group):
- **Private DNS Zone Contributor** role
  - Required to create DNS A records in private DNS zones when private endpoints are deployed
  - The template creates 6 private endpoints, each with a DNS zone group that registers A records
  - This role must be assigned on the resource group containing the private DNS zones, or individually on each DNS zone

#### On the Network Resource Group Containing the Existing Subnets:
- **Network Contributor** role on the resource group containing the private endpoint subnet (`peSubnetId`) and Function App integration subnet (`fnSubnetId`)
  - Required because the deployment joins private endpoints and the Function App to these existing subnets
  - The resource-group assignment is inherited by both subnets and replaces separate subnet-level assignments when both subnets are in the same resource group
  - Owner or Contributor on the CertLC deployment resource group does not grant permissions on a separate network resource group or subscription
  - This assignment grants Network Contributor permissions to all network resources in that resource group; if the subnets are in different resource groups, assign the role on each network resource group instead

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

# Grant Network Contributor on the resource group containing both existing subnets
az role assignment create `
  --assignee <user-or-service-principal-id> `
  --role "Network Contributor" `
  --scope "/subscriptions/<network-subscription-id>/resourceGroups/<network-resource-group>"
```

**Note**: If using a service principal for automated deployments, ensure it has these permissions before running the deployment.

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
| `runbookName` | Name of the primary runbook created on the Automation Account and invoked by the Function App. The actual `certlc.ps1` code is uploaded to this runbook post-deployment |
| `runtimeEnvironmentName` | Name of the custom PowerShell 7.6 runtime environment created on the Automation Account and used by both runbooks (default `certlc-PowerShell-7-6`; names cannot contain dots) |
| `hybridWorkerGroupName` | Name for the Hybrid Worker Group |
| `keyVaultName` | Name for the Key Vault |
| `logAnalyticsRetentionInDays` | Log Analytics Workspace retention in days (default 30) |
| `keyVaultSoftDeleteRetentionInDays` | Key Vault soft-delete retention in days (default 7) |
| `dataCollectionEndpointName` | Name for the Data Collection Endpoint |
| `dataCollectionRuleName` | Name for the Data Collection Rule |
| `automationAccountVarCA` | Certificate Authority name (CA_SERVER\\CA_NAME) |
| `automationAccountVarPfxRootFolder` | Root folder path for PFX certificates |
| `automationAccountVarSmtpFrom` | SMTP From email address |
| `automationAccountVarSmtpServer` | SMTP server hostname or IP |
| `automationAccountVarSmtpUser` | SMTP username for authentication |
| `automationAccountVarSmtpPassword` | SMTP password (encrypted in Automation Account) |
| `scheduleStartTime` | Start time for certlcstats schedule (defaults to 15 minutes after deployment) |

## Deployment

1. Configure `parameters.dev.bicepparam` using the parameter reference above.
2. Validate the template, parameters, permissions, policies, and referenced resources with an Azure-side preflight. This does not create or modify resources:

```powershell
az deployment group validate `
  --resource-group <your-resource-group> `
  --parameters .\parameters.dev.bicepparam
```

3. Preview the deployment changes using what-if:

```powershell
az deployment group what-if `
  --resource-group <your-resource-group> `
  --parameters .\parameters.dev.bicepparam
```

4. Review the what-if output and confirm that the proposed changes are expected.
5. Deploy the infrastructure using the Bicep template and parameter file:

```powershell
az deployment group create `
  --resource-group <your-resource-group> `
  --parameters .\parameters.dev.bicepparam
```

## Resources Created

The Bicep template creates and configures the following Azure resources:

### Data and Observability

#### 1. **Storage Account**
- **Type**: Standard LRS with hierarchical namespace disabled
- **Purpose**: Hosts the `certlc` queue for event-driven certificate lifecycle operations. It is also used by the Azure Function and stores Event Grid dead-lettered messages
- **Configuration**: 
  - Public network access disabled
  - Cross-tenant replication disabled
  - Default to Azure AD authentication
  - Blob and Queue services enabled
  - Dead-letter blob container `eventgrid-deadletter` for failed Event Grid deliveries
- **Private Endpoints**:
  - Blob service endpoint
  - Queue service endpoint

#### 2. **Log Analytics Workspace**
- **Type**: PerGB2018 pricing tier
- **Purpose**: Centralized logging and analytics for all CertLC components
- **Configuration**:
  - Retention period (parameterized, default 30 days)
  - Local (shared-key) authentication disabled — ingestion uses Entra ID only
- **Used by**: Application Insights, Azure Monitor, and custom tables for certificate statistics

#### 3. **Application Insights**
- **Type**: Web application monitoring
- **Purpose**: Application performance monitoring and diagnostics for the Function App
- **Configuration**:
  - Linked to Log Analytics Workspace
  - Local authentication disabled — telemetry is ingested via the Function App's managed identity (Monitoring Metrics Publisher role) using `APPLICATIONINSIGHTS_AUTHENTICATION_STRING=Authorization=AAD`

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

#### 7. **Azure Monitor Workbook**
- **Type**: Shared workbook for certificate statistics visualization
- **Purpose**: Provides a dashboard for monitoring certificate lifecycle and statistics
- **Configuration**:
  - Name: `certlcstats`
  - Initially empty (queries and visualizations can be added post-deployment)
  - Linked to Log Analytics Workspace as data source
  - Depends on Application Insights to ensure workspace stability

### Application and Automation

#### 8. **Function App (Flex Consumption Plan)**
- **Type**: Azure Functions on Flex Consumption plan
- **Purpose**: Event-driven processing of certificate lifecycle events from the queue
- **Configuration**:
  - Integrated with VNet via delegated subnet
  - Connected to Storage Account and Application Insights using its system-assigned managed identity for authentication (no instrumentation keys or connection strings with secrets)
  - Runtime: PowerShell 7.4
  - Hardened: HTTPS only, FTPS state disabled, public network access restricted to the private endpoint
- **Private Endpoint**: Secured with private endpoint for site access

#### 9. **Automation Account**
- **Type**: Basic SKU with System-Assigned Managed Identity
- **Purpose**: Orchestrates certificate operations with the Enterprise CA and Key Vault (runbook `certlc.ps1`); collects statistics about certificates in the KeyVault (runbook `certlcstats.ps1`)
- **Configuration**:
  - Public network access disabled
  - Custom PowerShell 7.6 runtime environment (default name `certlc-PowerShell-7-6`, parameterized) used by both runbooks, with default packages `Az` 15.1.0 and `Azure CLI` 2.77.0 preloaded
  - `disableLocalAuth: false` — kept enabled because legacy webhook authentication (key in query string) is still required by external callers that cannot use Entra ID
  - Includes encrypted variables used by the runbooks (CA name, PFX root folder, SMTP settings, Key Vault name, DCR details)
  - Two placeholder runbooks created: the primary runbook named by `runbookName` and `certlcstats` (code must be uploaded post-deployment)
  - Hybrid Worker Group for on-premises CA communication
  - Hourly schedule prepared for `certlcstats` runbook (disabled by default, requires manual activation)
  - Diagnostic settings enabled: JobLogs, JobStreams, AllMetrics sent to Log Analytics
- **Private Endpoints**:
  - Webhook endpoint (for Function App to trigger runbooks)
  - DSC and Hybrid Worker endpoint (for hybrid worker communication)

#### 10. **Hybrid Worker Group**
- **Type**: Azure Automation Hybrid Runbook Worker Group
- **Purpose**: Enables the automation account to execute runbooks on supported Windows Azure VMs with access to the Enterprise CA
- **Note**: Worker machines must be registered separately after deployment

### Security Resources

#### 11. **Key Vault**
- **Type**: Standard tier with RBAC authorization
- **Purpose**: Secure storage for certificates and secrets
- **Configuration**:
  - Public network access disabled
  - Soft delete enabled (retention parameterized, default 7 days)
  - Purge protection enabled (irreversible — soft-deleted objects cannot be purged before the retention window expires)
  - RBAC authorization mode
  - Diagnostic settings enabled: AuditEvent, AzurePolicyEvaluationDetails, AllMetrics sent to Log Analytics
- **Private Endpoint**: Secured with private endpoint for vault access

### Event Processing

#### 12. **Event Grid System Topic**
- **Type**: System Topic for Key Vault events
- **Purpose**: Captures certificate lifecycle events from Key Vault
- **Configuration**:
  - Uses system-assigned managed identity
  - Connected to Key Vault as event source
  - Topic type: `Microsoft.KeyVault.Vaults`

#### 13. **Event Grid Event Subscription**
- **Type**: Event subscription with Storage Queue destination
- **Purpose**: Routes certificate expiry events to the Storage Queue for processing
- **Configuration**:
  - Filters for `Microsoft.KeyVault.CertificateNearExpiry` events only
  - Delivers to `certlc` queue in Storage Account
  - Uses CloudEvents v1.0 schema
  - Message TTL: 1 day (86400 seconds)
  - Retry policy: 30 attempts over 1 day (1440 minutes)
  - **Dead-letter destination**: failed deliveries are written to the `eventgrid-deadletter` blob container on the Storage Account (using the system topic's managed identity)

### Networking

#### 14. **Private Endpoints** (6 total)
All PaaS resources are secured with private endpoints to disable public access:
- Storage Account Blob endpoint
- Storage Account Queue endpoint
- Function App site endpoint
- Automation Account webhook endpoint
- Automation Account DSC/Hybrid Worker endpoint
- Key Vault endpoint

Each private endpoint is linked to existing Private DNS Zones (they can be in another subscription/resource group) for name resolution.

#### 15. **Private DNS Zone Groups** (6 total)
Each private endpoint has an associated DNS zone group that links to the appropriate Private DNS Zones:
- `privatelink.blob.core.windows.net`
- `privatelink.queue.core.windows.net`
- `privatelink.azurewebsites.net`
- `privatelink.azure-automation.net`
- `privatelink.vaultcore.azure.net`

### Identity and Access Management

#### 16. **Role Assignments** (13 total)

The Bicep template automatically creates the following role assignments for the managed identities.

**Automation Account Managed Identity** (4 assignments):

| Role | Scope | Purpose |
|------|-------|---------|
| Key Vault Certificates Officer | Key Vault | Create and manage certificates in Key Vault |
| Key Vault Secrets Officer | Key Vault | Export certificates as PFX (access to private keys) |
| Reader | Automation Account (self) | Allow hybrid worker to read automation account variables |
| Monitoring Metrics Publisher | Data Collection Rule | Publish certificate statistics to custom Log Analytics table |

**Function App Managed Identity** (6 assignments):

| Role | Scope | Purpose |
|------|-------|---------|
| Storage Blob Data Owner | Storage Account | Function runtime storage operations |
| Storage Queue Data Contributor | Storage Account | Function's queue binding operations |
| Storage Queue Data Message Processor | Storage Account | Process and delete queue messages |
| Reader | Automation Account | Read automation account information |
| Automation Operator | Automation Account | Start and monitor runbook jobs |
| Monitoring Metrics Publisher | Application Insights | Function telemetry and monitoring |

**Event Grid System Topic Managed Identity** (3 assignments):

| Role | Scope | Purpose |
|------|-------|---------|
| Storage Queue Data Reader | Storage Account | Read queue metadata for event delivery |
| Storage Queue Data Message Sender | Storage Account | Send certificate expiry events to queue |
| Storage Blob Data Contributor | Storage Account | Write dead-lettered events to the `eventgrid-deadletter` blob container |

## Post-Deployment Steps

After deploying the infrastructure, complete these additional steps:

1. **Register the Hybrid Worker VM**:
  - In the Azure portal, open the deployed Automation Account, select **Hybrid worker groups**, and open the group named by `hybridWorkerGroupName`
  - Select **Hybrid Workers** > **+ Add**, select the Windows Azure VM, and add it to the group. This installs the extension-based Azure Automation Windows Hybrid Worker on the VM
  - On the VM's **Identity** page, confirm that its system-assigned managed identity is enabled
  - On the VM's **Extensions + applications** page, confirm that the Azure Automation Windows Hybrid Worker extension completed successfully. In the Automation Account, confirm that the VM appears in the configured group as an extension-based worker before starting any runbook
  - Only Windows Azure VMs are supported by this solution; Azure Arc-enabled and non-Azure workers have not been tested
  - For detailed installation and troubleshooting guidance, see [deploy an extension-based Hybrid Runbook Worker](https://learn.microsoft.com/azure/automation/extension-based-hybrid-runbook-worker-install)
2. **Upload Runbook Code**: 
  - Upload the actual `certlc.ps1` PowerShell code to the primary runbook named by `runbookName` (placeholder created during deployment)
   - Upload the actual PowerShell code for `certlcstats.ps1` runbook (placeholder created during deployment)
3. **Create the External-Client Webhook**:
  - Publish the primary runbook before creating its webhook
  - In the Automation Account, open the primary runbook named by `runbookName`, select **Webhooks** > **Add Webhook** > **Create new Webhook**, and configure an enabled webhook with an appropriate name and expiration date
  - Under **Parameters and run settings**, configure the webhook to run on the Hybrid Worker Group named by `hybridWorkerGroupName`; do not configure fixed runbook parameters because each external client supplies its request in the HTTP POST body
  - Copy the generated webhook URL before completing creation and store it in the customer's approved secret-management system. The URL contains the authentication token, is displayed only during creation, cannot be retrieved later, and must be treated like a password. Do not place it in source control, scripts, logs, tickets, or ordinary configuration files
  - Distribute the URL only to authorized external clients. Those clients must have routed HTTPS access on TCP 443 and private DNS resolution to the Automation Account webhook private endpoint, and must use TLS 1.2 or later
  - Track the webhook expiration date and rotate it before expiry. Create and distribute a replacement webhook URL before removing the old webhook
  - For webhook behavior and security guidance, see [start a runbook from a webhook](https://learn.microsoft.com/azure/automation/automation-webhooks)
4. **Enable Certificate Statistics Collection** (Optional):
   - The hourly schedule for `certlcstats` runbook is created but NOT linked
   - To enable automatic statistics collection:
     - Option A: Uncomment the `jobScheduleCertLCStats` resource in `certlc.bicep` and redeploy
     - Option B: Manually link the schedule `schedule-certlcstats-hourly` to the `certlcstats` runbook in Azure Portal
     - Option C: Use Azure CLI: `az automation job-schedule create`
   - The schedule will run the runbook every hour on the hybrid worker group
5. **Deploy Function App Code**:
  - After deployment, identify the Function App private endpoint and its private IP address. This information is available only after the endpoint has been created
  - Complete the deployment VM's publishing connectivity by configuring routing and firewall rules so it can reach the private endpoint over HTTPS on TCP 443, either from the same or a peered VNet, or through VPN/ExpressRoute
  - Verify from the deployment VM that private DNS resolves both `<function-app-name>.azurewebsites.net` and `<function-app-name>.scm.azurewebsites.net` to the private endpoint; the SCM endpoint is used to publish while public network access is disabled
    - Flex Consumption does not support PowerShell managed dependencies. Before publishing, download the modules used by the function into the `Modules` directory so they are included in the deployment package. From the repository root on the publishing VM, run:

      ```powershell
      Set-Location .\Functions\CertLCBridge
      Save-Module -Name Az.Accounts -RequiredVersion 5.5.3 -Path .\Modules -Repository PSGallery -Force
      Save-Module -Name Az.Automation -RequiredVersion 1.12.1 -Path .\Modules -Repository PSGallery -Force
      ```

      These commands download the pinned module versions and their dependencies from PowerShell Gallery, producing a reproducible Function App package. The downloaded contents of `Modules` are local deployment artifacts and are excluded from Git; only `Modules/.gitkeep` is tracked so the empty directory exists in a fresh clone. Run these commands whenever preparing a fresh checkout for publishing. Do not declare the modules as managed dependencies in `requirements.psd1`. For more information, see [including modules in app content](https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell#including-modules-in-app-content).
    - From the `Functions\CertLCBridge` project directory, publish the complete project. Publishing overwrites the Function App's existing deployed content:

      ```powershell
      func azure functionapp publish <function-app-name>
      ```

      Replace `<function-app-name>` with the deployed `functionAppName` parameter value. No PowerShell-specific option is required: the local project declares `FUNCTIONS_WORKER_RUNTIME=powershell`, and the Bicep template configures the target Function App for PowerShell 7.4. For command details, see [deploying a Flex Consumption app with Core Tools](https://learn.microsoft.com/azure/azure-functions/flex-consumption-how-to#deploy-your-code-project).

6. **Configure Function App Outbound Connectivity**: The Function App uses the public Application Insights ingestion endpoint for telemetry and also requires public Azure endpoints such as Microsoft Entra ID. Configure controlled internet egress for the delegated Function App subnet (`fnSubnetId`):
  - Configure the customer-provided firewall to allow outbound HTTPS on TCP 443 from the delegated subnet to the `AzureCloud` service tag. `AzureCloud` is intentionally broader than an Application Insights-specific tag so the function can also reach its other required Azure public endpoints
  - Configure the customer-provided firewall to perform source NAT (SNAT) to a public IP for outbound traffic from the delegated subnet
    - Verify that DNS can resolve the required public Azure endpoints and that Application Insights telemetry is received after the function starts
  - These firewall rules and SNAT configuration are not created by this template and must be configured in the customer network containing `fnSubnetId`. For details, see [Azure service tags](https://learn.microsoft.com/azure/virtual-network/service-tags-overview)
7. **Grant CA Permissions**: Assign the hybrid worker's computer account Enroll permissions on the CA templates
8. **Customize Workbook** (Optional): Add queries and visualizations to the `certlcstats` workbook for certificate monitoring
9. **Test End-to-End**:
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
- Storage, Function App, Automation Account, and Key Vault data-plane access use private endpoints with public access disabled. Azure Monitor endpoints, including Application Insights ingestion and the DCE, remain public and require controlled outbound access from the workloads
- Azure resource access uses managed identities and RBAC without storage keys, instrumentation keys, or Azure service-principal secrets. The optional SMTP integration can use the encrypted `automationAccountVarSmtpUser` and `automationAccountVarSmtpPassword` credentials, and external Automation webhook calls authenticate through the secret token embedded in the webhook URL. Protect and rotate those exceptions as credentials
- Sensitive parameters (like SMTP password) are marked with `@secure()` decorator
- Sensitive outputs (like DCR immutable ID) are protected with `@secure()` decorator
- All resources are tagged with `solution: 'CertLC'` for easy identification
- Role-based access control (RBAC) follows the principle of least privilege
- Automation Account variables for sensitive data are encrypted
- Key Vault uses RBAC authorization and soft delete protection
- The runbook never deletes certificates from Key Vault: revocations are recorded by disabling the specific version and tagging it (`Revoked=true`, `RevokedAt`, `RevocationReason`, `RevokedJobId`). Renewed versions are likewise tagged with `RenewedJobId` for traceability. A duplicate revocation against an already-revoked version is rejected up-front with an `ALREADY REVOKED` error and the previous audit tags are preserved. Vault soft-delete / purge-protection settings still apply to operator actions performed outside the runbook
- Diagnostic settings enabled on critical resources (Automation Account, Key Vault) for audit logging

## Files

- `certlc.bicep` - Main Bicep template
- `parameters.dev.bicepparam` - Bicep parameter file
- `README.md` - This file