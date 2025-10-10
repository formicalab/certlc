# Certificate Lifecycle Management (CertLC)

CertLC is a solution designed to fully automate X.509 certificate lifecycle operations on Azure-connected environments, integrating a Key Vault with a traditional Active Directory Enterprise CA.

* **Creation**
  * Creates new certificates on demand.
  * All private keys are generated and stored inside the target Key Vault.  
  * All certificates are signed by the Enterprise CA and safely stored in Key Vault
  * The resulting certificates are also made available inside a secured per-user/per-group folder as protected PFXs (user or group protection - no passwords used) for operator to pick up and install.

* **Renewal**
  * The key vault emits `Microsoft.KeyVault.CertificateNearExpiry` events for certificates near expiration. The event is used to trigger the automatic renewal process.
  * An Event Grid System Topic is used to send `Microsoft.KeyVault.CertificateNearExpiry` events to a storage queue
  * a Function App with queue bindings is used to get the events and forward them to Automation Account, triggering the execution of the renewal with the **certlc** runbook
  * A new certificate version is stored in Key Vault and exported as new PFX

* **Revocation**
  * Revokes the certificate in the CA and deletes it from the key vault

* **Statistics Collection**
  * The **certlcstats** runbook collects certificate statistics from Key Vault and publishes them to a Log Analytics custom table
  * Can run on-demand or on an hourly schedule for continuous monitoring
  * Statistics include certificate thumbprint, name, creation/expiration dates, subject, template, and DNS names

* **Runbook and Hybrid Worker Execution**  
  * The **certlc** runbook manages all certificate requests to the Enterprise CA and Key Vault operations
  * The **certlcstats** runbook collects and publishes certificate statistics for monitoring
  * All runbook execution is performed by **Azure Automation Hybrid Workers** able to orchestrate operations towards the CA and Key Vault

* **Security**  
  * All PaaS resources can have their public endpoint disabled - Private Endpoints are used for all communications 
  * No AD service accounts are used: all permissions are assigned to computer accounts and to the system-assigned managed identities of the PaaS resources 

## Architecture Highlights

- **Event-Driven**: Certificate expiry events flow from Key Vault → Event Grid → Storage Queue → Function App → Automation Account runbook
- **Hybrid Execution**: Runbooks execute on on-premises hybrid workers with direct access to Enterprise CA
- **Observability**: Comprehensive logging with Application Insights, Log Analytics, diagnostic settings, and custom tables for certificate statistics
- **Monitoring**: Azure Monitor workbook provides visualization of certificate lifecycle and statistics
- **Automation**: Optional hourly schedule for proactive certificate statistics collection
- **Secure by Default**: All PaaS resources use private endpoints, managed identities for authentication, and RBAC for authorization

## Repository Structure

```
Setup/
  certlc.bicep              # Main Bicep infrastructure template
  parameters.dev.bicepparam # Bicep parameters file
  README.md                 # Detailed setup and deployment documentation
Runbooks/
  certlc.ps1                # Main runbook with certificate lifecycle logic
  certlcstats.ps1           # Statistics collection runbook for Log Analytics custom table
Functions/
  CertLCBridge/             # Function App code (PowerShell 7.4)
LogAnalytics/
  customtable/              # Manual custom table setup (only needed if not using Bicep deployment)
Workbooks/
  certlc.workbook           # Azure Monitor workbook for certificate monitoring
Utilities/
  testnewcert.ps1           # Test script for new certificate enrollment
  testrenewcert.ps1         # Test script for certificate renewal
  testrevocationcert.ps1    # Test script for certificate revocation
```

## Setup

The solution infrastructure is deployed using **Azure Bicep** templates located in the `Setup/` folder. The Bicep template automates the creation of all required Azure resources with secure defaults.

### Quick Start

1. Review the detailed setup documentation in [`Setup/README.md`](Setup/README.md)
2. Configure the parameters in `Setup/parameters.dev.bicepparam`
3. Deploy using Azure CLI:
   ```powershell
   az deployment group create `
     --resource-group <your-resource-group> `
     --parameters .\Setup\parameters.dev.bicepparam
   ```

### What Gets Deployed

The Bicep template automatically creates and configures:
- **Storage Account** with `certlc` queue (LRS, private endpoints)
- **Key Vault** (RBAC mode, soft delete, private endpoint)
- **Automation Account** with PowerShell 7.2 runtime, placeholder runbooks, encrypted variables, hybrid worker group
- **Log Analytics Workspace** with custom table (`certlc_CL`) for certificate statistics
- **Application Insights** for monitoring and diagnostics
- **Function App** on Flex Consumption plan (PowerShell 7.4, VNet integration)
- **Data Collection Endpoint/Rule** for custom logs ingestion
- **Event Grid System Topic** and subscription for certificate expiry events
- **Azure Monitor Workbook** for certificate visualization
- **6 Private Endpoints** with DNS zone integration (Blob, Queue, Function, Automation Webhook, Automation DSC, Key Vault)
- **12 RBAC role assignments** for managed identities
- **Diagnostic settings** for Automation Account and Key Vault

### Post-Deployment

After infrastructure deployment, complete these steps:
1. **Register hybrid worker(s)** to the hybrid worker group
2. **Upload runbook code** (`certlc.ps1` and `certlcstats.ps1`) to the Automation Account, directly from Azure Portal
3. **Deploy Function App code** using Azure Functions Core Tools:

   - Install [Azure Functions Core Tools](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local?tabs=windows%2Cisolated-process%2Cnode-v4%2Cpython-v2%2Chttp-trigger%2Ccontainer-apps&pivots=programming-language-powershell#install-the-azure-functions-core-tools) if needed
   - Go to the `Functions/CertLCBridge` directory and execute:

      ```powershell
      # From the Functions/CertLCBridge folder:
      func azure functionapp publish <functionappname>
      ```

4. **Upload workbook code** to the Azure Monitor Workbook created by the Bicep deployment (edit the workbook in Advanced Editor mode and paste the content from `Workbooks/certlc.workbook`)
5. **Grant CA template permissions** to hybrid worker computer accounts (Enroll permission on certificate templates)
6. **(Optional) Enable hourly schedule** for certificate statistics collection
7. **Test end-to-end** using utility scripts in `Utilities/` folder

See [`Setup/README.md`](Setup/README.md) for complete prerequisites, RBAC requirements, detailed deployment steps, and troubleshooting.

Refer to inline comments in `certlc.ps1` for detailed documentation about request payloads and runbook behavior.

## Permissions

The following RBAC role assignments are automatically created by the Bicep deployment (plus 1 manual ACL configuration on the CA):

| Service Principal                        | RBAC Roles                           | Scope                  | Usage                                                                |
|------------------------------------------|--------------------------------------|------------------------|----------------------------------------------------------------------|
| Automation Account Managed Identity      | Key Vault Certificates Officer       | Key Vault              | Certificate requests                                                 |
|                                          | Key Vault Secrets Officer            | Key Vault              | PFX Export                                                           |
|                                          | Reader                               | Automation Account     | Runbook access to variables set on Automation Account                |
|                                          | Monitoring Metrics Publisher         | DCR                    | Publish logs to the custom table                                     |
| Function App Managed Identity            | Storage Blob Data Owner              | Storage Account        | Function runtime storage                                             |
|                                          | Storage Queue Data Contributor       | Storage Account        | Function's binding to the queue                                      |
|                                          | Storage Queue Data Message Processor | Storage Account        | Function's processing of queue messages                              |
|                                          | Reader                               | Automation Account     | Read automation account information                                  |
|                                          | Automation Operator                  | Automation Account     | Launch and monitor runbook jobs                                      |
|                                          | Monitoring Metrics Publisher         | Application Insights   | Function telemetry and monitoring                                    |
| Event Grid System Topic Managed Identity | Storage Queue Data Reader            | Storage Account        | Read queue metadata for event submission                             |
|                                          | Storage Queue Data Message Sender    | Storage Account        | Send certificate expiry events to the queue                          |
| Hybrid Worker(s) AD computer account     | Enroll (ACL)                         | CA's templates         | Allow certificate requests using the templates (manual configuration) |

