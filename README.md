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

* **Runbook and Hybrid Worker Execution**  
  * The **certlc** runbook manages all the requests to the Enterprise CA and the Key Vault
  * The execution is performed by an **Azure Automation Hybrid Worker** able to orchestrate operations towards the CA and the KeyVault

* **Security**  
  * All PaaS resources can have their public endpoint disabled - Private Endpoints are used for all communications 
  * No AD service accounts are used: all permissions are assigned to computer accounts and to the system-assigned managed identities of the PaaS resources 

## Repository Structure

```
Runbooks\certlc.ps1          # Main runbook with all logic
Runbooks\certlcstats.ps1     # Fill statistics in the custom log analytics table used by Azure Monitor workbook
Functions\CertLCBridge       # FunctionApp code
LogAnalytics\customtable     # Instructions to create the custom table
Workbooks\certlc.workbook    # Workbook code
```

## Setup (_very_ high-level)

1. Create the following resources:
    - a storage account containing a queue `certlc`
    - a key vault
    - an automation account with its managed identity, a hybrid worker group, and the automation variables required by the solution
    - a log analytics workbook
    - an application insights instance
    - a function app in a Flex Consumption plan
    - an Azure Monitor workbook
2. create private endpoints for the storage account, the key vault, the automation account and the function app; block their accesses from Internet
3. create the custom table used by the solution (see dedicated README file )
4. Assign the required permissions (see table below)
5. Deploy the runbooks `certlc.ps1` and `certlcstats.ps1`
6. Deploy the function app code
7. Deploy the workbook code

Refer to inline comments in `certlc.ps1` for detailed documentation about request payloads

## Permissions

The following 12 RBAC role assignments are automatically created by the Bicep deployment (plus 1 manual ACL configuration on the CA):

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

