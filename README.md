# Certificate Lifecycle Management (CertLC)

CertLC is a solution designed to fully automate X.509 certificate lifecycle operations on Azure-connected environments, integrating a Key Vault with a traditional Active Directory Enterprise CA.

* **Generate & Renew Certificates**
  * Creates **new certificates** on demand.
  * **Renews** existing certificates before expiry.
  * All certificates are signed by the Enterprise CA and stored in Key Vault
  * Certificates are made available inside a secured per-user/per-group folder as protected PFXs (user or group protection - no passwords used) for operator to pick up and install.

* **Azure Key Vault Integration**  
  * All private keys are generated and stored inside the target Key Vault.  
  * The key vault emits `Microsoft.KeyVault.CertificateNearExpiry` events for certificates near expiration. The event is used to trigger the automatic renewal process.

* **Event Grid** and **Function App**

  * An Event Grid System Topic is used to send `Microsoft.KeyVault.CertificateNearExpiry` events to a storage queue
  * a Function App with queue bindings is used to get the events and forward them to Automation Account, triggering the execution of the new/renewal runbook

* **Hybrid Worker Execution**  
  * An Automation Account handles the execution of a runbook on an **Azure Automation Hybrid Worker** 
  * The runbook manages all the requests to the Enterprise CA and the Key Vault

* **Security**  
  * All PaaS resources can have their public endpoint disabled - Private Endpoints are used for all communications 
  * No service accounts are used: all permissions are assigned to computer accounts and to the system-assigned managed identities of the PaaS resources 

## Repository Structure

```
Runbooks\certlc.ps1          # Main runbook with all logic
Functions\CertLCBridge       # FunctionApp code
```

## Setup (high-level)

1. Create storage account, automation account, key vault, function app
2. Assign the required permissions (see table below)
3. Deploy the runbook and the function app code
4. Refer to inline comments in [`certlc.ps1`](d:/source/repos/CertLC/certlc.ps1) for detailed parameter documentation

| Service Principal                         | Permissions                             | Scope              | Usage                                                   |
|-------------------------------------------|-----------------------------------------|--------------------|---------------------------------------------------------|
| Automation Account Managed Identity (*)   | Key Vault Certificates Officer          | Key Vault           | Certificate requests                                    |
|                                           | Key Vault Secrets Officer               | Key Vault           | PFX Export                                              |
|                                           | Reader                                  | Automation Account  | Runbook access to variables set on Automation Account   |
| Function Managed Identity                 | Reader                                  | Automation Account  | Launch and monitor jobs                                 |
|                                           | Automation Operator                     | Automation Account  | Launch and monitor jobs                                 |
| Hybrid Worker(s) Managed Identity         | Reader                                  | Automation Account  | Local troubleshooting / utilities executed locally from hybrid worker |
|                                           | Automation Operator                     | Automation Account  | Local troubleshooting / utilities executed locally from hybrid worker |
| Event Grid System Topic Managed Identity  | Storage Queue Data Reader               | Storage Account     | Submission of events to the queue                       |
|                                           | Storage Queue Data Message Sender       | Storage Account     | Submission of events to the queue                       |
| Function Managed Identity                 | Storage Queue Data Contributor          | Storage Account     | Function’s binding to the queue                         |
|                                           | Storage Queue Data Message Processor    | Storage Account     | Function’s binding to the queue                         |
| Hybrid Worker(s) Managed Identity         | Storage Queue Data Reader               | Storage Account     | Local troubleshooting / utilities executed locally from hybrid worker |
|                                           | Storage Queue Data Message Sender       | Storage Account     | Local troubleshooting / utilities executed locally from hybrid worker |
| Hybrid Worker(s) AD computer account      | Enroll (ACL)                            | CA’s templates      | Allow certificate requests using the templates          |
