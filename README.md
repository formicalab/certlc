# Certificate Lifecycle Management (CertLC)

CertLC is a PowerShell 7 runbook designed to fully automate X.509 certificate lifecycle operations on Azure-connected environments:

* **Generate & Renew Certificates**  
  * Creates **new certificates** on demand.  
  * **Renews** existing Key Vault certificates before expiry.  
  * Leverages an on-premises Microsoft AD Certification Authority (`$CA`).

* **Azure Key Vault Integration**  
  * All private keys are generated and stored inside the target Key Vault.  
  * Uses `Az.KeyVault` to create CSRs, import issued certificates and, when required, export secrets for PFX packaging.

* **Hybrid Worker Execution**  
  * Intended to run from an **Azure Automation Hybrid Worker** under a **system-assigned managed identity**.  
  * Automatically logs into Azure (`Connect-AzAccount -Identity`) and disables context autosave for isolation.

* **Webhook & Event Grid Triggers**  
  * Accepts HTTP webhooks for manual “New” or “Renew” requests.  
  * Listens to **Event Grid** `Microsoft.KeyVault.CertificateNearExpiry` events; messages are queued in Azure Storage and processed in batches for “autorenew”.

* **Log Analytics Telemetry**  
  * Writes structured log entries (`certlc_CL`) through the Azure Monitor Data Collection Rules API.

* **PFX Export (Optional)**  
  * Can export issued certificates as **PFX** files to a secured per-user folder (`$PfxRootFolder`) with ACLs granting `Read & Execute` to a designated user or group.

## Repository Structure

```
certlc.ps1          # Main runbook with all logic
```

## Usage

1. Deploy the runbook to an Automation Account with a Hybrid Worker.  
2. Configure the Automation variables (e.g., CA name, storage account, queue).  
3. Assign the automation account's identity (and, if you want to test by launching the script locally on workers, also workers’s managed identities) access to:

| Identity | Permission(s) | Scope |
|----------|---------------|-------|
| Automation Account / Hybrid Worker Managed Identity | Key Vault Certificate Officer, Key Vault Secret Officer | Key Vault |
| Automation Account / Hybrid Worker Managed Identity | Storage Queue Data Contributor, Reader and Data Access | Storage Account |
| Automation Account / Hybrid Worker Managed Identity | Reader | Automation Account |
| Automation Account / Hybrid Worker Managed Identity | Monitoring Metrics Publisher | Data Collection Rule used for log ingestion |

4. Make sure that the Event Grid Topic has: `Storage Queue Data Message Sender` on the storage account (it will send message to the queue)
5. The computer accounts of all the hybrid workers need to have the `Enroll` permissions on the CA templates
6. Trigger via Webhook for ad-hoc operations or rely on Event Grid for automatic renewals.

Refer to inline comments in [`certlc.ps1`](d:/source/repos/CertLC/certlc.ps1) for detailed parameter documentation and error handling flow.
