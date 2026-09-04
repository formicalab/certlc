# Certificate Lifecycle Management (CertLC)

CertLC is an event-driven certificate lifecycle management solution that integrates Azure Key Vault with an on-premises Windows Enterprise Certificate Authority (CA) for certificate creation, renewal, revocation, and inventory collection.

## Key Features

- **Certificate Creation**: Automatically request and issue new certificates from the Enterprise CA based on queue messages
- **Certificate Renewal**: Proactively renew certificates approaching expiration using Event Grid notifications
- **Certificate Chain Preservation**: Store the complete CA chain in Key Vault and export the private-key leaf with its intermediate certificates in the protected PFX
- **Certificate Revocation**: Revoke certificates on demand using the certificate thumbprint
- **Statistics Collection**: Gather and store certificate metadata in Log Analytics for monitoring and reporting
- **Proactive Alerting**: Optionally deploy a dedicated Action Group with alerts for poison messages, Event Grid delivery failures, failed Automation jobs, and stale statistics

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                    Azure                                        │
│  ┌────────────┐    ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Event Grid │───►│   Storage   │───►│ Function App │───►│ Automation       │  │
│  │ (KeyVault  │    │   Queue     │    │ (PowerShell) │    │ Account          │  │
│  │  events)   │    │             │    │              │    │                  │  │
│  └────────────┘    └─────────────┘    └──────────────┘    └────────┬─────────┘  │
│                                                                     │           │
│  ┌────────────┐                       ┌──────────────┐              │           │
│  │ Key Vault  │◄──────────────────────│ Certificate  │◄─────────────┘           │
│  │            │                       │ Operations   │                          │
│  └────────────┘                       └──────────────┘                          │
│                                                                                 │
│  ┌────────────┐    ┌─────────────┐                                              │
│  │    Log     │◄───│    DCR      │    Certificate statistics collection        │
│  │ Analytics  │    │             │                                              │
│  └────────────┘    └─────────────┘                                              │
└─────────────────────────────────────────────────────────────────────────────────┘
                                            │
                                            │ registered Hybrid Worker
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              On-Premises                                        │
│  ┌───────────────────────────────────┐                                          │
│  │    Enterprise Certificate         │    Certificate enrollment, renewal,     │
│  │    Authority (Windows CA)         │    and revocation via AD CS RPC         │
│  └───────────────────────────────────┘                                          │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Components and Responsibilities

| Component | Responsibility |
|-----------|----------------|
| Event Grid and Storage Queue | Event Grid sends Key Vault near-expiry events to the queue; external callers place custom creation and revocation requests on the same queue |
| Function App (`CertLCBridge`) | Serialize each queue message and start the configured Automation runbook directly with `Start-AzAutomationRunbook`; includes `OutboundTester` for connectivity checks |
| Automation Account | Host `certlc.ps1` for creation, renewal, and revocation, `certlcstats.ps1` for inventory collection, and an hourly statistics schedule that is created but not linked by default |
| Hybrid Worker | Run the PowerShell 7.6 runbooks with network access to Azure private endpoints, Active Directory, the Enterprise CA, and the PFX file location |
| Enterprise CA | Issue complete certificate chains and process enrollment and revocation requests through AD CS RPC/DCOM interfaces |
| Key Vault | Hold versioned certificates, private keys, complete certificate chains, and lifecycle tags |
| Log Analytics and Application Insights | Store latest-version certificate inventory and operational telemetry; the workbook shows expiration status/details, runbook job status, and per-job logs |
| Azure Monitor Alerts and Action Group | Notify operators about poison messages, Event Grid dead-lettering or delivery failures, failed runbooks, and missing statistics snapshots when alerting is enabled |

Azure-to-Azure calls use managed identities. Storage, Function App, Automation Account, and Key Vault data-plane access is private; the Hybrid Worker provides the boundary between Azure automation and the on-premises CA. Azure Monitor ingestion endpoints remain public and require controlled outbound access.

The Bicep deployment creates a custom PowerShell 7.6 Automation runtime named `certlc-PowerShell-7-6`, with the `Az` and `Azure CLI` modules loaded as default packages for both runbooks.

## How It Works

### Certificate Chain Contract

For creation and renewal, CertLC requests the complete PKCS#7 response from AD CS and requires one unambiguous, cryptographically valid chain with at least one intermediate CA:

```text
leaf certificate -> intermediate CA certificate(s) -> self-issued root CA certificate
```

The runbook merges that complete leaf-to-root sequence into the pending Key Vault certificate operation. It then downloads the exact secret version returned by the merge, verifies that Key Vault persisted the same certificates, and uses that verified copy for export. A latest-version race or a merge that loses part of the chain therefore causes the operation to fail instead of being reported as successful.

The exported, SID-protected PFX contains the private-key leaf and every intermediate CA certificate, but excludes the self-issued root. CertLC's chain selection follows the TLS certificate-list convention in [RFC 8446, Section 4.4.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2): the sender's certificate is first, each following certificate should certify the preceding certificate, and a trust anchor may be omitted because peers receive trust anchors independently. [RFC 5280, Sections 6 and 6.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-6) defines certification-path validation and states that a self-signed certificate supplied as the trust anchor is not part of the prospective certification path. Therefore, CertLC preserves the root in Key Vault as part of the CA response but does not distribute it as part of the deployable PFX; target systems must trust the root through their normal trust-store administration.

### Certificate Creation Flow

1. An external system or utility script sends a certificate request message to the Storage Queue
2. The Function App receives the message, authenticates with its managed identity, and starts the `certlc` runbook directly on the configured Hybrid Worker group
3. The runbook executes on the Hybrid Worker with access to the Enterprise CA
4. Before creating a CSR, the runbook verifies that it is running as Local System or a local administrator, resolves every `PfxProtectTo` principal to a SID, prepares the host-specific export folder and ACL, and proves write/delete access with a temporary probe
5. A certificate signing request (CSR) is submitted with the AD CS `ICertRequest` COM interface over RPC/DCOM
6. The runbook applies the [certificate chain contract](#certificate-chain-contract): validate the CA response, merge and verify the complete chain in Key Vault, then revalidate the export prerequisites and export the root-excluded PFX

### Certificate Renewal Flow

1. Azure Key Vault raises a `CertificateNearExpiry` event when a certificate approaches expiration
2. Event Grid captures the event and delivers it to the Storage Queue
3. The Function App triggers the renewal process through the Automation runbook
4. The Hybrid Worker requests a renewed certificate from the Enterprise CA. The new version is tagged with `RenewedJobId=<automation-job-id>` for traceability back to the renewal job
5. The runbook applies the [certificate chain contract](#certificate-chain-contract) and stores the renewal as a new Key Vault version without deleting the expiring version
6. **Revoked-latest short-circuit**: if the latest version of the certificate carries `Revoked=true`, the renewal branch logs a warning and exits without contacting the CA. Auto-renewal resumes only after an operator either issues a new version explicitly or clears the `Revoked` tag

### Certificate Revocation Flow

1. A revocation request with a certificate thumbprint (any version, current or older) is sent to the Storage Queue
2. The Function App triggers the `certlc` runbook
3. The runbook locates the matching Key Vault version by thumbprint using paginated Key Vault REST requests: it checks each certificate name's latest-version `x5t` first, then enumerates older versions when needed
4. **Idempotency guard**: if the version already carries `Revoked=true`, the runbook logs `ALREADY REVOKED` with the previous `RevokedAt`, `RevocationReason`, and `RevokedJobId`, then completes successfully so the duplicate queue message is acknowledged. The CA is not called again, no duplicate notification is sent, and existing tags are preserved
5. Otherwise, the runbook extracts the version's serial number and submits a revocation request to the CA for that serial
6. The matching Key Vault version is set to `enabled = false` and tagged with audit metadata (`Revoked=true`, `RevokedAt`, `RevocationReason`, `RevokedJobId`). Existing tags on the version (e.g. `NotifyTo`, `Hostname`, `PfxProtectTo`) are preserved. **No Key Vault objects are deleted by the runbook**; other versions of the same certificate are left untouched, and the certificate object remains in the vault for audit

### Key Vault Certificate Tags

CertLC stores the following tags on individual Key Vault certificate versions. Creation and renewal write a new version's operational tags; revocation starts with the selected version's existing tags and overlays its audit tags so unrelated metadata is preserved.

| Tag | Written by | Required and format | Purpose and consumers |
|-----|------------|---------------------|-----------------------|
| `CertificateTemplateName` | Creation and renewal | Required. Internal AD CS certificate template name, not its display name or OID | Records the issuing template and supplies the `Template` field collected by `certlcstats` |
| `Hostname` | Creation and renewal | Required. Lowercase hostname validated by the creation dispatcher | Selects the host-specific folder below the configured PFX root during renewal and export |
| `PfxProtectTo` | Creation and renewal | Required. Normalized, deduplicated domain principals or UPNs serialized as one semicolon-delimited string | Reconstructs the principal list used for SID-protected PFX export and target-folder ACLs during renewal |
| `NotifyTo` | Creation and renewal | Optional. Email addresses serialized as one semicolon-delimited string | Supplies recipients to lifecycle notification paths when SMTP is configured; revocation reads the tag from the specifically matched version |
| `RenewedJobId` | Renewal only | Present when the Automation job ID is available | Correlates a renewed certificate version with the Automation job that created it |
| `Revoked` | Revocation only | Required on a revoked version; literal string `true` | Prevents duplicate revocation and stops automatic renewal while the revoked version remains latest |
| `RevokedAt` | Revocation only | Required on a revoked version; UTC timestamp in `yyyy-MM-ddTHH:mm:ssZ` format | Records when CertLC completed the revocation |
| `RevocationReason` | Revocation only | Required on a revoked version; decimal string from `0` through `6` | Records the AD CS revocation reason code and is included in duplicate-revocation diagnostics |
| `RevokedJobId` | Revocation only | Present when the Automation job ID is available | Correlates the revocation with the Automation job and is included in duplicate-revocation diagnostics |

### Statistics Collection

1. The `certlcstats` runbook runs on a schedule (hourly by default, disabled until manually linked)
2. It enumerates certificate names in Key Vault and collects metadata from the latest version of each name
3. Certificate data is published to a custom Log Analytics table via Data Collection Rule
4. The Azure Monitor workbook shows certificate expiration status and details, runbook job status, and logs for selected jobs

### Proactive Alerting

Alerting is controlled by the Bicep `enableAlerts` parameter, which defaults to `false`. When enabled, the deployment creates a dedicated CertLC Action Group, Queue Storage write diagnostics, and six Azure Monitor alert rules:

- Event Grid dead-lettered and dropped events (severity 1)
- Repeated Event Grid delivery failures (severity 3)
- Messages written to the `certlc-poison` queue (severity 1)
- Failed, stopped, or suspended `certlc` and `certlcstats` Automation jobs (severity 2)
- No successful `certlcstats` completion within two hours (severity 2)

Action Group email receivers are configured per environment and use the common alert schema. The stale-statistics rule intentionally reports an unhealthy state while the hourly statistics schedule is not linked or successful.

### Resilience

The runbook's Key Vault REST reads for thumbprint discovery and exact secret retrieval, plus its LDAP template lookup, use a retry helper with up to four total attempts. It retries HTTP 408, 429, 500, 502, 503, and 504 responses and selected network, timeout, I/O, web, and COM exceptions. `Retry-After` takes precedence over exponential backoff with jitter, and delays are capped at 30 seconds. State-changing certificate creation/merge/update calls and CA enrollment/revocation calls are not passed through this retry helper, avoiding automatic duplicate side effects.

The Function bridge acknowledges a queue message only when the Automation job reaches `Completed`. `Failed`, `Stopped`, `Suspended`, and `Blocked` fail the Function invocation so queue retry and poison-message handling remain active. Transitional states are polled for up to `RunbookPollingTimeoutMinutes` (25 minutes in the Bicep deployment); an unknown state or elapsed deadline fails closed. Automation output retrieval is best-effort and cannot turn an otherwise completed lifecycle operation into a duplicate queue retry.

Queue-trigger retries are bounded by [host.json](Functions/CertLCBridge/host.json): CertLC currently uses `maxDequeueCount: 5` and `visibilityTimeout: 00:00:30`, so a failed message is processed at most five times with a 30-second delay between unsuccessful attempts. Every attempt starts a separate Automation job. After the fifth failure, the Functions host moves the message from `certlc` to `certlc-poison`; it is not retried again unless an operator resubmits it. These settings can be changed in `host.json` and redeployed, or overridden per environment with the Function App settings `AzureFunctionsJobHost__extensions__queues__maxDequeueCount` and `AzureFunctionsJobHost__extensions__queues__visibilityTimeout`.

## Repository Structure

```
CertLC/
├── README.md                    # This file - Solution overview
├── Setup/                       # Infrastructure deployment
│   ├── certlc.bicep            # Main Bicep template
│   ├── modules/                 # Service modules, workbook, and optional alerts
│   ├── parameters.dev.bicepparam
│   └── README.md               # Deployment instructions
├── Functions/                   # Azure Function App code
│   └── CertLCBridge/           # PowerShell function for queue processing
│       ├── QueueHandler/       # Queue trigger function
│       └── OutboundTester/     # HTTP trigger for testing connectivity
├── Runbooks/                    # Automation runbooks
│   ├── certlc.ps1              # Main certificate operations runbook
│   ├── certlcstats.ps1         # Certificate statistics collection
│   ├── normalnotification.html # Email template for successful operations
│   └── errornotification.html  # Email template for failures
├── LogAnalytics/               # Custom table configuration
│   └── customTable/            # Schema and transformation for certlcstats_CL table
├── Workbooks/                  # Azure Monitor workbooks
│   ├── certlcstats.workbook    # Tokenized certificate statistics dashboard deployed by Bicep
│   └── *.kql                   # KQL queries for visualizations
├── Utilities/                  # Helper scripts
│   ├── Export-PfxWithGroupProtection.ps1 # Export a Key Vault certificate as a SID-protected PFX
│   ├── Extract-KeyCer.ps1      # Extract a certificate and private key from a PFX
│   ├── Extract-KeyCerChain.ps1 # Extract every certificate, a full-chain bundle, and the leaf private key
│   ├── testnewcert.ps1         # Test certificate creation
│   ├── testnewcertchain.ps1    # Validate full-chain creation and PFX export
│   ├── testrenewcert.ps1       # Test certificate renewal
│   └── testrevocationcert.ps1  # Test certificate revocation
└── Tests/                      # Development and testing scripts
```

## Certificate Request Schema

Requests are sent as JSON messages to the Storage Queue using CloudEventSchema. The schema varies by operation type:

The runbook validates `specversion` (`1.0`) and `type`, and logs `id` when supplied. It consumes the operation-specific fields identified below. Other envelope and `data` fields shown in the examples are retained for CloudEvent/Event Grid compatibility but are not read by the current dispatcher.

**Creation Request:**

Consumed `data` fields: `VaultName`, `ObjectName`, `CertificateTemplate`, `CertificateSubject`, `CertificateDnsNames` (optional array), `Hostname`, `PfxProtectTo`, and `NotifyTo` (optional array). `CertificateTemplate` may be the template's internal name, display name, or OID; the runbook resolves and stores the internal name.

```json
{
  "id": "<event identifier, free field>",
  "source": "<free field, can be used to identify the requestor>",
  "specversion": "1.0",
  "type": "CertLC.NewCertificateRequest",
  "subject": "<name of the new certificate>",
  "time": "<event time, using format: 2025-06-08T19:52:25.1524887Z>",
  "data": {
    "Id": "<request id, free field>",
    "VaultName": "<key vault name>",
    "ObjectType": "Certificate",
    "ObjectName": "<name of the new certificate>",
    "CertificateTemplate": "<certificate template internal name, display name, or OID>",
    "CertificateSubject": "<certificate subject>",
    "CertificateDnsNames": [ "<dns name 1>", "<dns name 2>" ],
    "Hostname": "<hostname - used as folder name for exported PFX>",
    "PfxProtectTo": [ "<user or group to protect the PFX file>" ],
    "NotifyTo": [ "<email address to notify>" ]
  }
}
```

**Renewal Request** (from Event Grid CertificateNearExpiry event):

Consumed `data` fields: `VaultName` and `ObjectName`. The dispatcher deliberately reads the latest Key Vault version for that name and reconstructs the subject, SANs, template, export hostname, protection principals, and notification recipients from the certificate and its tags; the event's `Version`, `NBF`, and `EXP` values are not used.

```json
{
  "id": "<event identifier>",
  "source": "/subscriptions/<subscriptionid>/resourceGroups/<rg>/providers/Microsoft.KeyVault/<vault>",
  "specversion": "1.0",
  "type": "Microsoft.KeyVault.CertificateNearExpiry",
  "subject": "<name of the expiring certificate>",
  "time": "<event time, using format: 2025-06-08T19:52:25.1524887Z>",
  "data": {
    "Id": "https://<key vault name>.vault.azure.net/certificates/<certificate name>/<version>",
    "VaultName": "<key vault name>",
    "ObjectType": "Certificate",
    "ObjectName": "<certificate name>",
    "Version": "<certificate version>",
    "NBF": 1749411621,
    "EXP": 1749418821
  }
}
```

**Revocation Request:**

Consumed `data` fields: `VaultName`, `CertificateThumbprint`, and `RevocationReason`. The reason must parse as an integer from `0` through `6`.

```json
{
  "id": "<event identifier, free field>",
  "source": "<free field, can be used to identify the requestor>",
  "specversion": "1.0",
  "type": "CertLC.CertificateRevocationRequest",
  "subject": "<name of the certificate>",
  "time": "<event time, using format: 2025-06-08T19:52:25.1524887Z>",
  "data": {
    "Id": "<request id, free field>",
    "VaultName": "<key vault name>",
    "ObjectType": "Certificate",
    "CertificateThumbprint": "<certificate thumbprint>",
    "RevocationReason": "1"
  }
}
```

> **Note:** For the meaning of the accepted `0` through `6` revocation reasons, see [ICertAdmin::RevokeCertificate](https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-revokecertificate).

## Security Considerations

- **Managed Identities**: Azure service authentication does not use stored service credentials
- **Private Endpoints**: Storage, Function App, Automation Account, and Key Vault data-plane access uses private endpoints; Azure Monitor ingestion remains public
- **RBAC Authorization**: Key Vault uses Azure RBAC (not access policies) with least-privilege assignments
- **Encrypted Variables**: Non-Azure secrets required by the runbooks, such as SMTP credentials, are stored as encrypted Automation variables
- **Audit Logging**: Diagnostic settings enabled on Key Vault and Automation Account; enabling alerts also sends Queue Storage writes to Log Analytics for poison-message detection

## Getting Started

For deployment instructions, prerequisites, and configuration details, see the [Setup Guide](Setup/README.md).
