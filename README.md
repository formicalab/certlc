# Certificate Lifecycle Management (CertLC)

CertLC is an event-driven certificate lifecycle management solution that integrates Azure Key Vault with an on-premises Windows Enterprise Certificate Authority (CA) for certificate creation, renewal, revocation, and inventory collection.

## Key Features

- **Certificate Creation**: Automatically request and issue new certificates from the Enterprise CA based on queue messages
- **Certificate Renewal**: Proactively renew certificates approaching expiration using Event Grid notifications
- **Certificate Chain Preservation**: Store the complete CA chain in Key Vault and export the private-key leaf with its intermediate certificates in the protected PFX
- **Certificate Revocation**: Revoke certificates on demand using the certificate thumbprint
- **Statistics Collection**: Gather and store certificate metadata in Log Analytics for monitoring and reporting
- **Event Journey**: Search events or certificates and follow separate Function attempts, Automation jobs and their logs in the production workbook
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
| Automation Account | Host `certlc.ps1` for creation, renewal, and revocation, `certlcstats.ps1` for inventory collection, and its linked hourly statistics schedule |
| Hybrid Worker | Run the PowerShell 7.6 runbooks with network access to Azure private endpoints, Active Directory, the Enterprise CA, and the PFX file location |
| Enterprise CA | Issue complete certificate chains and process enrollment and revocation requests through AD CS RPC/DCOM interfaces |
| Key Vault | Hold versioned certificates, private keys, complete certificate chains, and lifecycle tags |
| Log Analytics and Application Insights | Store latest-version certificate inventory and operational telemetry; the workbook provides Statistics, Event Journey, Job logs and Function bridge views |
| Azure Monitor Alerts and Action Group | Notify operators about poison messages, Event Grid dead-lettering or delivery failures, failed runbooks, and missing statistics snapshots when alerting is enabled |

Azure-to-Azure calls use managed identities. Storage, Function App, Automation Account, and Key Vault data-plane access is private; the Hybrid Worker provides the boundary between Azure automation and the on-premises CA. Azure Monitor ingestion endpoints remain public and require controlled outbound access.

The Bicep deployment creates a custom PowerShell 7.6 Automation runtime named `certlc-PowerShell-7-6`, with the `Az` and `Azure CLI` modules loaded as default packages for both runbooks.

The main lifecycle runbook directly imports only `Az.Accounts` and `Az.KeyVault`. Removing its unused `Az.Storage` and `Az.Resources` imports does not remove packages from the Automation runtime or change the dependencies of other scripts.

## How It Works

### Certificate Chain Contract

For creation and renewal, CertLC requests the complete PKCS#7 response from AD CS and requires one unambiguous, cryptographically valid chain with at least one intermediate CA:

```text
leaf certificate -> intermediate CA certificate(s) -> self-issued root CA certificate
```

The runbook merges that complete leaf-to-root sequence into the pending Key Vault certificate operation. It then downloads the exact secret version returned by the merge, verifies that Key Vault persisted the same certificates, and uses that verified copy for export. A latest-version race or a merge that loses part of the chain therefore causes the operation to fail instead of being reported as successful.

AD CS PKCS#7 bundles are decoded with `SignedCms` without requiring a CMS signature: certificates-only bundles may be unsigned, while the existing certificate-chain checks remain mandatory. Key Vault PKCS#12 data is loaded with `X509CertificateLoader`, using `Exportable | EphemeralKeySet` so the private key remains exportable without being persisted to the worker's key store. `Pkcs12LoaderLimits.DangerousNoLimits` deliberately preserves the former explicit-password import policy and certificate attributes; adopting the loader's default limits would be a separate compatibility change. Both loaders now enforce their expected input format rather than auto-detecting unrelated certificate formats.

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
5. Otherwise, the runbook validates the already-fetched version's public certificate against the requested thumbprint, extracts its serial number, and submits a revocation request to the CA for that serial. Revocation never downloads the certificate's secret/PFX or private key
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

1. The `certlcstats` runbook runs hourly on the configured Hybrid Worker Group by default
2. It enumerates certificate names in Key Vault and collects metadata from the latest version of each name
3. Certificate data is published to a custom Log Analytics table via Data Collection Rule
4. The Azure Monitor workbook shows certificate expiration status and details, an Event Journey from event/certificate search through Function attempts and Automation jobs to logs, plus the existing job and Function bridge views

### Proactive Alerting

Alerting is controlled by the Bicep `enableAlerts` parameter, which defaults to `true`. When enabled, the deployment creates a dedicated CertLC Action Group, Queue Storage write diagnostics, and six Azure Monitor alert rules:

- Event Grid dead-lettered and dropped events (severity 1)
- Repeated Event Grid delivery failures (severity 3)
- Messages written to the `certlc-poison` queue (severity 1)
- Failed, stopped, or suspended `certlc` lifecycle Automation jobs (severity 2)
- Unhealthy statistics: `certlcstats` failed, stopped, or suspended without a later successful completion, or has no successful completion within two hours (severity 2)

Action Group email receivers are configured per environment and use the common alert schema. The statistics-health rule retains the resource name `alert-certlc-statistics-stale` and evaluates every five minutes over the last two hours. It remains unhealthy through missing data and created, queued, or running jobs; failure records aging out do not count as recovery. Only a recent `Completed` record strictly later than the latest failure makes it healthy. Azure then applies its stateful resolution delay (three healthy evaluation periods at this frequency), so recovery notification is not immediate. The rule also reports an unhealthy state when the hourly statistics schedule is disabled or has not completed successfully. Statistics jobs are excluded from the short-window lifecycle failure rule to avoid duplicate, cycling notifications. These source changes take effect only after deploying the alert updates.

The lifecycle-failure rule (`alert-certlc-automation-failure`) temporarily has automatic resolution disabled. It is stateless: expiration of failure records from its ten-minute window no longer sends a recovery notification, and a later successful run does not resolve it either. Repeated firing notifications are possible while the condition is met. This setting does not affect the statistics-health rule's success-based recovery.

### Resilience

The runbook's Key Vault REST reads for thumbprint discovery and exact secret retrieval, plus its LDAP template lookup, use a retry helper with up to four total attempts. It retries HTTP 408, 429, 500, 502, 503, and 504 responses and selected network, timeout, I/O, web, and COM exceptions. A positive `Retry-After` delta takes precedence and is capped at 30 seconds. Otherwise, the exponential base delay is capped at 30 seconds before jitter of less than `InitialDelayMs` (default 500 ms) is added. State-changing certificate creation/merge/update calls and CA enrollment/revocation calls are not passed through this retry helper, avoiding automatic duplicate side effects.

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
│   ├── certlc-jobid-test.ps1   # Retained Hybrid Worker job-identity diagnostic
│   ├── normalnotification.html # Email template for successful operations
│   └── errornotification.html  # Email template for failures
├── LogAnalytics/               # Custom table configuration
│   └── customTable/            # Schema and transformation for certlcstats_CL table
├── Workbooks/                  # Azure Monitor workbooks
│   ├── certlcstats.workbook    # Tokenized production workbook deployed by Bicep
│   ├── README.md              # Embedded-query index and maintenance guidance
│   └── *.kql                   # 18 queries matching the production workbook
├── Utilities/                  # Helper scripts
│   ├── Export-PfxWithGroupProtection.ps1 # Export a Key Vault certificate as a SID-protected PFX
│   ├── Extract-KeyCer.ps1      # Extract a certificate and private key from a PFX
│   ├── Extract-KeyCerChain.ps1 # Extract every certificate, a full-chain bundle, and the leaf private key
│   ├── testnewcert.ps1         # Test certificate creation
│   ├── testnewcertchain.ps1    # Validate full-chain creation and PFX export
│   ├── testrenewcert.ps1       # Test certificate renewal
│   └── testrevocationcert.ps1  # Test certificate revocation
└── Tests/                      # Local helper/dispatcher checks and legacy schema sample
  ├── certlc-refactoring.tests.ps1
  └── sample-eventgrideventschema.json
```

## Certificate Request Schema

Requests are sent as JSON messages to the Storage Queue using CloudEventSchema. The schema varies by operation type:

The runbook validates `specversion` (`1.0`) and `type`, and reads optional top-level `id` and `source` for diagnostics and the [correlation rules](#request-correlation) below. It consumes the operation-specific fields identified below and `data.Id` for notification details. Other envelope and `data` fields shown in the examples are retained for CloudEvent/Event Grid compatibility but are not read by the current dispatcher. The retained [Event Grid schema sample](Tests/sample-eventgrideventschema.json) shows the legacy `eventType`/`topic` envelope, not the CloudEvents input expected by the current dispatcher; use the request examples below for current inputs.

**Creation Request:**

Consumed `data` fields: `VaultName`, `ObjectName`, `CertificateTemplate`, `CertificateSubject`, `CertificateDnsNames` (optional array), `Hostname`, `PfxProtectTo`, and `NotifyTo` (optional array). `CertificateTemplate` may be the template's internal name, display name, or OID; the runbook resolves and stores the internal name.

`CertificateDnsNames` and `NotifyTo` may be omitted, `null`, or arrays (including `[]`). Non-null scalars, including empty strings, are rejected rather than silently converted to arrays. `data.Id` is optional in all three operations; when supplied it contributes notification details, not event correlation. The envelope's `specversion` is the CloudEvents contract version (`1.0`), not the runbook release version.

The dispatcher normalizes JSON and native webhook objects to case-insensitive dictionaries before validation. The envelope and `data` must each be a single object; arrays, scalars, and ambiguous case-only duplicate fields are rejected. Required strings must be actual nonblank strings. Creation validates local fields, hostname syntax, and protection-principal normalization before Key Vault or AD lookups. Revocation reason codes still accept integers or integer strings, including `0`. These stricter checks may reject malformed inputs previously accepted through coercion; valid request shapes and correlation rules are unchanged.

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

Renewal reads the SAN extension by numeric OID and enumerates only DNS names. IP, URI, and email SAN entries are not copied into the new request; DNS extraction does not depend on localized extension names or display formatting.

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

## Request Correlation

`correlationId` represents only the top-level nonblank string event `id`, never `data.Id` or a job-ID fallback. The Function forwards only the unchanged `jsonRequestBody`; there is no separate runbook `CorrelationId` input. The runbook populates correlation after parsing this explicit JSON input path. Direct `WebhookData` calls omit correlation, including native, JSON, and legacy PowerShell webhook envelopes. This distinguishes input paths, not authenticated caller identity: any caller supplying `jsonRequestBody` receives the same behavior as the Function. Custom IDs need not be GUIDs; missing, null, empty, whitespace-only, or non-string IDs leave correlation omitted.

The runbook checks Hybrid Worker execution, PowerShell 7.6+, and job identity before Azure authentication. Every custom log includes a separate `jobId` once discovered, including warnings, errors, verbose records, and serialization-failure records. Startup and payload-parsing failures omit `correlationId`. After explicit JSON parsing, validation and operation logs inherit the event ID when valid. `correlationIdSource` is no longer needed because the field never switches to execution identity. Nonblank logging-helper overrides are event IDs, not job IDs; they are not runbook inputs. Context cannot overwrite the reserved `jobId` or `correlationId` fields. These stream logs do not require Azure login, but module-loading failures and native cmdlet output are outside the custom logger contract. Early startup failures do not send SMTP notifications before notification configuration is available.

Event correlation is diagnostic metadata, not authorization or duplicate suppression. A retried event retains its correlation ID but receives a separate Function invocation and Automation job. `RenewedJobId`, `RevokedJobId`, and notification job references always use the actual Automation job ID. Event `source` is logged separately because IDs are unique within a producer's source, not necessarily across producers.

Every success and error email includes **Correlation ID** as the first row in its main details table. Emails can use the parsed top-level event ID from either input path, including direct `WebhookData`, without changing the stricter log correlation rules above. When no valid event ID is available, the row explicitly shows **Unavailable (no valid event ID)**; it never substitutes a job ID. The footer separately shows **Automation Job ID** when known. There is no duplicate **Event ID** row; the distinct **Request ID** (`data.Id`) remains. Values are HTML-encoded. Email delivery remains non-fatal and requires configured SMTP and recipients.

The Function preserves its workbook-sensitive plain-text messages and emits separate JSON `BridgeCorrelation` receipt/start association records in Application Insights trace messages. Missing event IDs remain omitted in both records; the started record independently includes the returned `jobId`. These can be joined to other traces using the platform `OperationId`; they are not automatic distributed tracing or custom properties. Reserved workbook-filter terms within association values are JSON-escaped and restored by JSON parsing. The runbook's JSON fields and streams remain compatible with Job History, which still groups by platform `JobId_g`. The independent stats runbook, its `SnapshotId`, ingestion schema, and existing workbook queries remain unchanged.

When upgrading from the separate-input version, publish and verify the Function first so it stops forwarding `CorrelationId`, then publish the runbook that removes the parameter. Update any other callers that explicitly pass it. During this transition the old runbook may use job-ID correlation; certificate behavior is unchanged. Verify actual telemetry ingestion after deployment. Temporary development tests are not distributed.

## Runbook Maintenance

The lifecycle helpers receive the export root (`PfxRootFolder`) and revocation CA (`CA`) explicitly from the dispatcher. Creation and renewal use the same ordered notification-details helper, populated from the completed operation result. Keep the `[ref]` result contract when changing dispatcher calls: structured logs share the success stream, so capturing the entire function output as metadata would also capture log records.

Long control-flow blocks should include concise comments explaining ownership, validation boundaries, ordering, or failure behavior. Preserve the comments around non-retried mutations, exact-version reads, chain checks, array shape, and native-resource cleanup. Comment-only edits can be verified by comparing PowerShell executable tokens before and after the change, in addition to syntax checks. Embedded templates and native declarations need their own format-appropriate documentation rather than injected PowerShell comments.

Renewal selects Certificate Template Information by numeric extension OID `1.3.6.1.4.1.311.21.7` and decodes its DER sequence with `System.Formats.Asn1`. It does not depend on localized extension names or formatted text. Both notification outcomes share one embedded HTML layout with fixed success/error styling and an optional error section; renewal and revocation also share notification-tag parsing.

Run the focused regression suite from the repository root with PowerShell 7.6 or later:

```powershell
./Tests/certlc-refactoring.tests.ps1
```

The suite extracts selected functions and the request-handling dispatcher using the PowerShell AST, mocks external operations, and creates temporary certificates only in memory. It does not execute runbook startup, authenticate to Azure, contact AD/AD CS, send email, or write PFX files. It covers request transports and validation, correlation, renewal/revocation routing, ASN.1 decoding, SMTP arguments, and notification rendering. Live Hybrid Worker certificate issuance and export remain separate integration checks.

## Workbook Maintenance

The production workbook has four tabs in order: **Statistics**, **Event Journey**, **Job logs**, and **Function bridge**. Event Journey uses **Search events/certificates**, shows **Found events (up to 500)**, and opens selected-event details and an expandable execution tree. All views share the original resource and time selectors.

Keep the resource placeholders in [Workbooks/certlcstats.workbook](Workbooks/certlcstats.workbook) unresolved. Bicep supplies the environment IDs at deployment time. The [workbook query index](Workbooks/README.md) maps all 18 standalone KQL files to their embedded counterparts; maintain both copies together. A workbook-only deployment does not publish the Function or either runbook. Prototype workbooks and temporary generators are not needed for deployment.

## Getting Started

For deployment instructions, prerequisites, and configuration details, see the [Setup Guide](Setup/README.md).
