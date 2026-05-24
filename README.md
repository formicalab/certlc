# Certificate Lifecycle Management (CertLC)

An automated certificate lifecycle management solution for Azure environments that integrates Azure Key Vault with an on-premises Enterprise Certificate Authority (CA) to handle certificate creation, renewal, revocation, and monitoring.

## Overview

CertLC provides end-to-end automation for managing certificates stored in Azure Key Vault when the issuing authority is an on-premises Windows Enterprise CA. The solution uses an event-driven architecture to respond to certificate lifecycle events and execute the appropriate operations.

### Key Features

- **Certificate Creation**: Automatically request and issue new certificates from the Enterprise CA based on queue messages
- **Certificate Renewal**: Proactively renew certificates approaching expiration using Event Grid notifications
- **Certificate Revocation**: Revoke certificates on demand using the certificate thumbprint
- **Statistics Collection**: Gather and store certificate metadata in Log Analytics for monitoring and reporting 

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                    Azure                                        │
│  ┌────────────┐    ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Event Grid │───►│   Storage   │───►│ Function App │───►│ Automation       │  │
│  │ (KeyVault  │    │   Queue     │    │ (PowerShell) │    │ Account          │  │
│  │  events)   │    │             │    │              │    │ (Hybrid Worker)  │  │
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
                                            │ Hybrid Worker
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              On-Premises                                        │
│  ┌───────────────────────────────────┐                                          │
│  │    Enterprise Certificate         │    Certificate enrollment, renewal,     │
│  │    Authority (Windows CA)         │    and revocation via CEP/CES           │
│  └───────────────────────────────────┘                                          │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Architecture Highlights

- **Event-Driven Processing**: Event Grid captures Key Vault certificate events (e.g., near-expiry) and routes them to a Storage Queue
- **Serverless Compute**: Azure Function App (Flex Consumption) processes queue messages and triggers Automation runbooks
- **Hybrid Execution**: Automation Account with Hybrid Worker enables secure communication with on-premises Enterprise CA
- **Private Networking**: All Azure PaaS resources are secured with private endpoints
- **Managed Identities**: No stored credentials - all Azure-to-Azure authentication uses system-assigned managed identities
- **Observability**: Application Insights for function monitoring, Log Analytics for certificate statistics and audit logs

## How It Works

### Certificate Creation Flow

1. An external system or utility script sends a certificate request message to the Storage Queue
2. The Function App receives the message and triggers the `certlc` runbook via webhook
3. The runbook executes on the Hybrid Worker with access to the Enterprise CA
4. A certificate signing request (CSR) is submitted to the CA using CEP/CES protocols
5. The issued certificate is imported into Azure Key Vault

### Certificate Renewal Flow

1. Azure Key Vault raises a `CertificateNearExpiry` event when a certificate approaches expiration
2. Event Grid captures the event and delivers it to the Storage Queue
3. The Function App triggers the renewal process through the Automation runbook
4. The Hybrid Worker requests a renewed certificate from the Enterprise CA. The new version is tagged with `RenewedJobId=<automation-job-id>` for traceability back to the renewal job
5. The renewed certificate replaces the expiring one in Key Vault
6. **Revoked-latest short-circuit**: if the latest version of the certificate carries `Revoked=true`, the renewal branch logs a warning and exits without contacting the CA. Auto-renewal resumes only after an operator either issues a new version explicitly or clears the `Revoked` tag

### Certificate Revocation Flow

1. A revocation request with a certificate thumbprint (any version, current or older) is sent to the Storage Queue
2. The Function App triggers the `certlc` runbook
3. The runbook locates the matching Key Vault version by thumbprint (LDAP-safe lookup, then a direct REST GET of the version metadata to read its `x5t`)
4. **Idempotency guard**: if the version already carries `Revoked=true`, the runbook fails fast with an `ALREADY REVOKED` log line that includes the previous `RevokedAt`, `RevocationReason`, and `RevokedJobId`. The CA is not called again and existing tags are preserved
5. Otherwise, the runbook extracts the version's serial number and submits a revocation request to the CA for that serial
6. The matching Key Vault version is set to `enabled = false` and tagged with audit metadata (`Revoked=true`, `RevokedAt`, `RevocationReason`, `RevokedJobId`). Existing tags on the version (e.g. `NotifyTo`, `Hostname`, `PfxProtectTo`) are preserved. **No Key Vault objects are deleted by the runbook**; other versions of the same certificate are left untouched, and the certificate object remains in the vault for audit

### Statistics Collection

1. The `certlcstats` runbook runs on a schedule (hourly by default, disabled until manually linked)
2. It enumerates all certificates in Key Vault and collects metadata
3. Certificate data is published to a custom Log Analytics table via Data Collection Rule
4. Azure Monitor Workbooks can visualize certificate inventory and expiration timelines

### Resilience

Idempotent Key Vault and LDAP reads (certificate-version listing, version metadata GET, AD template discovery) are wrapped in an exponential-backoff retry helper that recovers from transient HTTP 408/429/5xx, `Retry-After` throttling, and common network exceptions. Mutating calls (CA enrollment / revocation, tag writes) are **not** retried automatically — they are surfaced to the operator to avoid duplicate side-effects.

## Repository Structure

```
CertLC/
├── README.md                    # This file - Solution overview
├── Setup/                       # Infrastructure deployment
│   ├── certlc.bicep            # Main Bicep template
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
│   └── customTable/            # Schema and transformation for certlc_CL table
├── Workbooks/                  # Azure Monitor workbooks
│   ├── certlc.workbook         # Certificate statistics dashboard
│   └── *.kql                   # KQL queries for visualizations
├── Utilities/                  # Helper scripts
│   ├── testnewcert.ps1         # Test certificate creation
│   ├── testrenewcert.ps1       # Test certificate renewal
│   └── testrevocationcert.ps1  # Test certificate revocation
└── Tests/                      # Development and testing scripts
```

## Components

### Azure Function App (CertLCBridge)

PowerShell-based Azure Function that bridges the Storage Queue with the Automation Account:
- **QueueHandler**: Triggered by queue messages, parses the request payload, and invokes the appropriate Automation runbook
- **OutboundTester**: HTTP-triggered function for testing network connectivity from the Function App

### Automation Runbooks

- **certlc.ps1**: Main runbook handling certificate creation, renewal, and revocation operations. Executes on Hybrid Workers with CA access.
- **certlcstats.ps1**: Scheduled runbook that collects certificate metadata from Key Vault and publishes to Log Analytics.

Both runbooks run on a custom **PowerShell 7.6** runtime environment (default name `certlc-PowerShell-7-6`) created on the Automation Account by the Bicep template, with the `Az` and `Azure CLI` modules preloaded as default packages.

### Certificate Request Schema

Requests are sent as JSON messages to the Storage Queue using CloudEventSchema. The schema varies by operation type:

**Creation Request:**
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
    "CertificateTemplate": "<certificate template name>",
    "CertificateSubject": "<certificate subject>",
    "CertificateDnsNames": [ "<dns name 1>", "<dns name 2>" ],
    "Hostname": "<hostname - used as folder name for exported PFX>",
    "PfxProtectTo": [ "<user or group to protect the PFX file>" ],
    "NotifyTo": [ "<email address to notify>" ]
  }
}
```

**Renewal Request** (from Event Grid CertificateNearExpiry event):
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

> **Note:** For revocation reasons, see [ICertAdmin::RevokeCertificate](https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-revokecertificate) for possible values.

## Security Considerations

- **No Stored Secrets**: All Azure service authentication uses managed identities
- **Private Endpoints**: All PaaS resources are isolated from public internet
- **RBAC Authorization**: Key Vault uses Azure RBAC (not access policies) with least-privilege assignments
- **Encrypted Variables**: Sensitive automation variables (SMTP credentials) are stored encrypted
- **Audit Logging**: Diagnostic settings enabled on Key Vault and Automation Account

## Getting Started

For deployment instructions, prerequisites, and configuration details, see the [Setup Guide](Setup/README.md).
