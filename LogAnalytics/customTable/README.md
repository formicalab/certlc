# Custom Log Analytics table for CertLC statistics

This folder contains the **schema** and the **KQL transformation** applied to the custom Log Analytics table `certlc_CL`, which receives certificate inventory data published by the `certlcstats.ps1` runbook.

> **All resources described here are provisioned automatically by the Bicep template in [`Setup/certlc.bicep`](../../Setup/certlc.bicep).** The files in this folder are kept for reference and to make the schema/transformation auditable in source control. There is no manual portal procedure to follow.

## Files

| File | Purpose |
|------|---------|
| `certstats-schema.json` | Column definitions of the `certlc_CL` table (consumed by the Bicep template) |
| `certlcstats.transformation` | KQL transformation applied by the Data Collection Rule to incoming records (parses string dates and sets `TimeGenerated`) |

## What the Bicep deployment creates

- **Custom table** `certlc_CL` (the `_CL` suffix is implicit) in the Log Analytics workspace, with the schema in `certstats-schema.json`
- **Data Collection Endpoint** (DCE) for log ingestion
- **Data Collection Rule** (DCR) with:
  - Stream declaration `Custom-certlc_CL` *(case-sensitive)*
  - The transformation from `certlcstats.transformation`
  - Destination: the custom table in the Log Analytics workspace
- **Role assignment** `Monitoring Metrics Publisher` on the DCR for the Automation Account's managed identity
- **Automation variables** read by `certlcstats.ps1`:
  - `certlc-stats-keyvault` &mdash; vault to enumerate
  - `certlc-stats-ingestionurl` &mdash; DCE ingestion endpoint
  - `certlc-stats-immutableid` &mdash; DCR immutable ID
  - `certlc-stats-streamname` &mdash; `Custom-certlc_CL`

## Schema

The table has 8 columns (see `certstats-schema.json` for the authoritative definition): `TimeGenerated`, `Thumbprint`, `Name`, `Created`, `Expires`, `Subject`, `Template`, `DNSNames`.

## Querying the data

```kusto
certlc_CL
| order by TimeGenerated desc
| project TimeGenerated, Name, Thumbprint, Subject, Template, Expires
```

The Azure Monitor workbook in [`Workbooks/certlc.workbook`](../../Workbooks/certlc.workbook) consumes this table to render the certificate inventory dashboard.

## Modifying schema or transformation

Edit the JSON / KQL files in this folder, then redeploy `Setup/certlc.bicep`. Do **not** edit the table or DCR directly in the portal &mdash; the next Bicep deployment will overwrite portal changes.
