# Custom Log Analytics table for CertLC statistics

This folder contains an example payload and the **KQL transformation** applied to the custom Log Analytics table `certlcstats_CL`, which receives certificate inventory data published by the `certlcstats.ps1` runbook.

> **All resources described here are provisioned automatically by the Bicep template in [`Setup/certlc.bicep`](../../Setup/certlc.bicep).** The files in this folder are kept for reference and to make the schema/transformation auditable in source control. There is no manual portal procedure to follow.

## Files

| File | Purpose |
|------|---------|
| `certstats-schema.json` | Example records documenting the ingestion payload |
| `certlcstats.transformation` | Reference copy of the DCR transformation (parses string dates and sets `TimeGenerated`); keep it aligned with the inline Bicep definition |

## What the Bicep deployment creates

- **Custom table** `certlcstats_CL` in the Log Analytics workspace, with its schema declared in `Setup/modules/observability.bicep`
- **Data Collection Endpoint** (DCE) for log ingestion
- **Data Collection Rule** (DCR) with:
  - Stream declaration `Custom-certlcstats_CL` *(case-sensitive)*
  - The inline transformation in `Setup/modules/observability.bicep`, mirrored by `certlcstats.transformation`
  - Destination: the custom table in the Log Analytics workspace
- **Role assignment** `Monitoring Metrics Publisher` on the DCR for the Automation Account's managed identity
- **Automation variables** read by `certlcstats.ps1`:
  - `certlc-stats-keyvault` &mdash; vault to enumerate
  - `certlc-stats-ingestionurl` &mdash; DCE ingestion endpoint
  - `certlc-stats-immutableid` &mdash; DCR immutable ID
  - `certlc-stats-streamname` &mdash; `Custom-certlcstats_CL`

## Schema

The table has 9 columns: `TimeGenerated`, `SnapshotId`, `Thumbprint`, `Name`, `Created`, `Expires`, `Subject`, `Template`, `DNSNames`. All records produced by one runbook scan share the same `SnapshotId`.

## Querying the data

```kusto
certlcstats_CL
| order by TimeGenerated desc
| project TimeGenerated, Name, Thumbprint, Subject, Template, Expires
```

The Statistics tab in [`Workbooks/certlcstats.workbook`](../../Workbooks/certlcstats.workbook) consumes this table to render the certificate inventory dashboard. Event Journey, Job Logs and Function Bridge Logs use operational telemetry (`AppTraces`, `AppExceptions` and `AzureDiagnostics`). EventGrid adds native metrics, delivery-failure logs and labeled Function receipt evidence. Queue combines `StorageQueueLogs`, Function-host attempts, live approximate backlog and account-wide native metrics. Journey correlates host message/dequeue observations by invocation ID alongside Event Grid failures and Automation jobs. These views do not change this table, its schema or ingestion. Bicep resolves nine resource-ID placeholders and the fallback workspace scope; queue read/write/delete logs are enabled by the alerts module and are not backfilled. See the [query index](../../Workbooks/README.md) for the 35 standalone queries matching the workbook.

## Modifying schema or transformation

Edit the shared `certlcDataColumns` schema and/or inline `transformKql` in [Setup/modules/observability.bicep](../../Setup/modules/observability.bicep). Update the sample JSON and reference transformation in this folder to match, and adjust [Runbooks/certlcstats.ps1](../../Runbooks/certlcstats.ps1) and affected workbook queries when the payload changes. Validate and redeploy the infrastructure after reviewing the changes. The reference JSON and KQL files are not loaded by Bicep, so editing them alone does not alter the deployed table or DCR. Do **not** edit the table or DCR directly in the portal &mdash; the next Bicep deployment will overwrite portal changes.
