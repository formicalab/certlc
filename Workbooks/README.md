# Workbook Queries

[certlcstats.workbook](certlcstats.workbook) is the production source loaded by Bicep. Its tabs
are Statistics, Event Journey, Job logs and Function bridge. Keep the five resource-ID
placeholders and the fallback workspace placeholder unresolved in this file.

The 18 standalone queries below match the embedded workbook queries. Update both copies when
changing a query; only line endings and surrounding whitespace may differ. Journey files are
self-contained, including their shared correlation definitions, so each can be inspected or
run independently after supplying the workbook parameters.

| KQL File | Workbook Query |
| --- | --- |
| [parameter-log-analytics-workspaces.kql](parameter-log-analytics-workspaces.kql) | LogAnalyticsWorkspace |
| [parameter-automation-accounts.kql](parameter-automation-accounts.kql) | AutomationAccount |
| [parameter-main-runbooks.kql](parameter-main-runbooks.kql) | Runbook |
| [parameter-stats-runbooks.kql](parameter-stats-runbooks.kql) | StatsRunbook |
| [parameter-function-apps.kql](parameter-function-apps.kql) | FunctionApp |
| [stats-last-update.kql](stats-last-update.kql) | LastUpdateFormatted |
| [stats-certificate-status-summary.kql](stats-certificate-status-summary.kql) | Certificate status summary |
| [jobs-status-summary.kql](jobs-status-summary.kql) | Job status summary |
| [stats-certificate-details.kql](stats-certificate-details.kql) | Certificate details |
| [jobs-history.kql](jobs-history.kql) | Jobs |
| [function-bridge-summary.kql](function-bridge-summary.kql) | Function bridge summary |
| [function-bridge-volume-failures.kql](function-bridge-volume-failures.kql) | Function bridge trend |
| [function-bridge-slowest-operations.kql](function-bridge-slowest-operations.kql) | Slowest Function bridge operations |
| [operations-recent-failures.kql](operations-recent-failures.kql) | Recent failures |
| [function-bridge-invocations.kql](function-bridge-invocations.kql) | Function bridge invocations |
| [event-journey-events.kql](event-journey-events.kql) | event-list |
| [event-journey-context.kql](event-journey-context.kql) | event-context |
| [event-journey-timeline.kql](event-journey-timeline.kql) | event-timeline |

The five resource selectors use Azure Resource Graph. The remaining 13 queries read Log
Analytics. Journey shares the workbook's resource and time controls and uses source plus event
ID for identity, retaining separate invocation/job branches for repeated deliveries. Its search
supports event IDs, certificates, jobs, invocations, event types and sources. Event lists are
limited to 500 results; the selected tree includes up to 2000 log records plus parent nodes.
Missing telemetry means not observed within the selected time range, not necessarily failure.