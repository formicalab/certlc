# Workbook Queries

[certlcstats.workbook](certlcstats.workbook) is the production source loaded by Bicep. Its tabs
are Statistics, Event Journey, EventGrid, Queue, Job Logs and Function Bridge Logs. Keep the nine resource-ID
placeholders and the fallback workspace placeholder unresolved in this file.

The 35 standalone queries below match the embedded workbook queries. Update both copies when
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
| [parameter-event-grid-topics.kql](parameter-event-grid-topics.kql) | EventGridTopic |
| [parameter-event-grid-source.kql](parameter-event-grid-source.kql) | EventGridSource |
| [parameter-queue-storage-accounts.kql](parameter-queue-storage-accounts.kql) | QueueStorage |
| [parameter-queue-service.kql](parameter-queue-service.kql) | QueueService |
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
| [event-grid-failures.kql](event-grid-failures.kql) | eventgrid-failures |
| [event-grid-failure-details.kql](event-grid-failure-details.kql) | eventgrid-failure-details |
| [event-grid-failure-summary.kql](event-grid-failure-summary.kql) | eventgrid-failure-summary |
| [event-grid-observed-receipts.kql](event-grid-observed-receipts.kql) | eventgrid-observed-receipts |
| [queue-failures.kql](queue-failures.kql) | queue-failures |
| [queue-retry-summary.kql](queue-retry-summary.kql) | queue-retry-summary |
| [queue-operation-summary.kql](queue-operation-summary.kql) | queue-operation-summary |
| [queue-request-trend.kql](queue-request-trend.kql) | queue-request-trend |
| [queue-duration-trend.kql](queue-duration-trend.kql) | queue-duration-trend |
| [queue-operations.kql](queue-operations.kql) | queue-operations |
| [queue-operation-detail.kql](queue-operation-detail.kql) | queue-operation-detail |
| [queue-attempts.kql](queue-attempts.kql) | queue-attempts |
| [queue-message-detail.kql](queue-message-detail.kql) | queue-message-detail |

Nine resource parameter queries use Azure Resource Graph; the remaining 26 queries read Log Analytics.
Native Azure Monitor metrics supply Event Grid and queue-service charts. Read-only ARM queries
show the current approximate backlog of `certlc` and `certlc-poison` without consuming messages.
Journey shares the workbook's resource and time controls and uses source plus event
ID for identity, grouping invocations under queue-message branches when host evidence is available.
Its search supports event IDs, certificates, queue names, message IDs, jobs, invocations, event types and sources. Event lists are
limited to 500 results; the selected tree includes up to 2000 log records plus parent nodes.
Missing telemetry means not observed within the selected time range, not necessarily failure.

Journey combines ingested `BridgeCorrelation` receipt records with Event Grid `DeliveryFailures`
in `AzureDiagnostics`. Failure-only events remain visible without synthetic Function or job nodes.
Resource-ID sources are normalized to lowercase; source plus event ID establishes identity.
Missing event IDs remain isolated, and Event Grid `systemId` is never used as an event ID.
Events predating both sources and direct-webhook-only jobs do not appear in the event list;
Job Logs remains available for runbook history. Platform job state, logged operation outcome and
notification result are separate signals: a Completed job may legitimately report Skipped.
Full diagnostics and IDs remain available in exports, while the grid uses native horizontal
scrolling and cell truncation. Workbook readers need query access to the selected workspace and
read access to the selected Event Grid topic, storage queue resources and metrics.

Journey joins queue host observations by Function invocation ID, never timestamp proximity.
Each message retains separate dequeue attempts and their Function/job children. Insertion timestamps
are host-reported; age at dequeue includes retry delay, and retry gaps cover observed attempts only.
Host completion and Function duration are distinct from Automation job state and operation outcome.
Missing completion, deletion and poison movement are not inferred from successful processing.
Attempts without a correlated event receipt cannot be attributed to an event and remain available
in the Queue tab. Host observations are scoped to the selected Function, independently of Queue Storage.

Queue logs expose request failures, operation summaries, durations and request/message drilldowns.
The search info tooltip lists supported fields and literal matching rules. URI query strings are
excluded from request results to avoid exposing signatures and pop receipts. Request counts are
not message counts. Native metrics cover all queues in the selected storage account, without a
queue-name dimension; historical message count is hourly, unlike the current per-queue ARM counts.
The alerts module enables `StorageRead`, `StorageWrite` and `StorageDelete` diagnostics to the workspace.
New categories are not backfilled, and missing records are not evidence of an empty queue or deletion.

The integration Bicep module enables `DeliveryFailures` export to the existing workspace.
Logging starts after configuration and ingestion; historical failures are not backfilled.
System-topic diagnostics are not a complete per-event success history: a delivered metric means
delivery to the queue, not a successful renewal. Failed attempts can subsequently succeed.
The receipt table is explicitly Function-observed evidence, not an Event Grid success-log feed.
An empty failure view or missing metric samples do not establish that no failures occurred.
Topic publication totals include all source event types, whereas delivery charts distinguish
event subscriptions. The hidden `EventGridSource` parameter resolves the selected topic's source.

The workbook substitutes its shared parameters when executing these files. Standalone execution
must also supply `JourneySearch` or `SelectedEvent` using the query's base64 parameter syntax;
`SelectedEvent` is the complete key exported by the event-list query, not just a correlation ID.
Event Grid queries similarly use `EventGridSearch` and `SelectedFailureEvent` with base64 formatting.
Queue queries use `QueueFilter`, `QueueSearch`, `SelectedQueueOperation` and `SelectedQueueMessage`
with base64 formatting. Bicep binds `__QUEUE_STORAGE_ACCOUNT_ID__` and `__QUEUE_SERVICE_ID__`
from the deployed storage account. It loads the workbook with `loadJsonContent` and serializes
the parsed JSON before placeholder replacement, avoiding the smaller `loadTextContent` size limit.
No temporary TEST workbook, generator or test scripts are required to deploy this workbook.