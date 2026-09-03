<#

Input bindings are passed in via param block.

$QueueItem: the function runtime automatically decodes the message from base64.
If the function framework correctly recognizes it as a JSON message, it also converts it to PowerShell object (System.Management.Automation.OrderedHashtable)
Otherwise, it will be passed as a string.

The JSON message in $QueueItem is a CloudEventSchema event, which has the following format:

{
  "id": "<guid>",
  "source": "/subscriptions/<subscription id>/resourceGroups/<rgname>/providers/Microsoft.KeyVault/vaults/<keyvaultname>",
  "specversion": "1.0",
  "type": "Microsoft.KeyVault.CertificateNearExpiry",
  "subject": "mycert10",
  "time": "2025-06-11T20:12:27.934701Z",
  "data": {
    "Id": "https://<keyvaultname>.vault.azure.net/certificates/mycert10/<versionid>",
    "VaultName": "<keyvaultname>",
    "ObjectType": "Certificate",
    "ObjectName": "mycert10",
    "Version": "<versionid>",
    "NBF": 1749671927, # Not Before time in Unix timestamp format
    "EXP": 1749679127 # Expiration time in Unix timestamp format
  }
}

#>

param([object] $QueueItem, $TriggerMetadata)

# Prohibits references to uninitialized variables
Set-StrictMode -Version 1.0

# Ensure the script stops on errors
$ErrorActionPreference = "Stop"

# Explicitly load Az.Automation module (it seems that the function runtime does not load it automatically)
# Import-Module Az.Automation

# Ensure we only connect if needed - this is normally done at cold start by profile.ps1 but we want to ensure the context is valid
try {
  $context = Get-AzContext

  if (-not $context -or -not $context.Account -or $context.Account.Id -eq "NotLoggedIn") {
    Write-Warning "No valid Azure context found. Attempting Identity-based login..."
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    Write-Information "Identity-based login succeeded."
  }
  else {
    Write-Information "Using existing Azure context: $($context.Account.Id)"
  }
}
catch {
  throw "Failed to verify or establish Azure login context: $_"
}


# check if $QueueItem is a string, if so, something went wrong with the JSON deserialization
if ($QueueItem -is [string]) {
  Write-Error "Queue item is a string, expected a PowerShell object. This usually means the JSON deserialization failed. Check the string: $QueueItem"
}

# convert back to JSON to show the full message for debugging purposes and, later, to forward it to the webhook
$jsonQueueItem = $QueueItem | ConvertTo-Json -Depth 10 -Compress

# Write out the queue message and metadata to the information log.
Write-Information "CERTLC: full message received is: $jsonQueueItem"
Write-Information "CERTLC: event type: $($QueueItem.type)"
Write-Information "Queue item expiration time: $($TriggerMetadata.ExpirationTime)"
Write-Information "Queue item insertion time: $($TriggerMetadata.InsertionTime)"
Write-Information "Queue item next visible time: $($TriggerMetadata.NextVisibleTime)"
Write-Information "ID: $($TriggerMetadata.Id)"
Write-Information "Pop receipt: $($TriggerMetadata.PopReceipt)"
Write-Information "Dequeue count: $($TriggerMetadata.DequeueCount)"

# Retrieve Automation Account details from the function's App Settings (local.settings.json or Azure App Settings)

$AutomationAccountName = [Environment]::GetEnvironmentVariable("AutomationAccountName", "Process")
if ([string]::IsNullOrEmpty($AutomationAccountName)) {
  Write-Error "AutomationAccountName environment variable is not set or it is empty. Check function's App Settings."
}

$resourceGroupName = [Environment]::GetEnvironmentVariable("ResourceGroupName", "Process")
if ([string]::IsNullOrEmpty($resourceGroupName)) {
  Write-Error "ResourceGroupName environment variable is not set or it is empty. Check function's App Settings."
}

$HybridWorkerGroupName = [Environment]::GetEnvironmentVariable("HybridWorkerGroupName", "Process")
if ([string]::IsNullOrEmpty($HybridWorkerGroupName)) {
  Write-Error "HybridWorkerGroupName environment variable is not set or it is empty. Check function's App Settings."
}

$RunbookName = [Environment]::GetEnvironmentVariable("RunbookName", "Process")
if ([string]::IsNullOrEmpty($RunbookName)) {
  Write-Error "RunbookName environment variable is not set or it is empty. Check function's App Settings."
}

# Keep polling below the Function host's normal execution window. Operators can increase or
# decrease this limit through App Settings without changing the function code.
$runbookPollingTimeoutMinutes = 25
$configuredPollingTimeout = [Environment]::GetEnvironmentVariable("RunbookPollingTimeoutMinutes", "Process")
if (-not [string]::IsNullOrWhiteSpace($configuredPollingTimeout)) {
  $parsedPollingTimeout = 0
  if (-not [int]::TryParse($configuredPollingTimeout, [ref]$parsedPollingTimeout) -or
      $parsedPollingTimeout -lt 1 -or $parsedPollingTimeout -gt 180) {
    Write-Error "RunbookPollingTimeoutMinutes must be an integer from 1 through 180. Current value: '$configuredPollingTimeout'."
  }
  $runbookPollingTimeoutMinutes = $parsedPollingTimeout
}

Write-Information "Starting runbook $RunbookName in Automation Account $AutomationAccountName in Resource Group $ResourceGroupName on Hybrid Worker Group $HybridWorkerGroupName ..."

try {
  $res = Start-AzAutomationRunbook -Name $RunbookName -Parameters @{ 'jsonRequestBody' = $jsonQueueItem } -RunOn $HybridWorkerGroupName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
}
catch {
  throw "An error occurred while starting the runbook: $_"
}

if (-not $res -or -not $res.JobId) {
  Write-Error "Runbook did not return a JobId. Check the runbook for errors."
}

$jobId = $res.JobId

Write-Information "Runbook started with job id: $($res.JobId)"

# Poll with an explicit state policy so only Completed acknowledges the queue message. States
# that can still advance are observed until the deadline; failed or unknown states fail closed.
$pollingDeadline = [DateTime]::UtcNow.AddMinutes($runbookPollingTimeoutMinutes)
$pollingIntervalSeconds = 5
$continuingStates = @('New', 'Activating', 'Queued', 'Starting', 'Running', 'Resuming', 'Stopping', 'Disconnected')
$failedStates = @('Failed', 'Stopped', 'Suspended', 'Blocked')
$terminalError = $null
$job = $null

:pollAutomationJob while ($true) {
  try {
    $job = Get-AzAutomationJob -Id $jobId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
  }
  catch {
    throw "Unable to retrieve Automation job $jobId while polling: $_"
  }
  if ($null -eq $job -or [string]::IsNullOrWhiteSpace([string]$job.Status)) {
    throw "Automation job $jobId returned no job object or status while polling."
  }

  $jobStatus = [string]$job.Status
  Write-Information "Runbook job id: $jobId, status: $jobStatus"

  if ($jobStatus -eq 'Completed') {
    break pollAutomationJob
  }
  if ($jobStatus -in $failedStates) {
    $terminalError = "Automation job $jobId ended in unsuccessful terminal state '$jobStatus'."
    break pollAutomationJob
  }
  if ($jobStatus -notin $continuingStates) {
    $terminalError = "Automation job $jobId returned unrecognized state '$jobStatus'."
    break pollAutomationJob
  }
  if ([DateTime]::UtcNow -ge $pollingDeadline) {
    $terminalError = "Automation job $jobId did not reach a terminal state within $runbookPollingTimeoutMinutes minute(s); last state was '$jobStatus'."
    break pollAutomationJob
  }

  Start-Sleep -Seconds $pollingIntervalSeconds
}

# Retrieve output for diagnostics, but never retry a successfully completed lifecycle operation
# solely because Automation output retrieval is temporarily unavailable.
Write-Information "Runbook job id: $($jobId), output:"
$lastMsg = '<no output was returned>'
try {
  Get-AzAutomationJobOutput -Id $jobId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName | ForEach-Object {
    if ($_.Summary) {
      $lastMsg = $_.Summary
      Write-Information $lastMsg
    }
  }
}
catch {
  $lastMsg = "Automation output retrieval failed: $($_.Exception.Message)"
  Write-Warning "Runbook job id $jobId output could not be retrieved: $($_.Exception.Message)"
}

# Propagate every non-completed outcome so queue retry and poison-message handling remain active.
if ($terminalError) {
  throw "$terminalError Last runbook output: $lastMsg"
}

<# old code used to invoke the webhook directly, but now we use the runbook.

$webhookUrl = [Environment]::GetEnvironmentVariable("AutomationWebhookUrl", "Process")
if (-not $webhookUrl) {
    Write-Error "AutomationWebhookUrl is not set in the environment variables."
}

# Invoke the webhook. The $QueueItem will become WebhookData.RequestBody in runbook
Write-Information "Forwarding this payload to Automation Webhook..."

try {
    $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $jsonQueueItem -ContentType 'application/json'
    Write-Information "Webhook invoked successfully. Response from Automation Account is: $($response | ConvertTo-Json -Depth 3)"
}
catch {
    Write-Error "Failed to invoke webhook. $_"
}

#>