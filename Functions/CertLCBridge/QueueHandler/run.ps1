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

# wait for the runbook to complete
$job = Get-AzAutomationJob -Id $jobId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
while ($job.Status -ne 'Completed' -and $job.Status -ne 'Failed' -and $job.Status -ne 'Suspended') {
Write-Information "Runbook job id: $($jobId), status: $($job.Status)"
  Start-Sleep -Seconds 5
  $job = Get-AzAutomationJob -Id $jobId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
}
Write-Information "Runbook job id: $($jobId), status: $($job.Status)"

# write the output of the runbook
Write-Information "Runbook job id: $($jobId), output:"
Get-AzAutomationJobOutput -Id $job.JobId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName | ForEach-Object {
  if ($_.Summary) {
    $lastMsg = $_.Summary
    Write-Information $lastMsg
  }
}

# if the runbook failed, generate an error (this will stop the function execution and mark the queue item as failed)
if ($job.Status -eq 'Failed') {
  $errorMessage = "Runbook job id: $($jobId) has failed! Last message from job was: $lastMsg"
  Write-Error $errorMessage
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