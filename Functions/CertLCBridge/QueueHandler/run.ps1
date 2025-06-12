<#

Input bindings are passed in via param block.

$QueueItem: the function runtime automatically decodes the message from base64.
If the function framework correctly recognizes it as a JSON message, it also converts it to PowerShell object (System.Management.Automation.OrderedHashtable)
Otherwise, it will be passed as a string.

The JSON message in $QueueItem is a CloudEventSchema event, which has the following format:

{
  "id": "f36c5d73-a559-480d-b131-202c16c1c024",
  "source": "/subscriptions/4a570962-701a-475e-bf5b-8dc76ec748ff/resourceGroups/rg-shared-neu-001/providers/Microsoft.KeyVault/vaults/flazkv-shared-neu-001",
  "specversion": "1.0",
  "type": "Microsoft.KeyVault.CertificateNearExpiry",
  "subject": "mycert10",
  "time": "2025-06-11T20:12:27.934701Z",
  "data": {
    "Id": "https://flazkv-shared-neu-001.vault.azure.net/certificates/mycert10/604a2c253ee94f569f37265add7ca0a6",
    "VaultName": "flazkv-shared-neu-001",
    "ObjectType": "Certificate",
    "ObjectName": "mycert10",
    "Version": "604a2c253ee94f569f37265add7ca0a6",
    "NBF": 1749671927,
    "EXP": 1749679127
  }
}

#>

param([object] $QueueItem, $TriggerMetadata)

# Prohibits references to uninitialized variables
Set-StrictMode -Version 1.0

# Ensure the script stops on errors so that try/catch can be used to handle them
$ErrorActionPreference = "Stop"

# check if $QueueItem is a string, if so, something went wrong with the JSON deserialization
if ($QueueItem -is [string]) {
    Write-Error "Queue item is a string, expected a PowerShell object. This usually means the JSON deserialization failed. Check the string: $QueueItem"
}

# convert back to JSON to show the full message for debugging purposes and, later, to forward it to the webhook
$jsonQueueItem = $QueueItem | ConvertTo-Json -Depth 10 -Compress

# Write out the queue message and metadata to the information log.
Write-Information "CERTLC: full message received is: $jsonQueueItem"
Write-Information "CERTLC: event type: $($QueueItemObj.type)"
Write-Information "Queue item expiration time: $($TriggerMetadata.ExpirationTime)"
Write-Information "Queue item insertion time: $($TriggerMetadata.InsertionTime)"
Write-Information "Queue item next visible time: $($TriggerMetadata.NextVisibleTime)"
Write-Information "ID: $($TriggerMetadata.Id)"
Write-Information "Pop receipt: $($TriggerMetadata.PopReceipt)"
Write-Information "Dequeue count: $($TriggerMetadata.DequeueCount)"

# Retrieve from App Settings (local.settings.json or Azure App Settings)
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
