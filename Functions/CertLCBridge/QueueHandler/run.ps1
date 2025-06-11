# Input bindings are passed in via param block.
param([object] $QueueItem, $TriggerMetadata)

# The function runtime automatically decodes the message from base64
# and parses the resulting JSON into a PowerShell object (Hashtable) before passing it to your run.ps1.
# This allows picking up message properties directly from the $QueueItem object, for example: $QueueItem.id

#$triggerMetadata is not used in this example, it can provide additional context about the event trigger
# (see https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-powershell?tabs=portal#triggermetadata-parameter)


# However, since we need to forward the message to an Automation Webhook, we need to convert the QueueItem back to JSON
$jsonQueueItem = $QueueItem | ConvertTo-Json -Depth 10 -Compress

<# The JSON message is a CloudEventSchema event, which has the following format:

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

# Write out the queue message and metadata to the information log.
Write-Information "CERTLC: received an event of type: $($QueueItem.type)"
Write-Information "CERTLC: full message converted back to JSON is: $jsonQueueItem"
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

# Invoke the webhook. The $jsonEvent will become WebhookData.RequestBody in runbook
Write-Information "Forwarding this payload to Automation Webhook:`n$jsonQueueItem"

try {
    $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $jsonQueueItem -ContentType 'application/json'
    Write-Information "Webhook invoked successfully. Response from Automation Account is: $($response | ConvertTo-Json -Depth 3)"
}
catch {
    Write-Error "Failed to invoke webhook. $_"
}
