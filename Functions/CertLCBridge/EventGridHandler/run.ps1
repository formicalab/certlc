# This function is triggered by Event Grid 
# IMPORTANT: the code assumes that the Event Grid Subscription is using the CloudEventSchema

param($cloudEvent, $TriggerMetadata)

$ErrorActionPreference = 'Stop'

Write-Information "=== EventGridHandler function triggered ==="

<#

$cloudEvent is a hash table containing the json fields from the Event Grid event.
Converted back to JSON, if CloudEventSchema is used, has this format:

{
  "id": "51739d81-c68c-436b-a28c-52ebe1ebb37f",
  "source": "/subscriptions/<guid>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<keyvault>",
  "specversion": "1.0",
  "type": "Microsoft.KeyVault.CertificateNearExpiry",
  "subject": "mycert05",
  "time": "2025-06-08T17:45:12.2205855Z",
  "data": {
    "Id": "https://<keyvault>.vault.azure.net/certificates/mycert05/<version>",
    "VaultName": "<keyvault>",
    "ObjectType": "Certificate",
    "ObjectName": "mycert05",
    "Version": "<version>",
    "NBF": 1749403975,
    "EXP": 1749411175
  }
}

$triggerMetadata is not used in this example, it can provide additional context about the event trigger
(see https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-powershell?tabs=portal#triggermetadata-parameter)

#>

# Convert back the hastable object to the original JSON.
$jsonEvent = $cloudEvent | ConvertTo-Json -Depth 10 -Compress

# Retrieve from App Settings (local.settings.json or Azure App Settings)
$webhookUrl = [Environment]::GetEnvironmentVariable("AutomationWebhookUrl", "Process")
if (-not $webhookUrl) {
    Write-Error "AutomationWebhookUrl is not set in the environment variables."
}

try {

    Write-Information "Forwarding this payload to Automation Webhook:`n$jsonEvent"

    # Invoke the webhook. The $jsonEvent will become WebhookData.RequestBody in runbook
    $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $jsonEvent -ContentType 'application/json'
    Write-Information "Webhook invoked successfully. Response: $($response | ConvertTo-Json -Depth 3)"

} catch {
    Write-Error "Failed to invoke webhook. $_"
}
