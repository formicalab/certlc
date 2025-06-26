[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string] $CertName
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 1.0

# Variables
$storageAccountName = "flazstfnsharedneu001"
$queueName = "certlc"

# Create a storage context
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName

<#

Define the JSON message for new certificate request.
For new certificate requests, the body has a structure like this:

{
  "id": "<event idenfier>",
  "source": "/subscriptions/<subscriptionid>/resourceGroups/<keyvault resource group>/providers/Microsoft.KeyVault/<key vault name>",
  "specversion": "1.0",
  "type": "Microsoft.KeyVault.CertificateNearExpiry",
  "subject": "<name of the expiring certificate>",
  "time": "<event time, using format: 2025-06-08T19:52:25.1524887Z>",
  "data": {
    "Id": "https://<key vault name>.vault.azure.net/certificates/<certificate name>/<certificate version>",
    "VaultName": "<key vault name>",
    "ObjectType": "Certificate",
    "ObjectName": "<certificate name>",
    "Version": "<certificate version>",
    "NBF": 1749411621,  # not before date (epoch time)
    "EXP": 1749418821   # expiration date (epoch time)
  }
}

#>

# Define the JSON message emulating what arrives from the queue
$json = @"
{
  "id": "$(New-Guid)",
  "source": "/subscriptions/4a570962-701a-475e-bf5b-8dc76ec748ff/resourceGroups/rg-shared-neu-001/providers/Microsoft.KeyVault/vaults/flazkv-shared-neu-001",
  "specversion": "1.0",
  "type": "Microsoft.KeyVault.CertificateNearExpiry",
  "subject": "$certName",
  "time": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffffffZ' -AsUTC)",
  "data": {
    "Id": "https://flazkv-shared-neu-001.vault.azure.net/certificates/mycert05/7983b04bd0534cb0bf57e6b27c00f3bd",
    "VaultName": "flazkv-shared-neu-001",
    "ObjectType": "Certificate",
    "ObjectName": "$certName",
    "Version": "7983b04bd0534cb0bf57e6b27c00f3bd",
    "NBF": 1749411621,
    "EXP": 1749418821
  }
}
"@

$queue = Get-AzStorageQueue -Name $QueueName -Context $ctx
Write-Host ("Queued messages (approx.): " + $queue.ApproximateMessageCount)

$queueClient = $queue.QueueClient

# Send the message in base64 format
$base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))

$queueClient.SendMessage($base64)

Write-Host "Message sent to queue '$queueName'."


