<#

.SYNOPSIS
  This script tests the certificate RENEW request functionality of CertLC by sending a request to the queue, emulating the queue message normally received from the Event Grid subscription.

.DESCRIPTION
  This script sends a test message to the specified Azure Storage Queue, using the same message structure expected by the CertLC application for certificate renewal requests.
  The message is sent in base64 format to ensure compatibility with the queue's requirements.

.EXAMPLE
  .\testrenewcert.ps1 -StorageAccountName "storageaccountname" -QueueName "queuename" -CertName "mycert" -VaultName "keyvaultname"

  Send a new certificate renewal request to Azure Storage Queue

#>

#Requires -PSEdition Core


[CmdletBinding()]
param (
  [Parameter(Mandatory = $true)]
  [string] $StorageAccountName,

  [Parameter(Mandatory = $true)]
  [string] $QueueName = 'certlc',

  [Parameter(Mandatory = $true)]
  [string] $CertName,

  [Parameter(Mandatory = $true)]
  [string] $VaultName
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

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

# Define the JSON message emulating what arrives from the queue. Note that version, NBF, EXP, source are ignored
$json = @"
{
  "id": "$(New-Guid)",
  "source": "/subscriptions/4a570962-701a-475e-bf5b-8dc76ec748ff/resourceGroups/rg-shared-neu-001/providers/Microsoft.KeyVault/vaults/$vaultName",
  "specversion": "1.0",
  "type": "Microsoft.KeyVault.CertificateNearExpiry",
  "subject": "$certName",
  "time": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffffffZ' -AsUTC)",
  "data": {
    "Id": "https://$vaultName.vault.azure.net/certificates/$certName/7983b04bd0534cb0bf57e6b27c00f3bd",
    "VaultName": "$vaultName",
    "ObjectType": "Certificate",
    "ObjectName": "$certName",
    "Version": "7983b04bd0534cb0bf57e6b27c00f3bd",
    "NBF": 1749411621,
    "EXP": 1749418821
  }
}
"@

Write-Host "Using queue '$QueueName'" 

# Create a storage context
Write-Host "Creating storage context for account '$StorageAccountName' containing the queue '$QueueName'..."
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName

# Get the queue and check current messages
Write-Host "Checking queue '$QueueName' for existing messages..."
$queue = Get-AzStorageQueue -Name $QueueName -Context $ctx
Write-Host ('Queued messages (approx.): ' + $queue.ApproximateMessageCount)

# Send the message in base64 format
$base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
$queueClient = $queue.QueueClient

try {
  Write-Host "Sending the message to queue '$QueueName'..."
  $queueClient.SendMessage($base64)
  Write-Host "Message sent to queue '$queueName'."
}
catch {
  Write-Error "Failed to send request to the queue. $_"
}

