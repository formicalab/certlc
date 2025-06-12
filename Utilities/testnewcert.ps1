[CmdletBinding()]
param (
  [Parameter(Mandatory = $true)]
  [string] $CertName,
  [Parameter(Mandatory = $false)]
  [switch] $UseQueue
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 1.0

# Variables
$storageAccountName = "flazstfnsharedneu001"
$queueName = "certlc"
$AutomationWebhookUrl = "https://70cf67fa-9b4f-4a13-97c5-0c099a08c2df.webhook.ne.azure-automation.net/webhooks?token=pr3drGvacMp3tjlQIdnuvHTLG3KDwKxo74nu6dX%2bTYE%3d"

<#

Define the JSON message for new certificate request.
For new certificate requests, the body has a structure like this:

{
  "id": "<event identifier, free field>",
  "source": "<free field, can be used to identify the requestor>",
  "specversion": "1.0",
  "type": "CertLC.NewCertificateRequest",
  "subject": "<name of the new certificate>",
  "time": "<event time, using format: 2025-06-08T19:52:25.1524887Z>",
  "data": {
    "Id": "<request id, free field>",
    "VaultName": "<key vault name>",
    "ObjectType": "Certificate",
    "ObjectName": "<name of the new certificate>",
    "CertificateTemplate": "<certificate template name>",
    "CertificateSubject": "<certificate subject>",
    "CertificateDnsNames": [ "<dns name 1>", "<dns name 2>" ],  # optional, can be empty
    "PfxProtectTo": "<user or group to protect the PFX file>",  # optional, can be empty. If not specified, the PFX will not be downloaded
  }
}

#>

$json = @"
{
  "id": "$(New-Guid)",
  "source": "testnewcert.ps1",
  "specversion": "1.0",
  "type": "CertLC.NewCertificateRequest",
  "subject": "$certName",
  "time": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffffffZ' -AsUTC)",
  "data": {
    "Id": "Ticket01",
    "VaultName": "flazkv-shared-neu-001",
    "ObjectType": "Certificate",
    "ObjectName": "$certName",
    "CertificateTemplate": "Flab-ShortWebServer",
    "CertificateSubject": "CN=www.example.com",
    "CertificateDnsNames": [
      "www.example.com",
      "api.example.com"
    ],
    "PfxProtectTo": "formicalab\\marcello"
  }
}
"@

if ($UseQueue) {

  Write-Host "Using queue."

  # Create a storage context
  $ctx = New-AzStorageContext -StorageAccountName $storageAccountName

  $queue = Get-AzStorageQueue -Name $QueueName -Context $ctx
  Write-Host ("Queued messages (approx.): " + $queue.ApproximateMessageCount)

  $queueClient = $queue.QueueClient

  # Send the message in base64 format
  $base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))

  try {
    $queueClient.SendMessage($base64)
    Write-Host "Message sent to queue '$queueName'."
  }
  catch {
    Write-Error "Failed to send request to the queue. $_"
  }
}

else {
  
  Write-Host "Using Automation Webhook."

  # convert to object and convert back to JSON with -Compress in order to remove any formatting issues
  $jsonObject = $json | ConvertFrom-Json -Depth 10
  $json = $jsonObject | ConvertTo-Json -Depth 10 -Compress

  try {
    $response = Invoke-RestMethod -Uri $AutomationWebhookUrl -Method Post -Body $json -ContentType 'application/json'
    Write-Host "Webhook invoked successfully. Response from Automation Account is: $($response | ConvertTo-Json -Depth 3)"
  }
  catch {
    Write-Error "Failed to invoke webhook. $_"
  }
}