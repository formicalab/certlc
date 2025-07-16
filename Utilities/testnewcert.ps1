<#
.SYNOPSIS
  This script tests the new certificate request functionality of CertLC by sending a request to the queue or invoking a runbook via webhook.

.DESCRIPTION
  This script creates a JSON message for a new certificate request and sends it to either an Azure
  Storage Queue or invokes an Azure Automation Runbook via a webhook. It can also directly start a runbook
  on a hybrid worker group. The script allows for testing the new certificate request functionality in CertLC.

  The JSON message structure is defined in the script, and it includes fields such as the certificate name,
  vault name, certificate template, subject, DNS names, and the user or group to protect the PFX file to.

.EXAMPLE
  .\testnewcert.ps1 -CertName "TestCert" -UseQueue
  This command sends a new certificate request for "TestCert" to the Azure Storage Queue specified in the script.

  .\testnewcert.ps1 -CertName "TestCert" -UseWebhook
  This command invokes the Azure Automation Runbook via webhook for the new certificate request for "TestCert".

  .\testnewcert.ps1 -CertName "TestCert"
  This command directly starts the runbook for the new certificate request for "TestCert" on the hybrid worker group.
#>

#Requires -PSEdition Core

[CmdletBinding()]
param (
  [Parameter(Mandatory = $true)]
  [string] $CertName,
  [Parameter(Mandatory = $false)]
  [switch] $UseQueue,
  [Parameter(Mandatory = $false)]
  [switch] $UseWebhook
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 1.0

# Variables
$storageAccountName = "flazstfnsharedneu001"
$queueName = "certlc"
$AutomationWebhookUrl = "https://70cf67fa-9b4f-4a13-97c5-0c099a08c2df.webhook.ne.azure-automation.net/webhooks?token=pr3drGvacMp3tjlQIdnuvHTLG3KDwKxo74nu6dX%2bTYE%3d"
$AutomationAccountName = "aa-shared-neu-001"
$ResourceGroupName = "rg-shared-neu-001"
$HybridWorkerGroupName = "hwg-shared-neu-001"
$RunbookName = "certlc"
$VaultName = "flazkv-shared-neu-001"
$CertificateTemplate = "Flab-ShortWebServer"
$PfxProtectTo = "formicalab\\marcello"

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
    "VaultName": "$vaultName",
    "ObjectType": "Certificate",
    "ObjectName": "$certName",
    "CertificateTemplate": "$certificateTemplate",
    "CertificateSubject": "CN=www.example.com",
    "CertificateDnsNames": [
      "www.example.com",
      "api.example.com"
    ],
    "PfxProtectTo": "$PfxProtectTo"
  }
}
"@

# convert to object and convert back to JSON with -Compress in order to remove any formatting issues
$jsonObject = $json | ConvertFrom-Json -Depth 10
$json = $jsonObject | ConvertTo-Json -Depth 10 -Compress

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

elseif ($UseWebhook) {
  
  Write-Host "Using Runbook"

  try {
    $response = Invoke-RestMethod -Uri $AutomationWebhookUrl -Method Post -Body $json -ContentType 'application/json'
    Write-Host "Webhook invoked successfully, job id is $($response.JobIds)"
  }
  catch {
    if ($_.ErrorDetails.Message) {
      Write-Warning $_.ErrorDetails.Message
    }
    else {
      Write-Warning $_
    }
  }
}

else {
  Write-host "Using direct runbook invocation"

  try {
    $res = Start-AzAutomationRunbook -Name $RunbookName -Parameters @{ 'jsonRequestBody' = $json } -RunOn $HybridWorkerGroupName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
    Write-Host "Runbook started with job id: $($res.JobId)"   
  }
  catch {
    Write-Error "Failed to start runbook. $_"
  }

  # wait for the runbook to complete
  $job = Get-AzAutomationJob -Id $res.JobId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
  while ($job.Status -ne 'Completed' -and $job.Status -ne 'Failed' -and $job.Status -ne 'Suspended') {
    Write-Host "Runbook job status: $($job.Status)"
    Start-Sleep -Seconds 5
    $job = Get-AzAutomationJob -Id $res.JobId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
  }
  Write-Host "Runbook job status: $($job.Status)"

  # write the output of the runbook
  Write-Host "Runbook output:"
  Get-AzAutomationJobOutput -Id $job.JobId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName | ForEach-Object {
    if ($_.Summary) {
      Write-Host $_.Summary
    }
  }  
}
