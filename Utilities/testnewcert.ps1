<#
.SYNOPSIS
  This script tests the new certificate request functionality of CertLC by sending a request to the queue or invoking a runbook via webhook or directly

.DESCRIPTION
  This script creates a JSON message for a new certificate request and sends it to either an Azure
  Storage Queue or invokes an Azure Automation Runbook via a webhook. It can also directly start a runbook
  on a hybrid worker group. The script allows for testing the new certificate request functionality in CertLC.

  The JSON message structure is defined in the script, and it includes fields such as the certificate name,
  vault name, certificate template, subject, DNS names, and the user or group to protect the PFX file to.

.EXAMPLE
  .\testnewcert.ps1 -UseQueue -StorageAccountName "storageaccountname" -QueueName "queuename" -CertName "mycert" -VaultName "keyvaultname" -CertificateTemplate "WebServer" -PfxProtectTo @('domain\user') -Hostname "myhost"

  Send a new certificate request to Azure Storage Queue

.EXAMPLE
  .\testnewcert.ps1 -UseWebhook -AutomationWebhookUrl "https://70cf67fa-9b4f-4a13-....webhook.ne.azure-automation.net/webhooks?token=pr3..." -CertName "mycert" -VaultName "keyvaultname" -CertificateTemplate "WebServer" -PfxProtectTo @('domain\user') -Hostname "myhost"

  Invoke Azure Automation Runbook via webhook

.EXAMPLE
  .\testnewcert.ps1  -UseDirectRunbookInvocation -AutomationAccountName "aa-shared-neu-001" -AutomationAccountRGName "rg-shared-neu-001" -HybridWorkerGroupName "workergroup001" -RunbookName "certlc" -CertName "mycert" -VaultName "keyvaultname" -CertificateTemplate "WebServer" -PfxProtectTo @('domain\user')
  
  Directly start the runbook on a hybrid worker group

  #>

#Requires -PSEdition Core

[CmdletBinding()]
param (
  # Queue Parameter Set and switch
  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [switch] $UseQueue,
  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [string] $StorageAccountName,
  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [string] $QueueName = 'certlc',

  # Webhook Parameter Set and switch
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [switch] $UseWebhook,
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [string] $AutomationWebhookUrl,

  # Direct Runbook Invocation Parameter Set and switch
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [switch] $UseDirectRunbookInvocation,
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $AutomationAccountName,
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $AutomationAccountRGName,
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $HybridWorkerGroupName,
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $RunbookName = 'certlc',

  # Common parameters for all parameter sets
  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $VaultName,

  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $CertName,

  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $Subject = 'CN=www.example.com',

  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string[]] $CertificateDnsNames = @('www.example.com', 'api.example.com'),

  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $CertificateTemplate,

  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string] $Hostname,

  [Parameter(Mandatory = $true, ParameterSetName = 'Queue')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Webhook')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
  [string[]] $PfxProtectTo,

  [Parameter(ParameterSetName = 'Queue')]
  [Parameter(ParameterSetName = 'Webhook')]
  [Parameter(ParameterSetName = 'Direct')]
  [string[]] $NotifyTo
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

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
    "CertificateDnsNames": [ "<dns name 1>", "<dns name 2>", ... ],  # optional, can be empty
    "Hostname": "<hostname of the server where the certificate will be used>",  # it will be used also as folder name for exported PFX
    "PfxProtectTo": [ "<user or group to protect the PFX file>", "other user/group", ...],  # these principals will be also granted Read+Execute on PFX folder
    "NotifyTo": [ "<email address to notify>", "other email address", ... ],  # optional, email addresses to notify when the certificate is created
  }
}

#>

$data = [ordered]@{
  id          = (New-Guid)
  source      = 'testnewcert.ps1'
  specversion = '1.0'
  type        = 'CertLC.NewCertificateRequest'
  subject     = $CertName
  time        = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffffffZ' -AsUTC)
  data        = [ordered]@{
    Id                  = 'Ticket01'
    VaultName           = $VaultName
    ObjectType          = 'Certificate'
    ObjectName          = $CertName
    CertificateTemplate = $CertificateTemplate
    CertificateSubject  = $Subject
    CertificateDnsNames = $CertificateDnsNames
    Hostname            = $Hostname
    PfxProtectTo        = $PfxProtectTo
    NotifyTo            = $NotifyTo
  }
}

$json = $data | ConvertTo-Json -Depth 6 -Compress

# execution logic based on the parameter set
switch ($PSCmdlet.ParameterSetName) {

  'Queue' {

    #########
    # QUEUE #
    #########

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
  }

  'Webhook' {

    ###########
    # WEBHOOK #
    ###########

    Write-Host 'Using Webhook invocation'

    try {
      $response = Invoke-RestMethod -Uri $AutomationWebhookUrl -Method Post -Body $json -ContentType 'application/json'
      Write-Host "Webhook invoked successfully, job id is $($response.JobIds)"
    }
    catch {
      if ($_.ErrorDetails.Message) {
        Write-Error $_.ErrorDetails.Message
      }
      else {
        Write-Error $_
      }
    }

  }
  'Direct' {

    #############################
    # DIRECT RUNBOOK INVOCATION #
    #############################

    Write-Host 'Using direct runbook invocation'

    try {
      $res = Start-AzAutomationRunbook -Name $RunbookName -Parameters @{ 'jsonRequestBody' = $json } -RunOn $HybridWorkerGroupName -ResourceGroupName $AutomationAccountRGName -AutomationAccountName $AutomationAccountName
      Write-Host "Runbook started with job id: $($res.JobId)"   
    }
    catch {
      Write-Error "Failed to start runbook. $_"
    }

    # wait for the runbook to complete
    $job = Get-AzAutomationJob -Id $res.JobId -ResourceGroupName $AutomationAccountRGName -AutomationAccountName $AutomationAccountName
    while ($job.Status -ne 'Completed' -and $job.Status -ne 'Failed' -and $job.Status -ne 'Suspended') {
      Write-Host "Runbook job status: $($job.Status)"
      Start-Sleep -Seconds 5
      $job = Get-AzAutomationJob -Id $res.JobId -ResourceGroupName $AutomationAccountRGName -AutomationAccountName $AutomationAccountName
    }
    Write-Host "Runbook job status: $($job.Status)"

    # write the output of the runbook
    Write-Host 'Runbook output:'
    Get-AzAutomationJobOutput -Id $job.JobId -ResourceGroupName $AutomationAccountRGName -AutomationAccountName $AutomationAccountName | ForEach-Object {
      if ($_.Summary) {
        Write-Host $_.Summary
      }
    }  
  }

  default {
    Write-Error "Invalid parameter set: $($PSCmdlet.ParameterSetName). Specify one switch: -UseQueue, -UseWebhook, or -UseDirectRunbookInvocation."
  }

}


  

