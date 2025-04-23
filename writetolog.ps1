# test log ingestion

# force the runbook to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

############
# SETTINGS #
############

$ingestionUrl = "https://dce-certlc-itn-001-ws3i.italynorth-1.ingest.monitor.azure.com"
$DcrImmutableId = "dcr-0af8254b18bf4c06a6d2952f9f040938"
$table = "certlc_CL"  # the name of the custom log table, including "_CL" suffix

# Ensures you do not inherit an AzContext, snce we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
Write-output "Connecting to Azure using default identity..."
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    Write-Error "There is no system-assigned user identity. Aborting." 
    return
}

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection

# get a token for the ingestion endpoint
$secureToken = (Get-AzAccessToken -ResourceUrl "https://monitor.azure.com//.default"-AsSecureString ).Token
$token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))

$log_entry = @{
    # Define the structure of log entry, as it will be sent
    CorrelationId = [guid]::NewGuid().ToString()
    Status      = "Information"
    Progress    = 20
    Description = "This is a test log entry."
}

$body = $log_entry | ConvertTo-Json -Depth 10
# put the json body into an array [] - PowerShell 5.1 does support the -AsArray switch for ConvertTo-Json
$body ="[$body]"

$headers = @{"Authorization" = "Bearer $Token"; "Content-Type" = "application/json" };
$uri = "$ingestionUrl/dataCollectionRules/$DcrImmutableId/streams/Custom-$table" + "?api-version=2023-01-01";
Write-Output "Sending log entry..."

try {
    Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers
    Write-Output "Log entry sent successfully."
}
catch {

    # code required with old powershell 5.1, to obtain the response body from the exception
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Error $responseBody
}
