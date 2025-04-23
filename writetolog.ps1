# test log ingestion

# force the runbook to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

############
# SETTINGS #
############

$ingestionUrl = "https://dce-certlc-itn-001-ws3i.italynorth-1.ingest.monitor.azure.com"
$DcrImmutableId = "dcr-40e21e19fe5e46a4b57cdf34a7fcb383"
$table = "certlc_CL"  # the name of the custom log table, including "_CL" suffix
$clientId = "7ffb1a85-7351-4b58-911d-3c8f1cf03546"
$tenantId = "2b41bfe4-ee81-4fc6-ae54-f9e48fefb244"
$secret = "ld98Q~3XP1BqgeCfVEwkYN28yKVVTbxl8iU5SbkE"   # TODO: move to key vault instead of hardcoding it

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

# obtain a token for scope https://monitor.azure.com//.default" using the specific client id
$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
$body = "client_id=$clientId&scope=$scope&client_secret=$secret&grant_type=client_credentials";
$headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$token = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token

$log_entry = @{
    # Define the structure of log entry, as it will be sent
    Status      = "Information"
    Progress    = 20
    Description = "This is a test log entry."
}

$body = $log_entry | ConvertTo-Json -Depth 10
# put the json body into an array [] - PowerShell 5.1 does support the -AsArray switch for ConvertTo-Json
$body ="[$body]"

$headers = @{"Authorization" = "Bearer $Token"; "Content-Type" = "application/json" };
$uri = "$ingestionUrl/dataCollectionRules/$DcrImmutableId/streams/Custom-$table" + "?api-version=2023-01-01";
Write-Output "Sending log entry to $uri..."

$uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers

Write-Output "Response: $uploadResponse"