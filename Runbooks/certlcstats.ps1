#Requires -PSEdition Core
using module Az.Accounts
using module Az.KeyVault

################
# CERTLCSTATS  #
################

<#

CERTLCSTATS is a PowerShell runbook that populates certificate statistics from an Azure Key Vault into a Log Analytics workspace.
It is part of the CertLC (Certificate Lifecycle) solution

The script is designed to be run using PowerShell 7.x
Initially based on certlc solution https://learn.microsoft.com/en-us/azure/architecture/example-scenario/certificate-lifecycle/

#>

param(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData
)

<# Strict mode settings 3.0:
Prohibits references to uninitialized variables. This includes uninitialized variables in strings.
Prohibits references to non-existent properties of an object.
Prohibits function calls that use the syntax for calling methods.
Prohibit out of bounds or unresolvable array indexes.
#>
Set-StrictMode -Version 3.0

# Ensure the script stops on errors so that try/catch can be used to handle them
$ErrorActionPreference = 'Stop'

####################
# GLOBAL VARIABLES #
####################


########
# MAIN #
########

# Connect to Azure using the Automation Account's identity.
# Ensures we do not inherit an AzContext, since we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process
Write-Output 'Connecting to Azure using default identity...'
try {
    $AzureConnection = (Connect-AzAccount -Identity).Context
}
catch {
    Write-Output 'Error connecting to Azure using default identity, check if it is enabled.'
    throw
}

# set context
Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection | Out-Null

# Check if the script is running on Azure or on hybrid worker; assign jobId accordingly.
# https://rakhesh.com/azure/azure-automation-powershell-variables/
if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation/') {
    # We are in a Hybrid Runbook Worker
    $jobId = $env:PSPrivateMetadata
    Write-Output "Runbook running with job id $jobId on hybrid worker $($env:COMPUTERNAME)."
}
elseif ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
    # We are in Azure Automation. This is not acceptable because we need a hybrid worker to access the Key Vault with a Private Endpoint
    $jobId = $PSPrivateMetadata.JobId
    Write-Output "Runbook running with job id $jobId in Azure Automation. This is not supported, please use a Hybrid Runbook Worker to access the Key Vault with a Private Endpoint."
    throw
}

# Get the runbook variables from the Automation Account
# Since they are encrypted, we must use the internal cmdlet Get-AutomationVariable to retrieve them, not Get-AzAutomationVariable

$KeyVaultName = $null
$StreamName = $null
$ImmutableId = $null
$IngestionUrl = $null

Write-Output 'Retrieving runbook variables...'

try {
    $KeyVaultName = Get-AutomationVariable -Name 'certlc-stats-keyvault'   # Name of the Key Vault to monitor
    $StreamName = Get-AutomationVariable -Name 'certlc-stats-streamname'   # Name of the stream in the DCR
    $ImmutableId = Get-AutomationVariable -Name 'certlc-stats-immutableid' # Immutable ID of the Data Collection Rule
    $IngestionUrl = Get-AutomationVariable -Name 'certlc-stats-ingestionurl' # Ingestion endpoint URL of the Log Analytics workspace
}
catch {
    Write-Output "Error retrieving runbook variables, ensure that the following variables are set: certlc-stats-keyvault, certlc-stats-streamname, certlc-stats-immutableid, certlc-stats-ingestionurl"
    throw
}

if (-not $KeyVaultName -or -not $StreamName -or -not $ImmutableId -or -not $IngestionUrl) {
    Write-Output 'One or more required runbook variables are empty, please check the runbook variable settings.'
    throw
}

# Fetch all certificates from the Key Vault
Write-Output "Fetching certificates from Key Vault $KeyVaultName..."
# Wrap in array literal so a single returned object is still treated as a collection (avoids null Count edge case)
$certificates = @(Get-AzKeyVaultCertificate -VaultName $KeyVaultName)
$certCount = $certificates.Count
if (-not $certificates -or $certCount -eq 0) {
    Write-Output "No certificates found in Key Vault $KeyVaultName. Exiting."
    return
}
Write-Output "Found $certCount certificate(s)."

# Prepare output
$results = foreach ($certMeta in $certificates) {

    # Fetch full details (required for X.509 Subject / Extensions)
    $certDetails = Get-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certMeta.Name

    # Safety check: skip if no Certificate property (should not happen in practice)
    if (-not $certDetails.Certificate) {
        Write-Output "Skipping $($certMeta.Name): no Certificate property.";
        continue
    }

    # Extract DNS names (SAN) safely each iteration
    $CertificateDnsNames = $null
    $san = $certDetails.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
    if ($san) {
        $CertificateDnsNames = ($san.Format(0) -replace 'DNS Name=', '').Split(',').ForEach({ $_.Trim() }) | Where-Object { $_ }
    }

    [PSCustomObject]@{
        Thumbprint = $certDetails.Certificate.Thumbprint
        Name       = $certMeta.Name
        Created    = $certDetails.Created.ToString('o')     # ISO 8601 format required by Azure Monitor
        Expires    = $certDetails.Expires.ToString('o')     # ISO 8601 format required by Azure Monitor
        Subject    = $certDetails.Certificate.Subject
        Template   = $certDetails.Tags['CertificateTemplateName']
        DNSNames   = if ($CertificateDnsNames) { $CertificateDnsNames -join ', ' } else { 'N/A' }
    }
}

# get a token for the ingestion endpoint
Write-Output 'Getting access token for ingestion endpoint...'
# Use SecureString retrieval for compatibility with newer Az versions returning SecureString only
try {
    $accessTokenResponse = Get-AzAccessToken -ResourceUrl 'https://monitor.azure.com/.default' -AsSecureString
    $rawToken = $accessTokenResponse.Token
    if ($rawToken -is [System.Security.SecureString]) {
        $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($rawToken)
        )
    }
    else {
        # Some module versions may still return plain text
        $token = [string]$rawToken
    }
}
catch {
    Write-Output "Failed to obtain access token: $($_.Exception.Message)"
    throw
}
if (-not $token) {
    Write-Output 'Access token retrieval returned empty result.'
    throw
}

$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
$uri = ($ingestionUrl.TrimEnd('/')) + "/dataCollectionRules/$($immutableId)/streams/$($streamName)?api-version=2023-01-01"

# send all certificates in one go - they are very small so we should stay well within limits (~1MB)
$body = $results | ConvertTo-Json -Depth 10 -AsArray
$bytes = [Text.Encoding]::UTF8.GetByteCount($body)

# safety check for size. In any case we don't block sending, just warn and hope for the best
Write-Output "Sending all $certCount certificates; payload size will be ~${bytes} bytes):"
if ($bytes -gt 900000) {
    Write-Output "WARNING: Payload size $bytes bytes may exceed limit! Consider deleting old, expired certificates from the Key Vault or implementing chunking in the ingestion script."
}

# Write-Output $body    # enable for debug only

$maxAttempts = 3
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        $statusCode = 0
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers -TimeoutSec 60 -StatusCodeVariable statusCode
        Write-Output "All items ingested (attempt $attempt), status code $statusCode."
        break
    }
    catch {
        if ($attempt -eq $maxAttempts) {
            Write-Output "All items ingestion failed after $attempt attempts: $($_.Exception.Message)"
            throw
        }
        $delay = [Math]::Pow(2, $attempt)   # Exponential backoff: 2, 4, 8...
        Write-Output "All items ingestion attempt $attempt failed with status code $($statusCode): $($_.Exception.Message). Retrying in $delay s..."
        Start-Sleep -Seconds $delay
    }
}