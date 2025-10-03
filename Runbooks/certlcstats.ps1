#Requires -PSEdition Core
using module Az.Accounts
using module Az.KeyVault

################
# CERTLCSTATS  #
################

# CERTLCSTATS is a PowerShell runbook that populates certificate statistics from an Azure Key Vault into a Log Analytics workspace.
# It is part of the CertLC (Certificate Lifecycle) solution

# The script is designed to be run using PowerShell 7.x
# Initially based on certlc solution https://learn.microsoft.com/en-us/azure/architecture/example-scenario/certificate-lifecycle/

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $keyVaultName,
        
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $streamName,
        
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $immutableId,  # Data Collection Rule immutable ID (GUID)

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ingestionUrl,

    [Parameter(Mandatory = $false)]
    [object] $WebhookData
)

# Prohibits references to uninitialized variables (Latest enforces more checks than 1.0)
Set-StrictMode -Version Latest

# Ensure the script stops on errors so that try/catch can be used to handle them
$ErrorActionPreference = 'Stop'

####################
# GLOBAL VARIABLES #
####################

$statusThresholdDays = 30   # days before expiration to mark as 'Expiring Soon'

########
# MAIN #
########

# Connect to Azure. Ensures we do not inherit an AzContext, since we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
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

# Fetch all certificates from the Key Vault
Write-Output "Fetching certificates from Key Vault $keyVaultName..."
# Wrap in array literal so a single returned object is still treated as a collection (avoids null Count edge case)
$certificates = @(Get-AzKeyVaultCertificate -VaultName $keyVaultName)
$certCount = $certificates.Count
if (-not $certificates -or $certCount -eq 0) {
    Write-Output "No certificates found in Key Vault $keyVaultName. Exiting."
    return
}
Write-Output "Found $certCount certificate(s)."

# Prepare output
$utcNow = [DateTime]::UtcNow
$results = foreach ($certMeta in $certificates) {

    # Fetch full details (required for X.509 Subject / Extensions)
    $certDetails = Get-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certMeta.Name

    # Safety check: skip if no Certificate property (should not happen in practice)
    if (-not $certDetails.Certificate) {
        Write-Output "Skipping $($certMeta.Name): no Certificate property.";
        continue
    }

    # Status calculation using UTC
    $expires = $certDetails.Expires
    $status = if ($expires -lt $utcNow) { 'Expired' } elseif ($expires -lt $utcNow.AddDays($statusThresholdDays)) { 'Expiring Soon' } else { 'OK' }

    # Extract DNS names (SAN) safely each iteration
    $CertificateDnsNames = $null
    $san = $certDetails.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
    if ($san) {
        $CertificateDnsNames = ($san.Format(0) -replace 'DNS Name=', '').Split(',').ForEach({ $_.Trim() }) | Where-Object { $_ }
    }

    [PSCustomObject]@{
        Thumbprint = $certDetails.Certificate.Thumbprint
        Name       = $certMeta.Name
        Status     = $status
        Created    = $certDetails.Created.ToString('o')     # ISO 8601 format required by Azure Monitor
        Expires    = $expires.ToString('o')                 # ISO 8601 format required by Azure Monitor
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