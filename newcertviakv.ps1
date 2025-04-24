# Create a certificate request on key vault, retrieve the CSR, send to CA to sign it, merge into key vault
# See https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#creating-a-certificate-with-a-ca-not-partnered-with-key-vault

param
(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData   # the WebhookData is documented here: https://learn.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal
)

# force the runbook to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

###################
# STATIC SETTINGS #
###################

$PFXFolder = "C:\Temp"                  # folder where the PFX file will be downloaded
$CAServer = "flazdc03.formicalab.casa"  # CA server name
$VaultName = "flazkv-shared-neu-001"    # Key Vault name
$IngestionUrl = "https://dce-certlc-itn-001-ws3i.italynorth-1.ingest.monitor.azure.com"
$DcrImmutableId = "dcr-0af8254b18bf4c06a6d2952f9f040938"
$Table = "certlc_CL"  # the name of the custom log table, including "_CL" suffix

####################
# GLOBAL VARIABLES #
####################

$Progress = 0                                   # progress of the script
$LAToken = $null                                # token using to send logs to Log Analytics
$CorrelationId = [guid]::NewGuid().ToString()   # correlation ID for the log entry

#############
# FUNCTIONS #
#############

# logger: send log to Log Analytics workspace (if token is available) and to output
function Write-Log {
    param (
        [Parameter()]
        [string]$Description,
        [Parameter()]
        [string]$Level = "Information"
    )

    # send log to Log Analytics workspace (if token is available)
    if ($null -ne $LAToken) {
        $log_entry = @{
            CorrelationId = $CorrelationId
            Status        = $Level
            Progress      = $Progress
            Description   = $Description
        }
        $body = $log_entry | ConvertTo-Json -Depth 10
        # put the json body into an array [] - PowerShell 5.1 does support the -AsArray switch for ConvertTo-Json
        $body = "[$body]"
        $headers = @{"Authorization" = "Bearer $LAToken"; "Content-Type" = "application/json" };
        $uri = "$IngestionUrl/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table" + "?api-version=2023-01-01";
        Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers | Out-Null
    }

    # write to output
    if ($Level -eq "Error") {
        Write-Error "$(get-date): $($Level): [$(('{0:D3}' -f $Progress))] $Description"
    } elseif ($Level -eq "Warning") {
        Write-Warning "$(get-date): $($Level): [$(('{0:D3}' -f $Progress))] $Description"
    } else {
        Write-Output "$(get-date): $($Level): [$(('{0:D3}' -f $Progress))] $Description"
    }
}

########
# MAIN #
########

# Check if the script is running on Azure or on hybrid worker
Write-Log "Script started, checking worker..."
$envVars = Get-ChildItem env:
$HybridWorker = ($envVars | Where-Object { $_.name -like 'Fabric_*' } ).count -eq 0
if (-not $HybridWorker) {
    Write-Log "This workbook must be executed by a hybrid worker!" -Level "Error"
    return
}
$worker = $env:COMPUTERNAME
Write-Log "Running on $worker"
$Progress++

# see if Az module is installed
Write-Log "Checking if Az module is installed..."
if (-not (Get-InstalledModule -Name Az)) {
    Write-Log "Az module not installed!" -Level "Error"
    return
}
$Progress++

# Connect to azure

# Ensures you do not inherit an AzContext, snce we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
Write-Log "Connecting to Azure using default identity..."
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    Write-Log "There is no system-assigned user identity." -Level "Error"
    return
}
$Progress++

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection

# get a token for the ingestion endpoint
Write-Log "Getting token for ingestion endpoint..."
$secureToken = (Get-AzAccessToken -ResourceUrl "https://monitor.azure.com//.default"-AsSecureString ).Token
$LAToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))
$Progress++

# see if PSPKI module is installed
Write-Log "Check if PSPKI module is installed..."
if (-not (Get-InstalledModule -Name PSPKI)) {
    Write-Log "PSPKI module not installed!" -Level "Error"
    return
}
import-module PSPKI
$Progress++

# Parse the webhook data
if ($null -eq $WebhookData)
{
    Write-Log "Webhook data missing! Ensure the runbook is called from a webhook!" -Level "Error"
    return
}

try {
    $payload = ConvertFrom-Json -InputObject $WebhookData.RequestBody
} catch {
    Write-Log "Failed to parse webhook data as JSON. Error: $_" -Level "Error"
    return
}

if ($null -eq $payload)
{
    Write-Log "Webhook data is not valid JSON!" -Level "Error"
    return
}

$CertificateName = $payload.certificatename
$SubjectName = $payload.subjectname
$TemplateName = $payload.templatename
$DnsNames = $payload.dnsnames

if ([string]::IsNullOrWhiteSpace($CertificateName)) {
    Write-Log "Missing or empty mandatory parameter: 'certificatename'" -Level "Error"
    return
}
if ([string]::IsNullOrWhiteSpace($SubjectName)) {
    Write-Log "Missing or empty mandatory parameter: 'subjectname'" -Level "Error"
    return
}
if ([string]::IsNullOrWhiteSpace($TemplateName)) {
    Write-Log "Missing or empty mandatory parameter: 'templatename'" -Level "Error"
    return
}
# Validate DNSNames is an array of strings (if provided)
if ($DnsNames -and -not ($DnsNames -is [System.Collections.IEnumerable])) {
    Write-Log"'dnsnames' must be an array, if provided." -Level "Error"
    return
}

# write the parameters to the log
Write-Log "VaultName: $VaultName"
Write-Log "CAServer: $CAServer"
Write-Log "CertificateName: $CertificateName"
Write-Log "SubjectName: $SubjectName"
Write-Log "DnsNames: $($DnsNames -join ', ')"
Write-Log "TemplateName: $TemplateName"

$Progress++

# get CA details
Write-Log "Getting the CA details for $CAServer..."
$ca = Get-CertificationAuthority -ComputerName $CAServer
if ($null -eq $ca) {
    Write-Log "Error getting CA details: $CAServer not found" -Level "Error"
    return
}
$Progress++

# check if the template exists in AD
Write-Log "Checking if the template $TemplateName exists in AD..."
$tmpl = Get-CertificateTemplate -Name $TemplateName -ErrorAction SilentlyContinue
if ($null -eq $tmpl) {
    Write-Log "Template $($TemplateName) not found!" -Level "Error"
    return
}
$Progress++

# check if there is a deleted certificate with the same name in the key vault
Write-Log "Checking if there is a deleted certificate with the same name in the key vault..."
try {
    $deletedCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -InRemovedState
    if (($null -ne $deletedCert) -and ($null -ne $deletedCert.DeletedDate)) {
        Write-Log "Certificate $CertificateName is already in the key vault and in deleted state since $($deletedCert.DeletedDate). It must be purged before creating a new one; otherwise specify a different certificate name" -Level "Error"
        return
    }  
}
catch {
    Write-Log "Error checking for deleted certificate: $_" -Level "Error"
    return
}
$Progress++

# create certificate - if a previous request is in progress, reuse it
$csr = $null
try {
    $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertificateName | Where-Object { $_.Status -eq "inProgress" }
    if ($null -ne $op) {
        Write-Log "Certificate request is already in progress for this certificate: $CertificateName; reusing it." -Level "Warning"
        $csr = $op.CertificateSigningRequest
    }
    else {
        Write-Log "Creating a new CSR for certificate $CertificateName in key vault $VaultName..."
        $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $SubjectName -IssuerName "Unknown" -DnsName $DnsNames
        $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -CertificatePolicy $Policy
        $csr = $result.CertificateSigningRequest
    }
}
catch {
    Write-Log "Error generating CSR in Key Vault: $_" -Level "Error"
    return
}
$Progress++

# Write the CSR content to a temporary file
$csrFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertificateName.csr"
Set-Content -Path $csrFile -Value $csr
Write-Log "CSR file created: $csrFile"
$Progress++

# Send request to the CA and remove the CSR file
Write-Log "Sending request to the CA..."
try {
    $certificateRequest = Submit-CertificateRequest -CA $ca -Path $csrFile -Attribute "CertificateTemplate:$($TemplateName)"    
}
catch {
    Write-Log "Error sending request to the CA: $_" -Level "Error"
    return
}
finally {
    # remove the CSR file
    Remove-Item -Path $csrFile -Force -ErrorAction SilentlyContinue
}
if ($null -eq $certificateRequest) {
    Write-Log "Error sending request to the CA: empty response returned!" -Level "Error"
    return
}
$certificate = $certificateRequest.Certificate
if ($null -eq $certificate) {
    Write-Log "Error getting certificate from the CA: no X.509 certificate returned!" -Level "Error"
    return
}
$Progress++

# write the returned signed certificate to a temporary file
Write-Log "Exporting the signed certificate to a temporary file..."
$certFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertificateName.p7b"
try {
    Export-Certificate -Cert $certificate -FilePath $certFile -Type P7B | Out-Null    
}
catch {
    Write-Log "Error exporting certificate to file: $_" -Level "Error"
    return
}
Write-Log "Certificate file created: $certFile"
$Progress++

# use certutil -encode to convert the certificate to base64 - this is required to import a p7b file into the key vault
# (https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#formats-of-merge-csr-we-support)
Write-Log "Converting the certificate to base64..."
$certFileBase64 = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertificateName.b64"
$process = Start-Process -FilePath "certutil.exe" -ArgumentList "-encode", $certFile, $certFileBase64 -NoNewWindow -Wait -PassThru
Remove-Item -Path $certFile -Force -ErrorAction SilentlyContinue
if ($process.ExitCode -ne 0) {
    Write-Log "certutil.exe failed with exit code $($process.ExitCode)" -Level "Error"
    return
}
$Progress++

# import the certificate into the key vault
Write-Log "Importing the certificate $CertificateName into the key vault $VaultName..."
try {
    $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -FilePath $certFileBase64 
}
catch {
    Write-Log "Error importing certificate into the key vault: $_" -Level "Error"
    return
}
finally {
    Remove-Item -Path $certFileBase64 -Force -ErrorAction SilentlyContinue
}
Write-Log "Certificate imported into the key vault."
$Progress++

# if required, download the certificate to a local file in the pfx folder
if ($null -ne $pfxFolder) {

    # get the password for the PFX file from the key vault
    Write-Log "Retrieving the certificate password from Key Vault..."
    try {
        $CertPassword = (Get-AzKeyVaultSecret -VaultName $VaultName -Name "CertPassword").SecretValueText
    }
    catch {
        Write-Log "Failed to retrieve certificate password from Key Vault: $_" -Level "Error"
        return
    }
    $Progress++

    # create the folder if it does not exist
    if (-not (Test-Path -Path $pfxFolder)) {
        Write-Log "Creating the PFX folder: $pfxFolder"
        New-Item -Path $pfxFolder -ItemType Directory -Force | Out-Null
    }
    Write-Log "PFX folder verified: $pfxFolder"
    $Progress++

    # download the certificate to a local file in the pfx folder
    $pfxFile = Join-Path -Path $pfxFolder -ChildPath "$($CertificateName).pfx"
    Write-Log "Exporting the $CertificateName certificate to PFX file: $pfxFile"
    try {
        $CertBase64 = Get-AzKeyVaultSecret -VaultName $vaultName -Name $CertificateName -AsPlainText
        $CertBytes = [Convert]::FromBase64String($CertBase64)
        $x509Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($certBytes, $null, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $pfxFileByte = $x509Cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPassword)
        [IO.File]::WriteAllBytes($pfxFile, $pfxFileByte)
    }
    catch {
        Write-Log "Error exporting certificate to PFX: $_" -Level "Error"
        return
    }
    Write-Log "Certificate exported to PFX file: $pfxFile"
    $Progress++
}

$Progress = 100
Write-Log "All done"