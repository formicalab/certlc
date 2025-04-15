# Create a certificate request on key vault, retrieve the CSR, send to CA to sign it, merge into key vault
# See https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#creating-a-certificate-with-a-ca-not-partnered-with-key-vault

[CmdletBinding()]
param (
    [Parameter(HelpMessage = "Key Vault Name")]
    [string]$VaultName = "flazkv-shared-neu-001",

    [Parameter(HelpMessage = "Certificate Name")]
    [string]$CertName = "flab-shortwebserver-cert6",

    [Parameter(HelpMessage = "Certificate Subject Name")]
    [string]$SubjectName = "CN=server01.contoso.com",

    [Parameter(HelpMessage = "Certificate DNS Names")]
    [string[]]$DnsNames = @("server01.contoso.com", "server01.litware.com"),

    [Parameter(HelpMessage = "Certificate Authority server")]
    [string]$CAServer = "flazdc03.formicalab.casa",

    [Parameter(HelpMessage = "Certification Authority Template Name")]
    [string]$TemplateName = "Flab-ShortWebServer",

    [Parameter(HelpMessage = "PFX Folder")]
    [string]$PFXFolder = "C:\Temp"
)

# force the script to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

########
# MAIN #
########

# Check if the script is running on Azure or on hybrid worker
$envVars = Get-ChildItem env:
$HybridWorker = ($envVars | Where-Object { $_.name -like 'Fabric_*' } ).count -eq 0
if (-not $HybridWorker) {
    Write-Error "This workbook must be executed by a hybrid worker!"
    return
}

$worker = $env:COMPUTERNAME
Write-Output "Script started at $(Get-Date), running on $worker"
Write-Output "Using the following parameters:"
Write-Output "VaultName: $VaultName"
Write-Output "CertName: $CertName"
Write-Output "SubjectName: $SubjectName"
Write-Output "DnsNames: $($DnsNames -join ', ')"
Write-Output "CAServer: $CAServer"
Write-Output "TemplateName: $TemplateName"
Write-Output ""

# see if Az module is installed
Write-Output "Checking if Az module is installed..."
if (-not (Get-InstalledModule -Name Az)) {
    Write-Error "Az module not installed!"
    return
}

# see if PSPKI module is installed
Write-Output "Checking if PSPKI module is installed..."
if (-not (Get-InstalledModule -Name PSPKI)) {
    Write-Error "PSPKI module not installed!"
    return
}

# Connect to azure

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

# import other modules if needed
import-module PSPKI

# get CA details
Write-Output "Getting the CA details for $CAServer..."
$ca = Get-CertificationAuthority -ComputerName $CAServer
if ($null -eq $ca) {
    Write-Error "Error getting CA details: $CAServer not found"
    return
}

# check if there is a deleted certificate with the same name in the key vault
Write-Output "Checking if there is a deleted certificate with the same name in the key vault..."
try {
    $deletedCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -InRemovedState
    if (($null -ne $deletedCert) -and ($null -ne $deletedCert.DeletedDate)) {
        Write-Error "Certificate $CertName is already in the key vault and in deleted state since $($deletedCert.DeletedDate). It must be purged before creating a new one; otherwise specify a different certificate name"
        return
    }  
}
catch {
    Write-Error "Error checking for deleted certificate: $_"
    return
}

# create certificate - if a previous request is in progress, reuse it
$csr = $null
try {
    $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertName | Where-Object { $_.Status -eq "inProgress" }
    if ($null -ne $op) {
        Write-Output "Certificate request is already in progress for this certificate: $CertName; reusing it."
        $csr = $op.CertificateSigningRequest
    }
    else {
        Write-Output "Creating a new CSR for certificate $CertName in key vault $VaultName..."
        $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $SubjectName -IssuerName "Unknown" -DnsName $DnsNames
        $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificatePolicy $Policy
        $csr = $result.CertificateSigningRequest
    }
}
catch {
    Write-Error "Error generating CSR in Key Vault: $_"
    return
}

# Write the CSR content to a temporary file
$csrFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertName.csr"
Set-Content -Path $csrFile -Value $csr
Write-Output "CSR file created: $csrFile"

# Send request to the CA and remove the CSR file
Write-Output "Sending request to the CA..."
$certificateRequest = Submit-CertificateRequest -CA $ca -Path $csrFile -Attribute "CertificateTemplate:$($TemplateName)"
Remove-Item -Path $csrFile -Force -ErrorAction SilentlyContinue
if ($null -eq $certificateRequest) {
    Write-Error "Error sending request to the CA."
    return
}
Write-Output "Retrieving signed certificate from the CA..."
$certificate = $certificateRequest.Certificate
if ($null -eq $certificate) {
    Write-Error "Error getting certificate from the CA."
    return
}

# write the returned signed certificate to a temporary file
$certFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertName.p7b"
try {
    Export-Certificate -Cert $certificate -FilePath $certFile -Type P7B | Out-Null    
}
catch {
    Write-Error "Error exporting certificate to file: $_"
    return
}
Write-Output "Certificate file created: $certFile"

# use certutil -encode to convert the certificate to base64 - this is required to import a p7b file into the key vault
# (https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#formats-of-merge-csr-we-support)
Write-Output "Converting the certificate to base64..."
$certFileBase64 = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertName.b64"
$process = Start-Process -FilePath "certutil.exe" -ArgumentList "-encode", $certFile, $certFileBase64 -NoNewWindow -Wait -PassThru
Remove-Item -Path $certFile -Force -ErrorAction SilentlyContinue
if ($process.ExitCode -ne 0) {
    Write-Error "certutil.exe failed with exit code $($process.ExitCode)"
    return
}

# import the certificate into the key vault
Write-Output "Importing the certificate $CertName into the key vault $VaultName..."
try {
    $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -FilePath $certFileBase64 
}
catch {
    Write-Error "Error importing certificate into the key vault: $_"
    return
}
finally {
    Remove-Item -Path $certFileBase64 -Force -ErrorAction SilentlyContinue
}
Write-Output "Certificate imported into the key vault."

# if required, download the certificate to a local file in the pfx folder
if ($null -ne $pfxFolder) {

    # get the password for the PFX file from the key vault
    try {
 
        $CertPassword = (Get-AzKeyVaultSecret -VaultName $VaultName -Name "CertPassword").SecretValueText
    }
    catch {
        Write-Error "Failed to retrieve certificate password from Key Vault: $_"
        return
    }

    # create the folder if it does not exist
    if (-not (Test-Path -Path $pfxFolder)) {
        Write-Output "Creating the PFX folder: $pfxFolder"
        New-Item -Path $pfxFolder -ItemType Directory -Force | Out-Null
    }

    # download the certificate to a local file in the pfx folder
    $pfxFile = Join-Path -Path $pfxFolder -ChildPath "$($CertName).pfx"
    Write-Output "Exporting the $CertName certificate to PFX file: $pfxFile"
    try {
        $CertBase64 = Get-AzKeyVaultSecret -VaultName $vaultName -Name $CertName -AsPlainText
        $CertBytes = [Convert]::FromBase64String($CertBase64)
        $x509Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($certBytes, $null, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $pfxFileByte = $x509Cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPassword)
        [IO.File]::WriteAllBytes($pfxFile, $pfxFileByte)
    }
    catch {
        Write-Error "Error exporting certificate to PFX: $_"
        return
    }
}

Write-Host "All done - $(Get-Date)"