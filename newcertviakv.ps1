[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage = "Certificate Subject Name")]
    [string]$SubjectName = "CN=server01.contoso.com",
    [Parameter(Mandatory = $false, HelpMessage = "Certificate DNS Names")]
    [string[]]$DnsNames = @("server01.contoso.com","server01.litware.com"),
    [Parameter(Mandatory = $false, HelpMessage = "Certificate Template Name")]
    [string]$TemplateName = "Flab-ShortWebServer"
)
    
# create a certificate request on key vault, retrieve the CSR, send to CA to sign it, merge into key vault
# see https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#creating-a-certificate-with-a-ca-not-partnered-with-key-vault

# force the script to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

##############
# PARAMETERS #
############## 

$VaultName = "flazkv-shared-neu-001" # name of the Key Vault
$ObjectName = "flab-shortwebserver-cert4" # name of the certificate object in Key Vault
$certificationAuthority = "flazdc03.formicalab.casa" # CA server to send the request to

# see if Az module is installed
Write-Output "Checking if Az module is installed..."
if (-not (Get-InstalledModule -Name Az)) {
    Write-Error "Az module not installed!"
    exit 1
}

# see if PSPKI module is installed
Write-Output "Checking if PSPKI module is installed..."
if (-not (Get-InstalledModule -Name PSPKI)) {
    Write-Error "PSPKI module not installed!"
    exit 1
}

# login to Azure if not already logged in
if (-not (Get-AzContext)) {
    Write-Host "Logging in to Azure..."
    Connect-AzAccount -Identity
}

# get CA details
Write-Output "Getting the CA details for $certificationAuthority..."
$ca = Get-CertificationAuthority -ComputerName $certificationAuthority
if ($null -eq $ca) {
    Write-Error "Error getting CA details: $certificationAuthority not found"
    exit 1
}

# create certificate - if a previous request is in progress, reuse it
$op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $ObjectName | Where-Object { $_.Status -eq "inProgress" }
if ($null -ne $op) {
    Write-Output "Certificate request is already in progress for this certificate: $ObjectName; reusing it."
    $csr = $op.CertificateSigningRequest
}
else {
    try {
        Write-Output "Creating a new certificate in KV..."
        $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $SubjectName -IssuerName "Unknown" -DnsName $DnsNames
        $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $ObjectName -CertificatePolicy $Policy
        $csr = $result.CertificateSigningRequest
    }
    catch {
        Write-Error "Error generating CSR in Key Vault: $_"
        exit 1
    }
}

# Write the CSR content to a temporary file
$csrFile = [System.IO.Path]::GetTempFileName()
$csrFile = [System.IO.Path]::ChangeExtension($csrFile, ".csr")
Set-Content -Path $csrFile -Value $csr
Write-Output "CSR file created: $csrFile"

# Send request to the CA
Write-Output "Sending request to the CA..."
$certificateRequest = Submit-CertificateRequest -CA $ca -Path $csrFile -Attribute "CertificateTemplate:$($TemplateName)"
if ($null -eq $certificateRequest) {
    Write-Error "Error sending request to the CA."
    exit 1
}
Write-Output "Retrieving signed certificate from the CA..."
$certificate = $certificateRequest.Certificate
if ($null -eq $certificate) {
    Write-Error "Error getting certificate from the CA."
    exit 1
}

# write the returned signed certificate to a temporary file
$certFile = [System.IO.Path]::GetTempFileName()
$certFile = [System.IO.Path]::ChangeExtension($certFile, ".p7b")
Export-Certificate -Cert $certificate -FilePath $certFile -Type P7B
Write-Output "Certificate file created: $certFile"

# use certutil -encode to convert the certificate to base64 - this is required to import a p7b file into the key vault
# (https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#formats-of-merge-csr-we-support)
Write-Output "Converting the certificate to base64..."
$certFileBase64 = [System.IO.Path]::ChangeExtension($certFile, ".b64")
Start-Process -FilePath "certutil.exe" -ArgumentList "-encode", $certFile, $certFileBase64 -NoNewWindow -Wait

# import the certificate into the key vault
Write-Output "Importing the certificate into the key vault..."
try {
    $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $ObjectName -FilePath $certFileBase64 
}
catch {
    Write-Error "Error importing certificate into the key vault: $_"
    exit 1
}
Write-Output "Certificate imported into the key vault: $($newCert.Name)"

# cleanup temporary files
Remove-Item -Path $csrFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $certFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $certFileBase64 -Force -ErrorAction SilentlyContinue
Write-Output "Temporary files deleted."