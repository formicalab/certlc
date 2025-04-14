$ErrorActionPreference = "stop"

# ================================
# Parameters
# ================================
$CertTemplate       	= "Flab-ShortWebServer"
$CertSubject        	= "CN=server01.contoso.com"
$CertDNS 		= "server01.contoso.com"
$CertFriendlyName   	= "Flab Web Server Cert"
$KeyExportable      	= $true
$CA 			= "formicalab.casa\SubCA"
$password 		= "Password.123"

# Azure Key Vault Parameters
$KeyVaultName       = "flazkv-shared-neu-001"
$SecretName         = "flab-shortwebserver-cert"
$AzureResourceGroup = "rg-shared-neu-001"
$AzureLocation      = "northeurope"

# ================================
# 1. Request Certificate using Certeq
# ================================

write-Host "Request Certificate using certreq..."

$INFFile = "C:\temp\cert_request.inf"
$RequestFile = "C:\temp\cert_request.req"
$ResponseFile = "C:\temp\cert_response.cer"

# Build INF Request
$CertRequest = @"
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "$CertSubject"   ; For a wildcard use "CN=*.CONTOSO.COM" for example
; For an empty subject use the following line instead or remove the Subject line entierely
; Subject =
Exportable = $KeyExportable
KeyLength = 2048                    ; Common key sizes: 512, 1024, 2048, 4096, 8192, 16384
KeySpec = 1                         ; AT_KEYEXCHANGE
KeyUsage = 0xA0                     ; Digital Signature, Key Encipherment
MachineKeySet = True                ; The key belongs to the local computer account
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = CMC

; SAN

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$CertDNS"

[RequestAttributes]
CertificateTemplate= $CertTemplate
"@

# Write the updated INF request file
Set-Content -Path $INFFile -Value $CertRequest

# Compile the request
Start-Process -Wait -NoNewWindow -FilePath "certreq.exe" -ArgumentList " -new", $INFFile, $RequestFile

# Request the certificate
write-host "sending request with certreq..."
Start-Process -Wait -NoNewWindow -FilePath "certreq.exe" -ArgumentList " -submit $RequestFile $ResponseFile"

# Wait for certificate request to complete
Start-Sleep -Seconds 5

# ================================
# 2. Install the Certificate
# ================================
write-host "Installing the certificate..."
$Cert = Get-Content -Path $ResponseFile | Out-String
$Cert | Set-Content -Path "C:\temp\cert_installer.cer"
Import-Certificate -FilePath "C:\temp\cert_installer.cer" -CertStoreLocation "Cert:\LocalMachine\My"

# ================================
# 3. Export the Certificate to PFX
# ================================
write-host "Exporting the certificate to pfx..."
$Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" |
        Where-Object { $_.Subject -eq "$CertSubject" } |
        Sort-Object NotBefore -Descending |
        Select-Object -First 1

# Set Friendly Name
$Cert.FriendlyName = $CertFriendlyName

# Export the certificate as a PFX file
$pfxPath = "C:\temp\cert.pfx"
$pfxPassword = ConvertTo-SecureString -String $password -Force -AsPlainText
Export-PfxCertificate -Cert $Cert -FilePath $pfxPath -Password $pfxPassword


# ================================
# 4. Upload to Azure Key Vault
# ================================

write-host "Upload to key vault..."

if (-not (Get-Module -ListAvailable -Name Az)) {
    Install-Module -Name Az -Scope CurrentUser -Force
}
Import-Module Az

if (-not (Get-AzContext)) {
    Connect-AzAccount
}

$secret = Import-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $SecretName -FilePath $pfxPath -Password $pfxPassword -verbose

Write-Host "✅ Certificate uploaded to Azure Key Vault as '$SecretName'"
