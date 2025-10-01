<#
.SYNOPSIS
  Extract certificate (.cer) and private key (.key) from a PFX file.

.DESCRIPTION
  Loads a PFX and exports:
    - A PEM encoded certificate (.cer)
    - A PKCS#8 private key (.key), optionally encrypted (ENCRYPTED PRIVATE KEY)

  Supports RSA and ECDSA keys. Provides safety checks, optional overwrite control,
  optional private key encryption

.PARAMETER PfxPath
  Path to the PFX file (must exist).

.PARAMETER Password
  (Optional) Password for the PFX (SecureString). If omitted assumes no password / DPAPI.

.PARAMETER OutDirectory
  (Optional) Destination directory for outputs; defaults to the PFX directory.

.PARAMETER Overwrite
  Overwrite existing output files if they already exist.

.PARAMETER PrivateKeyPassword
  (Optional) SecureString password with which to encrypt the PKCS#8 private key.
  If provided, output file will be an 'ENCRYPTED PRIVATE KEY' PEM.

.PARAMETER PbeIterations
  Iteration count for password-based encryption (default 100_000). Ignored if not encrypting.

.EXAMPLE
  ./Extract-KeyCer.ps1 -PfxPath server.pfx -Overwrite

.EXAMPLE
  ./Extract-KeyCer.ps1 -PfxPath server.pfx -PrivateKeyPassword (Read-Host -AsSecureString 'Key pw')

.NOTES
  Ensure you understand the security implications of exporting an unencrypted private key.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $PfxPath,

    [Parameter()]
    [Security.SecureString] $Password,

    [Parameter()]
    [string] $OutDirectory,

    [Parameter()]
    [switch] $Overwrite,

    [Parameter()]
    [Security.SecureString] $PrivateKeyPassword,

    [Parameter()]
    [ValidateRange(1, 10000000)]
    [int] $PbeIterations = 100000
)

#Requires -PSEdition Core
Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

function Convert-SecureStringToPlain {
    param([Security.SecureString]$Secure)
    if (-not $Secure) { return $null }
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) } }
}

if (-not (Test-Path -Path $PfxPath -PathType Leaf)) {
    throw "PFX path '$PfxPath' not found."
}

if (-not $OutDirectory) { $OutDirectory = [IO.Path]::GetDirectoryName((Resolve-Path -Path $PfxPath)) }
if (-not (Test-Path -Path $OutDirectory)) { New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null }

$baseName = [IO.Path]::GetFileNameWithoutExtension($PfxPath)
$certPath = Join-Path $OutDirectory ($baseName + '.cer')
$keyPath  = Join-Path $OutDirectory ($baseName + '.key')

if (-not $Overwrite) {
    foreach ($f in @($certPath, $keyPath)) {
        if (Test-Path $f) { throw "Output file '$f' already exists. Use -Overwrite to replace." }
    }
}

$plainPfxPassword = Convert-SecureStringToPlain -Secure $Password

# Load PFX
try {
    $storageFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    $pfx = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $plainPfxPassword, $storageFlags)
}
catch {
    throw "Failed to load PFX '$PfxPath': $($_.Exception.Message)"
}
finally {
    if ($plainPfxPassword) { [Array]::Clear([char[]]$plainPfxPassword, 0, $plainPfxPassword.Length) }
}

if (-not $pfx.HasPrivateKey) { throw 'The PFX does not contain a private key.' }

# Determine key algorithm (RSA or ECDSA) using explicit extension classes (instance call failed in this environment)
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfx)
$ecdsa = if (-not $rsa) { [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($pfx) } else { $null }
if (-not ($rsa -or $ecdsa)) {
    throw 'Unsupported private key algorithm (only RSA and ECDSA supported).'
}

# Export certificate (Base64 wrap 64 chars)
$certDer = $pfx.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$certB64 = [Convert]::ToBase64String($certDer)
$certWrapped = ($certB64 -split '(.{1,64})' | Where-Object { $_ }) -join "`n"
$certPem = "-----BEGIN CERTIFICATE-----`n$certWrapped`n-----END CERTIFICATE-----`n"
Set-Content -Path $certPath -Value $certPem -Encoding ascii -NoNewline

# Export private key (PKCS#8, optionally encrypted)
$encrypt = $PrivateKeyPassword -ne $null
$plainKeyPassword = if ($encrypt) { Convert-SecureStringToPlain -Secure $PrivateKeyPassword } else { $null }

try {
    if ($encrypt -and [string]::IsNullOrEmpty($plainKeyPassword)) { throw 'PrivateKeyPassword provided is empty.' }

    if ($rsa) {
        # .NET exposes ExportPkcs8PrivateKey and ExportEncryptedPkcs8PrivateKey via extension methods
        if ($encrypt) {
            $pbe = [System.Security.Cryptography.PbeParameters]::new([System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $PbeIterations)
            $keyBytes = $rsa.ExportEncryptedPkcs8PrivateKey($plainKeyPassword, $pbe)
            $header = 'ENCRYPTED PRIVATE KEY'
        }
        else {
            $keyBytes = $rsa.ExportPkcs8PrivateKey()
            $header = 'PRIVATE KEY'
        }
    }
    else { # ECDSA
        if ($encrypt) {
            $pbe = [System.Security.Cryptography.PbeParameters]::new([System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $PbeIterations)
            $keyBytes = $ecdsa.ExportEncryptedPkcs8PrivateKey($plainKeyPassword, $pbe)
            $header = 'ENCRYPTED PRIVATE KEY'
        }
        else {
            $keyBytes = $ecdsa.ExportPkcs8PrivateKey()
            $header = 'PRIVATE KEY'
        }
    }
}
catch {
    throw "Failed to export private key: $($_.Exception.Message)"
}
finally {
    if ($plainKeyPassword) { [Array]::Clear([char[]]$plainKeyPassword, 0, $plainKeyPassword.Length) }
}

$keyB64 = [Convert]::ToBase64String($keyBytes)
$keyWrapped = ($keyB64 -split '(.{1,64})' | Where-Object { $_ }) -join "`n"
$keyPem = "-----BEGIN $header-----`n$keyWrapped`n-----END $header-----`n"
Set-Content -Path $keyPath -Value $keyPem -Encoding ascii -NoNewline

## (ACL hardening removed per request; private key may retain default file permissions)


Write-Host "Export complete:" -ForegroundColor Green
Write-Host "  Certificate: $certPath"
Write-Host "  Private Key: $keyPath" + $(if ($encrypt) { ' (encrypted)' } else { '' })

# Cleanup disposable objects
if ($rsa) { $rsa.Dispose() }
if ($ecdsa) { $ecdsa.Dispose() }
