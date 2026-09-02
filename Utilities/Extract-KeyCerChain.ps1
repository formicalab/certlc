<#
.SYNOPSIS
  Extract all certificates and the leaf private key from a PFX file.

.DESCRIPTION
  Loads every certificate embedded in a PFX and exports:
    - One PEM-encoded .cer file per certificate.
    - A leaf-to-root full-chain PEM bundle.
    - The private key associated with the leaf certificate, optionally encrypted.

  Supports RSA and ECDSA private keys. Supports password-protected PFX files and
  PFX files protected to Active Directory SIDs with DPAPI.

.PARAMETER PfxPath
  Path to the PFX file.

.PARAMETER Password
  Optional PFX password. Omit for an unprotected PFX or a PFX protected to SIDs.

.PARAMETER OutDirectory
  Destination directory. Defaults to the PFX directory.

.PARAMETER Overwrite
  Overwrite existing output files.

.PARAMETER PrivateKeyPassword
  Optional password used to encrypt the exported PKCS#8 private key.

.PARAMETER PbeIterations
  Iteration count for private-key password-based encryption. Defaults to 100,000.

.EXAMPLE
  ./Extract-KeyCerChain.ps1 -PfxPath server.pfx -Overwrite

.EXAMPLE
  ./Extract-KeyCerChain.ps1 -PfxPath server.pfx -PrivateKeyPassword (Read-Host -AsSecureString 'Key password')
#>

#Requires -PSEdition Core

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

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Convert-SecureStringToPlain {
    [OutputType([string])]
    param (
        [Parameter()]
        [Security.SecureString] $Secure
    )

    if (-not $Secure) { return $null }

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function Convert-CertificateToPem {
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $der = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $base64 = [Convert]::ToBase64String($der)
    $wrapped = ($base64 -split '(.{1,64})' | Where-Object { $_ }) -join "`n"
    "-----BEGIN CERTIFICATE-----`n$wrapped`n-----END CERTIFICATE-----`n"
}

function Test-DistinguishedNameEqual {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName] $Left,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName] $Right
    )

    [Convert]::ToBase64String($Left.RawData) -ceq [Convert]::ToBase64String($Right.RawData)
}

if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
    throw "PFX path '$PfxPath' not found."
}

$resolvedPfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
if (-not $OutDirectory) {
    $OutDirectory = [IO.Path]::GetDirectoryName($resolvedPfxPath)
}

if (-not (Test-Path -LiteralPath $OutDirectory)) {
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
}
$resolvedOutDirectory = (Resolve-Path -LiteralPath $OutDirectory).Path
$baseName = [IO.Path]::GetFileNameWithoutExtension($resolvedPfxPath)

$certificates = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
$plainPfxPassword = Convert-SecureStringToPlain -Secure $Password
try {
    $storageFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    $certificates.Import($resolvedPfxPath, $plainPfxPassword, $storageFlags)
}
catch {
    throw "Failed to load PFX '$resolvedPfxPath': $($_.Exception.Message)"
}
finally {
    $plainPfxPassword = $null
}

try {
    if ($certificates.Count -eq 0) {
        throw 'The PFX does not contain any certificates.'
    }

    $privateKeyCertificates = @($certificates | Where-Object { $_.HasPrivateKey })
    if ($privateKeyCertificates.Count -eq 0) {
        throw 'The PFX does not contain a certificate with a private key.'
    }
    if ($privateKeyCertificates.Count -gt 1) {
        throw "The PFX contains $($privateKeyCertificates.Count) certificates with private keys; the leaf certificate is ambiguous."
    }
    $leafCertificate = $privateKeyCertificates[0]

    $remainingCertificates = [Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    foreach ($certificate in $certificates) {
        if ($certificate.Thumbprint -cne $leafCertificate.Thumbprint) {
            $remainingCertificates.Add($certificate)
        }
    }

    $orderedChain = [Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    $currentCertificate = $leafCertificate
    while ($null -ne $currentCertificate) {
        $orderedChain.Add($currentCertificate)

        if (Test-DistinguishedNameEqual -Left $currentCertificate.SubjectName -Right $currentCertificate.IssuerName) {
            break
        }

        $parents = @($remainingCertificates | Where-Object {
            Test-DistinguishedNameEqual -Left $_.SubjectName -Right $currentCertificate.IssuerName
        })
        if ($parents.Count -eq 0) {
            break
        }
        if ($parents.Count -gt 1) {
            throw "Multiple possible issuers were found for certificate '$($currentCertificate.Subject)'."
        }

        $currentCertificate = $parents[0]
        $null = $remainingCertificates.Remove($currentCertificate)
    }

    $outputs = [Collections.Generic.List[object]]::new()
    $fullChainBuilder = [Text.StringBuilder]::new()
    $intermediateIndex = 0

    for ($index = 0; $index -lt $orderedChain.Count; $index++) {
        $certificate = $orderedChain[$index]
        $certificatePem = Convert-CertificateToPem -Certificate $certificate
        $null = $fullChainBuilder.Append($certificatePem)

        if ($index -eq 0) {
            $role = 'leaf'
        }
        elseif (Test-DistinguishedNameEqual -Left $certificate.SubjectName -Right $certificate.IssuerName) {
            $role = 'root'
        }
        else {
            $intermediateIndex++
            $role = 'intermediate-{0:D2}' -f $intermediateIndex
        }

        $outputs.Add([pscustomobject]@{
            Path        = Join-Path $resolvedOutDirectory "$baseName-$role.cer"
            Content     = $certificatePem
            Description = "Certificate ($role)"
        })
    }

    $additionalIndex = 0
    foreach ($certificate in @($remainingCertificates | Sort-Object Thumbprint)) {
        $additionalIndex++
        $shortThumbprint = $certificate.Thumbprint.Substring(0, [Math]::Min(12, $certificate.Thumbprint.Length))
        $outputs.Add([pscustomobject]@{
            Path        = Join-Path $resolvedOutDirectory ("$baseName-additional-{0:D2}-$shortThumbprint.cer" -f $additionalIndex)
            Content     = Convert-CertificateToPem -Certificate $certificate
            Description = 'Additional certificate'
        })
    }

    $outputs.Add([pscustomobject]@{
        Path        = Join-Path $resolvedOutDirectory "$baseName-fullchain.pem"
        Content     = $fullChainBuilder.ToString()
        Description = 'Full-chain bundle'
    })

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($leafCertificate)
    $ecdsa = if (-not $rsa) {
        [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($leafCertificate)
    }
    else {
        $null
    }

    try {
        if (-not ($rsa -or $ecdsa)) {
            throw 'Unsupported private key algorithm. Only RSA and ECDSA are supported.'
        }

        $encryptPrivateKey = $null -ne $PrivateKeyPassword
        $plainKeyPassword = if ($encryptPrivateKey) {
            Convert-SecureStringToPlain -Secure $PrivateKeyPassword
        }
        else {
            $null
        }

        try {
            if ($encryptPrivateKey -and [string]::IsNullOrEmpty($plainKeyPassword)) {
                throw 'PrivateKeyPassword was provided but is empty.'
            }

            $privateKey = if ($rsa) { $rsa } else { $ecdsa }
            if ($encryptPrivateKey) {
                $pbe = [System.Security.Cryptography.PbeParameters]::new(
                    [System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    $PbeIterations
                )
                $keyBytes = $privateKey.ExportEncryptedPkcs8PrivateKey($plainKeyPassword, $pbe)
                $keyHeader = 'ENCRYPTED PRIVATE KEY'
            }
            else {
                $keyBytes = $privateKey.ExportPkcs8PrivateKey()
                $keyHeader = 'PRIVATE KEY'
            }
        }
        finally {
            $plainKeyPassword = $null
        }

        $keyBase64 = [Convert]::ToBase64String($keyBytes)
        $keyWrapped = ($keyBase64 -split '(.{1,64})' | Where-Object { $_ }) -join "`n"
        $keyPem = "-----BEGIN $keyHeader-----`n$keyWrapped`n-----END $keyHeader-----`n"
        [Array]::Clear($keyBytes, 0, $keyBytes.Length)

        $outputs.Add([pscustomobject]@{
            Path        = Join-Path $resolvedOutDirectory "$baseName.key"
            Content     = $keyPem
            Description = if ($encryptPrivateKey) { 'Private key (encrypted)' } else { 'Private key (unencrypted)' }
        })
    }
    finally {
        if ($rsa) { $rsa.Dispose() }
        if ($ecdsa) { $ecdsa.Dispose() }
    }

    if (-not $Overwrite) {
        $existingPaths = @($outputs | Where-Object { Test-Path -LiteralPath $_.Path } | ForEach-Object { $_.Path })
        if ($existingPaths.Count -gt 0) {
            throw "Output file already exists: $($existingPaths -join ', '). Use -Overwrite to replace."
        }
    }

    foreach ($output in $outputs) {
        if ($PSCmdlet.ShouldProcess($output.Path, "Write $($output.Description)")) {
            Set-Content -LiteralPath $output.Path -Value $output.Content -Encoding ascii -NoNewline -Force:$Overwrite
        }
    }

    Write-Host "Exported $($certificates.Count) certificates:" -ForegroundColor Green
    foreach ($output in $outputs) {
        Write-Host "  $($output.Description): $($output.Path)"
    }
}
finally {
    foreach ($certificate in $certificates) {
        $certificate.Dispose()
    }
}