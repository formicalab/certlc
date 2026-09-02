<#
.SYNOPSIS
  Directly enroll a certificate and export a SID-protected PFX containing the leaf and intermediate CA certificates.

.DESCRIPTION
  Creates or reuses a pending Azure Key Vault certificate request, submits the CSR to an
  Active Directory Certificate Services CA, retrieves the complete chain as PKCS#7, and
  merges that response into Key Vault. The resulting PKCS#12 secret is loaded as a
  certificate collection and exported as a SID-protected PFX after removing the
  self-issued root certificate.

  This utility intentionally bypasses Storage Queues, Azure Functions, and Azure
  Automation. It requires an existing authenticated Az context and direct connectivity
  to both Key Vault and the enterprise CA.

.PARAMETER VaultName
  Name of the Azure Key Vault in which the certificate and private key are created.

.PARAMETER CertName
  Name of the Key Vault certificate and output PFX base name.

.PARAMETER CertificateTemplate
    Internal AD CS certificate template name (CN), not the display name.

.PARAMETER CA
  AD CS configuration string in ServerName\CAName format.

.PARAMETER Subject
  X.500 subject name for the certificate.

.PARAMETER CertificateDnsNames
  Optional DNS subject alternative names.

.PARAMETER Hostname
    Hostname of the server where the certificate will be used. Stored in the Key Vault certificate tags.

.PARAMETER PfxProtectTo
  Domain users or groups allowed to decrypt the PFX, such as DOMAIN\User.

.PARAMETER PfxPath
  Output PFX path. Defaults to .\<CertName>.pfx.

.PARAMETER Force
  Replace an existing output PFX.

.EXAMPLE
  .\testnewcertchain.ps1 `
    -VaultName 'flazkv-certlc-itn-001' `
    -CertName 'cert001' `
    -CertificateTemplate 'FlabShortWebServer' `
    -CA 'ca01.lab.local\Lab Issuing CA' `
    -PfxProtectTo @('lab\marcello') `
    -Subject 'CN=www.example.com' `
    -CertificateDnsNames @('www.example.com') `
    -Hostname 'webserver01' `
    -PfxPath '.\cert001.pfx' `
    -Verbose

.NOTES
  Prerequisites:
    - Windows PowerShell Core with Az.Accounts and Az.KeyVault installed.
    - An authenticated Az context with certificate and secret permissions on the vault.
    - DCOM/RPC connectivity and enrollment permission to the specified enterprise CA.
    - Domain connectivity sufficient to resolve every PfxProtectTo principal to a SID.
#>

#Requires -PSEdition Core
#Requires -Modules Az.Accounts, Az.KeyVault

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9-]{3,24}$')]
    [string] $VaultName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9-]+$')]
    [string] $CertName,

    [Parameter(Mandatory)]
    [ValidatePattern('^\S+$')]
    [string] $CertificateTemplate,

    [Parameter(Mandatory)]
    [ValidatePattern('^[^\\]+\\[^\\]+$')]
    [string] $CA,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Subject,

    [Parameter()]
    [string[]] $CertificateDnsNames,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Hostname,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]] $PfxProtectTo,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $PfxPath,

    [Parameter()]
    [switch] $Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

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

function Get-CaRequestDiagnostic {
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [object] $CertificateRequest
    )

    $requestId = try { $CertificateRequest.GetRequestId() } catch { 'unavailable' }
    $dispositionMessage = try { $CertificateRequest.GetDispositionMessage() } catch { 'unavailable' }
    $lastStatus = try { $CertificateRequest.GetLastStatus() } catch { $null }
    $statusText = if ($null -eq $lastStatus) {
        'unavailable'
    }
    else {
        '0x{0:X8}' -f ([uint32] ([int64] $lastStatus -band 0xFFFFFFFFL))
    }

    "Request ID: $requestId; CA message: $dispositionMessage; last status: $statusText"
}

function ConvertFrom-Base64Pkcs7 {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2Collection])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Content
    )

    $base64 = $Content -replace '(?m)^-----[^\r\n]+-----\s*$', '' -replace '\s', ''
    try {
        $bytes = [Convert]::FromBase64String($base64)
    }
    catch {
        throw "The CA chain response is not valid Base64 PKCS#7: $($_.Exception.Message)"
    }

    $collection = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    try {
        $collection.Import($bytes)
    }
    catch {
        throw "The CA chain response could not be decoded as PKCS#7: $($_.Exception.Message)"
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }

    Write-Output -NoEnumerate $collection
}

function Get-OrderedCertificateChain {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection] $Certificates,

        [Parameter(Mandatory)]
        [ValidateSet('CaResponse', 'KeyVaultSecret')]
        [string] $Source,

        [Parameter()]
        [switch] $ExcludeRoot
    )

    $leafCandidates = @(if ($Source -eq 'KeyVaultSecret') {
        $Certificates | Where-Object HasPrivateKey
    }
    else {
        $Certificates | Where-Object {
            $basicConstraints = $_.Extensions |
                Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } |
                Select-Object -First 1
            $null -eq $basicConstraints -or -not $basicConstraints.CertificateAuthority
        }
    })
    if ($leafCandidates.Count -ne 1) {
        throw "Expected exactly one leaf certificate in $Source; found $($leafCandidates.Count)."
    }

    $remaining = [Collections.Generic.List[Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    foreach ($certificate in $Certificates) {
        if ($certificate.Thumbprint -cne $leafCandidates[0].Thumbprint) {
            $remaining.Add($certificate)
        }
    }

    $ordered = [Collections.Generic.List[Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    $current = $leafCandidates[0]
    while ($null -ne $current) {
        $ordered.Add($current)
        if (Test-DistinguishedNameEqual -Left $current.SubjectName -Right $current.IssuerName) {
            break
        }

        $issuers = @($remaining | Where-Object {
            Test-DistinguishedNameEqual -Left $_.SubjectName -Right $current.IssuerName
        })
        if ($issuers.Count -ne 1) {
            throw "Expected one issuer for '$($current.Subject)' in $Source; found $($issuers.Count)."
        }

        $current = $issuers[0]
        $null = $remaining.Remove($current)
    }

    if ($remaining.Count -gt 0) {
        throw "$Source contains $($remaining.Count) certificate(s) outside the leaf's issuer chain."
    }
    if (-not (Test-DistinguishedNameEqual -Left $ordered[$ordered.Count - 1].SubjectName -Right $ordered[$ordered.Count - 1].IssuerName)) {
        throw "$Source does not terminate in a self-issued root certificate."
    }

    if ($ExcludeRoot) {
        $ordered.RemoveAt($ordered.Count - 1)
        if ($ordered.Count -lt 2) {
            throw "$Source contains no intermediate CA certificate after the root is excluded."
        }
    }

    $ordered.ToArray()
}

function Assert-CertificateSet {
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $Expected,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection] $Actual,

        [Parameter(Mandatory)]
        [string] $Context
    )

    $expectedThumbprints = @($Expected.Thumbprint | Sort-Object -Unique)
    $actualThumbprints = @($Actual.Thumbprint | Sort-Object -Unique)
    $missing = @($expectedThumbprints | Where-Object { $_ -notin $actualThumbprints })
    $unexpected = @($actualThumbprints | Where-Object { $_ -notin $expectedThumbprints })
    if ($Expected.Count -ne $Actual.Count -or $missing.Count -gt 0 -or $unexpected.Count -gt 0) {
        throw "$Context certificate mismatch. Expected $($Expected.Count), found $($Actual.Count). Missing: $($missing -join ', '); unexpected: $($unexpected -join ', ')."
    }
}

function Assert-CertificateChain {
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $Certificates
    )

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.DisableCertificateDownloads = $true
        $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $null = $chain.ChainPolicy.CustomTrustStore.Add($Certificates[-1])
        if ($Certificates.Count -gt 2) {
            foreach ($certificate in $Certificates[1..($Certificates.Count - 2)]) {
                $null = $chain.ChainPolicy.ExtraStore.Add($certificate)
            }
        }
        if (-not $chain.Build($Certificates[0])) {
            $status = ($chain.ChainStatus.StatusInformation | ForEach-Object { $_.Trim() }) -join '; '
            throw "AD CS returned an invalid certificate chain: $status"
        }
    }
    finally {
        $chain.Dispose()
    }
}

function Merge-KeyVaultCertificateChain {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $VaultName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CertificateName,

        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2[]] $Certificates,

        [Parameter(Mandatory)]
        [Security.SecureString] $Token
    )

    $x5c = @($Certificates | ForEach-Object {
        [Convert]::ToBase64String($_.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    })
    $body = @{ x5c = $x5c } | ConvertTo-Json -Depth 3 -Compress
    $escapedCertificateName = [Uri]::EscapeDataString($CertificateName)
    $uri = "https://$VaultName.vault.azure.net/certificates/$escapedCertificateName/pending/merge?api-version=2025-07-01"
    Write-Verbose "Submitting $($x5c.Count) explicitly encoded certificates to the Key Vault pending merge API."
    Invoke-RestMethod `
        -Uri $uri `
        -Method Post `
        -Authentication Bearer `
        -Token $Token `
        -ContentType 'application/json' `
        -Body $body
}

function Get-KeyVaultCertificateSecretValue {
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $VaultName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $SecretId,

        [Parameter(Mandatory)]
        [Security.SecureString] $Token
    )

    $secretUri = [Uri] $SecretId
    $expectedHost = "$VaultName.vault.azure.net"
    if (-not $secretUri.IsAbsoluteUri -or $secretUri.Scheme -ine 'https' -or $secretUri.Host -ine $expectedHost) {
        throw "Key Vault merge returned an unexpected secret ID '$SecretId'. Expected an HTTPS URL on '$expectedHost'."
    }

    $uri = "$($secretUri.AbsoluteUri.TrimEnd('/'))?api-version=2025-07-01"
    $secret = Invoke-RestMethod `
        -Uri $uri `
        -Method Get `
        -Authentication Bearer `
        -Token $Token `
        -ContentType 'application/json'

    if ($secret.contentType -ine 'application/x-pkcs12') {
        throw "The merged Key Vault secret has unexpected content type '$($secret.contentType)'; expected 'application/x-pkcs12'."
    }
    if ([string]::IsNullOrWhiteSpace($secret.value)) {
        throw "Key Vault returned an empty value for versioned secret '$SecretId'."
    }

    [string] $secret.value
}

function Export-SidProtectedPfx {
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $Certificates,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ProtectionRule,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath
    )

    if (-not ('CertLCChainNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class CertLCChainNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Blob
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptCreateProtectionDescriptor(
        string descriptor, uint flags, out IntPtr descriptorHandle);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptCloseProtectionDescriptor(IntPtr descriptorHandle);

    [DllImport("crypt32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr CertOpenStore(
        string storeProvider, uint encoding, IntPtr cryptProvider,
        uint flags, IntPtr parameters);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CertAddCertificateContextToStore(
        IntPtr store, IntPtr certificate, uint disposition, IntPtr outputContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CertCloseStore(IntPtr store, uint flags);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool PFXExportCertStoreEx(
        IntPtr store, ref Blob pfx, string password, IntPtr parameters, uint flags);
}
'@
    }

    $descriptorHandle = [IntPtr]::Zero
    $store = [IntPtr]::Zero
    $descriptorPointer = [IntPtr]::Zero
    $blob = [CertLCChainNative+Blob]::new()
    $pfxBytes = $null
    $passwordBytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(40)
    $password = [Convert]::ToBase64String($passwordBytes)
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)

    try {
        $result = [CertLCChainNative]::NCryptCreateProtectionDescriptor($ProtectionRule, 0, [ref] $descriptorHandle)
        if ($result -ne 0) {
            throw 'NCryptCreateProtectionDescriptor failed: 0x{0:X8}' -f $result
        }

        $store = [CertLCChainNative]::CertOpenStore('Memory', 0, [IntPtr]::Zero, 0x2000, [IntPtr]::Zero)
        if ($store -eq [IntPtr]::Zero) {
            throw 'CertOpenStore failed: 0x{0:X8}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }

        foreach ($certificate in $Certificates) {
            if (-not [CertLCChainNative]::CertAddCertificateContextToStore($store, $certificate.Handle, 3, [IntPtr]::Zero)) {
                throw "CertAddCertificateContextToStore failed for '$($certificate.Subject)': 0x$('{0:X8}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
        }

        $descriptorPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($descriptorPointer, $descriptorHandle)
        $flags = 0x0004 -bor 0x0010 -bor 0x0020

        if (-not [CertLCChainNative]::PFXExportCertStoreEx($store, [ref] $blob, $password, $descriptorPointer, $flags)) {
            throw 'PFX size query failed: 0x{0:X8}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }

        $blob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($blob.cbData)
        if (-not [CertLCChainNative]::PFXExportCertStoreEx($store, [ref] $blob, $password, $descriptorPointer, $flags)) {
            throw 'PFX export failed: 0x{0:X8}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }

        $pfxBytes = [byte[]]::new($blob.cbData)
        [Runtime.InteropServices.Marshal]::Copy($blob.pbData, $pfxBytes, 0, $blob.cbData)
        [IO.File]::WriteAllBytes($OutputPath, $pfxBytes)
    }
    finally {
        $password = $null
        if ($null -ne $pfxBytes) {
            [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
        }
        if ($blob.pbData -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($blob.pbData)
        }
        if ($descriptorPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($descriptorPointer)
        }
        if ($store -ne [IntPtr]::Zero) {
            [CertLCChainNative]::CertCloseStore($store, 0) | Out-Null
        }
        if ($descriptorHandle -ne [IntPtr]::Zero) {
            [CertLCChainNative]::NCryptCloseProtectionDescriptor($descriptorHandle) | Out-Null
        }
    }
}

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    throw 'No authenticated Az context exists. Run Connect-AzAccount and select the intended subscription before invoking this utility.'
}
$keyVaultToken = (Get-AzAccessToken -ResourceTypeName KeyVault -AsSecureString).Token

$effectiveDnsNames = @($CertificateDnsNames |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Select-Object -Unique)

$Hostname = $Hostname.Trim().ToLowerInvariant()
if ($Hostname -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253})$') {
    throw "Hostname '$Hostname' is not valid."
}

$normalizedPfxProtectTo = [Collections.Generic.List[string]]::new()
$seenPrincipals = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($rawPrincipal in $PfxProtectTo) {
    if ([string]::IsNullOrWhiteSpace($rawPrincipal)) {
        throw 'PfxProtectTo cannot contain an empty principal.'
    }

    $principal = $rawPrincipal.Trim() -replace '\\{2,}', '\'
    if ($seenPrincipals.Add($principal)) {
        $normalizedPfxProtectTo.Add($principal)
    }
}

$protectionSids = foreach ($principal in $normalizedPfxProtectTo) {
    try {
        ([Security.Principal.NTAccount] $principal).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "Could not resolve PfxProtectTo principal '$principal' to a SID: $($_.Exception.Message)"
    }
}
$protectionSids = @($protectionSids | Sort-Object -Unique)
$protectionRule = ($protectionSids | ForEach-Object { "SID=$_" }) -join ' OR '

if (-not $PfxPath) {
    $PfxPath = Join-Path (Get-Location) "$CertName.pfx"
}
$resolvedPfxPath = [IO.Path]::GetFullPath($PfxPath)
$outputDirectory = [IO.Path]::GetDirectoryName($resolvedPfxPath)
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}
if ((Test-Path -LiteralPath $resolvedPfxPath) -and -not $Force) {
    throw "Output PFX '$resolvedPfxPath' already exists. Use -Force to replace it."
}

$tags = @{
    CertificateTemplateName = $CertificateTemplate
    Hostname                = $Hostname
    PfxProtectTo            = $normalizedPfxProtectTo -join ';'
}

$operation = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertName -ErrorAction SilentlyContinue
if ($null -ne $operation -and $operation.Status -eq 'inProgress') {
    Write-Verbose "Reusing the in-progress Key Vault CSR for '$CertName'."
    $csr = $operation.CertificateSigningRequest
}
else {
    Write-Verbose "Creating a Key Vault CSR for '$CertName'."
    $policyParameters = @{
        SecretContentType = 'application/x-pkcs12'
        SubjectName       = $Subject
        IssuerName        = 'Unknown'
    }
    if ($effectiveDnsNames.Count -gt 0) {
        $policyParameters.DnsName = $effectiveDnsNames
    }
    $policy = New-AzKeyVaultCertificatePolicy @policyParameters
    $request = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificatePolicy $policy -Tag $tags
    $csr = $request.CertificateSigningRequest
}
if ([string]::IsNullOrWhiteSpace($csr)) {
    throw "Key Vault returned an empty CSR for certificate '$CertName'."
}

$certificateRequest = $null
$pkcs7Response = $null
try {
    Write-Verbose "Submitting the CSR to '$CA' with template '$CertificateTemplate'."
    $certificateRequest = New-Object -ComObject CertificateAuthority.Request
    $disposition = $certificateRequest.Submit(0x1, $csr, "CertificateTemplate:$CertificateTemplate", $CA)
    $caDiagnostic = Get-CaRequestDiagnostic -CertificateRequest $certificateRequest

    switch ($disposition) {
        2 { throw "The CA '$CA' denied the certificate request. $caDiagnostic" }
        3 {
            # CR_OUT_BASE64HEADER | CR_OUT_CHAIN. The chain response is PKCS#7.
            $pkcs7Response = $certificateRequest.GetCertificate(0x100)
        }
        5 { throw "The CA '$CA' left the request pending; this utility requires immediate issuance. $caDiagnostic" }
        default { throw "The CA '$CA' returned disposition $disposition instead of issuing the certificate. $caDiagnostic" }
    }
}
finally {
    if ($null -ne $certificateRequest) {
        [void] [Runtime.InteropServices.Marshal]::ReleaseComObject($certificateRequest)
    }
}

$caResponseCertificates = ConvertFrom-Base64Pkcs7 -Content $pkcs7Response
try {
    if ($caResponseCertificates.Count -lt 2) {
        throw "AD CS returned PKCS#7 containing only $($caResponseCertificates.Count) certificate(s); CR_OUT_CHAIN did not provide an issuer chain."
    }
    $caChain = Get-OrderedCertificateChain -Certificates $caResponseCertificates -Source CaResponse
    Assert-CertificateChain -Certificates $caChain
}
catch {
    foreach ($certificate in $caResponseCertificates) {
        $certificate.Dispose()
    }
    throw
}
Write-Verbose "AD CS PKCS#7 physically contains $($caChain.Count) certificates in a complete leaf-to-root chain."
foreach ($certificate in $caChain) {
    Write-Verbose "CA response member: $($certificate.Subject) (issuer: $($certificate.Issuer))"
}

$certificateBytes = $null
$keyVaultCertificates = $null
$exportedSubjects = @()
$temporaryPfxPath = Join-Path $outputDirectory ".$([IO.Path]::GetFileName($resolvedPfxPath)).$([guid]::NewGuid().ToString('N')).tmp"
try {
    Write-Verbose "Merging the explicit certificate chain into pending Key Vault certificate '$CertName'."
    $mergedCertificate = Merge-KeyVaultCertificateChain `
        -VaultName $VaultName `
        -CertificateName $CertName `
        -Certificates $caChain `
        -Token $keyVaultToken
    if ($null -eq $mergedCertificate -or
        [string]::IsNullOrWhiteSpace($mergedCertificate.id) -or
        [string]::IsNullOrWhiteSpace($mergedCertificate.sid)) {
        throw 'The Key Vault pending merge API returned no certificate bundle.'
    }

    $certificateUri = [Uri] $mergedCertificate.id
    if (-not $certificateUri.IsAbsoluteUri -or
        $certificateUri.Scheme -ine 'https' -or
        $certificateUri.Host -ine "$VaultName.vault.azure.net") {
        throw "Key Vault merge returned an unexpected certificate ID '$($mergedCertificate.id)'."
    }

    $certificatePath = $certificateUri.AbsolutePath.Trim('/').Split('/')
    if ($certificatePath.Count -ne 3 -or
        $certificatePath[0] -ine 'certificates' -or
        [Uri]::UnescapeDataString($certificatePath[1]) -cne $CertName -or
        [string]::IsNullOrWhiteSpace($certificatePath[2])) {
        throw "Key Vault merge returned an unexpected certificate ID '$($mergedCertificate.id)'."
    }

    $mergedTags = @{}
    $mergedTagProperty = $mergedCertificate.PSObject.Properties['tags']
    if ($null -ne $mergedTagProperty -and $null -ne $mergedTagProperty.Value) {
        foreach ($property in $mergedTagProperty.Value.PSObject.Properties) {
            $mergedTags[$property.Name] = [string] $property.Value
        }
    }
    foreach ($tag in $tags.GetEnumerator()) {
        $mergedTags[$tag.Key] = $tag.Value
    }

    $taggedCertificate = Update-AzKeyVaultCertificate `
        -VaultName $VaultName `
        -Name $CertName `
        -Version $certificatePath[2] `
        -Tag $mergedTags `
        -PassThru
    foreach ($tag in $tags.GetEnumerator()) {
        $actualTagValue = if ($null -eq $taggedCertificate.Tags) { $null } else { [string] $taggedCertificate.Tags[$tag.Key] }
        if ($actualTagValue -cne [string] $tag.Value) {
            throw "Key Vault certificate version '$($certificatePath[2])' is missing mandatory tag '$($tag.Key)'."
        }
    }
    Write-Verbose "Verified mandatory tags on Key Vault certificate version '$($certificatePath[2])'."

    Write-Verbose "Retrieving the exact merged PKCS#12 secret version '$($mergedCertificate.sid)'."
    $secretBase64 = Get-KeyVaultCertificateSecretValue `
        -VaultName $VaultName `
        -SecretId $mergedCertificate.sid `
        -Token $keyVaultToken

    $certificateBytes = [Convert]::FromBase64String($secretBase64)
    $secretBase64 = $null
    $keyVaultCertificates = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $importFlags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
        [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet

    $keyVaultCertificates.Import(
        $certificateBytes,
        [string]::Empty,
        $importFlags
    )

    Assert-CertificateSet -Expected $caChain -Actual $keyVaultCertificates -Context 'Key Vault persistence'
    Write-Verbose "Verified the Key Vault PKCS#12 secret physically contains all $($keyVaultCertificates.Count) submitted chain certificates."

    $exportChain = Get-OrderedCertificateChain -Certificates $keyVaultCertificates -Source KeyVaultSecret -ExcludeRoot
    $exportedSubjects = @($exportChain | ForEach-Object { $_.Subject })
    Write-Verbose "Exporting $($exportChain.Count) certificates solely from the Key Vault PKCS#12 secret after excluding the root."
    foreach ($certificate in $exportChain) {
        Write-Verbose "PFX member: $($certificate.Subject) (issuer: $($certificate.Issuer), private key: $($certificate.HasPrivateKey))"
    }

    Export-SidProtectedPfx -Certificates $exportChain -ProtectionRule $protectionRule -OutputPath $temporaryPfxPath

    $verificationCertificates = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    try {
        $verificationCertificates.Import(
            $temporaryPfxPath,
            [string]::Empty,
            $importFlags
        )
        Assert-CertificateSet -Expected $exportChain -Actual $verificationCertificates -Context 'Exported PFX'
        Write-Verbose "Verified the exported PFX physically contains all $($verificationCertificates.Count) expected certificates."
    }
    finally {
        foreach ($certificate in $verificationCertificates) {
            $certificate.Dispose()
        }
    }
    [IO.File]::Move($temporaryPfxPath, $resolvedPfxPath, [bool] $Force)
}
finally {
    Remove-Item -LiteralPath $temporaryPfxPath -Force -ErrorAction SilentlyContinue
    if ($null -ne $certificateBytes) {
        [Array]::Clear($certificateBytes, 0, $certificateBytes.Length)
    }
    if ($null -ne $keyVaultCertificates) {
        foreach ($certificate in $keyVaultCertificates) {
            $certificate.Dispose()
        }
    }
    foreach ($certificate in $caResponseCertificates) {
        $certificate.Dispose()
    }
}

Write-Host "PFX created: $resolvedPfxPath" -ForegroundColor Green
Write-Host 'Included certificates (root excluded):'
foreach ($exportedSubject in $exportedSubjects) {
    Write-Host "  $exportedSubject"
}