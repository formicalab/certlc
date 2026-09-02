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
  AD CS certificate template name.

.PARAMETER CA
  AD CS configuration string in ServerName\CAName format.

.PARAMETER Subject
  X.500 subject name for the certificate.

.PARAMETER CertificateDnsNames
  Optional DNS subject alternative names.

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
    -CertificateTemplate 'Flab Short WebServer' `
    -CA 'ca01.lab.local\Lab Issuing CA' `
    -PfxProtectTo @('lab\marcello') `
    -Subject 'CN=www.example.com' `
    -CertificateDnsNames @('www.example.com') `
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
    [ValidateNotNullOrEmpty()]
    [string] $VaultName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $CertName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $CertificateTemplate,

    [Parameter(Mandatory)]
    [ValidatePattern('^.+\\.+$')]
    [string] $CA,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Subject,

    [Parameter()]
    [string[]] $CertificateDnsNames,

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

function Get-OrderedCertificateChain {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection] $Certificates
    )

    $privateKeyCertificates = @($Certificates | Where-Object { $_.HasPrivateKey })
    if ($privateKeyCertificates.Count -ne 1) {
        throw "Expected exactly one certificate with a private key in the Key Vault PKCS#12 secret; found $($privateKeyCertificates.Count)."
    }

    $leaf = $privateKeyCertificates[0]
    $remaining = [Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    foreach ($certificate in $Certificates) {
        if ($certificate.Thumbprint -cne $leaf.Thumbprint) {
            $remaining.Add($certificate)
        }
    }

    $chain = [Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    $current = $leaf
    while ($null -ne $current) {
        $chain.Add($current)

        if (Test-DistinguishedNameEqual -Left $current.SubjectName -Right $current.IssuerName) {
            break
        }

        $issuers = @($remaining | Where-Object {
            Test-DistinguishedNameEqual -Left $_.SubjectName -Right $current.IssuerName
        })
        if ($issuers.Count -eq 0) {
            throw "The PKCS#12 chain is incomplete: issuer '$($current.Issuer)' for '$($current.Subject)' is missing."
        }
        if ($issuers.Count -gt 1) {
            throw "The PKCS#12 chain is ambiguous: multiple certificates match issuer '$($current.Issuer)'."
        }

        $current = $issuers[0]
        $null = $remaining.Remove($current)
    }

    if ($remaining.Count -gt 0) {
        throw "The Key Vault PKCS#12 secret contains $($remaining.Count) certificate(s) outside the leaf's issuer chain."
    }

    $lastCertificate = $chain[$chain.Count - 1]
    if (-not (Test-DistinguishedNameEqual -Left $lastCertificate.SubjectName -Right $lastCertificate.IssuerName)) {
        throw 'The returned certificate chain does not terminate in a self-issued root certificate.'
    }

    $chain.RemoveAt($chain.Count - 1)
    if ($chain.Count -lt 2) {
        throw 'After excluding the root, the chain contains no issuing CA certificate. The leaf appears to have been issued directly by the root CA.'
    }

    $chain.ToArray()
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
    $password = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(40))

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

$effectiveDnsNames = @($CertificateDnsNames |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Select-Object -Unique)

$protectionSids = foreach ($principal in $PfxProtectTo) {
    if ([string]::IsNullOrWhiteSpace($principal)) {
        throw 'PfxProtectTo cannot contain an empty principal.'
    }
    try {
        ([Security.Principal.NTAccount] $principal).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "Could not resolve PfxProtectTo principal '$principal' to a SID: $($_.Exception.Message)"
    }
}
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
    PfxProtectTo            = $PfxProtectTo -join ';'
    ChainTestUtility        = 'true'
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

$certificateRequest = $null
$pkcs7Response = $null
try {
    Write-Verbose "Submitting the CSR to '$CA' with template '$CertificateTemplate'."
    $certificateRequest = New-Object -ComObject CertificateAuthority.Request
    $disposition = $certificateRequest.Submit(0x1, $csr, "CertificateTemplate:$CertificateTemplate", $CA)

    switch ($disposition) {
        2 { throw "The CA '$CA' denied the certificate request." }
        3 {
            # CR_OUT_BASE64HEADER | CR_OUT_CHAIN. The chain response is PKCS#7.
            $pkcs7Response = $certificateRequest.GetCertificate(0x100)
        }
        5 { throw "The CA '$CA' left the request pending; this utility requires immediate issuance." }
        default { throw "The CA '$CA' returned unexpected disposition $disposition." }
    }
}
finally {
    if ($null -ne $certificateRequest) {
        [void] [Runtime.InteropServices.Marshal]::ReleaseComObject($certificateRequest)
    }
}

$temporaryPkcs7Path = Join-Path ([IO.Path]::GetTempPath()) "$([guid]::NewGuid().ToString('N')).p7b"
try {
    Set-Content -LiteralPath $temporaryPkcs7Path -Value $pkcs7Response -Encoding ascii
    Write-Verbose "Merging the PKCS#7 certificate chain into Key Vault certificate '$CertName'."
    $mergedCertificate = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -FilePath $temporaryPkcs7Path
    if ($null -eq $mergedCertificate) {
        throw 'Import-AzKeyVaultCertificate returned no certificate after the PKCS#7 merge.'
    }
}
finally {
    Remove-Item -LiteralPath $temporaryPkcs7Path -Force -ErrorAction SilentlyContinue
}

Write-Verbose "Retrieving the merged PKCS#12 secret for '$CertName'."
$secretBase64 = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertName -AsPlainText
if ([string]::IsNullOrWhiteSpace($secretBase64)) {
    throw "Key Vault returned an empty certificate secret for '$CertName'."
}

$certificateBytes = [Convert]::FromBase64String($secretBase64)
$secretBase64 = $null
$certificates = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
$exportedSubjects = @()
try {
    $certificates.Import(
        $certificateBytes,
        [string]::Empty,
        [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    )

    $exportChain = Get-OrderedCertificateChain -Certificates $certificates
    $exportedSubjects = @($exportChain | ForEach-Object { $_.Subject })
    Write-Verbose "The merged secret contains $($certificates.Count) certificates; exporting $($exportChain.Count) after excluding the root."
    foreach ($certificate in $exportChain) {
        Write-Verbose "PFX member: $($certificate.Subject) (issuer: $($certificate.Issuer), private key: $($certificate.HasPrivateKey))"
    }

    Export-SidProtectedPfx -Certificates $exportChain -ProtectionRule $protectionRule -OutputPath $resolvedPfxPath
}
finally {
    [Array]::Clear($certificateBytes, 0, $certificateBytes.Length)
    foreach ($certificate in $certificates) {
        $certificate.Dispose()
    }
}

Write-Host "PFX created: $resolvedPfxPath" -ForegroundColor Green
Write-Host 'Included certificates (root excluded):'
foreach ($exportedSubject in $exportedSubjects) {
    Write-Host "  $exportedSubject"
}