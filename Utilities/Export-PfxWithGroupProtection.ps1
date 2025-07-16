<#
  Minimal raw‑API export of a SID‑protected PFX (‑ProtectTo equivalent)
  without using Export‑PfxCertificate.

  Parameters:
    -VaultName: Name of the Key Vault containing the certificate.
    -CertName: Name of the certificate in the Key Vault.
    -ProtectTo: Array of SIDs to protect the PFX to.
    -PfxFile: Path to save the exported PFX file.
#>

#Requires -PSEdition Core
using module Az.KeyVault


param(
    [Parameter(Mandatory)]
    [string]$VaultName,

    [Parameter(Mandatory)]
    [string]$CertName,

    [Parameter(Mandatory)]
    [string[]]$ProtectTo,

    [Parameter(Mandatory)]
    [string]$PfxFile
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

Write-Host 'Getting certificate from Key Vault...'
$certBase64 = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertName -AsPlainText
$secretBytes = [Convert]::FromBase64String($certbase64)
$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($secretBytes, [string]::Empty, "Exportable")

# Add native interop helpers
if (-not ('Win32Native' -as [type])) {
    Add-Type -TypeDefinition @'
        using System;
        using System.Runtime.InteropServices;

        public static class Win32Native
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct BLOB
            {
                public uint cbData;
                public IntPtr pbData;
            }

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern int NCryptCreateProtectionDescriptor(
                string descriptor, uint flags, out IntPtr hDesc);

            [DllImport("ncrypt.dll")]
            public static extern int NCryptCloseProtectionDescriptor(IntPtr hDesc);

            [DllImport("crypt32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
            public static extern IntPtr CertOpenStore(
                string storeProvider, uint encoding, IntPtr hCryptProv,
                uint flags, IntPtr pvPara);

            [DllImport("crypt32.dll", SetLastError = true)]
            public static extern bool CertAddCertificateContextToStore(
                IntPtr hStore, IntPtr pCert, uint disp, IntPtr ppOut);

            [DllImport("crypt32.dll", SetLastError = true)]
            public static extern bool CertCloseStore(IntPtr hStore, uint flags);

            [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool PFXExportCertStoreEx(
                IntPtr hStore, ref BLOB pfx,
                string password, IntPtr pvPara, uint flags);
        }
'@
}

# 1. Build SID rule string: "SID=... OR SID=..."
$rule = ($ProtectTo | ForEach-Object {
        ([System.Security.Principal.NTAccount]$_
    ).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } | ForEach-Object { "SID=$_" } ) -join ' OR '
Write-Host "Protection rule: $rule"

# 2. Create protection descriptor
$hDesc = [IntPtr]::Zero
$hr = [Win32Native]::NCryptCreateProtectionDescriptor($rule, 0, [ref]$hDesc)
if ($hr) { throw 'NCryptCreateProtectionDescriptor failed: 0x{0:X}' -f $hr }
Write-Host "Protection descriptor handle: $hDesc"

try {
    # 3. Create memory store
    $store = [Win32Native]::CertOpenStore('Memory', 0, [IntPtr]::Zero, 0x2000, [IntPtr]::Zero)
    if ($store -eq [IntPtr]::Zero) {
        throw "CertOpenStore failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "Memory store handle: $store"

    try {
        # 4. Add the cert to the memory store
        if (-not [Win32Native]::CertAddCertificateContextToStore($store, $Cert.Handle, 3, [IntPtr]::Zero)) {
            throw "CertAddCertificateContextToStore failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        Write-Host 'Certificate added to store.'

        # 5. Wrap the handle in an IntPtr buffer
        $pvPara = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($pvPara, $hDesc)

        try {
            # 6. Query size (pass 1)
            $blob = New-Object Win32Native+BLOB
            $flags = 0x0004 -bor 0x0010 -bor 0x0020  # EXPORT_PRIVATE_KEYS | INCLUDE_EXTENDED_PROPERTIES | PROTECT_TO_DOMAIN_SIDS

            # generate a random password for the PFX (as per documentation, if not used the API should generate one, but it seems it does not and uses empty or "0" as passwords)
            $password = [System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(40))

            if (-not [Win32Native]::PFXExportCertStoreEx($store, [ref]$blob, $password, $pvPara, $flags)) {
                throw ("Size query failed: 0x{0:X}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
            Write-Host "PFX size: $($blob.cbData) bytes"

            # 7. Allocate, export (pass 2), save
            $blob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($blob.cbData)
            try {
                if (-not [Win32Native]::PFXExportCertStoreEx($store, [ref]$blob, $password, $pvPara, $flags)) {
                    throw ("Export failed: 0x{0:X}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
                }
                Write-Host 'PFX export successful.'

                $bytes = New-Object byte[] $blob.cbData
                [Runtime.InteropServices.Marshal]::Copy($blob.pbData, $bytes, 0, $blob.cbData)
                [System.IO.File]::WriteAllBytes($PfxFile, $bytes)
                Write-Host "✅ PFX written to $PfxFile"
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($blob.pbData)
            }
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($pvPara)
        }
    }
    finally {
        [Win32Native]::CertCloseStore($store, 0) | Out-Null
    }
}
finally {
    [Win32Native]::NCryptCloseProtectionDescriptor($hDesc) | Out-Null
}