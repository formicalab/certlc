#Requires -PSEdition Core

Set-StrictMode -Version Latest

# test with:
# $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("C:\cert.pfx", "password", [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
# Export-PfxWithGroupProtection -Certificate $cert -AccountName "CONTOSO\Admins" -OutputFile "C:\output.pfx"

# Define the native structures and P/Invoke signatures
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct CRYPT_DATA_BLOB
{
    public uint cbData;
    public IntPtr pbData;
}

public static class NativeMethods
{
    public const uint EXPORT_PRIVATE_KEYS = 0x0004;
    public const uint REPORT_NO_PRIVATE_KEY = 0x0001;
    public const uint REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = 0x0002;
    public const uint PKCS12_INCLUDE_EXTENDED_PROPERTIES = 0x0010;
    public const uint PKCS12_PROTECT_TO_DOMAIN_SIDS = 0x0020;
    public const uint PKCS12_EXPORT_PBES2_PARAMS = 0x0080;

    // https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-4
    public const uint NTE_BAD_KEY_STATE = 0x8009000B;
    public const uint NTE_BAD_FLAGS = 0x80090009;
    public const uint NTE_BAD_KEY = 0x80090003;
    public const uint NTE_PERM = 0x80090010;
    
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool PFXExportCertStoreEx(
        IntPtr hStore,
        ref CRYPT_DATA_BLOB pPFX,
        string szPassword,
        IntPtr pvPara,
        uint dwFlags
    );

    [DllImport("ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptCreateProtectionDescriptor(
        string szDescriptorString,
        uint dwFlags,
        out IntPtr phDescriptor
    );

    [DllImport("ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptFreeObject(
        IntPtr hObject
    );
}
"@

function Export-PfxWithGroupProtection {
    <#
    .SYNOPSIS
        Exports an X509Certificate2 to a PFX file protected by a domain user or group.
    .PARAMETER Certificate
        The X509Certificate2 object to export.
    .PARAMETER AccountName
        The domain user or group name in the format DOMAIN\name (e.g., CONTOSO\jdoe or CONTOSO\Admins).
    .PARAMETER OutputFile
        The path to save the exported PFX file.
    .EXAMPLE
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("C:\cert.pfx", "password")
        Export-PfxWithGroupProtection -Certificate $cert -AccountName "CONTOSO\Admins" -OutputFile "C:\output.pfx"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    try {
        # Resolve the account name to a SID
        $ntAccount = New-Object System.Security.Principal.NTAccount($AccountName)
        try {
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            throw "Failed to resolve '$AccountName' to a SID. Ensure the account exists and is in the format DOMAIN\name (e.g., CONTOSO\jdoe)."
        }

        Write-Output "Exporting certificate to $OutputFile with protection for $AccountName (SID: $sid)"

        # Verify the certificate has a private key
        if (-not $Certificate.HasPrivateKey) {
            throw "The certificate does not have a private key."
        }
        if (-not $Certificate.PrivateKey) {
            throw "The private key is not accessible."
        }

        # Create a temporary in-memory store and add the certificate
        $tempStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Memory", "LocalMachine")
        $tempStore.Open("ReadWrite")
        $tempStore.Add($Certificate)

        # Get the native store handle
        $storeHandle = $tempStore.StoreHandle
        if ($storeHandle -eq [IntPtr]::Zero) {
            throw "Failed to obtain the certificate store handle."
        }

        # Create the protection descriptor string using the resolved SID
        $descriptorString = "SID=$sid"

        # Create the protection descriptor
        Write-Output "Creating protection descriptor: $descriptorString"
        $descriptorHandle = [IntPtr]::Zero
        $ncryptResult = [NativeMethods]::NCryptCreateProtectionDescriptor($descriptorString, 0, [ref] $descriptorHandle)
        if ($ncryptResult -ne 0 -or $descriptorHandle -eq [IntPtr]::Zero) {
            throw "Failed to create protection descriptor. Error code: 0x{0:X}" -f $ncryptResult
        }

        try {

            $exportFlags = `
                [NativeMethods]::EXPORT_PRIVATE_KEYS -bor `
                [NativeMethods]::REPORT_NO_PRIVATE_KEY -bor `
                [NativeMethods]::REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY -bor `
                [NativeMethods]::PKCS12_INCLUDE_EXTENDED_PROPERTIES -bor `
                [NativeMethods]::PKCS12_PROTECT_TO_DOMAIN_SIDS

            # Phase 1: discover required size
            $pfxBlob = New-Object CRYPT_DATA_BLOB
            $pfxBlob.cbData = 0
            $pfxBlob.pbData = [IntPtr]::Zero
            [NativeMethods]::PFXExportCertStoreEx($storeHandle, [ref]$pfxBlob, $null, $descriptorHandle, $exportFlags) | Out-Null
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($errorCode -ne 0x000000EA) {    # ERROR_MORE_DATA
                throw "PFXExportCertStoreEx call failed with error code: 0x{0:X}" -f $error
            }

            # Allocate exactly what’s needed
            $pfxBlob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($pfxBlob.cbData)

            # Phase 2: actual export
            $success = [NativeMethods]::PFXExportCertStoreEx($storeHandle, [ref]$pfxBlob, $null, $descriptorHandle, $exportFlags) | Out-Null
            if (-not $success) {

                # this call can also fail with NTE_BAD_KEY_STATE or NTE_BAD_KEY or NTE_PERM if the private key is not exportable
                # (https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-pfxexportcertstoreex)
 
                $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                # free the buffer to avoid the unmanaged leak
                if ($pfxBlob.pbData -ne [IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pfxBlob.pbData)
                }                
                throw "PFXExportCertStoreEx call failed with error code: 0x{0:X}" -f $errorCode
            }

            try {

                # Copy the PFX data to a managed byte array
                $pfxBytes = New-Object byte[] $pfxBlob.cbData
                [System.Runtime.InteropServices.Marshal]::Copy($pfxBlob.pbData, $pfxBytes, 0, $pfxBlob.cbData)

                # Write the PFX data to the output file
                [System.IO.File]::WriteAllBytes($OutputFile, $pfxBytes)
                Write-Output "Certificate exported successfully to $OutputFile"
            }
            finally {
                # Free the unmanaged memory
                if ($pfxBlob.pbData -ne [IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pfxBlob.pbData)
                }
            }
        }
        finally {
            # Free the protection descriptor
            if ($descriptorHandle -ne [IntPtr]::Zero) {
                [NativeMethods]::NCryptFreeObject($descriptorHandle) | Out-Null
            }
        }
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
        throw
    }
    finally {
        # Close the temporary store
        if ($null -ne $tempStore) {
            $tempStore.Close()
        }
    }
}