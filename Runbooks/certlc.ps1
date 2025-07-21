#Requires -PSEdition Core
using module Az.Accounts
using module Az.KeyVault
using module Az.Storage
using module Az.Resources

##########
# CERTLC #
##########

# CERTLC is a PowerShell runbook that automates the process of obtaining or renewing certificates from an AD CA, integrated with Azure Key Vault.
# The key vault is used to generate all requests, storing the private keys safely.

# The script is designed to be run using PowerShell 7.x in an Azure Automation hybrid worker environment.
# Initially based on certlc solution https://learn.microsoft.com/en-us/azure/architecture/example-scenario/certificate-lifecycle/

param
(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData,
    [Parameter(Mandatory = $false)]
    [object] $jsonRequestBody
)

<#

When invoked from a webhook, the runbook receives the WebhookData parameter.
The WebhookData is documented here: https://learn.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal
It contains:
- WebhookData.WebhookName: the name of the webhook that triggered the runbook
- WebhookData.RequestHeaders: the headers of the request that triggered the runbook
- WebhookData.RequestBody: the body of the request that triggered the runbook

Note: using Powershell 7.x, the WebhookData is passed not as a structure but as a string and with a wrongly formatted JSON.
See the code in Main section for details and workaround.

We assume that WebhookData.RequestBody is a JSON string using CloudEventSchema.
For certificate near expiry events, the body has a structure like this:

{
  "id": "<event idenfier>",
  "source": "/subscriptions/<subscriptionid>/resourceGroups/<keyvault resource group>/providers/Microsoft.KeyVault/<key vault name>",
  "specversion": "1.0",
  "type": "Microsoft.KeyVault.CertificateNearExpiry",
  "subject": "<name of the expiring certificate>",
  "time": "<event time, using format: 2025-06-08T19:52:25.1524887Z>",
  "data": {
    "Id": "https://<key vault name>.vault.azure.net/certificates/<certificate name>/<certificate version>",
    "VaultName": "<key vault name>",
    "ObjectType": "Certificate",
    "ObjectName": "<certificate name>",
    "Version": "<certificate version>",
    "NBF": 1749411621,  # not before date (epoch time)
    "EXP": 1749418821   # expiration date (epoch time)
  }
}

For new certificate requests, the body has a structure like this:

{
  "id": "<event identifier, free field>",
  "source": "<free field, can be used to identify the requestor>",
  "specversion": "1.0",
  "type": "CertLC.NewCertificateRequest",
  "subject": "<name of the new certificate>",
  "time": "<event time, using format: 2025-06-08T19:52:25.1524887Z>",
  "data": {
    "Id": "<request id, free field>",
    "VaultName": "<key vault name>",
    "ObjectType": "Certificate",
    "ObjectName": "<name of the new certificate>",
    "CertificateTemplate": "<certificate template name>",
    "CertificateSubject": "<certificate subject>",
    "CertificateDnsNames": [ "<dns name 1>", "<dns name 2>" ],  # optional, can be empty
    "PfxProtectTo": "<user or group to protect the PFX file>",  # optional, can be empty. If not specified, the PFX will not be downloaded
  }
}

You can also pass the RequestBody parameter explicitly, which must be a JSON string with the same structure as above.
In this case, use the Start-AzAutomationRunbook cmdlet to start the runbook, passing the jsonRequestBody parameter:

Start-AzAutomationRunbook -Name "certlc" -Parameters @{ 'jsonRequestBody'=$jsonRequestBody }

Where $jsonRequestBody is a JSON string containing the RequestBody (the same as WebhookData.RequestBody when the webhook is used).

#>

# Prohibits references to uninitialized variables
Set-StrictMode -Version 1.0

# Ensure the script stops on errors so that try/catch can be used to handle them
$ErrorActionPreference = 'Stop'

###################################
# STATIC SETTINGS AND GLOBAL VARS #
###################################

$Version = '1.0'       # version of the script - must match specversion in the webhook body

#########################
# FUNCTIONS - Write-Log #
#########################

# Write-Log: send log to Log Analytics workspace (if token is available) and to output
function Write-Log {
    param (
        [Parameter()]
        [string]$Message,
        [Parameter()]
        [string]$Level = 'Information'
    )

    # write to output
    switch ($Level) {
        'Error' {
            Write-Output "$(Get-Date): $($Level): $Message"
        }
        'Warning' {
            Write-Warning "$(Get-Date): $($Level): $Message"
        }
        default {
            Write-Output "$(Get-Date): $($Level): $Message"
        }
    }
}

#############################################
# FUNCTIONS - Export-PfxWithGroupProtection #
#############################################

function Export-PfxWithGroupProtection {
    <#
    Export a PFX certificate from Azure Key Vault, protecting it to specified SIDs.
    This function does not use Export-PfxCertificate cmdlet, but instead uses native interop helpers
    to create a protection descriptor and export the PFX file.
    The exported PFX file can be protected to multiple SIDs (users or groups).

    Note: this function is used in the New-CertificateRequest function to export the certificate
    #>

    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ProtectTo,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PfxFile
    )

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

    # resolve SIDs and build the rulestring: "SID=... OR SID=..."
    $rule = ($ProtectTo | ForEach-Object {
            ([System.Security.Principal.NTAccount]$_).Translate([System.Security.Principal.SecurityIdentifier]).Value
        } | ForEach-Object { "SID=$_" } ) -join ' OR '

    # create protection descriptor
    $hDesc = [IntPtr]::Zero
    $hr = [Win32Native]::NCryptCreateProtectionDescriptor($rule, 0, [ref]$hDesc)
    if ($hr) {
        throw 'Export-PfxWithGroupProtection: NCryptCreateProtectionDescriptor failed: 0x{0:X}' -f $hr
    }
    Write-Log "Export-PfxWithGroupProtection: protection descriptor handle: $hDesc"

    try {

        # Create memory store
        $store = [Win32Native]::CertOpenStore('Memory', 0, [IntPtr]::Zero, 0x2000, [IntPtr]::Zero)
        if ($store -eq [IntPtr]::Zero) {
            throw 'Export-PfxWithGroupProtection: CertOpenStore failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        Write-Log "Export-PfxWithGroupProtection: memory store handle: $store"

        try {

            # Add the cert to the memory store
            if (-not [Win32Native]::CertAddCertificateContextToStore($store, $Cert.Handle, 3, [IntPtr]::Zero)) {
                throw "Export-PfxWithGroupProtection: CertAddCertificateContextToStore failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            Write-Log 'Export-PfxWithGroupProtection: certificate added to memory store.'

            # Wrap the handle in an IntPtr buffer
            $pvPara = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
            [Runtime.InteropServices.Marshal]::WriteIntPtr($pvPara, $hDesc)

            try {

                # generate a random password for the PFX (as per documentation, if not used the API should generate one, but it seems it does not and uses empty or "0" as passwords)
                $password = [System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(40))

                # Query size of PFX so that we know how much buffer to allocate (pass 1)
                $blob = New-Object Win32Native+BLOB
                $flags = 0x0004 -bor 0x0010 -bor 0x0020  # EXPORT_PRIVATE_KEYS | INCLUDE_EXTENDED_PROPERTIES | PROTECT_TO_DOMAIN_SIDS

                if (-not [Win32Native]::PFXExportCertStoreEx($store, [ref]$blob, $password, $pvPara, $flags)) {
                    throw ('Export-PfxWithGroupProtection:: size query failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
                }
                Write-Log "Export-PfxWithGroupProtection: PFX size will be: $($blob.cbData) bytes"

                # allocate memory for the PFX data (pass 2)
                $blob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($blob.cbData)

                # do export to the memory store
                try {
                    if (-not [Win32Native]::PFXExportCertStoreEx($store, [ref]$blob, $password, $pvPara, $flags)) {
                        throw ('Export-PfxWithGroupProtection: export to memory store failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
                    }
                    Write-Log 'Export-PfxWithGroupProtection: export to memory store successful.'

                    $password = $null  # clear the password variable to avoid keeping it in memory

                    # save the file
                    $bytes = New-Object byte[] $blob.cbData
                    [Runtime.InteropServices.Marshal]::Copy($blob.pbData, $bytes, 0, $blob.cbData)
                    [System.IO.File]::WriteAllBytes($PfxFile, $bytes)
                    Write-Log "Export-PfxWithGroupProtection: PFX exported to file: $PfxFile"
                }
                finally {
                    # free the allocated memory for PFX data
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($blob.pbData)
                }
            }
            finally {
                # free the IntPtr buffer
                [Runtime.InteropServices.Marshal]::FreeHGlobal($pvPara)
            }
        }
        finally {
            # close the memory store
            [Win32Native]::CertCloseStore($store, 0) | Out-Null
        }      
    }
    finally {
        # free the protection descriptor handle
        [Win32Native]::NCryptCloseProtectionDescriptor($hDesc) | Out-Null
    }
}

########################################
# FUNCTIONS - Find-TemplateNameFromOid #
########################################

<#
Find-TemplateNameFromOid: find the certificate template name by OID.
This function queries the Active Directory Certificate Services configuration to find the template name associated with a given OID.
This is used in the New-CertificateRenewalRequest function to get the template name from the certificate OID.
#>

function Find-TemplateNameFromOid {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$oid
    )

    $rootDse = [ADSI]"LDAP://RootDSE"
    $configDN = $rootDse.configurationNamingContext
    $searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
    $entry = [ADSI]$searchRoot
    $searcher = New-Object DirectoryServices.DirectorySearcher $entry
    $searcher.Filter = "(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID=$oid))"
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    $result = $searcher.FindOne()
    if ($null -eq $result) {
        return [string]::Empty
    }
    return $result.Properties["name"][0]
}


#############################################
# FUNCTIONS - New-CertificateRenewalRequest #
#############################################

function New-CertificateRenewalRequest {
    param (

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CA
    )

    # before processing the request, we need to obtain the other certificate details, such as template, subject, and DNS names
    Write-Log "Getting additional certificate details for $CertificateName from key vault $VaultName..."
    $cert = $null
    try {
        $cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
    }
    catch {
        throw "Error getting certificate details for $CertificateName from vault $($VaultName): $_"
    }

    if ($null -eq $cert) {
        throw "Error getting certificate details for $CertificateName from vault $($VaultName): empty response! Certificate may not exist in the vault."
    }

    # get the certificate subject
    $CertificateSubject = $cert.Certificate.Subject

    # get the DNS names from the certificate
    $CertificateDnsNames = $null
    $san = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
    if ($null -ne $san) {
        # $DNS.Format(0) returns a string like: DNS Name=server01.contoso.com, DNS Name=server01.litware.com.
        # Transform it into an array of DNS names using regex; remove the "DNS Name=" prefix and split by comma
        $CertificateDnsNames = ($san.Format(0) -replace 'DNS Name=', '').Split(',').Trim() | Where-Object { $_ -ne '' }
    }

    # get the OID of the Certificate Template
    $templateExtension = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Certificate Template Information' }
    if ($null -eq $templateExtension) {
        throw 'Error getting template information from certificate: the Certificate Template Information extensions was not found.'
    }
    # $templateExtension.Format($false) returns a string like:
    # - Template=Flab-ShortWebServer(1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736), Major Version Number=100, Minor Version Number=5
    # - Template=1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736, Major Version Number=100, Minor Version Number=5
    $asn = $templateExtension.Format($false)

    # extract the OID using a regex working for both cases
    $regex = [regex]'(?<=Template=(?:[^\(]*\()?)(\d+(?:\.\d+)+)'
    if (-not $regex.IsMatch($asn)) {
        throw "Error getting OID from certificate: Template OID not found in string: $asn"
    }
    $oid = $regex.Match($asn).Value

    # lookup the template name using the OID
    try {
        Write-Log "Looking up template name for OID: $oid"
        $certificateTemplate = Find-TemplateNameFromOid -Oid $oid    
    }
    catch {
        throw "Error getting OID from certificate: Find-TemplateNameFromOidAttribute failed for OID: $($oid): $_"
    }
    if ([string]::IsNullOrEmpty($certificateTemplate)) {
        throw "Error getting OID from certificate: Template name not found for OID: $oid"
    }
    Write-Log "Template name found for OID $($oid) is: $certificateTemplate"

    # get PfxProtectTo from the certificate tags
    $PfxProtectTo = $cert.Tags['PfxProtectTo']

    Write-Log "Certificate $CertificateName found in vault $($VaultName): Subject: $CertificateSubject, Template: $certificateTemplate ($oid), PfxProtectTo: $PfxProtectTo"
    if ($null -eq $CertificateDnsNames) {
        Write-Log 'Certificate DNS Names: N/A'
    }
    else {
        Write-Log "Certificate DNS Names: $($CertificateDnsNames -join ', ')"
    }

    # Now we have all the details to create the renew request.
    # Renew actually uses same code as New-CertificateRequest, so we can reuse it.
    # Exceptions will be caught directly in the main section of the script
    New-CertificateRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplate $certificateTemplate -CertificateSubject $CertificateSubject -CertificateDnsNames $CertificateDnsNames -CA $CA -PfxProtectTo $PfxProtectTo
}

######################################
# FUNCTIONS - New-CertificateRequest #
######################################

# New-CertificateRequest: create a new certificate request

function New-CertificateRequest {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateTemplate,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateSubject,

        [Parameter(Mandatory = $false)]
        [string[]]$CertificateDnsNames,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CA,

        [Parameter(Mandatory = $false)]
        [string]$PfxProtectTo
    )

    # create certificate - if a previous request is in progress, reuse it
    $csr = $null
    try {
        $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertificateName | Where-Object { $_.Status -eq 'inProgress' }
        if ($null -ne $op) {
            Write-Log "Certificate request is already in progress for this certificate: $CertificateName; reusing the existing request." -Level 'Warning'
            $csr = $op.CertificateSigningRequest
        }
        else {
            Write-Log "Creating a new CSR for certificate $CertificateName in key vault $VaultName..."
            if ($null -ne $CertificateDnsNames) {
                # create a new CSR with the DNS names
                $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType 'application/x-pkcs12' -SubjectName $CertificateSubject -IssuerName 'Unknown' -DnsName $CertificateDnsNames
            }
            else {
                # create a new CSR without DNS names
                $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType 'application/x-pkcs12' -SubjectName $CertificateSubject -IssuerName 'Unknown'
            }
            $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -CertificatePolicy $Policy -Tag @{ 'PfxProtectTo' = $PfxProtectTo }
            $csr = $result.CertificateSigningRequest
        }
    }
    catch {
        throw "Error generating CSR in Key Vault: $_"
    }

    # see https://www.sysadmins.lv/blog-en/introducing-to-certificate-enrollment-apis-part-3-certificate-request-submission-and-response-installation.aspx

    # CR_IN_BASE64HEADER = 0x0,
    # CR_IN_BASE64 = 0x1,
    # CR_IN_BINARY = 0x2,
    # CR_IN_ENCODEANY = 0xff,
    # CR_OUT_BASE64HEADER = 0x0,
    # CR_OUT_BASE64 = 0x1,
    # CR_OUT_BINARY = 0x2

    Write-Log "Sending request to the CA $CA..."
    try {
        $CertRequest = New-Object -ComObject CertificateAuthority.Request
        $CertRequestStatus = $CertRequest.Submit(0x1, $csr, "CertificateTemplate:$($CertificateTemplate)", $CA)

        # status is described in https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/c084a3e3-4df3-4a28-9a3b-6b08487b04f3?redirectedfrom=MSDN

        switch ($CertRequestStatus) {
            2 {
                throw "Request was denied. Check the CA $CA for details."
            }
            3 {
                Write-Log 'Certificate Request submitted successfully.'
                # https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-getcertificate?redirectedfrom=MSDN
                # 0 = CR_OUT_BASE64HEADER (BASE64 format with begin/end header - this is how the key vault expects the certificate in order to perform a merge)
                $CertEncoded = $CertRequest.GetCertificate(0x0)
                Write-Log "Certificate received from CA $CA"
            }
            5 {
                throw "Request to CA $CA is pending. This is not expected since this runbook can only process completed requests. Review the certiicate template and CA configuration to ensure that certificates are immediately issued."
            }
            default {
                throw "Request to CA $CA failed with status $($CertRequestStatus). Check codes in https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/c084a3e3-4df3-4a28-9a3b-6b08487b04f3?redirectedfrom=MSDN"
            }
        }

    }
    catch {
        throw "Error submitting request to the CA $($CA): $_"
    }

    # we need to save the certificate in a temporary file because the Import-AzKeyVaultCertificate cmdlet does not accept a base64 string as input
    $CertEncodedFile = New-TemporaryFile
    Set-Content -Path $CertEncodedFile -Value $CertEncoded

    # import the certificate into the key vault
    Write-Log "Importing the certificate $CertificateName into the key vault $VaultName..."
    try {
        $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -FilePath $CertEncodedFile
        if ($null -eq $newCert) {
            throw 'Error importing certificate into the key vault: Import-AzKeyVaultCertificate returned null!'
        }
    }
    catch {
        throw "Error importing certificate into the key vault: $_"
    }
    finally {
        Remove-Item -Path $CertEncodedFile -Force -ErrorAction SilentlyContinue
    }
    Write-Log 'Certificate imported into the key vault.'

    # if required, download the certificate to a local file in the pfx folder
    if ([string]::IsNullOrEmpty($PfxProtectTo)) {
        Write-Log 'PfxProtectTo is not specified, skipping PFX export.'
    }
    else {
        # create the root folder if it does not exist
        if (-not (Test-Path -Path $PfxRootFolder)) {
            Write-Log "Creating the PFX root folder: $PfxRootFolder"
            New-Item -Path $PfxRootFolder -ItemType Directory -Force | Out-Null
        }
        Write-Log "PFX root folder verified: $PfxRootFolder"

        # determine per-user or per-group folder name from $PfxProtectTo
        $principal = $null
        if ($PfxProtectTo -match '\\') {
            $principal = ($PfxProtectTo -split '\\')[-1]     # DOMAIN\username → username
        }
        elseif ($PfxProtectTo -match '@') {
            $principal = ($PfxProtectTo -split '@')[0]       # username@domain → username
        }
        else {
            $principal = $PfxProtectTo                       # already just username
        }

        # build full target folder path  (root folder\username)
        $PfxTargetFolder = Join-Path -Path $PfxRootFolder -ChildPath $principal

        # create the target folder if it does not exist
        if (-not (Test-Path -Path $PfxTargetFolder)) {
            Write-Log "Creating the target folder for PFX: $PfxTargetFolder"
            New-Item -Path $PfxTargetFolder -ItemType Directory -Force | Out-Null

            try {
                $acl = Get-Acl -Path $PfxTargetFolder
                # disable inheritance and remove existing inherited ACEs
                $acl.SetAccessRuleProtection($true, $false)

                $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
                    -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $propFlags = [System.Security.AccessControl.PropagationFlags]::None

                $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    'BUILTIN\Administrators', 'FullControl', $inheritFlags, $propFlags, 'Allow')
                $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    'NT AUTHORITY\SYSTEM', 'FullControl', $inheritFlags, $propFlags, 'Allow')
                $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $PfxProtectTo, 'ReadAndExecute', $inheritFlags, $propFlags, 'Allow')

                $acl.SetAccessRule($adminRule)
                $acl.SetAccessRule($systemRule)
                $acl.SetAccessRule($userRule)

                Set-Acl -Path $PfxTargetFolder -AclObject $acl
                Write-Log "ACL set on target folder for PFX: $($PfxTargetFolder): Administrators & SYSTEM FullControl, $PfxProtectTo Read+Execute"
            }
            catch {
                throw "Error setting permissions on the target folder for PFX $($PfxTargetFolder): $_"
            }
        }

        Write-Log "Target folder for PFX verified for PfxProtectTo $($PfxProtectTo): $PfxTargetFolder"
        $pfxFile = Join-Path -Path $PfxTargetFolder -ChildPath "$($CertificateName).pfx"

        # get the certificate from the key vault
        Write-Log "Certificate $($CertificateName): getting the certificate from key vault $VaultName to export it to PFX file $pfxFile..."
        try {
            $certBase64 = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertificateName -AsPlainText
        }
        catch {
            throw "Error getting certificate $CertificateName from key vault $($VaultName): $_"
        }

        if ([string]::IsNullOrEmpty($certBase64)) {
            throw "Error getting certificate $CertificateName from key vault $($VaultName): the certificate is empty!"
        }

        # convert the base64 string to a byte array and create an X509Certificate2 object
        $certBytes = [Convert]::FromBase64String($certBase64)
        $certBase64 = $null
        $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes, [string]::Empty, 'Exportable')
        # $x509Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes, [string]::Empty, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $certBytes = $null

        # test exportability of private key
        if (-not $x509Cert.HasPrivateKey) {
            $x509Cert = $null
            throw "Error exporting certificate $CertificateName to PFX file: the private key is not available!"
        }
        Write-Log "Certificate $($CertificateName): private key is available."

        try {
            $x509cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) | Out-Null
            Write-Log "Certificate $($CertificateName): private key is exportable."
        }
        catch {
            $x509Cert = $null
            throw "Error exporting certificate $CertificateName to PFX file: the private key is present but not exportable!"
        }

        # remove the PFX file if it already exists, to ensure we always export a fresh copy
        if (Test-Path -Path $pfxFile) {
            Write-Log "Removing existing PFX file: $pfxFile"
            try {
                Remove-Item -Path $pfxFile -Force
            }
            catch {
                $x509Cert = $null
                throw "Error removing existing PFX file: $($pfxFile): $_"
            }
        }
        else {
            Write-Log "No existing PFX file found: $pfxFile"
        }

        # do the actual export to PFX file

        <#

        Old code using Export-PfxCertificate cmdlet, which sometimes fails with "The private key is not exportable" error.

        try {
            Export-PfxCertificate -Cert $x509Cert -FilePath $pfxFile -ProtectTo $PfxProtectTo -ErrorAction Stop | Out-Null
        }
        catch {
            throw "Error exporting certificate to PFX protecting it to $($PfxProtectTo): $_"
        }
        finally {
            $x509Cert = $null
        }
        #>

        # new code using native interop helpers
        try {
            Export-PfxWithGroupProtection -Cert $x509Cert -ProtectTo $PfxProtectTo -PfxFile $pfxFile
        }
        catch {
            throw "Error exporting certificate to PFX protecting it to $($PfxProtectTo): $_"
        }
        finally {
            $x509Cert = $null
        }

        # check if the PFX file was created successfully
        if (-not (Test-Path -Path $pfxFile)) {
            throw "Error exporting certificate to PFX file: $pfxFile does not exist after export!"
        }

        Write-Log "Certificate $CertificateName exported to PFX file $pfxFile"
    }
}

#################################
# MAIN - modules and parameters #
#################################

# Connect to Azure. Ensures we do not inherit an AzContext, since we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
Write-Log 'Connecting to Azure using default identity...'
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    $msg = 'There is no system-assigned user identity.'
    Write-Log $msg -Level 'Error'
    throw $msg
}

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection

# Check if the script is running on Azure or on hybrid worker; assign jobId accordingly.
# https://rakhesh.com/azure/azure-automation-powershell-variables/
if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation/') {
    # We are in a Hybrid Runbook Worker
    $jobId = $env:PSPrivateMetadata
    Write-Log "Runbook running with job id $jobId on hybrid worker $($env:COMPUTERNAME)."
}
elseif ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
    # We are in Azure Automation
    $jobId = $PSPrivateMetadata.JobId
    $msg = "Runbook running with job id $jobId in Azure Automation. This runbook must be executed by a hybrid worker instead!"
    Write-Log $msg -Level 'Error'
    throw $msg
}
else {
    # We are in a local environment - not supported anymore because we cannot get the encrypted variables from the automation account in this case
    $msg = 'Runbook running in a local environment. This runbook must be executed by a hybrid worker instead!'
    Write-Log $msg -Level 'Error'
    throw $msg
}

# Automation account variables
# Note: since they are encrypted, you must use the internal cmdlet Get-AutomationVariable to retrieve them, not Get-AzAutomationVariable

try {
    # Get the CA from the automation account variable
    $CA = Get-AutomationVariable -Name 'certlc-ca'
}
catch {
    $msg = "Error getting automation account variable 'certlc-ca'. Ensure the variable exists in the automation account!"
    Write-Log $msg -Level 'Error'
    throw $msg
}
# Ensure the CA variable is not empty
if ([string]::IsNullOrEmpty($CA)) {
    $msg = "The automation account variable 'certlc-ca' is empty!"
    Write-Log $msg -Level 'Error'
    throw $msg
}

try {
    # Get the PfxRootFolder from the automation account variable
    $PfxRootFolder = Get-AutomationVariable -Name 'certlc-pfxrootfolder'
}
catch {
    $msg = "Error getting automation account variable 'certlc-pfxrootfolder'. Ensure the variable exists in the automation account!"
    Write-Log $msg -Level 'Error'
    throw $msg
}
# Ensure the PfxRootFolder variable is not empty
if ([string]::IsNullOrEmpty($PfxRootFolder)) {
    $msg = "The automation account variable 'certlc-pfxrootfolder' is empty!"
    Write-Log $msg -Level 'Error'
    throw $msg
}

# Check if we have the jsonRequestBody parameter
if ([string]::IsNullOrEmpty($jsonRequestBody)) {

    # No explicit RequestBody parameter, so we will use WebhookData
    # Try to parse the webhook data

    if ([string]::IsNullOrEmpty($WebhookData)) {
        $msg = 'Both RequestBody and WebhookData parameters are missing or empty! Call the runbook from a webhook or pass the RequestBody parameter explicitly with Start-AzAutomationRunbook!'
        Write-Log $msg -level 'Error'
        throw $msg
    }

    Write-Log "WebhookData received is: $($WebhookData)"

    <#

    Using Powershell 7.x, the WebhookData string contains a wrongly formatted JSON...
    (see https://learn.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal#create-a-webhook)
    such as:
    {WebhookName:certlc,RequestBody:{"id":"e1a6f79d-fed0-4e2c-80a6-3cfd09ee3b13","source":"/subscriptions/...etc

    The problem here is that WebhookName, RequestBody and RequestHeader are not enclosed in double quotes.
    We try to parse the JSON but, if it fails, we 'manually' extract the RequestBody via regex and convert it from JSON to object.

    #>

    # Try to parse WebhookData as JSON first
    try {
        $request = ConvertFrom-Json -InputObject $WebhookData
        $requestBody = $request.RequestBody
    }
    catch {
        # Fallback to regex extraction for broken format. The following regex matches these cases:
        # - RequestBody is enclosed in double quotes (valid case):   "RequestBody":"{...}"
        # - RequestBody is not enclosed in double quotes (invalid case):   RequestBody:{...}
        # - After RequestBody there is an array:  RequestBody:[{...}] or "RequestBody":[{...},{...}]
        # The regex properly handles nested JSON objects, checking that braces are balanced.

        Write-Log 'Failed to parse WebhookData as JSON. Attempting to extract RequestBody using regex...' -Level 'Warning'

        if ($WebhookData -match '"?RequestBody"?\s*:\s*((?:{([^{}]|(?<open>{)|(?<-open>}))*(?(open)(?!))})|(?:\[([^\[\]]|(?<open>\[)|(?<-open>\]))*(?(open)(?!))\]))') {
            $jsonRequestBody = $matches[1]
            try {
                $RequestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10
            }
            catch {
                $msg = "Failed to parse WebhookData.RequestBody using regex, error: $_"
                Write-Log $msg -Level 'Error'
                throw $msg
            }
        }
        else {
            $msg = 'WebhookData.RequestBody not recognized using regex!'
            Write-Log $msg -Level 'Error'
            throw $msg
        }
    }

    if ([string]::IsNullOrEmpty($requestBody)) {
        $msg = 'WebhookData.RequestBody is empty! Ensure the runbook is called from a webhook!'
        Write-Log $msg -Level 'Error'
        throw $msg
    }
}

else {
    # parse the jsonRequestBody parameter as JSON
    Write-Log "jsonRequestBody received is: $($jsonRequestBody)"
    try {
        $requestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10
    }
    catch {
        $msg = "Failed to parse jsonRequestBody parameter as JSON: $_"
        Write-Log $msg -Level 'Error'
        throw $msg
    }
}

# now that we have a valid requestBody object, check some fields and detect request type

# check version
if ([string]::IsNullOrEmpty($requestBody.specversion)) {
    $msg = "Missing or empty mandatory parameter: 'specversion' in request body!"
    Write-Log $msg -Level 'Error'
    throw $msg
}
if ($requestBody.specversion -ne $Version) {
    $msg = "The version specified in the request, $($requestBody.specversion), does not match the script version $Version!"
    Write-Log $msg -Level 'Error'
    throw $msg
}
else {
    Write-Log "specversion: $($requestBody.specversion)"
}

# process requests based on type
if ([string]::IsNullOrEmpty($requestBody.type)) {
    $msg = "Missing or empty mandatory parameter: 'type' in request body!"
    Write-Log $msg -Level 'Error'
    throw $msg
}
else {
    Write-Log "Request type: $($requestBody.type)"
}

switch ($requestBody.type) {

    'Microsoft.KeyVault.CertificateNearExpiry' {

        # get required parameters
        $VaultName = $requestBody.data.VaultName
        $CertificateName = $requestBody.data.ObjectName

        # start formal validation of mandatory parameters:

        if ([string]::IsNullOrEmpty($VaultName)) {
            throw "Missing or empty mandatory parameter: 'VaultName'!"
        }

        if ([string]::IsNullOrEmpty($CertificateName)) {
            throw "Missing or empty mandatory parameter: 'ObjectName'!"
        }

        # invoke renewal
        try {
            New-CertificateRenewalRequest -VaultName $VaultName -CertificateName $CertificateName -CA $CA
        }
        catch {
            $msg = "Error processing certificate renew request: $_"
            Write-Log $msg -Level 'Error'
            throw $msg
        }
    }

    'CertLC.NewCertificateRequest' {

        # get required parameters
        $VaultName = $requestBody.data.VaultName
        $CertificateName = $requestBody.data.ObjectName
        $CertificateTemplate = $requestBody.data.CertificateTemplate
        $CertificateSubject = $requestBody.data.CertificateSubject
        $CertificateDnsNames = $requestBody.data.CertificateDnsNames
        $PfxProtectTo = $requestBody.data.PfxProtectTo

        # start formal validation of mandatory parameters:

        # VaultName
        if ([string]::IsNullOrEmpty($VaultName)) {
            $msg = "Missing or empty mandatory parameter: 'data.VaultName' in request body!"
            Write-Log $msg -Level 'Error'
            throw $msg
        }

        # CertificateName: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateName)) {
            $msg = "Missing or empty mandatory parameter: 'data.CertificateName' in request body!"
            Write-Log $msg -Level 'Error'
            throw $msg
        }

        # CertificateName: check if the certificate already exists in the key vault
        try {
            $deletedCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -InRemovedState
        }
        catch {
            $msg = "Error checking for deleted certificate: $_"
            Write-Log $msg -Level 'Error'
            throw $msg
        }
        if (($null -ne $deletedCert) -and ($null -ne $deletedCert.DeletedDate)) {
            $msg = "Certificate $CertificateName is already in the key vault and in deleted state since $($deletedCert.DeletedDate). It must be purged before creating a new one; otherwise specify a different certificate name."
            Write-Log $msg -Level 'Error'
            throw $msg
        }

        # CertificateTemplate: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateTemplate)) {
            $msg = "Missing or empty mandatory parameter: 'data.CertificateTemplate' in request body!"
            Write-Log $msg -Level 'Error'
            throw $msg
        }

        # CertificateSubject: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateSubject)) {
            $msg = "Missing or empty mandatory parameter: 'data.CertificateSubject' in request body!"
            Write-Log $msg -Level 'Error'
            throw $msg
        }

        # DnsNames (optional, but if specified, must be an array)
        if ($CertificateDnsNames -and $CertificateDnsNames -isnot [array]) {
            $msg = "Parameter 'CertificateDnsNames' is not an array!"
            Write-Log $msg -Level 'Error'
            throw $msg
        }

        # remove all escape backslashes from PfxProtectTo, ensuring that only one backslash is present
        if ($PfxProtectTo -and $PfxProtectTo -match '\\') {
            Write-Log "PfxProtectTo contains backslashes: $PfxProtectTo"
            # replace multiple backslashes with a single one
            $PfxProtectTo = $PfxProtectTo -replace '\\+', '\'
            Write-Log "PfxProtectTo after removing extra backslashes: $PfxProtectTo"
        }

        # end of validation. Now process the new certificate request

        if ($null -ne $CertificateDnsNames) {
            Write-Log "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplate, subject $CertificateSubject, DNS names $($CertificateDnsNames -join ', ')..."
        }
        else {
            Write-Log "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplate, subject $CertificateSubject..."
        }

        try {
            New-CertificateRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplate $CertificateTemplate -CertificateSubject $CertificateSubject -CertificateDnsNames $CertificateDnsNames -CA $CA -PfxProtectTo $PfxProtectTo
        }
        catch {
            $msg = "Error processing new certificate request: $_"
            Write-Log $msg -Level 'Error'
            throw $msg
        }
    }

    default {
        $msg = "Unknown request type: $($requestBody.type). Supported values are: Microsoft.KeyVault.CertificateNearExpiry, CertLC.NewCertificateRequest!"
        Write-Log $msg -Level 'Error'
        throw $msg
    }
}

##############
# MAIN - end #
##############

Write-Log 'Runbook completed successfully.'