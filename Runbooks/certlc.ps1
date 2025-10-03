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
    "CertificateDnsNames": [ "<dns name 1>", "<dns name 2>", ... ],  # optional, can be empty
    "Hostname": "<hostname of the server where the certificate will be used>",  # it will be used also as folder name for exported PFX
    "PfxProtectTo": [ "<user or group to protect the PFX file>", "other user/group", ...],  # these principals will be also granted Read+Execute on PFX folder
  }
}

For certificate revocation requests, the body has a structure like this:

{
  "id": "<event identifier, free field>",
  "source": "<free field, can be used to identify the requestor>",
  "specversion": "1.0",
  "type": "CertLC.CertificateRevocationRequest",
  "subject": "<name of the new certificate>",
  "time": "<event time, using format: 2025-06-08T19:52:25.1524887Z>",
  "data": {
    "Id": "<request id, free field>",
    "VaultName": "<key vault name>",
    "ObjectType": "Certificate",
    "ObjectName": "<name of the new certificate>",
    "RevocationReason": "1",  # see https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-revokecertificate for possible values
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

function Write-Log {
    <#
        .SYNOPSIS
            Emit a structured JSON log entry.
        .DESCRIPTION
            Writes a single-line JSON object with standard fields plus optional custom context.
            Protects reserved keys, filters null/empty context entries, supports adjustable JSON depth.
        .NOTES
            Backward compatible: positional Message, optional -Level, existing -CorrelationId.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter()][ValidateSet('Information', 'Warning', 'Error', 'Verbose')][string]$Level = 'Information',
        [Parameter(Mandatory)][string]$Section,
        [Parameter()][string]$CorrelationId,
        [Parameter()][hashtable]$Context,
        [Parameter()][int]$JsonDepth = 5
    )

    $reservedKeys = 'timestamp','level','message','section','correlationId'
    $entry = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        level     = $Level
        section   = $Section
        message   = $Message
    }
    if ($CorrelationId) { $entry.correlationId = $CorrelationId }

    if ($Context) {
        foreach ($k in $Context.Keys) {
            $v = $Context[$k]
            if ($null -eq $v -or ($v -is [string] -and [string]::IsNullOrWhiteSpace($v))) { continue }
            $targetKey = if ($reservedKeys -contains $k) { "ctx_$k" } else { $k }
            $entry[$targetKey] = $v
        }
    }

    try { $json = $entry | ConvertTo-Json -Compress -Depth $JsonDepth }
    catch {
        $json = ([ordered]@{ timestamp=(Get-Date).ToString('o'); level='Error'; message='Failed to serialize log entry'; originalMessage=$Message; serializationError=$_.Exception.Message }) | ConvertTo-Json -Compress
    }

    switch ($Level) {
        'Error'   { Write-Output $json }    # don't use Write-Error to avoid breaking Automation job log parsing
        'Warning' { Write-Warning $json }
        'Verbose' { Write-Verbose $json }
        default   { Write-Output $json }
    }
}

##################################
# FUNCTIONS - Invoke-LogAndThrow #
##################################

# Helper to log an error message and throw an exception with optional inner exception
function Invoke-LogAndThrow {
    <#
        .SYNOPSIS
            Log an error and throw a terminating exception.
        .DESCRIPTION
            Emits a structured error log (with flattened exception details) and then throws a System.Exception.
            Backward compatible with prior -Inner usage via alias.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
        [Parameter(Mandatory)][string]$Section,
        [Parameter()][string]$CorrelationId,
        [Parameter()][Alias('Inner')][System.Exception]$InnerException,
        [Parameter()][hashtable]$Context
    )

    function Convert-ExceptionToObject {
        param([System.Exception]$Exception, [int]$MaxDepth = 2)
        if (-not $Exception) { return $null }
        $o = [ordered]@{ type=$Exception.GetType().FullName; message=$Exception.Message }
        if ($Exception.HResult) { $o.hresult = $Exception.HResult }
        if ($Exception.StackTrace) { $o.stackTrace = $Exception.StackTrace }
        if ($Exception.InnerException -and $MaxDepth -gt 0) {
            $o.inner = Convert-ExceptionToObject -Exception $Exception.InnerException -MaxDepth ($MaxDepth - 1)
        }
        return $o
    }

    $ctx = @{}
    if ($Context) { $ctx = @{} + $Context }
    if ($InnerException) { $ctx.exception = Convert-ExceptionToObject -Exception $InnerException }

    Write-Log -Level 'Error' -Message $Message -Section $Section -CorrelationId $CorrelationId -Context $ctx
    if ($InnerException) { throw ([System.Exception]::new($Message, $InnerException)) }
    throw ([System.Exception]::new($Message))
}

####################################
# FUNCTIONS - Test-HostnameFormat  #
####################################

# Validate hostname format (simple regex)
function Test-HostnameFormat {
    param(
        [Parameter()]
        [string]$Hostname
    )

    if ([string]::IsNullOrWhiteSpace($Hostname)) { return $true }
    $h = $Hostname.Trim()
    if ($h -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253})$') { return $false }
    return $true
}

####################################
# FUNCTIONS - Format-PfxProtectTo  #
####################################

# Format PfxProtectTo array consistently (trim, collapse backslashes, de-dupe case-insensitive)
function Format-PfxProtectTo {
    param(
        [Parameter()] [object] $InputValue
    )

    if (-not $InputValue) { return @() }

    # Wrap single string
    if ($InputValue -isnot [System.Array]) {
        $InputValue = @($InputValue)
    }

    # Trim, remove empties, collapse multiple backslashes
    $normalized = foreach ($raw in $InputValue) {
        if ($null -eq $raw) { continue }
        $s = [string]$raw
        $s = $s.Trim()
        if ($s -eq '') { continue }
        if ($s -match '\\{2,}') {
            $s = ($s -replace '\\{2,}', '\')
        }
        $s
    }

    # Case-insensitive de-dupe preserving first
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $out = foreach ($n in $normalized) {
        if ($seen.Add($n)) { $n }
    }
    return $out
}

##########################################
# FUNCTIONS - Convert-PfxProtectToForTag #
##########################################

# Convert PfxProtectTo array to tag-safe string
function Convert-PfxProtectToForTag {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Value
    )

    if (-not $Value -or $Value.Count -eq 0) { return '' }
    
    # Trim, remove empties, dedupe (case-insensitive), preserve order of first occurrence
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $clean = foreach ($v in $Value) {
        $t = ($v | ForEach-Object { ($_ ?? '') }) -as [string]
        $t = $t.Trim()
        if ($t -and $seen.Add($t)) { $t }
    }
    return ($clean -join ';')
}

###########################################
# FUNCTIONS - Convert-PfxProtectToFromTag #
###########################################

# Parse tag string into PfxProtectTo array
function Convert-PfxProtectToFromTag {
    param(
        [Parameter(Mandatory = $true)]
        [string] $TagValue
    )

    if ([string]::IsNullOrWhiteSpace($TagValue)) { return @() }

    # Parse then normalize to keep parity with input handling
    $raw = $TagValue.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    return Format-PfxProtectTo -InputValue $raw
}

#############################################
# FUNCTIONS - Export-PfxWithGroupProtection #
#############################################

<#
Export a PFX certificate from Azure Key Vault, protecting it to specified SIDs.
This function does not use Export-PfxCertificate cmdlet, but instead uses native interop helpers
to create a protection descriptor and export the PFX file.
The exported PFX file can be protected to multiple SIDs (users or groups).

Note: this function is used in the New-CertificateCreationRequest function to export the certificate
#>
function Export-PfxWithGroupProtection {

    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,

        [Parameter(Mandatory = $true)]
        [string[]]$ProtectTo,

        [Parameter(Mandatory = $true)]
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
    Write-Log -Section 'Export-PfxWithGroupProtection' "Protection descriptor handle: $hDesc"

    try {

        # Create memory store
        $store = [Win32Native]::CertOpenStore('Memory', 0, [IntPtr]::Zero, 0x2000, [IntPtr]::Zero)
        if ($store -eq [IntPtr]::Zero) {
            throw 'Export-PfxWithGroupProtection: CertOpenStore failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        Write-Log -Section 'Export-PfxWithGroupProtection' "Memory store handle: $store"

        try {

            # Add the cert to the memory store
            if (-not [Win32Native]::CertAddCertificateContextToStore($store, $Cert.Handle, 3, [IntPtr]::Zero)) {
                throw "Export-PfxWithGroupProtection: CertAddCertificateContextToStore failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            Write-Log -Section 'Export-PfxWithGroupProtection' 'Certificate added to memory store.'

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
                Write-Log -Section 'Export-PfxWithGroupProtection' "PFX size will be: $($blob.cbData) bytes"

                # allocate memory for the PFX data (pass 2)
                $blob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($blob.cbData)

                # do export to the memory store
                try {
                    if (-not [Win32Native]::PFXExportCertStoreEx($store, [ref]$blob, $password, $pvPara, $flags)) {
                        throw ('Export-PfxWithGroupProtection: export to memory store failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
                    }
                    Write-Log -Section 'Export-PfxWithGroupProtection' 'Export to memory store successful.'

                    $password = $null  # clear the password variable to avoid keeping it in memory

                    # save the file
                    $bytes = New-Object byte[] $blob.cbData
                    [Runtime.InteropServices.Marshal]::Copy($blob.pbData, $bytes, 0, $blob.cbData)
                    [System.IO.File]::WriteAllBytes($PfxFile, $bytes)
                    Write-Log -Section 'Export-PfxWithGroupProtection' "PFX exported to file: $PfxFile"
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

#################################
# FUNCTIONS - Find-TemplateName #
#################################

<#
Find-TemplateName: find the certificate template name by OID or CN or DisplayName.
This function queries the Active Directory Certificate Services configuration to find the template name associated with a given OID or CN or DisplayName.
#>

function Find-TemplateName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$cnOrDisplayNameOrOid
    )

    $rootDse = [ADSI]'LDAP://RootDSE'
    $configDN = $rootDse.configurationNamingContext
    $searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
    $entry = [ADSI]$searchRoot
    $searcher = New-Object DirectoryServices.DirectorySearcher $entry
    $searcher.Filter = "(&(objectClass=pKICertificateTemplate)(|(cn=$cnOrDisplayNameOrOid)(displayName=$cnOrDisplayNameOrOid)(msPKI-Cert-Template-OID=$cnOrDisplayNameOrOid)))"
    $searcher.PropertiesToLoad.Add('name') | Out-Null
    $result = $searcher.FindOne()
    if ($null -eq $result) {
        return [string]::Empty
    }
    return $result.Properties['name'][0]
}

#############################################
# FUNCTIONS - New-CertificateRenewalRequest #
#############################################

# Renew an existing certificate in Key Vault by creating a new request to the specified CA.
# The certificate details (template, subject, DNS names) are obtained from the existing certificate in the vault.
function New-CertificateRenewalRequest {
    param (
        [Parameter(Mandatory = $true)][string]$VaultName,
        [Parameter(Mandatory = $true)][string]$CertificateName,
        [Parameter(Mandatory = $true)][string]$CA
    )

    # before processing the request, we need to obtain the other certificate details, such as template, subject, and DNS names
    Write-Log -Section 'New-CertificateRenewalRequest' -Message "Getting additional certificate details for $CertificateName from key vault $VaultName..."
    $cert = $null
    try {
        $cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
    }
    catch {
        throw [System.Exception]::new("New-CertificateRenewalRequest: Error getting certificate details for $CertificateName from vault $VaultName", $_.Exception)
    }
    if ($null -eq $cert) {
        # Wrap $VaultName to avoid parsing the trailing colon as part of the variable token in some Automation parsing contexts
        throw [System.Exception]::new("New-CertificateRenewalRequest: Error getting certificate details for $CertificateName from vault $($VaultName): empty response! Certificate may not exist in the vault.")
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
        throw [System.Exception]::new('New-CertificateRenewalRequest: Error getting template information from certificate: the Certificate Template Information extension was not found.')
    }
    # $templateExtension.Format($false) returns a string like:
    # - Template=Flab-ShortWebServer(1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736), Major Version Number=100, Minor Version Number=5
    # - Template=1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736, Major Version Number=100, Minor Version Number=5
    $asn = $templateExtension.Format($false)

    # extract the OID using a regex working for both cases
    $regex = [regex]'(?<=Template=(?:[^\(]*\()?)(\d+(?:\.\d+)+)'
    if (-not $regex.IsMatch($asn)) {
        throw [System.Exception]::new("New-CertificateRenewalRequest: Error getting OID from certificate: Template OID not found in string: $asn")
    }
    $oid = $regex.Match($asn).Value

    # lookup the template name using the OID
    try {
        Write-Log -Section 'New-CertificateRenewalRequest' "Looking up template name for OID: $oid"
        $certificateTemplateName = Find-TemplateName -cnOrDisplayNameOrOid $oid
    }
    catch { throw [System.Exception]::new("New-CertificateRenewalRequest: Error resolving template name for OID $oid", $_.Exception) }
    if ([string]::IsNullOrEmpty($certificateTemplateName)) {
        # Wrap $oid before the colon to ensure unambiguous variable expansion
        throw [System.Exception]::new("New-CertificateRenewalRequest: Error resolving template name for OID $($oid): template not found in AD.")
    }
    Write-Log -Section 'New-CertificateRenewalRequest' -Message "Template name found for OID $($oid) is: $certificateTemplateName"

    # get Hostname from the certificate tags
    $Hostname = $cert.Tags['Hostname']
    if ([string]::IsNullOrWhiteSpace($Hostname)) {
        throw [System.Exception]::new("New-CertificateRenewalRequest: Missing mandatory Hostname tag on certificate $CertificateName in vault $VaultName.")
    }
    Write-Log -Section 'New-CertificateRenewalRequest' -Message "Hostname: $Hostname"

    # get PfxProtectTo from the certificate tags
    $rawPfxProtectTo = $cert.Tags['PfxProtectTo']
    $PfxProtectTo = Convert-PfxProtectToFromTag -TagValue $rawPfxProtectTo
    if (-not $PfxProtectTo -or $PfxProtectTo.Count -eq 0) {
        throw [System.Exception]::new("New-CertificateRenewalRequest: Missing mandatory PfxProtectTo tag on certificate $CertificateName in vault $VaultName.")
    }
    Write-Log -Section 'New-CertificateRenewalRequest' -Message "PfxProtectTo principals: $($PfxProtectTo -join ', ')"

    Write-Log -Section 'New-CertificateRenewalRequest' -Message "Certificate $CertificateName details: Subject: $CertificateSubject, Template: $certificateTemplateName ($oid)"

    if ($null -eq $CertificateDnsNames) {
        Write-Log -Section 'New-CertificateRenewalRequest' -Message 'Certificate DNS Names: N/A'
    }
    else {
        Write-Log -Section 'New-CertificateRenewalRequest' -Message "Certificate DNS Names: $($CertificateDnsNames -join ', ')"
    }

    # Now we have all the details to create the renew request.
    # Renew actually uses same code as New-CertificateCreationRequest, so we can reuse it.
    # Exceptions will be caught directly in the main section of the script
    Write-Log -Section 'New-CertificateRenewalRequest' -Message "Got all required information to process the certificate renewal request for $CertificateName in vault $VaultName"
    Write-Log -Section 'New-CertificateRenewalRequest' -Message 'The operation will now continue as a new certificate creation request. See next log entries for details.'
    New-CertificateCreationRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplateName $certificateTemplateName -CertificateSubject $CertificateSubject -CertificateDnsNames $CertificateDnsNames -CA $CA -Hostname $Hostname -PfxProtectTo $PfxProtectTo
}

##############################################
# FUNCTIONS - New-CertificateCreationRequest #
##############################################

# Create a new certificate request to the specified CA using the provided details.
# The certificate is created in the specified Key Vault, which generates the private key and CSR.
function New-CertificateCreationRequest {
    param (
        [Parameter(Mandatory = $true)][string]$VaultName,
        [Parameter(Mandatory = $true)][string]$CertificateName,
        [Parameter(Mandatory = $true)][string]$CertificateTemplateName,
        [Parameter(Mandatory = $true)][string]$CertificateSubject,
        [Parameter()][string[]]$CertificateDnsNames,
        [Parameter(Mandatory = $true)][string]$CA,
        [Parameter(Mandatory = $true)][string]$Hostname,
        [Parameter(Mandatory = $true)][string[]]$PfxProtectTo
    )

    # prepare tags for the certificate
    $tagPfxValue = Convert-PfxProtectToForTag -Value $PfxProtectTo
    $tags = @{
        'PfxProtectTo'            = $tagPfxValue
        'CertificateTemplateName' = $CertificateTemplateName
    }
    if ($Hostname) { $tags['Hostname'] = $Hostname }

    # create certificate CSR - if a previous request is in progress, reuse it
    $csr = $null
    try {
        $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertificateName | Where-Object { $_.Status -eq 'inProgress' }
    }
    catch { throw [System.Exception]::new('New-CertificateCreationRequest, KeyVault: Error querying existing certificate operation', $_.Exception) }
    if ($null -ne $op) {
        Write-Log -Section 'New-CertificateCreationRequest' -Message "KeyVault: Certificate request is already in progress in $VaultName for this certificate: $CertificateName; reusing the existing request." -Level 'Warning'
        $csr = $op.CertificateSigningRequest
    }
    else {
        Write-Log -Section 'New-CertificateCreationRequest' -Message "Creating a new CSR for certificate $CertificateName in key vault $VaultName..."
        if ($null -ne $CertificateDnsNames) {
            $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType 'application/x-pkcs12' -SubjectName $CertificateSubject -IssuerName 'Unknown' -DnsName $CertificateDnsNames
        }
        else {
            $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType 'application/x-pkcs12' -SubjectName $CertificateSubject -IssuerName 'Unknown'
        }
        try {
            $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -CertificatePolicy $Policy -Tag $tags
        }
        catch {
            throw [System.Exception]::new('New-CertificateCreationRequest, KeyVault: Error generating CSR in Key Vault', $_.Exception)
        }
        $csr = $result.CertificateSigningRequest
    }

    # see https://www.sysadmins.lv/blog-en/introducing-to-certificate-enrollment-apis-part-3-certificate-request-submission-and-response-installation.aspx

    # CR_IN_BASE64HEADER = 0x0,
    # CR_IN_BASE64 = 0x1,
    # CR_IN_BINARY = 0x2,
    # CR_IN_ENCODEANY = 0xff,
    # CR_OUT_BASE64HEADER = 0x0,
    # CR_OUT_BASE64 = 0x1,
    # CR_OUT_BINARY = 0x2

    Write-Log -Section 'New-CertificateCreationRequest' -Message "CA: Sending request to the CA $CA using template $($CertificateTemplateName) for certificate $CertificateName..."
    try {
        $CertRequest = New-Object -ComObject CertificateAuthority.Request
        $CertRequestStatus = $CertRequest.Submit(0x1, $csr, "CertificateTemplate:$CertificateTemplateName", $CA)
    }
    catch { throw [System.Exception]::new("New-CertificateCreationRequest: CA: Error submitting request to $CA", $_.Exception) }

    switch ($CertRequestStatus) {
        2 { throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request was denied. Check the CA $CA for details.") }
        3 {
            Write-Log -Section 'New-CertificateCreationRequest' -Message "CA: Certificate Request for $CertificateName submitted successfully."
            try {
                $CertEncoded = $CertRequest.GetCertificate(0x0)
            }
            catch {
                throw [System.Exception]::new("New-CertificateCreationRequest: CA: Error retrieving issued certificate from CA $CA", $_.Exception)
            }
            Write-Log -Section 'New-CertificateCreationRequest' -Message "Certificate received from CA $CA"
        }
        5 {
            throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request to $CA is pending. This runbook expects immediate issuance. Review template/CA configuration.")
        }
        default {
            throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request to $CA failed with status $CertRequestStatus")
        }
    }

    # we need to save the certificate in a temporary file because the Import-AzKeyVaultCertificate cmdlet does not accept a base64 string as input
    $CertEncodedFile = New-TemporaryFile
    Set-Content -Path $CertEncodedFile -Value $CertEncoded

    # import the certificate into the key vault
    Write-Log -Section 'New-CertificateCreationRequest' -Message "KeyVault: Importing the certificate $CertificateName into the key vault $VaultName..."
    try {
        $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -FilePath $CertEncodedFile
        if ($null -eq $newCert) {
            throw [System.Exception]::new('New-CertificateCreationRequest: KeyVault: Error importing certificate into the key vault: returned null result.')
        }
    }
    catch {
        throw [System.Exception]::new("New-CertificateCreationRequest: KeyVault: Error importing certificate $CertificateName into key vault $VaultName", $_.Exception)
    }
    finally {
        # Always remove temporary file
        Remove-Item -Path $CertEncodedFile -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Section 'New-CertificateCreationRequest' -Message "KeyVault: Certificate $CertificateName imported into the key vault $($VaultName)."

    # Create root folder if needed
    if (-not (Test-Path -Path $PfxRootFolder)) {
        Write-Log -Section 'New-CertificateCreationRequest' -Message "PFX: Creating the PFX root folder: $PfxRootFolder"
        New-Item -Path $PfxRootFolder -ItemType Directory -Force | Out-Null
    }
    Write-Log -Section 'New-CertificateCreationRequest' -Message "PFX: Root folder verified: $PfxRootFolder"

    $PfxTargetFolder = Join-Path -Path $PfxRootFolder -ChildPath $Hostname

    if (-not (Test-Path -Path $PfxTargetFolder)) {
        Write-Log -Section 'New-CertificateCreationRequest' -Message "PFX: Creating the target folder for PFX: $PfxTargetFolder"
        New-Item -Path $PfxTargetFolder -ItemType Directory -Force | Out-Null
    }

    # Set ACLs on the target folder. This operation is repeated, for security, even if the folder already exists.
    try {
        # Start with current ACL, then fully protect (no inheritance, do not preserve inherited ACEs)
        $acl = Get-Acl -Path $PfxTargetFolder
        $acl.SetAccessRuleProtection($true, $false)  # protect; remove inherited

        # Remove any existing explicit ACEs so only our defined set remains
        foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRule($rule) }

        $inheritFlags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propFlags = [System.Security.AccessControl.PropagationFlags]::None

        # Required full-control principals
        foreach ($adm in @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
            $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($adm, 'FullControl', $inheritFlags, $propFlags, 'Allow')
            $acl.AddAccessRule($ace)
        }

        # Limited principals (Read & Execute)
        foreach ($principal in $PfxProtectTo) {
            if ([string]::IsNullOrWhiteSpace($principal)) { continue }
            $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($principal, 'ReadAndExecute', $inheritFlags, $propFlags, 'Allow')
            $acl.AddAccessRule($ace)
        }

        Set-Acl -Path $PfxTargetFolder -AclObject $acl
        Write-Log -Section 'New-CertificateCreationRequest' -Message "PFX: ACL set on target folder (inheritance disabled, custom ACEs only): $PfxTargetFolder"
    }
    catch {
        throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Error setting permissions on $PfxTargetFolder", $_.Exception)
    }

    $pfxFile = Join-Path -Path $PfxTargetFolder -ChildPath "$($CertificateName).pfx"
    Write-Log -Section 'New-CertificateCreationRequest' -Message "PFX: Export path: $pfxFile"

    Write-Log -Section 'New-CertificateCreationRequest' -Message "PFX: Retrieving secret for $CertificateName from vault $VaultName..."
    try {
        $certBase64 = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertificateName -AsPlainText
    }
    catch {
        throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Error retrieving secret for $CertificateName", $_.Exception)
    }
    if ([string]::IsNullOrEmpty($certBase64)) {
        throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Retrieved secret is empty for $CertificateName")
    }

    $certBytes = [Convert]::FromBase64String($certBase64); $certBase64 = $null
    $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes, [string]::Empty, 'Exportable')
    $certBytes = $null
    if (-not $x509Cert.HasPrivateKey) {
        $x509Cert = $null; throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Private key missing for $CertificateName")
    }
    try {
        $null = $x509Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
    }
    catch {
        $x509Cert = $null; throw [System.Exception]::new('New-CertificateCreationRequest: PFX: Private key not exportable', $_.Exception)
    }

    if (Test-Path -Path $pfxFile) {
        Write-Log -Section 'New-CertificateCreationRequest' -Message "PFX: Removing existing file $pfxFile"
        try {
            Remove-Item -Path $pfxFile -Force
        }
        catch {
            $x509Cert = $null; throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Cannot remove existing file $pfxFile", $_.Exception)
        }
    }

    try {
        Export-PfxWithGroupProtection -Cert $x509Cert -ProtectTo $PfxProtectTo -PfxFile $pfxFile
    }
    catch {
        throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Export failure for $CertificateName", $_.Exception)
    }
    finally {
        $x509Cert = $null
    }

    if (-not (Test-Path -Path $pfxFile)) {
        throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Export did not create $pfxFile")
    }
    Write-Log -Section 'New-CertificateCreationRequest' -Message "PFX: Certificate $CertificateName exported to $pfxFile"
}

################################################
# FUNCTIONS - New-CertificateRevocationRequest #
################################################

# Revoke an existing certificate in Key Vault by sending a revocation request to the specified CA.
function New-CertificateRevocationRequest {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 6)]
        [Int64]$RevocationReason
    )

    # get the certificate from the key vault
    Write-Log -Section 'New-CertificateRevocationRequest' -Message "KeyVault: Certificate $($CertificateName): getting the certificate from key vault $VaultName to obtain details..."
    try {
        $certBase64 = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertificateName -AsPlainText
    }
    catch {
        throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Error getting certificate $CertificateName from key vault $VaultName", $_.Exception)
    }
    if ([string]::IsNullOrEmpty($certBase64)) {
        throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Certificate $CertificateName secret is empty in key vault $VaultName")
    }

    # convert the base64 string to a byte array and create an X509Certificate2 object
    $certBytes = [Convert]::FromBase64String($certBase64)
    $certBase64 = $null
    $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes, [string]::Empty, 'Exportable')
    # $x509Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes, [string]::Empty, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
    # save the serial number
    $serialNumber = $x509Cert.SerialNumber

    # cleanup objects that are no longer needed
    $x509Cert = $null      
    $certBytes = $null

    Write-Log -Section 'New-CertificateRevocationRequest' -Message "CA: Sending revocation request for certificate $CertificateName to the CA $CA using reason $($RevocationReason)..."

    try {
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
        $certadmin.RevokeCertificate($CA, $serialNumber, $RevocationReason, 0)
    }
    catch {
        throw [System.Exception]::new("New-CertificateRevocationRequest: CA: Error revoking certificate $CertificateName in CA $CA", $_.Exception)
    }
    Write-Log -Section 'New-CertificateRevocationRequest' -Message "CA: Certificate $CertificateName revoked successfully in CA $($CA)."

    # remove the certificate from the key vault
    Write-Log -Section 'New-CertificateRevocationRequest' -Message "KeyVault: Removing certificate $CertificateName from key vault $($VaultName)..."
    try {
        Remove-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -Force
    }
    catch {
        throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Error removing certificate $CertificateName from key vault $VaultName", $_.Exception)
    }
    Write-Log -Section 'New-CertificateRevocationRequest' -Message "KeyVault: Certificate $CertificateName removed from key vault $($VaultName)."
}

####################
# MAIN DISPATCHER  #
####################

# Connect to Azure. Ensures we do not inherit an AzContext, since we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
Write-Log -Section 'Dispatcher' -Message 'Connecting to Azure using default identity...'
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    Invoke-LogAndThrow -Section 'Dispatcher' -Message 'There is no system-assigned user identity.' -Inner $_.Exception
}

# set context
Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection | Out-Null

# Check if the script is running on Azure or on hybrid worker; assign jobId accordingly.
# https://rakhesh.com/azure/azure-automation-powershell-variables/
if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation/') {
    # We are in a Hybrid Runbook Worker
    $jobId = $env:PSPrivateMetadata
    Write-Log -Section 'Dispatcher' -Message "Runbook running with job id $jobId on hybrid worker $($env:COMPUTERNAME)."
}
elseif ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
    # We are in Azure Automation
    $jobId = $PSPrivateMetadata.JobId
    Invoke-LogAndThrow -Section 'Dispatcher' -Message "Runbook running with job id $jobId in Azure Automation. This runbook must be executed by a hybrid worker instead!"
}
else {
    # We are in a local environment - not supported anymore because we cannot get the encrypted variables from the automation account in this case
    Invoke-LogAndThrow -Section 'Dispatcher' -Message 'Runbook running in a local environment. This runbook must be executed by a hybrid worker instead!'
}

 # TODO: decide if we want to use $jobId as correlation id in the logs

# Automation account variables
# Note: since they are encrypted, you must use the internal cmdlet Get-AutomationVariable to retrieve them, not Get-AzAutomationVariable

try {
    # Get the CA from the automation account variable
    $CA = Get-AutomationVariable -Name 'certlc-ca'
}
catch { Invoke-LogAndThrow -Section 'Dispatcher' -Message "Error getting automation account variable 'certlc-ca'. Ensure the variable exists in the automation account!" -Inner $_.Exception }
# Ensure the CA variable is not empty
if ([string]::IsNullOrEmpty($CA)) { Invoke-LogAndThrow -Section 'Dispatcher' -Message "The automation account variable 'certlc-ca' is empty!" }

try {
    # Get the PfxRootFolder from the automation account variable
    $PfxRootFolder = Get-AutomationVariable -Name 'certlc-pfxrootfolder'
}
catch { Invoke-LogAndThrow -Section 'Dispatcher' -Message "Error getting automation account variable 'certlc-pfxrootfolder'. Ensure the variable exists in the automation account!" -Inner $_.Exception }
# Ensure the PfxRootFolder variable is not empty
if ([string]::IsNullOrEmpty($PfxRootFolder)) { Invoke-LogAndThrow -Section 'Dispatcher' -Message "The automation account variable 'certlc-pfxrootfolder' is empty!" }

# Check if we have the jsonRequestBody parameter
if ([string]::IsNullOrEmpty($jsonRequestBody)) {

    # No explicit RequestBody parameter, so we will use WebhookData
    # Try to parse the webhook data

    if ([string]::IsNullOrEmpty($WebhookData)) { Invoke-LogAndThrow -Section 'Dispatcher' -Message 'Both RequestBody and WebhookData parameters are missing or empty! Call the runbook from a webhook or pass the RequestBody parameter explicitly with Start-AzAutomationRunbook!' }

    Write-Log -Section 'Dispatcher' -Message "WebhookData received is: $($WebhookData)"

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

        Write-Log -Section 'Dispatcher' -Message 'Failed to parse WebhookData as JSON. Attempting to extract RequestBody using regex...' -Level 'Warning'

        if ($WebhookData -match '"?RequestBody"?\s*:\s*((?:{([^{}]|(?<open>{)|(?<-open>}))*(?(open)(?!))})|(?:\[([^\[\]]|(?<open>\[)|(?<-open>\]))*(?(open)(?!))\]))') {
            $jsonRequestBody = $matches[1]
            try {
                $RequestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10
            }
            catch {
                Invoke-LogAndThrow -Section 'Dispatcher' -Message 'Failed to parse WebhookData.RequestBody using regex' -Inner $_.Exception
            }
        }
        else { Invoke-LogAndThrow -Section 'Dispatcher' -Message 'WebhookData.RequestBody not recognized using regex!' }
    }

    if ([string]::IsNullOrEmpty($requestBody)) { Invoke-LogAndThrow -Section 'Dispatcher' -Message 'WebhookData.RequestBody is empty! Ensure the runbook is called from a webhook!' }
}

else {
    # parse the jsonRequestBody parameter as JSON
    Write-Log -Section 'Dispatcher' -Message "jsonRequestBody received is: $($jsonRequestBody)"
    try {
        $requestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10
    }
    catch { Invoke-LogAndThrow -Section 'Dispatcher' -Message 'Failed to parse jsonRequestBody parameter as JSON' -Inner $_.Exception }
}

# now that we have a valid requestBody object, check some fields and detect request type

# check version
if ([string]::IsNullOrEmpty($requestBody.specversion)) { Invoke-LogAndThrow -Section 'Dispatcher' -Message "Missing or empty mandatory string parameter: 'specversion' in request body!" }
if ($requestBody.specversion -ne $Version) { Invoke-LogAndThrow -Section 'Dispatcher' -Message "The version specified in the request, $($requestBody.specversion), does not match the script version $Version!" }
else {
    Write-Log -Section 'Dispatcher' -Message "specversion: $($requestBody.specversion)"
}

if ([string]::IsNullOrEmpty($requestBody.type)) { Invoke-LogAndThrow -Section 'Dispatcher' -Message "Missing or empty mandatory string parameter: 'type' in request body!" }
else { Write-Log -Section 'Dispatcher' -Message "request type: $($requestBody.type)" }



# Process requests based on type

switch ($requestBody.type) {

    'Microsoft.KeyVault.CertificateNearExpiry' {

        # get parameters
        $VaultName = $requestBody.data.VaultName
        $CertificateName = $requestBody.data.ObjectName

        # start formal validation of mandatory parameters
        if ([string]::IsNullOrEmpty($VaultName)) { Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'VaultName'!" }
        if ([string]::IsNullOrEmpty($CertificateName)) { Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'ObjectName'!" }

        # invoke renewal
        Write-Log -Section 'Dispatcher.Request' -Message "Performing certificate renewal for certificate $CertificateName in vault $VaultName..."
        try {
            New-CertificateRenewalRequest -VaultName $VaultName -CertificateName $CertificateName -CA $CA
        }
        catch { Invoke-LogAndThrow -Section 'Dispatcher.Request' -Message 'Error processing certificate renew request' -Inner $_.Exception }

        # confirm completion
        Write-Log -Section 'Dispatcher' -Message "Certificate $CertificateName was successfully renewed."
    }

    'CertLC.NewCertificateRequest' {

        # get parameters
        $VaultName = $requestBody.data.VaultName
        $CertificateName = $requestBody.data.ObjectName
        $CertificateTemplate = $requestBody.data.CertificateTemplate
        $CertificateSubject = $requestBody.data.CertificateSubject
        $CertificateDnsNames = $requestBody.data.CertificateDnsNames
        $Hostname = $requestBody.data.Hostname
        $PfxProtectTo = $requestBody.data.PfxProtectTo

        # start formal validation of mandatory parameters:

        # VaultName: presence and non-empty check
        if ([string]::IsNullOrEmpty($VaultName)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'data.VaultName' in request body!"
        }

        # CertificateName: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateName)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'data.ObjectName' in request body!"
        }

        # CertificateName: check if the certificate already exists in the key vault
        try {
            $deletedCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -InRemovedState
        }
        catch {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message 'Error checking for deleted certificate' -Inner $_.Exception
        }
        if (($null -ne $deletedCert) -and ($null -ne $deletedCert.DeletedDate)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Certificate $CertificateName is deleted since $($deletedCert.DeletedDate). Purge it or use a different name."
        }

        # CertificateTemplate: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateTemplate)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'data.CertificateTemplate' in request body!"
        }

        # CertificateTemplate: check if the template exists in AD; caller may have specified the template name (CN) or the display name or the OID. We need the 'name' attribute
        try {
            $CertificateTemplateName = Find-TemplateName -cnOrDisplayNameOrOid $CertificateTemplate
        }
        catch {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message 'Error resolving template name' -Inner $_.Exception
        }
        if ([string]::IsNullOrEmpty($CertificateTemplateName)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Certificate template $CertificateTemplate not found in Active Directory!"
        }

        # CertificateSubject: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateSubject)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'data.CertificateSubject' in request body!"
        }

        # DnsNames (optional, but if specified, must be an array)
        if ($CertificateDnsNames -and $CertificateDnsNames -isnot [array]) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Parameter 'CertificateDnsNames' is not an array!"
        }

        # Hostname
        if ([string]::IsNullOrWhiteSpace($Hostname)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'data.Hostname' in request body!"
        }
        $originalHostname = $Hostname
        $Hostname = $Hostname.Trim().ToLower()
        if (-not (Test-HostnameFormat -Hostname $Hostname)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Hostname '$Hostname' contains invalid characters."
        }
        if (-not $originalHostname.Equals($Hostname, 'OrdinalIgnoreCase')) {
            Write-Log -Section 'Dispatcher.Validation' "Hostname normalized: '$originalHostname' -> '$Hostname'"
        }

        # PfxProtectTo
        if (-not $PfxProtectTo) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing mandatory parameter 'PfxProtectTo'!"
        }
        $PfxProtectTo = Format-PfxProtectTo -InputValue $PfxProtectTo
        if ($PfxProtectTo.Count -eq 0) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message 'PfxProtectTo list is empty after normalization!'
        }

        # end of validation. Now process the new certificate request

        if ($null -ne $CertificateDnsNames) {
            Write-Log -Section 'Dispatcher.Request' -Message "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplateName, subject $CertificateSubject, DNS names $($CertificateDnsNames -join ', '), Hostname $Hostname, PfxProtectTo $($PfxProtectTo -join ', ')..."
        }
        else {
            Write-Log -Section 'Dispatcher.Request' -Message "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplateName, subject $CertificateSubject, Hostname $Hostname, PfxProtectTo $($PfxProtectTo -join ', ')..."
        }

        try {
            New-CertificateCreationRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplateName $CertificateTemplateName -CertificateSubject $CertificateSubject -CertificateDnsNames $CertificateDnsNames -CA $CA -Hostname $Hostname -PfxProtectTo $PfxProtectTo
        }
        catch {
            Invoke-LogAndThrow -Section 'Dispatcher.Request' -Message 'Error processing new certificate request' -Inner $_.Exception
        }

        # confirm completion
        Write-Log -Section 'Dispatcher' -Message "Certificate $CertificateName was successfully created."
    }

    'CertLC.CertificateRevocationRequest' {

        # get required parameters
        $VaultName = $requestBody.data.VaultName
        $CertificateName = $requestBody.data.ObjectName
        $RevocationReasonString = $requestBody.data.RevocationReason

        # VaultName: presence and non-empty check
        if ([string]::IsNullOrEmpty($VaultName)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'data.VaultName' in request body!"
        }

        # CertificateName: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateName)) {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'data.ObjectName' in request body!"
        }

        # RevocationReason: presence and integer check
        $RevocationReason = $null
        if (-not [string]::IsNullOrEmpty($RevocationReasonString)) {
            # try to convert to integer
            try {
                $RevocationReason = [Int64]::Parse($RevocationReasonString)
            }
            catch { Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Invalid integer value for 'data.RevocationReason' in request body!" -Inner $_.Exception }
        }
        else {
            Invoke-LogAndThrow -Section 'Dispatcher.Validation' -Message "Missing or empty mandatory string parameter: 'data.RevocationReason' in request body!"
        }

        # RevocationReason: see https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-revokecertificate
        # 0 = CRL_REASON_UNSPECIFIED,
        # 1 = CRL_REASON_KEY_COMPROMISE,
        # 2 = CRL_REASON_CA_COMPROMISE,
        # 3 = CRL_REASON_AFFILIATION_CHANGED,
        # 4 = CRL_REASON_SUPERSEDED,
        # 5 = CRL_REASON_CESSATION_OF_OPERATION,
        # 6 = CRL_REASON_CERTIFICATE_HOLD

        if ($RevocationReason -notin 0, 1, 2, 3, 4, 5, 6) { Invoke-LogAndThrow -Section 'Dispatcher' -Message "Revocation request validation: Invalid integer value for 'data.RevocationReason'. Supported: 0-6." }

        # end of validation. Now process the certificate revocation request

        Write-Log -Section 'Dispatcher.Request' -Message "Performing certificate revocation request for certificate $CertificateName using vault $VaultName with reason $RevocationReason..."
        try {
            New-CertificateRevocationRequest -VaultName $VaultName -CertificateName $CertificateName -RevocationReason $RevocationReason
        }
        catch {
            Invoke-LogAndThrow -Section 'Dispatcher.Request' -Message 'Error processing certificate revocation request' -Inner $_.Exception
        }

        # confirm completion
        Write-Log -Section 'Dispatcher' -Message "Certificate $CertificateName was successfully revoked."
    }

    default {
        Invoke-LogAndThrow -Section 'Dispatcher' -Message "Unknown request type: $($requestBody.type). Supported values: Microsoft.KeyVault.CertificateNearExpiry, CertLC.NewCertificateRequest, CertLC.CertificateRevocationRequest."
    }
}