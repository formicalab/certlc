#Requires -PSEdition Core
# Only these modules own the Az commands used by this runbook.
using module Az.Accounts
using module Az.KeyVault

##########
# CERTLC #
##########

<#

CERTLC is a PowerShell runbook that automates the process of obtaining, renewing or revoking certificates from an AD CA integrated with Azure Key Vault.
The key vault is used to generate all requests, storing the private keys safely.

The script is designed to be run using PowerShell 7.x in an Azure Automation hybrid worker environment.
Initially based on certlc solution https://learn.microsoft.com/en-us/azure/architecture/example-scenario/certificate-lifecycle/

#>

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
See the code in main Dispatcher section for details and workaround.

We assume that WebhookData.RequestBody is a JSON string using CloudEventSchema.

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
    "NotifyTo": [ "<email address to notify>", "other email address", ... ],  # optional, email addresses to notify when the certificate is created
  }
}

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
    "CertificateThumbprint": "<certificate thumbprint>",
    "RevocationReason": "1"  # see https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-revokecertificate for possible values
  }
}

Revocation semantics:
- The thumbprint may refer to ANY version of the certificate in the key vault (latest or older).
  The runbook locates the specific version whose x5t matches the supplied thumbprint.
- The CA revokes the corresponding serial number using the supplied reason code.
- In Key Vault, the matched version is set to attributes.enabled=false and tagged with
  Revoked=true, RevokedAt=<UTC ISO-8601>, RevocationReason=<n>, RevokedJobId=<automation job id>.
  Existing tags on the version (e.g. NotifyTo, Hostname, PfxProtectTo) are preserved.
- The certificate object and other versions of the same certificate are NEVER deleted or modified.
- If the revoked version is the latest version of the certificate, a warning is logged and
  any subsequent CertificateNearExpiry event for the same certificate is ignored by the
  renewal flow (it checks the latest version's Revoked tag and exits without renewing).

You can also pass the jsonRequestBody parameter explicitly, which must be a JSON string with the same structure as above.
In this case, use the Start-AzAutomationRunbook cmdlet to start the runbook, passing the jsonRequestBody parameter:

Start-AzAutomationRunbook -Name "certlc" -Parameters @{ 'jsonRequestBody'=$jsonRequestBody }

Where $jsonRequestBody is a JSON string containing the RequestBody (the same as WebhookData.RequestBody when the webhook is used).

Correlation comes only from the parsed jsonRequestBody's top-level nonblank string id,
never data.Id or the Automation job ID. This is the Function's input path, not proof of
caller identity: other callers supplying jsonRequestBody have the same behavior.
Direct WebhookData calls, startup, and missing/invalid event IDs omit correlationId.
Logs include the separate jobId field once the actual Automation job ID is discovered.
Correlation is diagnostic only: audit tags and notification job references always use the actual job ID.

#>

<# Strict mode settings 3.0:
Prohibits references to uninitialized variables. This includes uninitialized variables in strings.
Prohibits references to non-existent properties of an object.
Prohibits function calls that use the syntax for calling methods.
Prohibit out of bounds or unresolvable array indexes.
#>
Set-StrictMode -Version 3.0

# Ensure the script stops on errors
$ErrorActionPreference = 'Stop'

#region ### Static settings and global variables ###

###################################
# STATIC SETTINGS AND GLOBAL VARS #
###################################

# CloudEvents envelope contract, not the runbook release version.
$CloudEventSpecVersion = '1.0'

# Correlation stays unknown until the Function-path payload supplies a valid event id.
# Keep invocation state distinct from the logging helpers' optional override parameters.
$script:CertLCCorrelationId = ''

<# Unified SMTP / Email layout
 New-CertLCNotificationBody supplies fixed success/error colors and spacing to one layout.
 $CertificateErrorEmailSectionHtml is inserted only when substantive error details exist.

 Usage (example):
     $body = New-CertLCNotificationBody -Title 'Certificate renewed' -Summary 'Renewal completed.' -Details ([ordered]@{ Certificate = $name })
   Send-NotificationEmail -Body $body ...
#>

$CertificateNotificationEmailBodyHtml = @'
<html>
    <body style="margin:0;padding:0;background:#eef2f6;font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.5;color:#17202a;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;background:#eef2f6;">
            <tr>
                <td align="center" style="padding:24px 12px;">
                    <table role="presentation" width="640" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:640px;background:#ffffff;border:1px solid __BORDER_COLOR__;">
                        <tr><td style="padding:22px 24px;background:__HEADER_COLOR__;color:#ffffff;font-size:20px;font-weight:600;">__TITLE__</td></tr>
                        <tr><td style="padding:18px 24px 8px;color:#263746;">__SUMMARY__</td></tr>
                        <tr><td style="padding:10px 24px __DETAILS_BOTTOM_PADDING__;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;border:1px solid #d8e2ec;">__DETAILS__</table>
                        </td></tr>
                        __ERROR_SECTION__
                        <tr><td style="padding:14px 24px;background:#f7f9fb;border-top:1px solid #d8e2ec;font-size:11px;color:#5a6b7b;">__FOOTER__</td></tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
</html>
'@

$CertificateErrorEmailSectionHtml = @'
                        <tr><td style="padding:0 24px 24px;">
                            <div style="background:#fff1f0;border:1px solid #f3b7b2;padding:14px 16px;color:#7a271a;font-family:Consolas,'Courier New',monospace;font-size:12px;line-height:1.5;">__ERROR_DETAILS__</div>
                        </td></tr>
'@

# Error notifications can be raised at any point in a dispatcher path. This ordered map is
# initialized empty for the runbook invocation and replaced when the request type is known.
# Each dispatcher then enriches it as validated values become available, allowing failures to
# include useful context without requiring every call to Write-CertLCLogAndThrow to repeat it.
$script:CertificateNotificationContext = [ordered]@{}

#endregion

#region ### Write-CertLCLog ###

###############################
# FUNCTIONS - Write-CertLCLog #
###############################

<#

.SYNOPSIS
    Emit a structured JSON log entry

.DESCRIPTION
    Writes a single-line JSON object with standard fields plus optional custom context.
    The log entry is written to the output stream, warning stream, or verbose stream depending on the Level parameter.

.PARAMETER Message
    The log message.

.PARAMETER Level
    The log level. Possible values: Information (default), Warning, Error, Verbose.

.PARAMETER Section
    The section or context of the log entry (e.g., function name).

.PARAMETER CorrelationId
    An optional nonblank event-ID override for logging helpers, never a job-ID fallback.
    Blank values inherit the runbook's event correlation, including error-helper forwarding.

.PARAMETER Context
    An optional hashtable of additional context to include in the log entry.

.PARAMETER JsonDepth
    The maximum depth for JSON serialization of the log entry. Default is 5.

.EXAMPLE
    Write-CertLCLog -Message "Certificate created successfully" -Level "Information" -Section "Create-Certificate" -CorrelationId $correlationId -Context @{ certName = $certName; vaultName = $vaultName } -JsonDepth 3

.NOTES
    The log entry is a single-line JSON object with the following fields:
    - timestamp: ISO 8601 formatted timestamp of the log entry
    - level: log level
    - section: section or context of the log entry
    - message: log message
    - correlationId: optional event ID
    - jobId: actual Automation execution ID, when discovered
    - additional fields from the Context hashtable, with keys prefixed with "ctx_" if they conflict with reserved keys

    Reserved keys that cannot be used in Context without prefixing: timestamp, level, message, section, correlationId, jobId

    If JSON serialization fails, an error log entry is emitted instead.

#>

function Write-CertLCLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter()][ValidateSet('Information', 'Warning', 'Error', 'Verbose')][string]$Level = 'Information',
        [Parameter(Mandatory)][string]$Section,
        [Parameter()][string]$CorrelationId,
        [Parameter()][hashtable]$Context,
        [Parameter()][int]$JsonDepth = 5
    )

    # Execution identity is owned by the runbook, not caller-supplied log context.
    $reservedKeys = 'timestamp', 'level', 'message', 'section', 'correlationId', 'jobId'
    $entry = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        level     = $Level
        section   = $Section
        message   = $Message
    }
    # Resolve blank forwarded arguments as defaults, not overrides. Get-Variable also lets
    # this helper log early failures or run in isolation without uninitialized-variable errors.
    $effectiveCorrelationId = $CorrelationId
    if ([string]::IsNullOrWhiteSpace($effectiveCorrelationId)) {
        $correlationVariable = Get-Variable -Name CertLCCorrelationId -Scope Script -ErrorAction Ignore
        # PSVariable always exposes Value; default only null and retain the whitespace checks.
        $effectiveCorrelationId = [string](${correlationVariable}?.Value ?? '')
    }
    if (-not [string]::IsNullOrWhiteSpace($effectiveCorrelationId)) {
        $entry.correlationId = $effectiveCorrelationId
    }

    # Discovery can fail before jobId exists. Keep early/isolated logging StrictMode-safe
    # and never substitute execution identity for an absent event identity.
    $jobVariable = Get-Variable -Name jobId -Scope Script -ErrorAction Ignore
    # PSVariable.Value is defined even when its value is null; keep the result string-typed.
    $executionJobId = [string](${jobVariable}?.Value ?? '')
    if (-not [string]::IsNullOrWhiteSpace($executionJobId)) {
        $entry.jobId = $executionJobId
    }

    # Preserve logger-owned identity fields when callers supply overlapping context keys.
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
        # Drop the problematic context but preserve workbook fields and known correlation.
        # Serialize only scalar strings here, independently of the caller's requested depth.
        $fallbackEntry = [ordered]@{
            timestamp = (Get-Date).ToString('o')
            level = 'Error'
            section = $Section
            message = 'Failed to serialize log entry'
            originalMessage = $Message
            serializationError = $_.Exception.Message
        }
        if (-not [string]::IsNullOrWhiteSpace($effectiveCorrelationId)) {
            $fallbackEntry.correlationId = $effectiveCorrelationId
        }
        # Preserve the independently discovered job even if custom context cannot serialize.
        if (-not [string]::IsNullOrWhiteSpace($executionJobId)) {
            $fallbackEntry.jobId = $executionJobId
        }
        $json = $fallbackEntry | ConvertTo-Json -Compress
    }

    switch ($Level) {
        'Error' { Write-Output $json }    # don't use Write-Error to avoid breaking Automation job log parsing
        'Warning' { Write-Warning $json }
        'Verbose' { Write-Verbose $json }
        default { Write-Output $json }
    }
}

#endregion

#region ### Send-NotificationEmail ###

######################################
# FUNCTIONS - Send-NotificationEmail #
######################################

<#

.SYNOPSIS
    Send a notification email using the specified SMTP server.

.DESCRIPTION
    Sends an email with the specified subject and body to the given recipients using the provided SMTP server.
    Supports optional SMTP authentication.

.PARAMETER SmtpServer
    The SMTP server to use for sending the email.

.PARAMETER FromAddress
    The from address to use for the email.

.PARAMETER To
    An array of recipient email addresses.

.PARAMETER Subject
    The subject of the email.

.PARAMETER Body
    The body of the email (HTML format).

.PARAMETER SmtpCredential
    An optional PSCredential for SMTP authentication.

.EXAMPLE
    $smtpCredential = Get-Credential -UserName "smtpuser" -Message "Enter SMTP password"
    Send-NotificationEmail -SmtpServer "smtp.example.com" -FromAddress "<sender@example.com>" -To "<recipient@example.com>" -Subject "Test Email" -Body "<h1>This is a test email</h1>" -SmtpCredential $smtpCredential

.NOTES
    This function does not throw on failure, but logs a warning instead, to avoid a loop if called from Write-CertLCLogAndThrow.
    The cmdlet Send-MailMessage is used, which now deprecated but still available in PowerShell 7.x, and there is no native replacement yet.
    The cmdlet warning about being deprecated is silenced to avoid polluting the log.
#>

function Send-NotificationEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SmtpServer,
        [Parameter(Mandatory)][string]$FromAddress,
        [Parameter(Mandatory)][string[]]$To,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Body,
        [Parameter()][pscredential]$SmtpCredential
    )

    try {

        # Omit Credential for anonymous relays rather than binding a null credential.
        $mailParameters = @{
            SmtpServer = $SmtpServer
            From = $FromAddress
            To = $To
            Subject = $Subject
            Body = $Body
            BodyAsHtml = $true
            WarningAction = 'SilentlyContinue'
        }
        if ($null -ne $SmtpCredential) { $mailParameters.Credential = $SmtpCredential }
        Send-MailMessage @mailParameters

        Write-CertLCLog -Message "Notification email sent to: $($To -join ', ')" -Section 'Send-NotificationEmail'
    }
    catch {
        # don't throw if email sending fails, just log the error
        Write-CertLCLog -Level 'Warning' -Message "Error sending notification email to $($To -join ', '): $($_.Exception.Message)" -Section 'Send-NotificationEmail'
    }
}

#endregion

#region ### ConvertFrom-CertLCNotifyToTag ###

#############################################
# FUNCTIONS - ConvertFrom-CertLCNotifyToTag #
#############################################

<#
.SYNOPSIS
    Split a certificate's notification tag into trimmed, nonempty email addresses.
.DESCRIPTION
    Preserves address order, casing, and duplicates. Missing tags produce an empty array;
    callers retain their existing logging and optional-notification decisions.
#>
function ConvertFrom-CertLCNotifyToTag {
    [OutputType([string[]])]
    param([AllowNull()][AllowEmptyString()][string]$TagValue)

    # The framework split options perform the same trim/filter pass in one operation.
    $options = [System.StringSplitOptions]::TrimEntries -bor [System.StringSplitOptions]::RemoveEmptyEntries
    $addresses = if ($null -eq $TagValue) { @() } else { $TagValue.Split(';', $options) }
    Write-Output -NoEnumerate @($addresses)
}

#endregion

#region ### ConvertTo-CertLCHtmlText ###

########################################
# FUNCTIONS - ConvertTo-CertLCHtmlText #
########################################

<#
.SYNOPSIS
    Encode a value for safe insertion into a CERTLC HTML notification.

.DESCRIPTION
    HTML-encodes every scalar value before joining collections and embedded newlines with
    trusted HTML line breaks. Callers must pass data values through this function; only fixed
    markup generated by the notification renderer is inserted into templates without encoding.

.PARAMETER Value
    A scalar or collection to render. Null becomes an empty string.

.OUTPUTS
    An HTML-safe string. Collection items and source line breaks are separated by <br />.
#>
function ConvertTo-CertLCHtmlText {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    $encodedValues = @($Value) | ForEach-Object {
        ([System.Net.WebUtility]::HtmlEncode([string]$_)) -replace '\r?\n', '<br />'
    }
    return $encodedValues -join '<br />'
}

#endregion

#region ### New-CertLCNotificationDetailsHtml ###

#################################################
# FUNCTIONS - New-CertLCNotificationDetailsHtml #
#################################################

<#
.SYNOPSIS
    Render an ordered notification detail dictionary as email-compatible table rows.

.DESCRIPTION
    Preserves dictionary order so operational fields appear predictably, omits null and empty
    optional values, and encodes both labels and values. The returned string is trusted table
    markup intended only for the __DETAILS__ placeholder in the CERTLC templates.

.PARAMETER Details
    Label/value pairs to render. Ordered dictionaries are preferred for stable presentation.

.OUTPUTS
    HTML table-row markup, or a single explanatory row when no details are available.
#>
function New-CertLCNotificationDetailsHtml {
    [CmdletBinding()]
    param([Parameter()][System.Collections.IDictionary]$Details)

    if (-not $Details -or $Details.Count -eq 0) {
        return '<tr><td style="padding:10px 12px;color:#5a6b7b;">No additional details are available.</td></tr>'
    }

    # Omit absent optional values, then encode labels and values before inserting HTML.
    $rows = foreach ($entry in $Details.GetEnumerator()) {
        if ($null -eq $entry.Value -or
            ($entry.Value -is [string] -and [string]::IsNullOrWhiteSpace($entry.Value)) -or
            ($entry.Value -is [array] -and $entry.Value.Count -eq 0)) {
            continue
        }
        $label = ConvertTo-CertLCHtmlText -Value $entry.Key
        $value = ConvertTo-CertLCHtmlText -Value $entry.Value
        '<tr><td style="width:34%;padding:9px 12px;border-bottom:1px solid #e4e9ee;background:#f7f9fb;color:#445566;font-weight:600;vertical-align:top;">{0}</td><td style="padding:9px 12px;border-bottom:1px solid #e4e9ee;color:#17202a;word-break:break-word;">{1}</td></tr>' -f $label, $value
    }
    return $rows -join ''
}

#endregion

#region ### New-CertLCCreationNotificationDetails ###

#####################################################
# FUNCTIONS - New-CertLCCreationNotificationDetails #
#####################################################

<#
.SYNOPSIS
    Map a completed creation or renewal result to ordered success-notification details.

.DESCRIPTION
    Reports committed certificate and PFX values. Rendering and correlation remain owned
    by the shared notification renderer; RequestId is supplied explicitly by the caller.
#>
function New-CertLCCreationNotificationDetails {
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$OperationResult,
        [Parameter(Mandatory = $true)][ValidateSet('Creation', 'Renewal')][string]$Operation,
        [Parameter()][AllowNull()][object]$RequestId
    )

    # Preserve the existing email field order, raw values, and timestamp formatting.
    return [ordered]@{
        Operation                   = $Operation
        'Certificate name'          = $OperationResult.CertificateName
        Subject                     = $OperationResult.Subject
        'DNS names'                 = $OperationResult.DnsNames
        Template                    = $OperationResult.TemplateName
        Thumbprint                  = $OperationResult.Thumbprint
        'Serial number'             = $OperationResult.SerialNumber
        Issuer                      = $OperationResult.Issuer
        # Keep validity and persisted-version fields together for operational comparison.
        'Valid from (UTC)'          = $OperationResult.NotBeforeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        'Valid until (UTC)'         = $OperationResult.NotAfterUtc.ToString('yyyy-MM-dd HH:mm:ss')
        'Key Vault'                 = $OperationResult.VaultName
        'Key Vault version'         = $OperationResult.CertificateVersion
        Hostname                    = $OperationResult.Hostname
        # These artifact details describe the verified export, not the requested destination.
        'PFX filename'              = $OperationResult.PfxFileName
        'PFX path'                  = $OperationResult.PfxPath
        'PFX size'                  = "$($OperationResult.PfxSizeBytes) bytes"
        'PFX certificate count'     = $OperationResult.ChainCertificateCount
        'PFX protection principals' = $OperationResult.PfxProtectTo
        # The shared renderer adds the Correlation ID row for every email type.
        'Request ID'                = $RequestId
    }
}

#endregion

#region ### New-CertLCNotificationBody ###

##########################################
# FUNCTIONS - New-CertLCNotificationBody #
##########################################

<#
.SYNOPSIS
    Build a complete success or error notification from the shared embedded HTML layout.

.DESCRIPTION
    Selects error styling and an error section when ErrorDetails is supplied. Dynamic values
    are encoded individually, while the detail rows and fixed footer
    markup remain trusted renderer output. Literal String.Replace calls are used because the
    placeholders are fixed tokens and must not be interpreted as regular expressions.

.PARAMETER Title
    Heading displayed in the colored notification banner.

.PARAMETER Summary
    Short human-readable outcome displayed above the detail table.

.PARAMETER Details
    Ordered label/value pairs rendered into the detail table.

.PARAMETER ErrorDetails
    Optional exception text. Supplying a nonblank value selects error styling and content.

.PARAMETER JobId
    Optional actual Automation execution identifier, labelled separately in the footer.

.PARAMETER CorrelationId
    Optional event ID. Emails fall back to parsed event identity from either input path,
    independently of log routing; absent identity is displayed as Unavailable, never a job ID.

.OUTPUTS
    A complete HTML document suitable for Send-NotificationEmail.
#>
function New-CertLCNotificationBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Summary,
        [Parameter()][System.Collections.IDictionary]$Details,
        [Parameter()][string]$ErrorDetails,
        [Parameter()][string]$JobId,
        [Parameter()][string]$CorrelationId
    )

    # Only fixed renderer-owned values enter CSS or raw markup. Blank error text keeps
    # the success layout; the error section retains its original table row and spacing.
    $isError = -not [string]::IsNullOrWhiteSpace($ErrorDetails)
    $borderColor = $isError ? '#e1b4b4' : '#ccd6e0'
    $headerColor = $isError ? '#b42318' : '#0b5cab'
    $detailsPadding = $isError ? '16px' : '24px'
    $errorSection = $isError ? $CertificateErrorEmailSectionHtml : ''
    $template = $CertificateNotificationEmailBodyHtml.Replace('__BORDER_COLOR__', $borderColor).
        Replace('__HEADER_COLOR__', $headerColor).
        Replace('__DETAILS_BOTTOM_PADDING__', $detailsPadding).
        Replace('__ERROR_SECTION__', $errorSection)
    $footer = 'Automated message &bull; CERTLC'
    # Keep the execution identifier separate from the correlation row in the main details.
    if (-not [string]::IsNullOrWhiteSpace($JobId)) {
        $footer += '<br />Automation Job ID: <span style="word-break:break-all;">' + (ConvertTo-CertLCHtmlText -Value $JobId) + '</span>'
    }
    # Resolve logging correlation first, then the parsed event ID for direct webhook emails.
    # This email-only fallback does not alter the stricter input-path rule used by log records.
    if ([string]::IsNullOrWhiteSpace($CorrelationId)) {
        $correlationVariable = Get-Variable -Name CertLCCorrelationId -Scope Script -ErrorAction Ignore
        # Null defaults do not replace the blank-value checks or the event fallback below.
        $CorrelationId = [string](${correlationVariable}?.Value ?? '')
    }
    if ([string]::IsNullOrWhiteSpace($CorrelationId)) {
        $eventVariable = Get-Variable -Name requestEventId -Scope Script -ErrorAction Ignore
        if ($null -ne $eventVariable -and $eventVariable.Value -is [string]) {
            $CorrelationId = $eventVariable.Value
        }
    }
    # Always display correlation prominently for both outcomes, even for early error emails.
    # Copy details without mutating the caller or allowing custom details to replace identity.
    $emailDetails = [ordered]@{
        'Correlation ID' = if ([string]::IsNullOrWhiteSpace($CorrelationId)) { 'Unavailable (no valid event ID)' } else { $CorrelationId }
    }
    if ($Details) {
        foreach ($detail in $Details.GetEnumerator()) {
            if ($detail.Key -ine 'Correlation ID') { $emailDetails[$detail.Key] = $detail.Value }
        }
    }

    # Only the renderer's table markup bypasses scalar encoding during template expansion.
    $body = $template.Replace('__TITLE__', (ConvertTo-CertLCHtmlText -Value $Title))
    $body = $body.Replace('__SUMMARY__', (ConvertTo-CertLCHtmlText -Value $Summary))
    $body = $body.Replace('__DETAILS__', (New-CertLCNotificationDetailsHtml -Details $emailDetails))
    $body = $body.Replace('__ERROR_DETAILS__', (ConvertTo-CertLCHtmlText -Value $ErrorDetails))
    return $body.Replace('__FOOTER__', $footer)
}

#endregion

#region ### Send-SuccessNotification ###

########################################
# FUNCTIONS - Send-SuccessNotification #
########################################

<#
.SYNOPSIS
    Send a rendered success notification for a completed certificate operation.

.DESCRIPTION
    Provides the shared SMTP guard and rendering path used by creation, renewal, and revocation.
    Notification delivery is deliberately non-fatal because Send-NotificationEmail logs SMTP
    failures rather than turning a completed certificate operation into a failed runbook job.

.PARAMETER Details
    Ordered operation metadata rendered as the notification detail table.

.PARAMETER JobId
    Optional Automation job identifier included in the message footer.

.NOTES
    BodyText remains an alias for Summary so existing callers are backward compatible.
#>
function Send-SuccessNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][Alias('BodyText')][string]$Summary,
        [Parameter()][System.Collections.IDictionary]$Details,
        [Parameter()][string]$JobId,
        [Parameter()][string[]]$NotifyTo,
        [Parameter()][string]$SmtpServer,
        [Parameter()][string]$FromAddress,
        [Parameter()][pscredential]$SmtpCredential
    )

    # Delivery is optional and must not invalidate an already committed certificate operation.
    if (-not $NotifyTo) { return }
    if ([string]::IsNullOrEmpty($SmtpServer)) {
        Write-CertLCLog -Section $Section -Level 'Warning' -Message 'Notification requested but SMTP is not configured. Skipping email notification.'
        return
    }

    $body = New-CertLCNotificationBody -Title $Subject -Summary $Summary -Details $Details -JobId $JobId
    Send-NotificationEmail -SmtpServer $SmtpServer -FromAddress $FromAddress -To $NotifyTo -Subject $Subject -Body $body -SmtpCredential $SmtpCredential
}

#endregion

#region ### Write-CertLCLogAndThrow ###

#######################################
# FUNCTIONS - Write-CertLCLogAndThrow #
#######################################

<#

.SYNOPSIS
    Log an error, send an email notification if needed, and throw a terminating exception.

.DESCRIPTION
    Emits a structured error log (with flattened exception details) and then throws a System.Exception.
    If an InnerException is provided, it is included in the log and wrapped in the thrown exception.
    Sends email notifications to specified addresses if NotifyTo is provided.

    .PARAMETER Message
        The error message to log and include in the exception.

    .PARAMETER Section
        The section or context of the error (e.g., function name).

    .PARAMETER CorrelationId
        An optional nonblank override; blank values inherit the runbook's effective correlation.

    .PARAMETER InnerException
        An optional inner exception to include in the log and wrap in the thrown exception.

    .PARAMETER Context
        An optional hashtable of additional context to include in the log.

    .PARAMETER NotifyTo
        An optional array of email addresses to notify about the error.

    .PARAMETER SmtpServer
        The SMTP server to use for sending email notifications.

    .PARAMETER FromAddress
        The from address to use for sending email notifications.

    .PARAMETER SmtpCredential
        An optional PSCredential for SMTP authentication.

.OUTPUTS
    None. This function always throws a terminating exception.

.EXAMPLE
    try {
        # some code that may fail
    }
    catch {
        Write-CertLCLogAndThrow -Message "Operation failed" -Section "MyFunction" -CorrelationId $correlationId -InnerException $_.Exception -Context @{ detail = "additional info" } -NotifyTo @("admin@example.com") -SmtpServer "smtp.example.com" -FromAddress "noreply@example.com" -SmtpCredential $smtpCredential
    }

#>

function Write-CertLCLogAndThrow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
        [Parameter(Mandatory)][string]$Section,
        [Parameter()][string]$CorrelationId,
        [Parameter()][Alias('Inner')][System.Exception]$InnerException,
        [Parameter()][hashtable]$Context,
        [Parameter()][string[]]$NotifyTo,
        [Parameter()][string]$SmtpServer,
        [Parameter()][string]$FromAddress,
        [Parameter()][pscredential]$SmtpCredential
    )

    #region ### Convert-ExceptionToObject ###

    #########################################
    # FUNCTIONS - Convert-ExceptionToObject #
    #########################################

    <#
    .SYNOPSIS
        Flatten an exception into bounded, JSON-friendly diagnostic fields.

    .DESCRIPTION
        Keeps exception type, message, HRESULT, and stack trace without serializing the
        full exception graph. Remains local to the terminating-error logging helper.

    .PARAMETER Exception
        Exception to describe. A null value returns null.

    .PARAMETER MaxDepth
        Maximum number of inner-exception levels to include; defaults to two.

    .OUTPUTS
        Ordered dictionary of diagnostic fields, or null when no exception is supplied.
    #>
    function Convert-ExceptionToObject {
        param([System.Exception]$Exception, [int]$MaxDepth = 2)
        if (-not $Exception) { return $null }
        $o = [ordered]@{ type = $Exception.GetType().FullName; message = $Exception.Message }
        if ($Exception.HResult) { $o.hresult = $Exception.HResult }
        if ($Exception.StackTrace) { $o.stackTrace = $Exception.StackTrace }
        if ($Exception.InnerException -and $MaxDepth -gt 0) {
            $o.inner = Convert-ExceptionToObject -Exception $Exception.InnerException -MaxDepth ($MaxDepth - 1)
        }
        return $o
    }

    #endregion

    # Copy caller context before attaching diagnostics; never mutate the caller's dictionary.
    $ctx = @{}
    if ($Context) { $ctx = @{} + $Context }
    if ($InnerException) { $ctx.exception = Convert-ExceptionToObject -Exception $InnerException }

    # Send email if needed. Note that we may not have the NotifyTo list in all cases.
    # For example, for a renewal, if the error occurs before we read the certificate details including the NotifyTo tag, we don't have the To list.
    # In this case, skip the email sending.
    # Also skip email sending if SMTP is not configured.

    if ($NotifyTo -and -not [string]::IsNullOrEmpty($SmtpServer)) {
        $subject = "Error in CERTLC runbook"
        $errorDetails = $Message

        if ($InnerException) {
            $errorDetails += "`n`nInner exception: $($InnerException.GetType().FullName): $($InnerException.Message)"
        }
        # Stage identifies the failing function. The dispatcher context adds only values known
        # before the failure; New-CertLCNotificationDetailsHtml omits blank optional fields.
        $notificationDetails = [ordered]@{ Stage = $Section }
        foreach ($entry in $script:CertificateNotificationContext.GetEnumerator()) {
            $notificationDetails[$entry.Key] = $entry.Value
        }
        # This function can run before the dispatcher discovers the Automation job id. Resolve it
        # dynamically so StrictMode does not turn error notification into a second error.
        $jobVariable = Get-Variable -Name jobId -Scope Script -ErrorAction Ignore
        # Get-Variable returns PSVariable or null, so Value access remains StrictMode-safe.
        $notificationJobId = [string](${jobVariable}?.Value ?? '')
        # Match the error log's explicit event override, or inherit parsed invocation correlation.
        $body = New-CertLCNotificationBody `
            -Title 'Certificate operation failed' `
            -Summary 'CERTLC could not complete the requested certificate operation.' `
            -Details $notificationDetails `
            -ErrorDetails $errorDetails `
            -JobId $notificationJobId `
            -CorrelationId $CorrelationId
        Send-NotificationEmail -SmtpServer $SmtpServer -FromAddress $FromAddress -To $NotifyTo -Subject $subject -Body $body -SmtpCredential $SmtpCredential
    }
    elseif ($NotifyTo -and [string]::IsNullOrEmpty($SmtpServer)) {
        Write-CertLCLog -Level 'Warning' -Message "Error notification requested but SMTP is not configured. Skipping email notification." -Section $Section
    }

    # Record the original failure after any best-effort notification attempt.
    Write-CertLCLog -Level 'Error' -Message $Message -Section $Section -CorrelationId $CorrelationId -Context $ctx

    # Throw a terminating exception
    if ($InnerException) {
        throw ([System.Exception]::new($Message, $InnerException))
    }
    throw ([System.Exception]::new($Message))
}

#endregion

#region ### Invoke-WithRetry ###

################################
# FUNCTIONS - Invoke-WithRetry #
################################

<#
.SYNOPSIS
    Execute a script block with retries on transient failures (HTTP 408/429/5xx and common
    network / AD / COM exceptions). Intended for IDEMPOTENT operations only (GET REST calls,
    AD reads, etc.). NEVER wrap a non-idempotent operation such as a certificate import,
    a CertRequest.Submit, or an Update-AzKeyVaultCertificate -- a retry could double-apply.

.PARAMETER ScriptBlock
    The block to execute. Must be safe to re-run on transient failures (idempotent).
    Pass it with .GetNewClosure() if it references variables from the caller's scope.

.PARAMETER OperationName
    Short label included in retry / failure log lines.

.PARAMETER Section
    Log section, propagated to Write-CertLCLog. Defaults to 'Invoke-WithRetry'.

.PARAMETER MaxAttempts
    Total attempts including the first one. Defaults to 4 (initial + 3 retries).

.PARAMETER InitialDelayMs
    Base delay (ms) before the first retry. Subsequent delays grow exponentially with jitter,
    capped at 30 seconds. Defaults to 500.

.NOTES
    Retry-After response headers (sent by Key Vault and other Azure services on 429 / 503) are
    honoured when present and take precedence over the computed backoff.
#>
function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][string]$OperationName,
        [Parameter()][string]$Section = 'Invoke-WithRetry',
        [Parameter()][int]$MaxAttempts = 4,
        [Parameter()][int]$InitialDelayMs = 500
    )

    # HTTP status codes considered transient.
    $retryableHttp = @(408, 429, 500, 502, 503, 504)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            $err = $_
            $ex = $err.Exception
            $isLastAttempt = ($attempt -ge $MaxAttempts)

            # Try to read an HTTP status code if this is an Invoke-RestMethod / Invoke-WebRequest failure.
            $statusCode = $null
            $retryAfterMs = $null
            $respProp = $ex.PSObject.Properties['Response']
            if ($null -ne $respProp -and $null -ne $respProp.Value) {
                try { $statusCode = [int]$respProp.Value.StatusCode } catch { $statusCode = $null }
                # Retry-After is optional; malformed headers must not mask the original error.
                try {
                    $ra = $respProp.Value.Headers.RetryAfter
                    if ($null -ne $ra -and $null -ne $ra.Delta) {
                        $retryAfterMs = [int]$ra.Delta.TotalMilliseconds
                    }
                }
                catch { $retryAfterMs = $null }
            }

            # Decide whether this exception is worth retrying.
            $shouldRetry = $false
            if ($null -ne $statusCode -and $retryableHttp -contains $statusCode) {
                $shouldRetry = $true
            }
            elseif ($ex -is [System.Net.Http.HttpRequestException] -or
                $ex -is [System.TimeoutException] -or
                $ex -is [System.IO.IOException] -or
                $ex -is [System.Net.WebException] -or
                $ex -is [System.Runtime.InteropServices.COMException]) {
                $shouldRetry = $true
            }

            # Exhaustion and non-transient failures retain their original exception identity.
            if (-not $shouldRetry -or $isLastAttempt) {
                throw
            }

            # Cap a positive Retry-After at 30s; otherwise cap the exponential base before jitter.
            if ($null -ne $retryAfterMs -and $retryAfterMs -gt 0) {
                $delayMs = [Math]::Min($retryAfterMs, 30000)
            }
            else {
                $delayMs = [Math]::Min(30000, $InitialDelayMs * [Math]::Pow(2, $attempt - 1))
                $delayMs += (Get-Random -Minimum 0 -Maximum $InitialDelayMs)
            }

            # Emit the selected delay before sleeping so retry latency remains diagnosable.
            $statusInfo = if ($null -ne $statusCode) { "HTTP $statusCode" } else { $ex.GetType().Name }
            Write-CertLCLog -Section $Section -Level 'Warning' -Message "[$OperationName] Attempt $attempt of $($MaxAttempts) failed ($statusInfo): $($ex.Message). Retrying after $([int]$delayMs)ms..."
            Start-Sleep -Milliseconds ([int]$delayMs)
        }
    }
}

#endregion

#region ### Format-PfxProtectTo ###

###################################
# FUNCTIONS - Format-PfxProtectTo #
###################################

<#

.SYNOPSIS
    Normalize and format the PfxProtectTo array.

.DESCRIPTION
    This function takes an input value (string or array of strings) representing users or groups
    to protect the PFX file to, and normalizes it by trimming whitespace, collapsing multiple backslashes,
    removing empty entries, and de-duplicating entries in a case-insensitive manner while preserving the order of first occurrence.

.PARAMETER InputValue
    The input value to normalize, which can be a single string or an array of strings.

.OUTPUTS
    An array of normalized strings.

.EXAMPLE
    $input = @(" DOMAIN\User1 ", "DOMAIN\\Group1", "DOMAIN\User1", "", "DOMAIN\User2")
    $normalized = Format-PfxProtectTo -InputValue $input
    # $normalized will be @("DOMAIN\User1", "DOMAIN\Group1", "DOMAIN\User2")

#>

function Format-PfxProtectTo {
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter()] [object] $InputValue
    )

    if (-not $InputValue) {
        Write-Output -NoEnumerate @()
        return
    }

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
    # PowerShell enumerates arrays written by return, collapsing zero items to $null and one item
    # to a scalar. Suppress enumeration so callers always receive the documented array type.
    Write-Output -NoEnumerate @($out)
}

#endregion

#region ### Convert-PfxProtectToForTag ###

##########################################
# FUNCTIONS - Convert-PfxProtectToForTag #
##########################################

<#

.SYNOPSIS
    Convert an array of strings into a semicolon-separated string suitable for storing in a tag.

.DESCRIPTION
    This function takes an array of strings (representing users or groups to protect the PFX file to)
    and converts it into a single semicolon-separated string, trimming whitespace, removing empty entries,
    and de-duplicating entries in a case-insensitive manner while preserving the order of first occurrence.

.PARAMETER Value
    The array of strings to convert.

.OUTPUTS
    A semicolon-separated string suitable for storing in a tag.

.EXAMPLE
    $protectTo = @("DOMAIN\User1", " DOMAIN\Group1 ", "DOMAIN\User1", "", "DOMAIN\User2")
    $tagValue = Convert-PfxProtectToForTag -Value $protectTo
    # $tagValue will be "DOMAIN\User1;DOMAIN\Group1;DOMAIN\User2"

#>

function Convert-PfxProtectToForTag {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Value
    )

    # Delegate normalization (trim, drop empties, collapse backslashes, dedupe) to Format-PfxProtectTo
    # to keep both helpers in sync; then join with semicolons for tag storage.
    return ((Format-PfxProtectTo -InputValue $Value) -join ';')
}

#endregion

#region ### Convert-PfxProtectToFromTag ###

###########################################
# FUNCTIONS - Convert-PfxProtectToFromTag #
###########################################

<#

.SYNOPSIS
    Parse a PfxProtectTo tag string into an array of strings.

.DESCRIPTION
    This function takes a semicolon-separated string (as stored in the PfxProtectTo tag)
    and parses it into an array of strings, trimming whitespace and ignoring empty entries.
    The output is normalized using Format-PfxProtectTo to ensure consistent formatting.

.PARAMETER TagValue
    The semicolon-separated string from the PfxProtectTo tag.

.OUTPUTS
    An array of strings representing the users or groups to protect the PFX file to.

.EXAMPLE
    $tagValue = "DOMAIN\User1; DOMAIN\Group1; ; ;DOMAIN\User2"
    $protectTo = Convert-PfxProtectToFromTag -TagValue $tagValue
    # $protectTo will be @("DOMAIN\User1", "DOMAIN\Group1", "DOMAIN\User2")

#>

function Convert-PfxProtectToFromTag {
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $TagValue
    )

    if ([string]::IsNullOrWhiteSpace($TagValue)) {
        Write-Output -NoEnumerate @()
        return
    }

    # The shared normalizer already trims and removes empty entries after splitting.
    $normalized = Format-PfxProtectTo -InputValue $TagValue.Split(';')
    Write-Output -NoEnumerate @($normalized)
}

#endregion

#region ### Initialize-PfxExportTarget ###

##########################################
# FUNCTIONS - Initialize-PfxExportTarget #
##########################################

<#
.SYNOPSIS
    Prepare and validate the filesystem and principals required for PFX export.

.DESCRIPTION
    Resolves every protection principal to a SID, creates the host-specific target directory,
    applies its final ACL, and verifies write/delete access with a temporary probe file.
    Call this before certificate issuance so invalid export prerequisites fail without creating
    irreversible CA or Key Vault state.

.PARAMETER PfxRootFolder
    Root directory below which host-specific PFX directories are created.

.PARAMETER Hostname
    Single safe path segment used as the host-specific directory name.

.PARAMETER ProtectTo
    Domain users or groups that receive ReadAndExecute access and can decrypt the PFX.

.OUTPUTS
    PSCustomObject containing TargetFolder and the resolved ProtectionSids.
#>
function Initialize-PfxExportTarget {
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PfxRootFolder,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ProtectTo
    )

    # SID-protected PKCS#12 export and NTFS ACLs depend on Windows cryptography and security APIs.
    if (-not $IsWindows) {
        throw [System.PlatformNotSupportedException]::new('Initialize-PfxExportTarget: SID-protected PFX export requires a Windows Hybrid Worker.')
    }

    # The final ACL grants write access only to Local System and local Administrators. Verify
    # the worker token belongs to one of those identities before changing any directory ACL.
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $workerIdentityName = $currentIdentity.Name
        $currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
        $workerCanApplyAcl = $currentIdentity.IsSystem -or
        $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally {
        # WindowsIdentity owns a native token handle; release it before filesystem work begins.
        $currentIdentity.Dispose()
    }
    if (-not $workerCanApplyAcl) {
        throw [System.Security.SecurityException]::new("Initialize-PfxExportTarget: Worker identity '$workerIdentityName' must run as Local System or a local administrator to apply the PFX directory ACL.")
    }

    # Keep the direct function-call contract as strict as the dispatcher so Hostname cannot
    # introduce rooted paths, traversal segments, wildcard expansion, or alternate separators.
    if ($Hostname -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253})$') {
        throw [System.ArgumentException]::new("Initialize-PfxExportTarget: Hostname '$Hostname' is not a safe directory name.", 'Hostname')
    }

    try {
        # Canonicalize both paths and require the target to remain an immediate child of the
        # configured root before creating either directory.
        $rootPath = [System.IO.Path]::GetFullPath($PfxRootFolder)
        $targetPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($rootPath, $Hostname))
        $rootPrefix = $rootPath.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $targetPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.ArgumentException]::new("Target path '$targetPath' is outside PFX root '$rootPath'.")
        }

        # Directory.CreateDirectory is idempotent and treats wildcard characters literally,
        # which is safer here than provider wildcard expansion through New-Item.
        $null = [System.IO.Directory]::CreateDirectory($rootPath)
        $null = [System.IO.Directory]::CreateDirectory($targetPath)
    }
    catch {
        throw [System.Exception]::new("Initialize-PfxExportTarget: Cannot prepare PFX directory for host '$Hostname' below '$PfxRootFolder'.", $_.Exception)
    }

    # Resolve every requested identity before any certificate request is created. The returned
    # SID objects are reused by ACL construction and native PFX protection to avoid late lookup.
    $protectionSids = [System.Collections.Generic.List[System.Security.Principal.SecurityIdentifier]]::new()
    foreach ($principal in $ProtectTo) {
        try {
            $sid = ([System.Security.Principal.NTAccount]$principal).Translate(
                [System.Security.Principal.SecurityIdentifier]
            )
            $protectionSids.Add($sid)
        }
        catch {
            throw [System.Exception]::new("Initialize-PfxExportTarget: Cannot resolve PfxProtectTo principal '$principal' to a Windows SID.", $_.Exception)
        }
    }

    try {
        # Build the complete ACL in memory and apply it once so the target never observes a
        # partially assembled permission set.
        $acl = Get-Acl -LiteralPath $targetPath
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) {
            $null = $acl.RemoveAccessRule($rule)
        }

        # Administrators and SYSTEM manage exports; protected recipients receive read access only.
        $inheritFlags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        $fullControlSids = @(
            [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null),
            [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        )
        foreach ($sid in $fullControlSids) {
            $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid, 'FullControl', $inheritFlags, $propagationFlags, 'Allow'
            )
            $acl.AddAccessRule($accessRule)
        }
        # Apply recipient permissions to this folder and to subsequently exported files.
        foreach ($sid in $protectionSids) {
            $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid, 'ReadAndExecute', $inheritFlags, $propagationFlags, 'Allow'
            )
            $acl.AddAccessRule($accessRule)
        }
        Set-Acl -LiteralPath $targetPath -AclObject $acl

        # DeleteOnClose validates create, write, flush, close, and delete rights without leaving
        # reusable probe data in the certificate export directory.
        $probePath = [System.IO.Path]::Combine($targetPath, ".certlc-preflight-$([Guid]::NewGuid().ToString('N')).tmp")
        $probeStream = [System.IO.FileStream]::new(
            $probePath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::DeleteOnClose
        )
        # Force the probe to disk, then release it even if the write or flush fails.
        try {
            $probeStream.WriteByte(0)
            $probeStream.Flush($true)
        }
        finally {
            $probeStream.Dispose()
        }
        # A surviving probe means delete rights are insufficient for this export location.
        if ([System.IO.File]::Exists($probePath)) {
            throw [System.IO.IOException]::new("Preflight probe file '$probePath' was not deleted on close.")
        }
    }
    catch {
        throw [System.Exception]::new("Initialize-PfxExportTarget: PFX directory '$targetPath' cannot accept the required ACL and file operations.", $_.Exception)
    }

    # This function returns a data object to its caller. Route its log away from the success
    # stream so assignment captures only the object below, not a mixed log-and-result array.
    Write-CertLCLog -Section 'Initialize-PfxExportTarget' -Message "PFX: Export prerequisites validated for target folder $targetPath and $($protectionSids.Count) protection principal(s)." | Write-Information -InformationAction Continue
    return [pscustomobject]@{
        TargetFolder   = $targetPath
        ProtectionSids = $protectionSids.ToArray()
    }
}

#endregion

#region ### Test-DistinguishedNameEqual ###

###########################################
# FUNCTIONS - Test-DistinguishedNameEqual #
###########################################

<#
.SYNOPSIS
    Compare two X.500 distinguished names by their encoded values.

.DESCRIPTION
    Certificate subject and issuer strings can use different formatting while representing
    the same distinguished name. Comparing RawData avoids formatting-dependent mismatches.

.PARAMETER Left
    The first distinguished name to compare.

.PARAMETER Right
    The second distinguished name to compare.
#>
function Test-DistinguishedNameEqual {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName]$Left,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName]$Right
    )

    return [Convert]::ToBase64String($Left.RawData) -ceq [Convert]::ToBase64String($Right.RawData)
}

#endregion

#region ### ConvertFrom-Base64Pkcs7 ###

#######################################
# FUNCTIONS - ConvertFrom-Base64Pkcs7 #
#######################################

<#
.SYNOPSIS
    Decode a Base64 PKCS#7 certificate response.

.DESCRIPTION
    Removes optional PEM headers and whitespace, decodes the PKCS#7 payload, and imports all
    certificates into one X509Certificate2Collection. Temporary decoded bytes are cleared.

.PARAMETER Content
    Base64 or PEM-formatted PKCS#7 certificate content returned by AD CS.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2Collection
#>
function ConvertFrom-Base64Pkcs7 {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2Collection])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Content
    )

    # AD CS can return either plain Base64 or Base64 with PEM boundary lines.
    $base64 = $Content -replace '(?m)^-----[^\r\n]+-----\s*$', '' -replace '\s', ''
    try {
        $bytes = [Convert]::FromBase64String($base64)
    }
    catch {
        throw [System.Exception]::new("ConvertFrom-Base64Pkcs7: CA response is not valid Base64 PKCS#7: $($_.Exception.Message)", $_.Exception)
    }

    $collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    try {
        # AD CS returns a PKCS#7 SignedData certificate bundle, possibly without signers.
        # Decode only: the existing chain checks validate the certificates, not a CMS signature.
        $signedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
        $signedCms.Decode($bytes)
        $collection = $signedCms.Certificates
    }
    catch {
        # This helper owns extracted certificates until it returns; callers dispose them later.
        foreach ($certificate in $collection) {
            $certificate.Dispose()
        }
        throw [System.Exception]::new("ConvertFrom-Base64Pkcs7: CA response could not be decoded as PKCS#7: $($_.Exception.Message)", $_.Exception)
    }
    finally {
        # Certificate bytes are public material, but clearing transient buffers keeps cleanup
        # consistent with the later PKCS#12 path, which also carries private-key material.
        [Array]::Clear($bytes, 0, $bytes.Length)
    }

    # PowerShell normally enumerates collections on output. Preserve the collection object so
    # strict-mode callers can reliably use .Count even when a response contains one certificate.
    Write-Output -NoEnumerate $collection
}

#endregion

#region ### Get-OrderedCertificateChain ###

###########################################
# FUNCTIONS - Get-OrderedCertificateChain #
###########################################

<#
.SYNOPSIS
    Order a certificate collection from leaf to self-issued root.

.DESCRIPTION
    Selects exactly one leaf, follows encoded issuer-to-subject relationships, and rejects
    ambiguous issuers, unrelated certificates, or a chain without a self-issued root.

.PARAMETER Certificates
    The certificate collection to order.

.PARAMETER Source
    Identifies whether the collection came from AD CS or a Key Vault PKCS#12 secret. AD CS
    leaf selection uses Basic Constraints; Key Vault leaf selection uses the private key.

.PARAMETER ExcludeRoot
    Remove the self-issued root after ordering. At least one intermediate must remain.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2[]
#>
function Get-OrderedCertificateChain {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Certificates,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CaResponse', 'KeyVaultSecret')]
        [string]$Source,

        [Parameter()]
        [switch]$ExcludeRoot
    )

    # Key Vault's PKCS#12 identifies the leaf by its private key; the public-only AD CS response
    # instead identifies it structurally as the sole non-CA certificate.
    # Wrap the complete conditional expression. Wrapping only each branch still permits
    # PowerShell to unwrap a one-item result before assignment under strict mode.
    $leafCandidates = @(if ($Source -eq 'KeyVaultSecret') {
            $Certificates | Where-Object HasPrivateKey
        }
        else {
            $Certificates | Where-Object {
                $basicConstraints = $_.Extensions |
                Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } |
                Select-Object -First 1
                $null -eq $basicConstraints -or -not $basicConstraints.CertificateAuthority
            }
        })
    # Ambiguous or absent leaves are unsafe even if individual certificates are valid.
    if ($leafCandidates.Count -ne 1) {
        throw [System.Exception]::new("Get-OrderedCertificateChain: Expected exactly one leaf certificate in $Source; found $($leafCandidates.Count).")
    }

    # Keep unconsumed certificates in a mutable list so each issuer can be used exactly once.
    # Removing each selected issuer also prevents cycles from being accepted as a valid chain.
    $remaining = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    foreach ($certificate in $Certificates) {
        if ($certificate.Thumbprint -cne $leafCandidates[0].Thumbprint) {
            $remaining.Add($certificate)
        }
    }

    # Walk from the unique leaf until a self-issued endpoint is reached.
    $ordered = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    $current = $leafCandidates[0]
    while ($null -ne $current) {
        $ordered.Add($current)
        if (Test-DistinguishedNameEqual -Left $current.SubjectName -Right $current.IssuerName) {
            break
        }

        # Encoded distinguished-name comparison avoids locale and formatting differences in
        # the display strings exposed by Subject and Issuer.
        # Exactly one match is required: zero means the chain is incomplete, while multiple
        # matches make it ambiguous.
        $issuers = @($remaining | Where-Object {
                Test-DistinguishedNameEqual -Left $_.SubjectName -Right $current.IssuerName
            })
        if ($issuers.Count -ne 1) {
            throw [System.Exception]::new("Get-OrderedCertificateChain: Expected one issuer for '$($current.Subject)' in $Source; found $($issuers.Count).")
        }

        $current = $issuers[0]
        $null = $remaining.Remove($current)
    }

    # Reject unrelated certificates and incomplete chains before optionally stripping the root.
    if ($remaining.Count -gt 0) {
        throw [System.Exception]::new("Get-OrderedCertificateChain: $Source contains $($remaining.Count) certificate(s) outside the leaf's issuer chain.")
    }
    if (-not (Test-DistinguishedNameEqual -Left $ordered[$ordered.Count - 1].SubjectName -Right $ordered[$ordered.Count - 1].IssuerName)) {
        throw [System.Exception]::new("Get-OrderedCertificateChain: $Source does not terminate in a self-issued root certificate.")
    }

    # Export policy still requires at least one intermediate after removing the trust anchor.
    if ($ExcludeRoot) {
        $ordered.RemoveAt($ordered.Count - 1)
        if ($ordered.Count -lt 2) {
            throw [System.Exception]::new("Get-OrderedCertificateChain: $Source contains no intermediate CA certificate after the root is excluded.")
        }
    }

    # Prevent output-pipeline enumeration so a one-item result remains an array for strict mode.
    Write-Output -NoEnumerate $ordered.ToArray()
}

#endregion

#region ### Assert-CertificateSet ###

#####################################
# FUNCTIONS - Assert-CertificateSet #
#####################################

<#
.SYNOPSIS
    Assert that two certificate collections contain exactly the same certificates.

.DESCRIPTION
    Compares certificate counts and unique thumbprints. This detects missing, unexpected,
    and duplicate certificates without relying on collection order.

.PARAMETER Expected
    The expected certificates.

.PARAMETER Actual
    The certificate collection being verified.

.PARAMETER Context
    Description included in a mismatch error.
#>
function Assert-CertificateSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Expected,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Actual,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Context
    )

    # Count comparison detects duplicate certificate bags that unique thumbprints alone hide.
    $expectedThumbprints = @($Expected.Thumbprint | Sort-Object -Unique)
    $actualThumbprints = @($Actual.Thumbprint | Sort-Object -Unique)
    $missing = @($expectedThumbprints | Where-Object { $_ -notin $actualThumbprints })
    $unexpected = @($actualThumbprints | Where-Object { $_ -notin $expectedThumbprints })
    if ($Expected.Count -ne $Actual.Count -or $missing.Count -gt 0 -or $unexpected.Count -gt 0) {
        throw [System.Exception]::new("Assert-CertificateSet: $Context certificate mismatch. Expected $($Expected.Count), found $($Actual.Count). Missing: $($missing -join ', '); unexpected: $($unexpected -join ', ').")
    }
}

#endregion

#region ### Assert-CertificateChain ###

#######################################
# FUNCTIONS - Assert-CertificateChain #
#######################################

<#
.SYNOPSIS
    Cryptographically validate an ordered certificate chain without network retrieval.

.DESCRIPTION
    Builds the supplied leaf-to-root chain using only its final certificate as a custom trust
    root and its intermediate certificates as the extra store. Revocation and certificate
    downloads are disabled so validation cannot silently supplement the supplied collection.

.PARAMETER Certificates
    Certificates ordered from leaf to self-issued root.
#>
function Assert-CertificateChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates
    )

    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        # Validate only the physical CA response. Downloads could conceal a missing intermediate.
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.DisableCertificateDownloads = $true
        $chain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $null = $chain.ChainPolicy.CustomTrustStore.Add($Certificates[-1])

        # The first item is the leaf and the last is the custom root; only middle items belong
        # in ExtraStore. Avoid constructing a descending range when there are no intermediates.
        if ($Certificates.Count -gt 2) {
            foreach ($certificate in $Certificates[1..($Certificates.Count - 2)]) {
                $null = $chain.ChainPolicy.ExtraStore.Add($certificate)
            }
        }

        # Structural ordering alone is insufficient; verify certificate signatures and validity.
        if (-not $chain.Build($Certificates[0])) {
            $status = ($chain.ChainStatus.StatusInformation | ForEach-Object { $_.Trim() }) -join '; '
            throw [System.Exception]::new("Assert-CertificateChain: AD CS returned an invalid certificate chain: $status")
        }
    }
    finally {
        $chain.Dispose()
    }
}

#endregion

#region ### Merge-KeyVaultCertificateChain ###

##############################################
# FUNCTIONS - Merge-KeyVaultCertificateChain #
##############################################

<#
.SYNOPSIS
    Merge an ordered certificate chain into a pending Key Vault certificate request.

.DESCRIPTION
    Exports every supplied certificate as DER, encodes the certificates into the Key Vault
    x5c JSON array, and completes an existing pending certificate operation through the
    Key Vault REST API. Certificates must be supplied in leaf-to-root order.

.PARAMETER VaultName
    Name of the Key Vault containing the pending certificate request.

.PARAMETER CertificateName
    Name of the pending Key Vault certificate.

.PARAMETER Certificates
    The complete certificate chain in leaf-to-root order.

.PARAMETER Token
    SecureString bearer token for the Key Vault data-plane resource.

.OUTPUTS
    PSCustomObject containing the completed Key Vault certificate bundle.

.NOTES
    The pending merge POST is intentionally not retried because it changes service state.
    An automatic retry could obscure whether Key Vault completed the first request.
#>
function Merge-KeyVaultCertificateChain {
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9-]{3,24}$')]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9-]+$')]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [ValidateCount(2, 2147483647)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Security.SecureString]$Token
    )

    # Key Vault requires each x5c member to contain the Base64-encoded DER certificate.
    # Preserve the supplied leaf-to-root order because the pending merge API consumes the
    # array as the certificate chain associated with the Key Vault-generated private key.
    $x5c = @($Certificates | ForEach-Object {
            [Convert]::ToBase64String($_.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        })
    $body = @{ x5c = $x5c } | ConvertTo-Json -Depth 3 -Compress
    $escapedCertificateName = [Uri]::EscapeDataString($CertificateName)
    $uri = "https://$VaultName.vault.azure.net/certificates/$escapedCertificateName/pending/merge?api-version=2025-07-01"

    # This function returns the Key Vault response object. Keep its informational log off the
    # success stream so callers do not receive a mixed log-and-response array under StrictMode.
    Write-CertLCLog -Section 'Merge-KeyVaultCertificateChain' -Message "KeyVault: Submitting $($x5c.Count) explicitly encoded certificate(s) for pending certificate $CertificateName in vault $VaultName." | Write-Information -InformationAction Continue

    # Do not wrap this state-changing POST in Invoke-WithRetry. A transport failure can occur
    # after Key Vault commits the merge, making an automatic retry operationally ambiguous.
    try {
        $response = Invoke-RestMethod `
            -Uri $uri `
            -Method POST `
            -Authentication Bearer `
            -Token $Token `
            -ContentType 'application/json' `
            -Body $body
    }
    catch {
        throw [System.Exception]::new("Merge-KeyVaultCertificateChain: Key Vault pending merge failed for certificate $CertificateName in vault $VaultName.", $_.Exception)
    }

    # The exact certificate and secret version identifiers are required by later steps. Read
    # properties defensively because strict mode rejects access to omitted REST properties.
    $idProperty = if ($null -eq $response) { $null } else { $response.PSObject.Properties['id'] }
    $sidProperty = if ($null -eq $response) { $null } else { $response.PSObject.Properties['sid'] }
    if ($null -eq $idProperty -or [string]::IsNullOrWhiteSpace([string]$idProperty.Value) -or
        $null -eq $sidProperty -or [string]::IsNullOrWhiteSpace([string]$sidProperty.Value)) {
        throw [System.Exception]::new('Merge-KeyVaultCertificateChain: Key Vault pending merge returned no certificate or secret version identifier.')
    }

    return $response
}

#endregion

#region ### Get-KeyVaultCertificateSecretValue ###

##################################################
# FUNCTIONS - Get-KeyVaultCertificateSecretValue #
##################################################

<#
.SYNOPSIS
    Retrieve the PKCS#12 value for an exact Key Vault certificate secret version.

.DESCRIPTION
    Validates the versioned secret identifier returned by Key Vault, retrieves that exact
    secret through the Key Vault REST API, and verifies that it contains a non-empty PKCS#12
    value. The request uses the runbook retry helper because a version-specific GET is idempotent.

.PARAMETER VaultName
    Name of the Key Vault that must own the secret identifier.

.PARAMETER SecretId
    Versioned Key Vault secret identifier returned in the certificate merge response.

.PARAMETER Token
    SecureString bearer token for the Key Vault data-plane resource.

.OUTPUTS
    System.String containing the Base64-encoded PKCS#12 secret value.
#>
function Get-KeyVaultCertificateSecretValue {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9-]{3,24}$')]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Security.SecureString]$Token
    )

    # Treat the service-returned identifier as untrusted input. Restrict it to the expected
    # HTTPS data-plane host before allowing Invoke-RestMethod to make a request.
    try {
        $secretUri = [Uri]$SecretId
    }
    catch {
        throw [System.ArgumentException]::new("Get-KeyVaultCertificateSecretValue: Key Vault returned an invalid secret ID '$SecretId'.", 'SecretId', $_.Exception)
    }
    # Reject alternate hosts, ports, and extra URI components before attaching the bearer token.
    $expectedHost = "$VaultName.vault.azure.net"
    if (-not $secretUri.IsAbsoluteUri -or
        $secretUri.Scheme -ine 'https' -or
        $secretUri.Host -ine $expectedHost -or
        -not $secretUri.IsDefaultPort -or
        -not [string]::IsNullOrEmpty($secretUri.Query) -or
        -not [string]::IsNullOrEmpty($secretUri.Fragment)) {
        throw [System.ArgumentException]::new("Get-KeyVaultCertificateSecretValue: Expected an HTTPS secret ID on '$expectedHost'; received '$SecretId'.", 'SecretId')
    }

    # A certificate-backed secret ID must identify one concrete version. Reject collection,
    # latest-version, or unrelated Key Vault resource paths before issuing the GET.
    $pathSegments = @($secretUri.AbsolutePath.Trim('/').Split('/'))
    if ($pathSegments.Count -ne 3 -or
        $pathSegments[0] -ine 'secrets' -or
        [string]::IsNullOrWhiteSpace([Uri]::UnescapeDataString($pathSegments[1])) -or
        [string]::IsNullOrWhiteSpace($pathSegments[2])) {
        throw [System.ArgumentException]::new("Get-KeyVaultCertificateSecretValue: Expected a versioned certificate secret ID; received '$SecretId'.", 'SecretId')
    }

    $uri = "$($secretUri.AbsoluteUri.TrimEnd('/'))?api-version=2025-07-01"

    # Copy function-scope values into locals before creating the closure. This ensures
    # GetNewClosure captures both values when Invoke-WithRetry executes the script block.
    $requestUri = $uri
    $requestToken = $Token
    $operation = {
        Invoke-RestMethod `
            -Uri $requestUri `
            -Method GET `
            -Authentication Bearer `
            -Token $requestToken `
            -ContentType 'application/json'
    }.GetNewClosure()

    try {
        # Version-specific secret retrieval is idempotent and safe for transient retries.
        $secret = Invoke-WithRetry `
            -ScriptBlock $operation `
            -OperationName "KV GET certificate secret $($pathSegments[1])/$($pathSegments[2])" `
            -Section 'Get-KeyVaultCertificateSecretValue'
    }
    catch {
        throw [System.Exception]::new("Get-KeyVaultCertificateSecretValue: Failed to retrieve versioned secret '$SecretId'.", $_.Exception)
    }

    # Read REST properties defensively for strict mode and require Key Vault's PKCS#12 marker.
    $contentTypeProperty = if ($null -eq $secret) { $null } else { $secret.PSObject.Properties['contentType'] }
    if ($null -eq $contentTypeProperty -or [string]$contentTypeProperty.Value -ine 'application/x-pkcs12') {
        $actualContentType = if ($null -eq $contentTypeProperty) { '<missing>' } else { [string]$contentTypeProperty.Value }
        throw [System.Exception]::new("Get-KeyVaultCertificateSecretValue: Secret '$SecretId' has content type '$actualContentType'; expected 'application/x-pkcs12'.")
    }

    # A valid content-type marker alone does not guarantee usable certificate material.
    $valueProperty = if ($null -eq $secret) { $null } else { $secret.PSObject.Properties['value'] }
    if ($null -eq $valueProperty -or [string]::IsNullOrWhiteSpace([string]$valueProperty.Value)) {
        throw [System.Exception]::new("Get-KeyVaultCertificateSecretValue: Key Vault returned an empty value for versioned secret '$SecretId'.")
    }

    return [string]$valueProperty.Value
}

#endregion

#region ### Export-PfxWithGroupProtection ###

#############################################
# FUNCTIONS - Export-PfxWithGroupProtection #
#############################################

<#
.SYNOPSIS
    Export a certificate collection to a PFX file protected to specified SIDs.

.DESCRIPTION
    This function exports selected certificates retrieved from Azure Key Vault to one PFX file protected to specified SIDs.
    It does not use Export-PfxCertificate cmdlet, but instead uses native interop helpers to create a protection descriptor and export the PFX file.
    The collection contains the private-key leaf and its intermediate certificates, with the self-issued root excluded before this function is called.
    The exported PFX file can be protected to multiple SIDs (users or groups).

.PARAMETER Certificates
    One or more X509Certificate2 objects to include in the exported PFX. The leaf certificate
    carries the private key; issuer certificates contribute their public certificate material.

.PARAMETER ProtectionSids
    SIDs resolved and validated by Initialize-PfxExportTarget before certificate issuance.

.PARAMETER PfxFile
    The path to the output PFX file.

.EXAMPLE
    $protectTo = @("DOMAIN\User1", "DOMAIN\Group1")
    $pfxFile = "C:\path\to\output.pfx"
    $preflight = Initialize-PfxExportTarget -PfxRootFolder 'C:\path\to' -Hostname 'output' -ProtectTo $protectTo
    Export-PfxWithGroupProtection -Certificates @($cert) -ProtectionSids $preflight.ProtectionSids -PfxFile $pfxFile
#>
function Export-PfxWithGroupProtection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates,

        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier[]]$ProtectionSids,

        [Parameter(Mandatory = $true)]
        [string]$PfxFile
    )

    # Add native interop helpers
    # .NET's managed export API supports password-protected PKCS#12 but not Windows SID
    # protection. These declarations bridge to NCrypt for the protection descriptor and to
    # Crypt32 for importing and exporting a native certificate store. BLOB is the unmanaged
    # byte-buffer shape expected by both PFX APIs; this function owns every returned handle.
    if (-not ('CertLCPfxNative' -as [type])) {
        Add-Type -TypeDefinition @'
        using System;
        using System.Runtime.InteropServices;

        public static class CertLCPfxNative
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

            [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr PFXImportCertStore(
                ref BLOB pfx, string password, uint flags);

            [DllImport("crypt32.dll", SetLastError = true)]
            public static extern bool CertCloseStore(IntPtr hStore, uint flags);

            [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool PFXExportCertStoreEx(
                IntPtr hStore, ref BLOB pfx,
                string password, IntPtr pvPara, uint flags);
        }
'@
    }

    # Build the protection descriptor only from SIDs that passed the early export preflight.
    # NCrypt protection descriptors use an access-rule expression. OR grants decryption to any
    # one of the validated user or group SIDs rather than requiring every identity to match.
    $rule = ($ProtectionSids | ForEach-Object { "SID=$($_.Value)" }) -join ' OR '

    # create protection descriptor
    $hDesc = [IntPtr]::Zero
    $hr = [CertLCPfxNative]::NCryptCreateProtectionDescriptor($rule, 0, [ref]$hDesc)
    if ($hr) {
        throw 'Export-PfxWithGroupProtection: NCryptCreateProtectionDescriptor failed: 0x{0:X}' -f $hr
    }
    Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "Protection descriptor handle: $hDesc"

    $sourcePfxBytes = $null
    $sourcePfxBuffer = [IntPtr]::Zero
    $store = [IntPtr]::Zero
    $passwordBytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(40)
    $password = [System.Convert]::ToBase64String($passwordBytes)
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)

    try {
        # Import an intermediate in-memory PKCS#12 into a non-persistent native store. This
        # preserves the private-key association that is lost when only certificate contexts
        # are copied into a new memory store.
        $sourcePfxBytes = ([System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Certificates).Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
            $password)
        $sourcePfxBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($sourcePfxBytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($sourcePfxBytes, 0, $sourcePfxBuffer, $sourcePfxBytes.Length)
        # Construct the interop value type directly; its native layout is unchanged.
        $sourcePfx = [CertLCPfxNative+BLOB]::new()
        $sourcePfx.cbData = $sourcePfxBytes.Length
        $sourcePfx.pbData = $sourcePfxBuffer
        $store = [CertLCPfxNative]::PFXImportCertStore([ref]$sourcePfx, $password, 0x0001 -bor 0x8000)
        if ($store -eq [IntPtr]::Zero) {
            throw 'Export-PfxWithGroupProtection: PFXImportCertStore failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "Private-key PFX imported into native memory store: $store"

        try {
            Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "$($Certificates.Count) certificate(s) imported into native memory store."

            # Wrap the handle in an IntPtr buffer
            $pvPara = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
            [Runtime.InteropServices.Marshal]::WriteIntPtr($pvPara, $hDesc)

            try {

                # PFXExportCertStoreEx follows the standard two-pass Win32 buffer pattern.
                # Query size of PFX so that we know how much buffer to allocate (pass 1)
                # The size-query pass requires a zero-initialized native blob.
                $blob = [CertLCPfxNative+BLOB]::new()
                # Fail if any private key cannot be exported; include private keys and extended
                # properties; and interpret pvPara as the NCrypt SID-protection descriptor.
                $flags = 0x0002 -bor 0x0004 -bor 0x0010 -bor 0x0020  # REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | EXPORT_PRIVATE_KEYS | INCLUDE_EXTENDED_PROPERTIES | PROTECT_TO_DOMAIN_SIDS

                if (-not [CertLCPfxNative]::PFXExportCertStoreEx($store, [ref]$blob, $password, $pvPara, $flags)) {
                    throw ('Export-PfxWithGroupProtection:: size query failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
                }
                Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "PFX size will be: $($blob.cbData) bytes"

                # allocate memory for the PFX data (pass 2)
                # The allocation uses the exact unmanaged buffer size reported by pass 1.
                $blob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($blob.cbData)

                # do export to the memory store
                try {
                    if (-not [CertLCPfxNative]::PFXExportCertStoreEx($store, [ref]$blob, $password, $pvPara, $flags)) {
                        throw ('Export-PfxWithGroupProtection: export to memory store failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
                    }
                    Write-CertLCLog -Section 'Export-PfxWithGroupProtection' 'Export to memory store successful.'

                    $password = $null  # Release this reference; the managed string is not erased.

                    # save the file
                    # Allocate the same zero-filled byte buffer using its typed constructor.
                    $bytes = [byte[]]::new($blob.cbData)
                    [Runtime.InteropServices.Marshal]::Copy($blob.pbData, $bytes, 0, $blob.cbData)
                    [System.IO.File]::WriteAllBytes($PfxFile, $bytes)
                    Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "PFX exported to file: $PfxFile"
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
            [CertLCPfxNative]::CertCloseStore($store, 0) | Out-Null
        }
    }
    finally {
        # Release resources in reverse ownership order and clear the managed PKCS#12 byte array.
        # Dropping the password reference does not erase the immutable managed string.
        $password = $null
        if ($sourcePfxBuffer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($sourcePfxBuffer)
        }
        if ($null -ne $sourcePfxBytes) {
            [Array]::Clear($sourcePfxBytes, 0, $sourcePfxBytes.Length)
        }
        # free the protection descriptor handle
        [CertLCPfxNative]::NCryptCloseProtectionDescriptor($hDesc) | Out-Null
    }
}

#endregion

#region ### Get-CertLCTemplateOid ###

#####################################
# FUNCTIONS - Get-CertLCTemplateOid #
#####################################

<#
.SYNOPSIS
    Decode the AD CS template OID without localized extension names or formatted text.
.DESCRIPTION
    Reads Certificate Template Information (1.3.6.1.4.1.311.21.7) as a DER sequence
    containing the template OID and up to two optional unsigned version integers.
    Rejects malformed or trailing data. The caller retains ownership of the certificate.
#>
function Get-CertLCTemplateOid {
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $extension = $Certificate.Extensions['1.3.6.1.4.1.311.21.7']
    if ($null -eq $extension) {
        throw [System.ArgumentException]::new('Certificate Template Information extension was not found.')
    }

    # Decode the encoded value, never Format() output or FriendlyName. Read the entire
    # structure so malformed version fields cannot be mistaken for a usable template.
    $reader = [System.Formats.Asn1.AsnReader]::new(
        [System.ReadOnlyMemory[byte]]::new($extension.RawData), [System.Formats.Asn1.AsnEncodingRules]::DER)
    $sequence = $reader.ReadSequence()
    $templateOid = $sequence.ReadObjectIdentifier()
    foreach ($versionField in 'major', 'minor') {
        if ($sequence.HasData) {
            $version = $sequence.ReadInteger()
            if ($version -lt 0 -or $version -gt [uint32]::MaxValue) {
                throw [System.ArgumentException]::new("Invalid template $versionField version: expected an unsigned 32-bit integer.")
            }
        }
    }
    $sequence.ThrowIfNotEmpty()
    $reader.ThrowIfNotEmpty()
    return $templateOid
}

#endregion

#region ### Find-TemplateName ###

#################################
# FUNCTIONS - Find-TemplateName #
#################################

<#
.SYNOPSIS
    Find certificate template name by OID or CN or DisplayName

.DESCRIPTION
    Find-TemplateName: find the certificate template name by OID or CN or DisplayName.
    This function queries the Active Directory Certificate Services configuration to find the template name associated with a given OID or CN or DisplayName.

.PARAMETER cnOrDisplayNameOrOid
    The certificate template OID or CN or DisplayName to search for.

.OUTPUTS
    The certificate template name if found, otherwise an empty string.

.EXAMPLE
    $templateName = Find-TemplateName -cnOrDisplayNameOrOid "WebServer"
#>

function Find-TemplateName {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$cnOrDisplayNameOrOid
    )

    # Initialize before acquisition so partial failures remain safe under StrictMode.
    $rootDse = $null
    $entry = $null
    $searcher = $null
    try {
        $rootDse = [ADSI]'LDAP://RootDSE'
        $configDN = $rootDse.configurationNamingContext
        $searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
        $entry = [ADSI]$searchRoot
        # Keep the explicit search root and existing caller-owned disposal boundary.
        $searcher = [System.DirectoryServices.DirectorySearcher]::new($entry)

        # Escape the search value per RFC 4515 before interpolation into the LDAP filter.
        # Values may originate in request payloads or certificate metadata; neither is trusted
        # as LDAP filter syntax. Escapes: \ * ( ) NUL -> \5c \2a \28 \29 \00.
        $escaped = $cnOrDisplayNameOrOid `
            -replace '\\', '\5c' `
            -replace '\*', '\2a' `
            -replace '\(', '\28' `
            -replace '\)', '\29' `
            -replace "`0", '\00'
        $searcher.Filter = "(&(objectClass=pKICertificateTemplate)(|(cn=$escaped)(displayName=$escaped)(msPKI-Cert-Template-OID=$escaped)))"
        $searcher.PropertiesToLoad.Add('name') | Out-Null
        # AD reads are idempotent; retry transient DC unavailability (COMException etc.).
        $findOne = { $searcher.FindOne() }.GetNewClosure()
        $result = Invoke-WithRetry -ScriptBlock $findOne -OperationName "AD template lookup '$cnOrDisplayNameOrOid'" -Section 'Find-TemplateName'
        if ($null -eq $result) {
            return [string]::Empty
        }
        return $result.Properties['name'][0]
    }
    finally {
        # This scope owns all three objects; release the searcher before its directory roots.
        if ($null -ne $searcher) { $searcher.Dispose() }
        if ($null -ne $entry) { $entry.Dispose() }
        if ($null -ne $rootDse) { $rootDse.Dispose() }
    }
}

#endregion

#region ### Get-CaRequestDiagnostic ###

#######################################
# FUNCTIONS - Get-CaRequestDiagnostic #
#######################################

<#
.SYNOPSIS
    Retrieve diagnostic details for an AD CS certificate request.

.DESCRIPTION
    Reads the request ID, CA disposition message, and last HRESULT from an
    ICertRequest COM object. Each property is retrieved independently because
    AD CS may leave individual diagnostics unavailable for some dispositions.

.PARAMETER CertificateRequest
    The CertificateAuthority.Request COM object after Submit has returned.

.OUTPUTS
    System.String containing the available CA request diagnostics.
#>
function Get-CaRequestDiagnostic {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$CertificateRequest
    )

    $requestId = try { $CertificateRequest.GetRequestId() } catch { 'unavailable' }
    $dispositionMessage = try { $CertificateRequest.GetDispositionMessage() } catch { 'unavailable' }
    $lastStatus = try { $CertificateRequest.GetLastStatus() } catch { $null }

    if ([string]::IsNullOrWhiteSpace([string]$dispositionMessage)) {
        $dispositionMessage = 'unavailable'
    }

    # COM exposes HRESULT values as signed integers; normalize to eight-digit hexadecimal
    # so the value can be looked up directly in AD CS and Windows error documentation.
    $statusText = if ($null -eq $lastStatus) {
        'unavailable'
    }
    else {
        '0x{0:X8}' -f ([uint32]([int64]$lastStatus -band 0xFFFFFFFFL))
    }

    "Request ID: $requestId; CA message: $dispositionMessage; last status: $statusText"
}

#endregion

#region ### Get-RecoverableKeyVaultCertificateOperation ###

###########################################################
# FUNCTIONS - Get-RecoverableKeyVaultCertificateOperation #
###########################################################

<#
.SYNOPSIS
    Reconcile an ambiguous Key Vault certificate-creation response with server state.

.DESCRIPTION
    Add-AzKeyVaultCertificate starts an asynchronous operation. A transport or client-side error
    can occur after Key Vault has accepted the request, leaving a usable pending CSR even though
    the caller observed a failure. This helper performs bounded, read-only checks and returns only
    an in-progress operation containing a CSR. Completed, failed, empty, or unreadable operations
    are not considered recoverable.

.PARAMETER VaultName
    The Key Vault containing the certificate operation.

.PARAMETER CertificateName
    The certificate whose pending operation should be reconciled.

.PARAMETER AttemptCount
    Maximum number of state reads. Defaults to three to cover brief control-plane propagation.

.PARAMETER DelaySeconds
    Delay between reads. Set to zero only for deterministic tests.

.OUTPUTS
    The recoverable pending certificate operation, or null when no safe continuation exists.
#>
function Get-RecoverableKeyVaultCertificateOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$CertificateName,
        [Parameter()][ValidateRange(1, 10)][int]$AttemptCount = 3,
        [Parameter()][ValidateRange(0, 30)][int]$DelaySeconds = 1
    )

    # Reconcile using bounded reads only; never resubmit a possibly accepted creation request.
    for ($attempt = 1; $attempt -le $AttemptCount; $attempt++) {
        try {
            $operation = Get-AzKeyVaultCertificateOperation `
                -VaultName $VaultName `
                -Name $CertificateName `
                -ErrorAction Stop
            # Only a still-pending operation with a usable CSR can safely resume issuance.
            if ($null -ne $operation -and
                $operation.Status -eq 'inProgress' -and
                $operation.CertificateSigningRequest) {
                return $operation
            }
        }
        catch {
            Write-CertLCLog `
                -Section 'Get-RecoverableKeyVaultCertificateOperation' `
                -Level 'Warning' `
                -Message "KeyVault: Reconciliation attempt $attempt could not read certificate operation for $CertificateName in vault ${VaultName}: $($_.Exception.Message)"
        }

        # Pause only between reads; the caller decides how to handle exhausted reconciliation.
        if ($attempt -lt $AttemptCount -and $DelaySeconds -gt 0) {
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    return $null
}

#endregion

#region ### New-CertificateCreationRequest ###

##############################################
# FUNCTIONS - New-CertificateCreationRequest #
##############################################

<#
.SYNOPSIS
    Create a Key Vault certificate request, merge the complete CA chain, and export a root-excluded PFX protected to specified users/groups.

.DESCRIPTION
    This function creates a new certificate request in Azure Key Vault and submits it to the specified Certificate Authority (CA) for issuance.
    It prepares the necessary tags, handles existing in-progress requests, and uses the Certificate Enrollment API to retrieve and validate the complete certificate chain.
    The complete leaf-to-root chain is merged into Key Vault. The exact merged secret version is verified and exported as a PFX containing the private-key leaf and all intermediates, while excluding the self-issued root.

.PARAMETER VaultName
    The name of the Azure Key Vault where the certificate will be stored.

.PARAMETER CertificateName
    The name of the certificate to create.

.PARAMETER CertificateTemplateName
    The name of the certificate template to use for the request.

.PARAMETER CertificateSubject
    The subject name for the certificate.

.PARAMETER CertificateDnsNames
    An array of DNS names to include in the certificate.

.PARAMETER CA
    The CA to which the certificate request will be submitted.

.PARAMETER Hostname
    The hostname associated with the certificate. The certificate will be exported into a folder named after this hostname. It is meant to be the name of the server where the certificate will be used.
    This is also stored as a tag in the certificate.

.PARAMETER PfxProtectTo
        An array of users or groups (in domain\user or UPN format) to protect the exported PFX file to.

.PARAMETER PfxRootFolder
    The export root supplied by the caller, containing the per-host PFX folders.

.PARAMETER NotifyTo
    An optional array of email addresses to notify about the certificate request status.

.EXAMPLE
    $result = New-CertificateCreationRequest -VaultName "MyKeyVault" -CertificateName "MyCertificate" -CertificateTemplateName "WebServer" -CertificateSubject "CN=www.example.com" -CertificateDnsNames @("www.example.com","example.com") -CA "MyCA\MyInstance" -Hostname "webserver01" -PfxProtectTo @("DOMAIN\User1", "DOMAIN\Group1") -NotifyTo @("admin@example.com") -PfxRootFolder 'C:\CertificateExports'
#>

function New-CertificateCreationRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$VaultName,
        [Parameter(Mandatory = $true)][string]$CertificateName,
        [Parameter(Mandatory = $true)][string]$CertificateTemplateName,
        [Parameter(Mandatory = $true)][string]$CertificateSubject,
        [Parameter()][string[]]$CertificateDnsNames,
        [Parameter(Mandatory = $true)][string]$CA,
        [Parameter(Mandatory = $true)][string]$Hostname,
        [Parameter(Mandatory = $true)][string[]]$PfxProtectTo,
        [Parameter()][string[]]$NotifyTo,
        # When this request is the second leg of an auto-renewal, the dispatcher
        # passes the current Automation job id; it is stamped on the new version's tags
        # for audit symmetry with RevokedJobId.
        [Parameter()][string]$RenewedJobId,
        # The function emits structured logs to the success output stream. A reference parameter
        # returns metadata without forcing callers to capture and suppress those log records.
        # PowerShell variable names are case-insensitive: local variables must never be named
        # $result because that would overwrite this typed $Result parameter after side effects.
        [Parameter()][ref]$Result,
        # Require the export root explicitly instead of resolving dispatcher scope.
        [Parameter(Mandatory = $true)][string]$PfxRootFolder
    )

    # Validate every local export dependency before creating a Key Vault CSR or contacting the
    # CA. This prevents bad paths, ACL rights, or domain principals from causing late failure.
    $pfxPreparation = Initialize-PfxExportTarget `
        -PfxRootFolder $PfxRootFolder `
        -Hostname $Hostname `
        -ProtectTo $PfxProtectTo
    $PfxTargetFolder = $pfxPreparation.TargetFolder
    $ProtectionSids = $pfxPreparation.ProtectionSids

    # prepare tags for the certificate
    $tagPfxValue = Convert-PfxProtectToForTag -Value $PfxProtectTo
    $tags = @{
        'PfxProtectTo'            = $tagPfxValue
        'CertificateTemplateName' = $CertificateTemplateName
    }
    if ($Hostname) {
        $tags['Hostname'] = $Hostname
    }
    # NotifyTo may arrive as a single string or an array; avoid using .Count on a scalar string
    if ($NotifyTo) {
        $tags['NotifyTo'] = (@($NotifyTo) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ';'
    }
    if (-not [string]::IsNullOrEmpty($RenewedJobId)) {
        $tags['RenewedJobId'] = $RenewedJobId
    }

    # create certificate CSR - if a previous request is in progress, reuse it
    $csr = $null
    $op = $null
    $operationResult = $null
    try {
        # Retrieve existing operation (may return $null if none). Then evaluate Status separately.
        $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertificateName -ErrorAction SilentlyContinue
        if ($null -ne $op) {
            if ($op.Status -ne 'inProgress') { $op = $null }
        }
    }
    catch {
        throw [System.Exception]::new('New-CertificateCreationRequest, KeyVault: Error querying existing certificate operation', $_.Exception)
    }
    if ($null -ne $op) {
        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "KeyVault: Certificate request is already in progress in $VaultName for this certificate: $CertificateName; reusing the existing request." -Level 'Warning'
        $csr = $op.CertificateSigningRequest
    }

    # otherwise create a new request
    else {
        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "Creating a new CSR for certificate $CertificateName in key vault $VaultName..."

        # check the DNS names
        $effectiveDns = $null
        if ($CertificateDnsNames) {
            # Filter out null/empty/whitespace and de-duplicate
            $effectiveDns = $CertificateDnsNames |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
        }
        # Omit DnsName entirely when filtering leaves no names, preserving SDK defaults.
        $policyParameters = @{
            SecretContentType = 'application/x-pkcs12'
            SubjectName       = $CertificateSubject
            IssuerName        = 'Unknown'
        }
        if ($effectiveDns) {
            $policyParameters.DnsName = $effectiveDns
        }
        $Policy = New-AzKeyVaultCertificatePolicy @policyParameters

        # create the request in the key vault
        try {
            # Keep this local name distinct from the case-insensitive [ref] $Result parameter.
            $certificateOperation = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -CertificatePolicy $Policy -Tag $tags
            $csr = $certificateOperation.CertificateSigningRequest
        }
        catch {
            # The create request is not safe to repeat blindly: Key Vault may have committed it
            # before the client observed an exception. Continue only when a bounded read confirms
            # the exact certificate now has an in-progress operation with a reusable CSR.
            $addException = $_.Exception
            $op = Get-RecoverableKeyVaultCertificateOperation `
                -VaultName $VaultName `
                -CertificateName $CertificateName
            if ($null -eq $op) {
                throw [System.Exception]::new('New-CertificateCreationRequest, KeyVault: Error generating CSR in Key Vault and no recoverable pending operation was found', $addException)
            }

            $csr = $op.CertificateSigningRequest
            Write-CertLCLog `
                -Section 'New-CertificateCreationRequest' `
                -Level 'Warning' `
                -Message "KeyVault: CSR creation reported an error after the pending operation was accepted for certificate $CertificateName in vault $VaultName; continuing with the recovered request. Original error: $($addException.Message)"
        }
    }

    # see https://www.sysadmins.lv/blog-en/introducing-to-certificate-enrollment-apis-part-3-certificate-request-submission-and-response-installation.aspx

    # CR_IN_BASE64HEADER = 0x0,
    # CR_IN_BASE64 = 0x1,
    # CR_IN_BINARY = 0x2,
    # CR_IN_ENCODEANY = 0xff,
    # CR_OUT_BASE64HEADER = 0x0,
    # CR_OUT_BASE64 = 0x1,
    # CR_OUT_BINARY = 0x2
    # CR_OUT_CHAIN = 0x100

    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "CA: Sending request to the CA $CA using template $($CertificateTemplateName) for certificate $CertificateName..."
    $CertRequest = $null
    $pkcs7Response = $null
    try {
        $CertRequest = New-Object -ComObject CertificateAuthority.Request
        $CertRequestStatus = $CertRequest.Submit(0x1, $csr, "CertificateTemplate:$CertificateTemplateName", $CA)

        # ICertRequest::Submit disposition codes (see wincrypt.h)
        $CR_DISP_DENIED = 2
        $CR_DISP_ISSUED = 3
        $CR_DISP_UNDER_SUBMISSION = 5

        switch ($CertRequestStatus) {
            $CR_DISP_DENIED {
                $caDiagnostic = Get-CaRequestDiagnostic -CertificateRequest $CertRequest
                throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request was denied by $CA. $caDiagnostic")
            }
            $CR_DISP_ISSUED {
                Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "CA: Certificate Request for $CertificateName submitted successfully."
                # CR_OUT_BASE64HEADER | CR_OUT_CHAIN returns PKCS#7 containing the issued leaf
                # and every issuer certificate through the self-issued root.
                $pkcs7Response = $CertRequest.GetCertificate(0x100)
                Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "Complete certificate chain received from CA $CA."
            }
            $CR_DISP_UNDER_SUBMISSION {
                $caDiagnostic = Get-CaRequestDiagnostic -CertificateRequest $CertRequest
                throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request to $CA is pending. This runbook expects immediate issuance. $caDiagnostic")
            }
            default {
                $caDiagnostic = Get-CaRequestDiagnostic -CertificateRequest $CertRequest
                throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request to $CA returned disposition $CertRequestStatus instead of issuing the certificate. $caDiagnostic")
            }
        }
    }
    catch {
        # Keep the CA diagnostic in the outer message because Automation logging may display
        # Exception.Message without rendering the complete inner-exception chain.
        throw [System.Exception]::new("New-CertificateCreationRequest: CA: Error submitting request to $CA. $($_.Exception.Message)", $_.Exception)
    }
    finally {
        if ($CertRequest) {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($CertRequest)
            $CertRequest = $null
        }
    }

    $keyVaultCertificates = $null
    $exportChain = $null
    $caResponseCertificates = ConvertFrom-Base64Pkcs7 -Content $pkcs7Response
    try {
        # Validate the physical CA response before sending any certificate material to Key Vault.
        # This rejects leaf-only, ambiguous, disconnected, and cryptographically invalid chains.
        if ($caResponseCertificates.Count -lt 2) {
            throw [System.Exception]::new("New-CertificateCreationRequest: CA returned PKCS#7 containing only $($caResponseCertificates.Count) certificate(s); the issuer chain is missing.")
        }
        $caChain = Get-OrderedCertificateChain -Certificates $caResponseCertificates -Source CaResponse
        Assert-CertificateChain -Certificates $caChain

        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "CA: Validated $($caChain.Count) certificate(s) in the complete leaf-to-root chain for $CertificateName."
        foreach ($certificate in $caChain) {
            Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "CA chain member: subject '$($certificate.Subject)', issuer '$($certificate.Issuer)'."
        }

        # Reuse the Automation Account's managed-identity Az context and keep the Key Vault
        # bearer token as a SecureString through merge and exact-version secret retrieval.
        $keyVaultToken = $null
        try {
            $tokenResult = Get-AzAccessToken -ResourceTypeName KeyVault -AsSecureString
            if ($null -eq $tokenResult -or $null -eq $tokenResult.Token) {
                throw [System.Exception]::new('Get-AzAccessToken returned no secure token.')
            }
            $keyVaultToken = $tokenResult.Token
        }
        catch {
            throw [System.Exception]::new("New-CertificateCreationRequest: KeyVault: Error acquiring a data-plane token for vault $VaultName.", $_.Exception)
        }

        try {
            Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "KeyVault: Merging the complete certificate chain into pending certificate $CertificateName in vault $VaultName..."
            $mergedCertificate = Merge-KeyVaultCertificateChain `
                -VaultName $VaultName `
                -CertificateName $CertificateName `
                -Certificates $caChain `
                -Token $keyVaultToken

            # Treat the service-returned certificate ID as untrusted input. The version is used
            # for an exact tag update, so it must belong to the expected vault and certificate.
            try {
                $certificateUri = [Uri][string]$mergedCertificate.id
            }
            catch {
                throw [System.Exception]::new("New-CertificateCreationRequest: KeyVault returned an invalid certificate ID '$($mergedCertificate.id)'.", $_.Exception)
            }
            # A returned URI must remain on the expected authenticated data-plane endpoint.
            if (-not $certificateUri.IsAbsoluteUri -or
                $certificateUri.Scheme -ine 'https' -or
                $certificateUri.Host -ine "$VaultName.vault.azure.net" -or
                -not $certificateUri.IsDefaultPort -or
                -not [string]::IsNullOrEmpty($certificateUri.Query) -or
                -not [string]::IsNullOrEmpty($certificateUri.Fragment)) {
                throw [System.Exception]::new("New-CertificateCreationRequest: KeyVault returned an unexpected certificate ID '$($mergedCertificate.id)'.")
            }

            # Pin later tag updates and export to the exact certificate version from this merge.
            $certificatePath = @($certificateUri.AbsolutePath.Trim('/').Split('/'))
            if ($certificatePath.Count -ne 3 -or
                $certificatePath[0] -ine 'certificates' -or
                [Uri]::UnescapeDataString($certificatePath[1]) -cne $CertificateName -or
                [string]::IsNullOrWhiteSpace($certificatePath[2])) {
                throw [System.Exception]::new("New-CertificateCreationRequest: KeyVault returned an unexpected certificate ID '$($mergedCertificate.id)'.")
            }
            $certificateVersion = $certificatePath[2]

            # Key Vault replaces tags as one set. Start with tags returned by the merge, retain
            # unrelated values, and overlay the current request's mandatory and optional tags.
            $mergedTags = @{}
            $mergedTagProperty = $mergedCertificate.PSObject.Properties['tags']
            if ($null -ne $mergedTagProperty -and $null -ne $mergedTagProperty.Value) {
                if ($mergedTagProperty.Value -is [System.Collections.IDictionary]) {
                    foreach ($key in $mergedTagProperty.Value.Keys) {
                        $mergedTags[$key] = [string]$mergedTagProperty.Value[$key]
                    }
                }
                else {
                    # REST deserialization may represent tags as properties rather than a dictionary.
                    foreach ($property in $mergedTagProperty.Value.PSObject.Properties) {
                        $mergedTags[$property.Name] = [string]$property.Value
                    }
                }
            }

            # Overlay request tags while retaining unrelated service-side metadata.
            $tagUpdateRequired = $false
            foreach ($tag in $tags.GetEnumerator()) {
                if (-not $mergedTags.ContainsKey($tag.Key) -or $mergedTags[$tag.Key] -cne [string]$tag.Value) {
                    $tagUpdateRequired = $true
                }
                $mergedTags[$tag.Key] = [string]$tag.Value
            }

            if ($tagUpdateRequired) {
                Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "KeyVault: Updating request tags on certificate $CertificateName version $certificateVersion."
                try {
                    # Do not retry this state-changing update automatically. The merged tag set
                    # makes a deliberate, exact-version replacement through the Az cmdlet.
                    $taggedCertificate = Update-AzKeyVaultCertificate `
                        -VaultName $VaultName `
                        -Name $CertificateName `
                        -Version $certificateVersion `
                        -Tag $mergedTags `
                        -PassThru
                }
                catch {
                    throw [System.Exception]::new("New-CertificateCreationRequest: KeyVault: Error updating tags on certificate $CertificateName version $certificateVersion.", $_.Exception)
                }

                # Normalize the cmdlet response to a hashtable so verification is independent
                # of the concrete dictionary type returned by the installed Az.KeyVault version.
                $verifiedTags = @{}
                if ($null -ne $taggedCertificate -and $null -ne $taggedCertificate.Tags) {
                    foreach ($key in $taggedCertificate.Tags.Keys) {
                        $verifiedTags[$key] = [string]$taggedCertificate.Tags[$key]
                    }
                }
            }
            else {
                # The merge response represents the exact new version and already contains every
                # requested tag, so no additional state-changing call is necessary.
                $verifiedTags = $mergedTags
            }

            foreach ($tag in $tags.GetEnumerator()) {
                if (-not $verifiedTags.ContainsKey($tag.Key) -or $verifiedTags[$tag.Key] -cne [string]$tag.Value) {
                    throw [System.Exception]::new("New-CertificateCreationRequest: KeyVault certificate $CertificateName version $certificateVersion is missing expected tag '$($tag.Key)'.")
                }
            }

            Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "KeyVault: Complete certificate chain merged and request tags verified for certificate $CertificateName version $certificateVersion in vault $VaultName."

            # Use the sid returned by this merge instead of a latest-version lookup. This binds
            # PFX creation to the exact certificate version completed by the current operation.
            Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "KeyVault: Retrieving exact PKCS#12 secret version for certificate $CertificateName version $certificateVersion..."
            $secretBase64 = Get-KeyVaultCertificateSecretValue `
                -VaultName $VaultName `
                -SecretId ([string]$mergedCertificate.sid) `
                -Token $keyVaultToken

            $certificateBytes = $null
            try {
                $certificateBytes = [Convert]::FromBase64String($secretBase64)
                $secretBase64 = $null
                $importFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet

                # EphemeralKeySet keeps the Key Vault private key out of the Hybrid Worker's
                # persistent user and machine key stores while it is prepared for PFX export.
                # Preserve the legacy explicit-password Import behavior for this exact Key Vault
                # secret: default loader limits would filter attributes and add new rejection limits.
                $keyVaultCertificates = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12Collection(
                    $certificateBytes, [string]::Empty, $importFlags,
                    [System.Security.Cryptography.X509Certificates.Pkcs12LoaderLimits]::DangerousNoLimits)

                # The final PFX must be built only from material physically returned by Key Vault.
                # Comparing against the CA response proves that the merge persisted every member.
                Assert-CertificateSet -Expected $caChain -Actual $keyVaultCertificates -Context 'Key Vault persistence'
                $exportChain = Get-OrderedCertificateChain `
                    -Certificates $keyVaultCertificates `
                    -Source KeyVaultSecret `
                    -ExcludeRoot

                Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "KeyVault: Verified $($keyVaultCertificates.Count) persisted chain certificate(s); $($exportChain.Count) leaf/intermediate certificate(s) selected for PFX export after root exclusion."
                foreach ($certificate in $exportChain) {
                    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX chain member: subject '$($certificate.Subject)', issuer '$($certificate.Issuer)', private key '$($certificate.HasPrivateKey)'."
                }
            }
            catch {
                # The loader owns failed loads; after it returns, this scope owns the collection.
                # Dispose it if validation fails before the later PFX cleanup block is reached.
                if ($null -ne $keyVaultCertificates) {
                    foreach ($certificate in $keyVaultCertificates) {
                        $certificate.Dispose()
                    }
                    $keyVaultCertificates = $null
                }
                throw
            }
            finally {
                # The decoded PKCS#12 contains private-key material and must not remain in memory
                # beyond collection import. The Base64 reference is also released promptly.
                $secretBase64 = $null
                if ($null -ne $certificateBytes) {
                    [Array]::Clear($certificateBytes, 0, $certificateBytes.Length)
                }
            }
        }
        finally {
            # SecureString implements IDisposable. Release the token as soon as all Key Vault
            # merge and exact-version retrieval work is complete.
            if ($null -ne $keyVaultToken) {
                $keyVaultToken.Dispose()
            }
        }
    }
    finally {
        # The PKCS#7 decoder owns these certificate objects until this creation path finishes
        # validating and merging them; dispose every member on both success and failure.
        foreach ($certificate in $caResponseCertificates) {
            $certificate.Dispose()
        }
    }

    try {
        # All remaining PFX work consumes the verified Key Vault collection. Keeping it inside
        # this try/finally guarantees that ephemeral private-key handles are always released.

        # Reapply and revalidate the prerequisites because CA and Key Vault operations may take
        # long enough for directory permissions or domain membership to change after preflight.
        $pfxPreparation = Initialize-PfxExportTarget `
            -PfxRootFolder $PfxRootFolder `
            -Hostname $Hostname `
            -ProtectTo $PfxProtectTo
        $PfxTargetFolder = $pfxPreparation.TargetFolder
        $ProtectionSids = $pfxPreparation.ProtectionSids

        $pfxFile = Join-Path -Path $PfxTargetFolder -ChildPath "$($CertificateName).pfx"
        $temporaryPfxFile = Join-Path -Path $PfxTargetFolder -ChildPath ".$($CertificateName).$([Guid]::NewGuid().ToString('N')).tmp"
        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Export path: $pfxFile"

        # Preserve the previous explicit private-key exportability check. Capture and clear the
        # probe because a PFX byte array contains sensitive private-key material.
        $privateKeyProbe = $null
        try {
            $privateKeyProbe = $exportChain[0].Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        }
        catch {
            throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Private key is not exportable for certificate $CertificateName.", $_.Exception)
        }
        finally {
            if ($null -ne $privateKeyProbe) {
                [Array]::Clear($privateKeyProbe, 0, $privateKeyProbe.Length)
            }
        }

        try {
            # Export only certificates physically downloaded from the exact Key Vault secret.
            # The ordered set contains the private-key leaf and intermediates, but not the root.
            Export-PfxWithGroupProtection `
                -Certificates $exportChain `
                -ProtectionSids $ProtectionSids `
                -PfxFile $temporaryPfxFile

            # A Hybrid Worker may create a PFX protected to other domain SIDs without being
            # authorized to decrypt it. Verify successful non-empty output without reopening it.
            if (-not (Test-Path -LiteralPath $temporaryPfxFile -PathType Leaf)) {
                throw [System.Exception]::new("PFX export did not create temporary file $temporaryPfxFile.")
            }
            $temporaryPfx = Get-Item -LiteralPath $temporaryPfxFile
            if ($temporaryPfx.Length -le 0) {
                throw [System.Exception]::new("PFX export created an empty temporary file $temporaryPfxFile.")
            }

            # The temporary file is created in the target directory so replacement stays on the
            # same volume. An existing valid PFX remains untouched until export fully succeeds.
            [System.IO.File]::Move($temporaryPfxFile, $pfxFile, $true)
        }
        catch {
            throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Export failure for $CertificateName.", $_.Exception)
        }
        finally {
            # Move removes the temporary path on success; this handles every failure path.
            Remove-Item -LiteralPath $temporaryPfxFile -Force -ErrorAction SilentlyContinue
        }

        if (-not (Test-Path -LiteralPath $pfxFile -PathType Leaf)) {
            throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Export did not create $pfxFile")
        }

        # Capture notification-safe metadata while the leaf certificate and verified PFX file
        # are still available. No private key bytes, secret values, or SMTP credentials enter
        # this object.
        $pfxFileInfo = Get-Item -LiteralPath $pfxFile
        $leafCertificate = $exportChain[0]
        $operationResult = [pscustomobject]@{
            PSTypeName            = 'CertLC.CertificateCreationResult'
            CertificateName       = $CertificateName
            VaultName             = $VaultName
            CertificateVersion    = $certificateVersion
            TemplateName          = $CertificateTemplateName
            # Snapshot public certificate fields before disposing the imported collection.
            Subject               = $leafCertificate.Subject
            DnsNames              = @($CertificateDnsNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            Thumbprint            = $leafCertificate.Thumbprint
            SerialNumber          = $leafCertificate.SerialNumber
            Issuer                = $leafCertificate.Issuer
            NotBeforeUtc          = $leafCertificate.NotBefore.ToUniversalTime()
            NotAfterUtc           = $leafCertificate.NotAfter.ToUniversalTime()
            # Export details refer to the published file, not the temporary staging artifact.
            Hostname              = $Hostname
            PfxProtectTo          = @($PfxProtectTo)
            PfxFileName           = $pfxFileInfo.Name
            PfxPath               = $pfxFileInfo.FullName
            PfxSizeBytes          = $pfxFileInfo.Length
            ChainCertificateCount = $exportChain.Count
        }

        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Certificate $CertificateName exported with $($exportChain.Count) leaf/intermediate chain member(s) to $pfxFile."
    }
    finally {
        # Dispose every certificate imported from the Key Vault PKCS#12. This also releases the
        # ephemeral private-key handle associated with the leaf certificate.
        if ($null -ne $keyVaultCertificates) {
            foreach ($certificate in $keyVaultCertificates) {
                $certificate.Dispose()
            }
        }
    }

    # Dispatcher callers use the reference parameter so Write-CertLCLog output remains on the
    # Automation stream. Direct callers that omit it receive the same object conventionally.
    if ($PSBoundParameters.ContainsKey('Result')) {
        $Result.Value = $operationResult
    }
    else {
        $operationResult
    }
}

#endregion

#region ### Get-CertificateByThumbprint ###

###########################################
# FUNCTIONS - Get-CertificateByThumbprint #
###########################################

<#

.SYNOPSIS
    Finds a certificate version in Azure Key Vault by thumbprint.

.DESCRIPTION
    Searches the specified Azure Key Vault for the version of any certificate whose thumbprint
    (x5t) matches the supplied value. The thumbprint may correspond to any version of any
    certificate - current ("latest") or older.

    Algorithm:
      1. List certificates with GET /certificates?api-version=2025-07-01 (one entry per
         certificate name; the x5t exposed there is the thumbprint of the latest version
         only). If a match is found here, the matched version is the latest version of that
         certificate.
      2. If no match in step 1, for each certificate listed in step 1 enumerate its versions
         via GET /certificates/{name}/versions?api-version=2025-07-01 and compare x5t.

    Pagination is handled for both listings via nextLink.

.PARAMETER VaultName
    The name of the Azure Key Vault to query.

.PARAMETER Thumbprint
    The thumbprint of the certificate version to find (hex format; spaces, dashes and
    colons are stripped and case is normalized to uppercase).

.OUTPUTS
    [pscustomobject] with properties:
      - Name     : certificate name in the vault
      - Version  : version identifier of the matched version
      - IsLatest : $true if the matched version is the latest version of the certificate
    Returns $null when no version with the supplied thumbprint exists in the vault.

.EXAMPLE
    $match = Get-CertificateByThumbprint -VaultName 'mykeyvault' -Thumbprint '7CB8B52E7BA87B221534BB9B04A7FFF2D3FA59BA'
    if ($match) { "Found $($match.Name) version $($match.Version) (latest: $($match.IsLatest))" }

.NOTES
    Uses Key Vault REST API version 2025-07-01.
    Requires an active Azure context with the certificates/list permission on the vault.

#>

function Get-CertificateByThumbprint {
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [string]$Thumbprint
    )

    # Thumbprints are identifiers: normalize hex casing independently of worker culture.
    $normalizedThumbprint = ($Thumbprint -replace '[^a-fA-F0-9]', '').ToUpperInvariant()

    if ([string]::IsNullOrEmpty($normalizedThumbprint)) {
        throw [System.ArgumentException]::new('Get-CertificateByThumbprint: Thumbprint is empty after normalization.', 'Thumbprint')
    }

    # Helper: Convert base64url thumbprint to hex
    $convertToHex = {
        param([string]$base64Url)
        $base64 = $base64Url.Replace('-', '+').Replace('_', '/')
        switch ($base64.Length % 4) {
            2 { $base64 += '==' }
            3 { $base64 += '=' }
        }
        $bytes = [Convert]::FromBase64String($base64)
        # Match X2 formatting exactly: uppercase, two hex digits per byte, no separators.
        return [Convert]::ToHexString($bytes)
    }

    # Helper: Extract the last URL segment (certificate name or version) from a KV resource id
    $lastSegment = {
        param([string]$id)
        return ($id -split '/')[-1]
    }

    # Helper: Invoke Key Vault REST API
    # Fetch the access token once per lookup, not per page. Pass the SecureString directly
    # through -Authentication Bearer -Token so this code does not convert it to plaintext
    # or allocate an unmanaged BSTR; Invoke-RestMethod constructs the Authorization header.
    $secureToken = $null
    try {
        $tokenResult = Get-AzAccessToken -ResourceTypeName KeyVault -AsSecureString
        $secureToken = $tokenResult.Token
        $invokeApi = {
            param([string]$uri)
            # $secureToken lives in the enclosing function scope. GetNewClosure() only captures
            # variables that are LOCAL to the script block where it is invoked, so we first pull
            # the token into this scope before creating the closure.
            $tok = $secureToken
            $op = {
                Invoke-RestMethod -Uri $uri -Method GET -Authentication Bearer -Token $tok -ContentType 'application/json'
            }.GetNewClosure()
            return Invoke-WithRetry -ScriptBlock $op -OperationName "KV GET $uri" -Section 'Get-CertificateByThumbprint'
        }

        $vaultBaseUrl = "https://$VaultName.vault.azure.net"
        $apiVersion = '2025-07-01'

        # Step 1: enumerate certificates (one entry per cert name; x5t is the LATEST version's thumbprint)
        # While iterating we also collect the certificate names so step 2 can fall back to per-cert version listings.
        # Retain a mutable typed list for the fallback version-enumeration pass.
        $certificateNames = [System.Collections.Generic.List[string]]::new()
        $uri = "$vaultBaseUrl/certificates?api-version=$apiVersion"

        try {
            do {
                $response = & $invokeApi $uri

                if ($response.value) {
                    foreach ($cert in $response.value) {
                        # Capture the certificate name for the possible step-2 pass
                        if ($cert.id) {
                            # /certificates listing ids have the shape: <vaultBaseUrl>/certificates/<name>
                            $name = & $lastSegment $cert.id
                            if (-not [string]::IsNullOrEmpty($name)) {
                                [void]$certificateNames.Add($name)
                            }
                        }

                        if ($cert.x5t) {
                            $certThumbprint = & $convertToHex $cert.x5t
                            if ($certThumbprint -eq $normalizedThumbprint) {
                                # We matched against the latest-version thumbprint. The id of the listing
                                # entry does NOT contain a version segment, so we resolve the latest version
                                # id explicitly via /certificates/{name}.
                                $certName = & $lastSegment $cert.id
                                $bundleUri = "$vaultBaseUrl/certificates/$certName" + "?api-version=$apiVersion"
                                $bundle = & $invokeApi $bundleUri
                                $version = & $lastSegment $bundle.id
                                return [pscustomobject]@{
                                    Name     = $certName
                                    Version  = $version
                                    IsLatest = $true
                                }
                            }
                        }
                    }
                }

                $uri = $response.nextLink
            } while ($uri)
        }
        catch {
            throw [System.Exception]::new("Get-CertificateByThumbprint: Failed to enumerate certificates in vault '$VaultName'.", $_.Exception)
        }

        # Step 2: no match against any latest version. Enumerate every cert's versions and compare x5t.
        try {
            foreach ($name in $certificateNames) {
                $uri = "$vaultBaseUrl/certificates/$name/versions?api-version=$apiVersion"
                do {
                    $response = & $invokeApi $uri
                    if ($response.value) {
                        foreach ($ver in $response.value) {
                            if ($ver.x5t) {
                                $certThumbprint = & $convertToHex $ver.x5t
                                if ($certThumbprint -eq $normalizedThumbprint) {
                                    # /certificates/{name}/versions listing ids have the shape:
                                    #   <vaultBaseUrl>/certificates/<name>/<version>
                                    $version = & $lastSegment $ver.id
                                    return [pscustomobject]@{
                                        Name     = $name
                                        Version  = $version
                                        IsLatest = $false
                                    }
                                }
                            }
                        }
                    }
                    $uri = $response.nextLink
                } while ($uri)
            }
        }
        catch {
            throw [System.Exception]::new("Get-CertificateByThumbprint: Failed to enumerate certificate versions in vault '$VaultName'.", $_.Exception)
        }

        return $null
    }
    finally {
        # Both search passes share this token; dispose it after every return or failure.
        if ($null -ne $secureToken) { $secureToken.Dispose() }
    }
}

#endregion

#region ### New-CertificateRevocationRequest ###

################################################
# FUNCTIONS - New-CertificateRevocationRequest #
################################################

<#

.SYNOPSIS
    Revoke a specific version of a certificate by sending a revocation request to the CA, then
    disable that version in Key Vault and tag it with audit metadata.

.DESCRIPTION
    This function revokes the specified version of a certificate stored in Azure Key Vault:
        1. Uses the supplied version-specific public certificate, or reads it from Key Vault,
            to extract the X.509 serial number without retrieving private-key material.
      2. Submits a revocation request to the Certificate Authority (CA) for that serial.
      3. Disables that Key Vault version (attributes.enabled=false) and tags it with
         Revoked=true, RevokedAt, RevocationReason, RevokedJobId. Existing tags on the
         version are preserved (read-merge-write).
    The certificate object is NEVER deleted from Key Vault. Other versions of the same
    certificate are not touched.

.PARAMETER VaultName
    The name of the Azure Key Vault where the certificate is stored.

.PARAMETER CertificateName
    The name of the certificate to revoke.

.PARAMETER CertificateVersion
    The version identifier of the certificate version to revoke.

.PARAMETER CA
    The CA configuration supplied by the caller for the revocation request.

.PARAMETER RevocationReason
    The reason for revocation, specified as an integer value (0-6) according to the CRLReason codes:
        0 - Unspecified
        1 - Key Compromise
        2 - CA Compromise
        3 - Affiliation Changed
        4 - Superseded
        5 - Cessation of Operation
        6 - Certificate Hold

.PARAMETER JobId
    The Automation runbook job id; written into the RevokedJobId tag for traceability.

.PARAMETER Certificate
    The public X.509 certificate from the exact Key Vault version being revoked.
    If omitted, the function reads that version's public certificate from Key Vault.
    The supplied certificate remains owned by the caller and is not disposed here.

.PARAMETER ExpectedThumbprint
    When supplied, must match the public certificate before any CA or Key Vault mutation.

.EXAMPLE
    New-CertificateRevocationRequest -VaultName 'MyKeyVault' -CertificateName 'MyCertificate' -CertificateVersion 'abc123...' -RevocationReason 1 -JobId $jobId -CA 'MyCA\MyInstance'

#>
function New-CertificateRevocationRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [string]$CertificateVersion,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 6)]
        [Int64]$RevocationReason,

        [Parameter(Mandatory = $false)]
        [string]$JobId,

        # Optional: pre-fetched tags of the specific version (passed by the dispatcher to avoid a
        # second Get-AzKeyVaultCertificate round-trip). If not provided, the function fetches them.
        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$ExistingTags,

        # As in the creation function, the reference return keeps structured log output visible
        # while delivering notification metadata separately to the dispatcher.
        [Parameter(Mandatory = $false)]
        [ref]$Result,

        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedThumbprint,

        # Require the target CA explicitly instead of resolving dispatcher scope.
        [Parameter(Mandatory = $true)]
        [string]$CA
    )

    # Prefer the caller's exact-version public certificate; fetch it only when not supplied.
    $existingVersion = $null
    if (-not $PSBoundParameters.ContainsKey('Certificate')) {
        Write-CertLCLog -Section 'New-CertificateRevocationRequest' -Message "KeyVault: Reading public certificate $CertificateName version $CertificateVersion from vault $VaultName..."
        try {
            $existingVersion = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -Version $CertificateVersion
        }
        catch {
            throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Error getting public certificate $CertificateName version $CertificateVersion from key vault $VaultName", $_.Exception)
        }
        if ($null -ne $existingVersion -and $null -ne $existingVersion.Certificate) {
            $Certificate = $existingVersion.Certificate
        }
    }
    # Refuse to revoke until both the serial and any caller-provided thumbprint are verified.
    if ($null -eq $Certificate -or [string]::IsNullOrWhiteSpace($Certificate.SerialNumber)) {
        throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Public certificate $CertificateName version $CertificateVersion is missing or has no serial number.")
    }
    if ($PSBoundParameters.ContainsKey('ExpectedThumbprint') -and $Certificate.Thumbprint -ine $ExpectedThumbprint) {
        throw [System.Exception]::new("New-CertificateRevocationRequest: Public certificate thumbprint does not match the requested thumbprint for $CertificateName version $CertificateVersion.")
    }

    # Retain public metadata for the result without retrieving the certificate's private key.
    $serialNumber = $Certificate.SerialNumber
    $certificateSubject = $Certificate.Subject
    $certificateIssuer = $Certificate.Issuer
    $certificateThumbprint = $Certificate.Thumbprint
    $certificateNotBeforeUtc = $Certificate.NotBefore.ToUniversalTime()
    $certificateNotAfterUtc = $Certificate.NotAfter.ToUniversalTime()

    Write-CertLCLog -Section 'New-CertificateRevocationRequest' -Message "CA: Sending revocation request for certificate $CertificateName version $CertificateVersion (serial $serialNumber) to the CA $CA using reason $($RevocationReason)..."

    # Initialize before COM activation so the finally block remains safe under StrictMode
    # when New-Object fails before assigning the CertificateAuthority.Admin instance.
    $CertAdmin = $null
    try {
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
        $CertAdmin.RevokeCertificate($CA, $serialNumber, $RevocationReason, 0)
    }
    catch {
        throw [System.Exception]::new("New-CertificateRevocationRequest: CA: Error revoking certificate $CertificateName version $CertificateVersion (serial $serialNumber) in CA $CA", $_.Exception)
    }
    finally {
        # Release COM ownership on either CA success or failure; callers still own certificates.
        if ($CertAdmin) {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($CertAdmin)
            $CertAdmin = $null
        }
    }

    Write-CertLCLog -Section 'New-CertificateRevocationRequest' -Message "CA: Certificate $CertificateName version $CertificateVersion (serial $serialNumber) revoked successfully in CA $($CA)."

    # disable the specific version in key vault and tag it with revocation audit metadata.
    # The Key Vault Update Certificate PATCH endpoint replaces tags wholesale, so we must
    # start from the existing tags on this version, merge our revocation keys, and write back.
    Write-CertLCLog -Section 'New-CertificateRevocationRequest' -Message "KeyVault: Disabling certificate $CertificateName version $CertificateVersion in key vault $($VaultName) and tagging it as revoked..."

    # Source the existing tags: prefer the caller-provided snapshot to avoid a second round-trip;
    # otherwise fetch the version now.
    $sourceTags = $null
    if ($PSBoundParameters.ContainsKey('ExistingTags') -and $null -ne $ExistingTags) {
        $sourceTags = $ExistingTags
    }
    elseif ($null -ne $existingVersion) {
        $sourceTags = $existingVersion.Tags
    }
    else {
        # A missing tag snapshot needs one exact-version read before the replacement PATCH.
        try {
            $existingVersion = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -Version $CertificateVersion
        }
        catch {
            throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Error reading certificate $CertificateName version $CertificateVersion from key vault $VaultName for tag merge", $_.Exception)
        }
        if ($null -ne $existingVersion) { $sourceTags = $existingVersion.Tags }
    }

    # build merged tag set: start from existing tags (if any), then overlay revocation metadata
    $mergedTags = @{}
    if ($null -ne $sourceTags) {
        foreach ($k in $sourceTags.Keys) {
            $mergedTags[$k] = [string]$sourceTags[$k]
        }
    }
    # Audit fields override older values, but all unrelated tags remain in the replacement set.
    $mergedTags['Revoked'] = 'true'
    $revokedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $mergedTags['RevokedAt'] = $revokedAt
    $mergedTags['RevocationReason'] = [string]$RevocationReason
    if (-not [string]::IsNullOrEmpty($JobId)) {
        $mergedTags['RevokedJobId'] = $JobId
    }

    # Update-AzKeyVaultCertificate wraps PATCH /certificates/{name}/{version}: -Enable $false and
    # -Tag are applied in a single atomic call.
    try {
        $null = Update-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -Version $CertificateVersion -Enable $false -Tag $mergedTags -PassThru -ErrorAction Stop
    }
    catch {
        throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Error disabling/tagging certificate $CertificateName version $CertificateVersion in key vault $VaultName", $_.Exception)
    }
    Write-CertLCLog -Section 'New-CertificateRevocationRequest' -Message "KeyVault: Certificate $CertificateName version $CertificateVersion in key vault $($VaultName) has been disabled and tagged as revoked. The certificate object and other versions (if any) are left untouched."

    # Return only public identity and committed audit metadata after both revocation steps.
    $operationResult = [pscustomobject]@{
        PSTypeName         = 'CertLC.CertificateRevocationResult'
        CertificateName    = $CertificateName
        VaultName          = $VaultName
        CertificateVersion = $CertificateVersion
        Subject            = $certificateSubject
        Thumbprint         = $certificateThumbprint
        SerialNumber       = $serialNumber
        Issuer             = $certificateIssuer
        # Validity remains certificate metadata; revocation fields describe this operation.
        NotBeforeUtc       = $certificateNotBeforeUtc
        NotAfterUtc        = $certificateNotAfterUtc
        RevocationReason   = $RevocationReason
        RevokedAt          = $revokedAt
        JobId              = $JobId
    }
    # Preserve normal return behavior for direct callers while allowing the dispatcher to keep
    # structured log records on the Automation output stream.
    if ($PSBoundParameters.ContainsKey('Result')) {
        $Result.Value = $operationResult
    }
    else {
        $operationResult
    }
}

#endregion

#region ### ConvertTo-CertLCRequestMap ###

##########################################
# FUNCTIONS - ConvertTo-CertLCRequestMap #
##########################################

<#
.SYNOPSIS
    Normalize a JSON or native request object to a case-insensitive dictionary.
.DESCRIPTION
    Missing optional keys return null under StrictMode. Values retain their original
    types and array shapes; only object containers are normalized, without serialization.
.PARAMETER Value
    A parsed JSON dictionary or native webhook object. Scalars and arrays are rejected.
.PARAMETER Label
    Request location included in validation errors.
#>
function ConvertTo-CertLCRequestMap {
    [OutputType([hashtable])]
    param([AllowNull()][object]$Value, [string]$Label = 'request body')

    if ($Value -is [System.Collections.IDictionary]) {
        $entries = $Value.GetEnumerator()
    }
    # The [pscustomobject] accelerator also matches PSObject-wrapped JSON scalars and
    # arrays. The concrete base type admits native objects without admitting those shapes.
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) {
        $entries = foreach ($property in $Value.PSObject.Properties) {
            [System.Collections.DictionaryEntry]::new($property.Name, $property.Value)
        }
    }
    else {
        throw [System.ArgumentException]::new("Expected a single object for '$Label'.")
    }

    # Use PowerShell's case-insensitive map for native and JSON inputs alike. Reject
    # ambiguous case-only duplicate keys instead of choosing a different field silently.
    $normalized = @{}
    foreach ($entry in $entries) {
        if ($entry.Key -isnot [string] -or $normalized.ContainsKey($entry.Key)) {
            throw [System.ArgumentException]::new("Invalid or duplicate field in '$Label': '$($entry.Key)'.")
        }
        $normalized[$entry.Key] = $entry.Value
    }
    return $normalized
}

#endregion

#region ### Assert-CertLCRequestFields ###

##########################################
# FUNCTIONS - Assert-CertLCRequestFields #
##########################################

<#
.SYNOPSIS
    Validate required strings and optional arrays without coercing request values.
.DESCRIPTION
    Missing or null optional arrays are accepted; scalars are not promoted to arrays.
    Domain rules such as hostname syntax, principal normalization, and reason codes
    remain with the dispatcher. Callers own structured logging and email context.
#>
function Assert-CertLCRequestFields {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Data,
        [string[]]$RequiredStrings = @(),
        [string[]]$OptionalArrays = @(),
        [string]$Prefix = 'data.'
    )

    foreach ($name in $RequiredStrings) {
        $value = $Data[$name]
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
            throw [System.ArgumentException]::new("Missing, empty, or invalid mandatory string parameter: '$Prefix$name' in request body!")
        }
    }
    foreach ($name in $OptionalArrays) {
        # Indexing a normalized map returns null for omitted optional properties.
        if ($null -ne $Data[$name] -and $Data[$name] -isnot [array]) {
            throw [System.ArgumentException]::new("Parameter '$Prefix$name' is not an array!")
        }
    }
}

#endregion

#region ### Find-CertLCJobId ###

###################################
# FUNCTIONS - Find-CertLCJobId    #
###################################

<#
.SYNOPSIS
    Resolve this execution's Automation job ID from its unique JSON Output marker.
.DESCRIPTION
    Scan Running jobs for the configured runbook, follow paginated Output streams,
    and require one job containing the exact identityMarker in section JobIdentity.
    The caller must emit the marker through Write-CertLCLog before invoking this
    function; emitting it here would capture it with the returned job ID instead.
.PARAMETER Marker
    Random per-execution marker already written to the Automation Output stream.
.PARAMETER AccountResourceId
    ARM resource ID of the Automation account whose jobs will be searched.
.PARAMETER RunbookName
    Published runbook name, independent of worker-generated script filenames.
.PARAMETER AzureContext
    Explicit managed-identity context with permission to read jobs and job streams.
.PARAMETER MaxPasses
    Maximum scans to allow for Output visibility; defaults to eight.
.OUTPUTS
    System.String. The unique, verified Automation job ID in canonical GUID format.
.NOTES
    Fails closed on missing or ambiguous identity. The 120-second budget is checked
    between requests, not a hard HTTP timeout. No worker metadata or trace is read.
#>
function Find-CertLCJobId {
    param(
        [Parameter(Mandatory)][string]$Marker,
        [Parameter(Mandatory)][string]$AccountResourceId,
        [Parameter(Mandatory)][string]$RunbookName,
        [Parameter(Mandatory)][object]$AzureContext,
        [ValidateRange(1, 12)][int]$MaxPasses = 8
    )

    # Keep the API scope and scan clock local to this lookup, not shared logger state.
    $baseUri = "https://management.azure.com$AccountResourceId"
    $api = 'api-version=2024-10-23'
    $clock = [System.Diagnostics.Stopwatch]::StartNew()

    <#
    .SYNOPSIS
        Read an Automation object or all collection pages within this account.
    .DESCRIPTION
        Reject escaped/repeated links and failed responses; tolerate omitted nextLink.
        Uses an explicit managed-identity profile and the enclosing account scope and clock.
    #>
    function Get-CertLCAutomationData {
        param([string]$Uri, [object]$RequestContext)
        $visited = [System.Collections.Generic.HashSet[string]]::new()
        do {
            # Validate every page before sending the authenticated request.
            if (-not $Uri.StartsWith("$baseUri/", [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Automation API link escaped the account scope.' }
            if (-not $visited.Add($Uri)) { throw 'Automation API returned a repeated pagination link.' }
            if ($clock.Elapsed.TotalSeconds -ge 120) { throw 'Automation identity lookup exceeded its scan budget.' }
            $response = Invoke-AzRestMethod -Method GET -Uri $Uri -DefaultProfile $RequestContext -ErrorAction Stop
            if ($response.StatusCode -ne 200) { throw "Automation API GET failed: HTTP $($response.StatusCode)." }
            $page = ConvertFrom-Json -InputObject $response.Content -AsHashtable -ErrorAction Stop
            if ($page.ContainsKey('value')) { $page['value'] } else { $page }
            $Uri = [string]$page['nextLink']
        } while (-not [string]::IsNullOrWhiteSpace($Uri))
    }

    # Check every Running job for this runbook and identify ours by its exact marker.
    # Do not assume the first or most recently started job is ours.
    $filter = [uri]::EscapeDataString("properties/runbook/name eq '$($RunbookName.Replace("'", "''"))' and properties/status eq 'Running'")
    for ($pass = 1; $pass -le $MaxPasses; $pass++) {
        $matchingJobIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($candidate in @(Get-CertLCAutomationData "$baseUri/jobs?$api&`$filter=$filter" -RequestContext $AzureContext)) {
            $candidateId = ([guid]$candidate.properties.jobId).ToString('D')
            if ($candidateId -eq [guid]::Empty.ToString()) { throw 'Automation API returned an empty job ID.' }
            $jobUri = "$baseUri/jobs/$candidateId"
            foreach ($stream in @(Get-CertLCAutomationData "$jobUri/streams?$api&`$filter=properties/streamType%20eq%20'Output'" -RequestContext $AzureContext)) {
                # Read full records, not potentially truncated summaries; ignore unrelated output.
                $record = Get-CertLCAutomationData "$jobUri/streams/$($stream.properties.jobStreamId)?$api" -RequestContext $AzureContext
                if ($record.properties.streamType -ne 'Output') { continue }
                try { $entry = ConvertFrom-Json $record.properties.streamText -AsHashtable -ErrorAction Stop }
                catch { continue }
                if ($entry -is [System.Collections.IDictionary] -and $entry['section'] -ceq 'JobIdentity' -and
                    $entry['identityMarker'] -is [string] -and $entry['identityMarker'] -ceq $Marker) {
                    $null = $matchingJobIds.Add($candidateId)
                }
            }
        }

        # Duplicate records from one job are harmless; matches in different jobs are not.
        if ($matchingJobIds.Count -gt 1) { throw "Identity marker matched $($matchingJobIds.Count) different jobs; refusing ambiguous identity." }
        if ($matchingJobIds.Count -eq 1) {
            $foundId = @($matchingJobIds)[0]
            $confirmed = Get-CertLCAutomationData "$baseUri/jobs/$foundId`?$api" -RequestContext $AzureContext
            if (([guid]$confirmed.properties.jobId).ToString('D') -ne $foundId -or
                $confirmed.properties.runbook.name -ne $RunbookName -or $confirmed.properties.status -ne 'Running') {
                throw 'The matching job failed identity verification.'
            }
            return $foundId
        }
    }
    throw 'The marker was not visible in any running job Output stream within the probe budget.'
}

#endregion

#region ### Dispatcher ###

###############
# DISPATCHER  #
###############

# Reject unsupported hosts before Azure authentication. Automation captures runbook streams
# without Connect-AzAccount; event correlation is not available until request parsing below.
# Resolve identity through authenticated Automation APIs, independently of event correlation.

if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
    # Azure Automation sandbox: not supported (we require the hybrid worker for CA access).
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Runbook running in Azure Automation sandbox. This runbook must be executed by a hybrid worker instead!'
}
elseif ($env:AZUREPS_HOST_ENVIRONMENT -ne 'AzureAutomation/') {
    # We are in a local environment - not supported anymore because we cannot get the encrypted variables from the automation account in this case
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Runbook running in a local environment. This runbook must be executed by a hybrid worker instead!'
}

# Keep the supported runtime aligned with the PowerShell 7.6+ Hybrid Worker diagnostic.
if ($PSVersionTable.PSVersion -lt [version]'7.6') {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'This runbook requires PowerShell 7.6 or later.'
}

# Emit outside the resolver so its return-value assignment cannot swallow this Output record.
# The random marker is not an Automation ID or event correlation ID; neither is guessed.
$jobId = $null
$identityMarker = 'CERTLC-JOB-IDENTITY:' + [guid]::NewGuid().ToString('D')
Write-CertLCLog -Section 'JobIdentity' -Message 'Resolving Automation job identity.' -Context @{ identityMarker = $identityMarker }

# Use explicit account/runbook configuration, not undocumented environment metadata or paths.
# Internal Automation variables are available on the Hybrid Worker before Connect-AzAccount.
try {
    $identityAccountId = Get-AutomationVariable -Name 'certlc-automationaccountid' -ErrorAction Stop
    $identityRunbookName = Get-AutomationVariable -Name 'certlc-runbookname' -ErrorAction Stop
    if ($identityAccountId -isnot [string] -or $identityAccountId -notmatch '^/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/[^/?#]+/providers/Microsoft\.Automation/automationAccounts/[^/?#]+$' -or
        $identityRunbookName -isnot [string] -or [string]::IsNullOrWhiteSpace($identityRunbookName)) {
        throw 'Set certlc-automationaccountid to the Automation account ARM resource ID and certlc-runbookname to this published runbook name.'
    }
    $identitySubscriptionId = ([guid]$identityAccountId.Split('/')[2]).ToString('D')
}
catch {
    Write-CertLCLogAndThrow -Section 'JobIdentity' -Message 'Unable to load Automation identity lookup configuration.' -InnerException $_.Exception
}

# Authenticate before API discovery. Early failures have no jobId until it is verified.
$null = Disable-AzContextAutosave -Scope Process
Write-CertLCLog -Section 'Dispatcher' -Message 'Connecting to Azure using default identity...'
try {
    $AzureConnection = (Connect-AzAccount -Identity -Subscription $identitySubscriptionId -ErrorAction Stop).Context
    Set-AzContext -SubscriptionId $identitySubscriptionId -DefaultProfile $AzureConnection -ErrorAction Stop | Out-Null
}
catch {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Unable to authenticate or select the Automation subscription using managed identity.' -InnerException $_.Exception
}

# Fail before certificate operations if no unique Running job owns our exact JSON marker.
try {
    $jobId = Find-CertLCJobId -Marker $identityMarker -AccountResourceId $identityAccountId -RunbookName $identityRunbookName -AzureContext $AzureConnection
}
catch {
    Write-CertLCLogAndThrow -Section 'JobIdentity' -Message 'Cannot determine the Automation job ID using the Output marker.' -InnerException $_.Exception
}
$jobIdSource = 'AutomationApiMarker'
Write-CertLCLog -Section 'JobIdentity' -Message 'Automation job identity resolved.' -Context @{ jobIdSource = $jobIdSource }

# The logger now includes jobId independently; correlation remains absent until event parsing.
# Delay the positive host message until execution identity is available for all normal
# startup records. Rejections above still log immediately without inventing an identifier.
Write-CertLCLog -Section 'Dispatcher' -Message "Hybrid Runbook Worker confirmed: $($env:COMPUTERNAME)."

# Emit a readable ID followed by structured diagnostic details through the existing logger.
# The source, worker, runtime, and host marker help diagnose future worker behavior changes.
Write-CertLCLog -Section 'Dispatcher' -Message "Automation Job ID: $jobId"
Write-CertLCLog -Section 'Dispatcher' -Message ([ordered]@{
    JobId = $jobId
    JobIdSource = $jobIdSource
    Worker = $env:COMPUTERNAME
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    HostEnvironment = $env:AZUREPS_HOST_ENVIRONMENT
} | ConvertTo-Json -Compress)

# Get the runbook variables from the Automation Account
# Since they are encrypted, we must use the internal cmdlet Get-AutomationVariable to retrieve them, not Get-AzAutomationVariable

Write-CertLCLog -Section 'Dispatcher' -Message 'Retrieving automation account variables...'

# Retrieve all variables (using Ignore to not pollute $Error collection if missing; will check later the mandatory ones)
$SmtpServer = Get-AutomationVariable -Name 'certlc-smtpserver' -ErrorAction Ignore
$FromAddress = Get-AutomationVariable -Name 'certlc-smtpfrom' -ErrorAction Ignore
$SmtpUser = Get-AutomationVariable -Name 'certlc-smtpuser' -ErrorAction Ignore
$SmtpPassword = Get-AutomationVariable -Name 'certlc-smtppassword' -ErrorAction Ignore
$CA = Get-AutomationVariable -Name 'certlc-ca' -ErrorAction Ignore
$PfxRootFolder = Get-AutomationVariable -Name 'certlc-pfxrootfolder' -ErrorAction Ignore

# Validate mandatory variables first
if ([string]::IsNullOrEmpty($CA)) {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "The automation account variable 'certlc-ca' is missing or empty. Ensure this variable exists in the automation account."
}

if ([string]::IsNullOrEmpty($PfxRootFolder)) {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "The automation account variable 'certlc-pfxrootfolder' is missing or empty. Ensure this variable exists in the automation account."
}

# Validate SMTP variables.
# - If SmtpServer is empty, no other SMTP variable may be set.
# - If SmtpServer is set, FromAddress is required; SmtpUser and SmtpPassword must be both set or both empty.
if ([string]::IsNullOrEmpty($SmtpServer)) {
    foreach ($pair in @(
            @{ Name = 'certlc-smtpfrom'; Value = $FromAddress },
            @{ Name = 'certlc-smtpuser'; Value = $SmtpUser },
            @{ Name = 'certlc-smtppassword'; Value = $SmtpPassword }
        )) {
        if (-not [string]::IsNullOrEmpty($pair.Value)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "The automation account variable '$($pair.Name)' is set, but 'certlc-smtpserver' is missing or empty. When SmtpServer is not configured, all other SMTP variables must be missing or empty."
        }
    }
    Write-CertLCLog -Section 'Dispatcher' -Message 'SMTP: Email notifications are disabled (SmtpServer is not configured).'
}
else {
    if ([string]::IsNullOrEmpty($FromAddress)) {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "The automation account variable 'certlc-smtpserver' is set, but 'certlc-smtpfrom' is missing or empty. Both must be set to send email."
    }
    # Partial SMTP credentials indicate configuration drift rather than anonymous delivery.
    $userSet = -not [string]::IsNullOrEmpty($SmtpUser)
    $passSet = -not [string]::IsNullOrEmpty($SmtpPassword)
    if ($userSet -xor $passSet) {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "The automation account variables 'certlc-smtpuser' and 'certlc-smtppassword' must be both set (to use SMTP authentication) or both empty (for unauthenticated email). Currently only one of them is set."
    }
}

# Prepare the SMTP credentials (only if SmtpServer is configured)
$SmtpCredential = $null
if (-not [string]::IsNullOrEmpty($SmtpServer)) {
    if (-not [string]::IsNullOrEmpty($SmtpUser) -and -not [string]::IsNullOrEmpty($SmtpPassword)) {
        $SmtpSecurePassword = ConvertTo-SecureString -String $SmtpPassword -AsPlainText -Force
        $SmtpCredential = [pscredential]::new($SmtpUser, $SmtpSecurePassword)
        $SmtpSecurePassword = $null
        Write-CertLCLog -Section 'Dispatcher' -Message 'SMTP: Authentication will be used to send email.'
    }
    else {
        # Anonymous SMTP is supported only when the relay allows this worker explicitly.
        Write-CertLCLog -Section 'Dispatcher' -Message 'SMTP: No authentication will be used to send email. Ensure the SMTP server allows unauthenticated email from this host!' -Level 'Warning'
    }
}

# Common SMTP arguments, splatted by Write-CertLCLogAndThrow and Send-SuccessNotification call sites.
# Splatting an empty/null SmtpServer is intentional: the helpers treat that as "SMTP disabled".
$smtpArgs = @{
    SmtpServer     = $SmtpServer
    FromAddress    = $FromAddress
    SmtpCredential = $SmtpCredential
}

# Check if we have the jsonRequestBody parameter
# Capture the original input path before the legacy webhook parser reuses jsonRequestBody.
# This is a routing distinction, not an authenticated assertion of the caller's identity.
$usesJsonRequestBody = -not [string]::IsNullOrEmpty($jsonRequestBody)
if (-not $usesJsonRequestBody) {

    # No explicit jsonRequestBody parameter, so we will use WebhookData

    if ([string]::IsNullOrEmpty($WebhookData)) {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Both jsonRequestBody and WebhookData parameters are missing or empty! Call the runbook from a webhook or pass the jsonRequestBody parameter explicitly with Start-AzAutomationRunbook!'
    }

    Write-CertLCLog -Section 'Dispatcher' -Message "WebhookData received is: $($WebhookData)"

    <#

    Try to parse the webhook data.
    Using Powershell 7.x, the WebhookData string contains a wrongly formatted JSON, such as:
    {WebhookName:certlc,RequestBody:{"id":"e1a6f79d-fed0-4e2c-80a6-3cfd09ee3b13","source":"/subscriptions/...etc
    (see https://learn.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal#create-a-webhook)

    The problem here is that WebhookName, RequestBody and RequestHeader are not enclosed in double quotes.
    We try to parse the JSON but, if it fails, we 'manually' extract the RequestBody via regex and convert it from JSON to object.

    #>

    # Accept a native webhook envelope or its JSON representation. Keep the existing
    # malformed PowerShell webhook fallback below for envelopes that are not valid JSON.
    try {
        $request = if ($WebhookData -is [string]) { ConvertFrom-Json -InputObject $WebhookData -Depth 10 -AsHashtable -NoEnumerate } else { $WebhookData }
        $request = ConvertTo-CertLCRequestMap -Value $request -Label 'webhook envelope'
        $requestBody = $request['RequestBody']
    }
    catch {
        # Fallback to regex extraction for broken format. The following regex matches these cases:
        # - RequestBody is enclosed in double quotes (valid case):   "RequestBody":"{...}"
        # - RequestBody is not enclosed in double quotes (invalid case):   RequestBody:{...}
        # - After RequestBody there is an array:  RequestBody:[{...}] or "RequestBody":[{...},{...}]
        # The regex properly handles nested JSON objects, checking that braces are balanced.

        Write-CertLCLog -Level Warning -Section 'Dispatcher' -Message 'Cannot parse WebhookData as JSON. Attempting to extract RequestBody using regex instead...'

        if ($WebhookData -match '"?RequestBody"?\s*:\s*((?:{([^{}]|(?<open>{)|(?<-open>}))*(?(open)(?!))})|(?:\[([^\[\]]|(?<open>\[)|(?<-open>\]))*(?(open)(?!))\]))') {
            $jsonRequestBody = $matches[1]
            Write-CertLCLog -Section 'Dispatcher' -Message "Regex extracted RequestBody: $jsonRequestBody"
            try {
                $RequestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10 -AsHashtable -NoEnumerate
            }
            catch {
                # The extracted body may contain literal escape sequences (e.g. \r\n, \") from callers that
                # double-serialized the JSON (sent an already-escaped string as the HTTP body).
                # Try unescaping those sequences and parsing again before giving up.
                Write-CertLCLog -Level Warning -Section 'Dispatcher' -Message "First parse attempt failed: $($_.Exception.Message). Attempting to unescape literal \r\n and \`" sequences and retry..."
                $jsonRequestBody = $jsonRequestBody -replace '\\r\\n', "`r`n" -replace '\\"', '"'
                Write-CertLCLog -Section 'Dispatcher' -Message "Unescaped RequestBody: $jsonRequestBody"
                try {
                    $RequestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10 -AsHashtable -NoEnumerate
                    Write-CertLCLog -Section 'Dispatcher' -Message 'Successfully parsed RequestBody after unescaping.'
                }
                catch {
                    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Failed to parse WebhookData.RequestBody using regex (even after unescaping)' -Inner $_.Exception
                }
            }
        }
        else { Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'WebhookData.RequestBody not recognized using regex!' }
    }

    if ($null -eq $requestBody) {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'WebhookData.RequestBody is empty! Ensure the runbook is called from a webhook!'
    }
}

else {
    # parse the jsonRequestBody parameter as JSON
    Write-CertLCLog -Section 'Dispatcher' -Message "jsonRequestBody received is: $($jsonRequestBody)"
    try {
        $requestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10 -AsHashtable -NoEnumerate
    }
    catch {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Failed to parse jsonRequestBody parameter as JSON' -Inner $_.Exception
    }
}

# Valid webhook envelopes commonly contain RequestBody as a JSON string. Normalize it
# before reading identity so native, JSON, and legacy webhook paths share one contract.
if ($requestBody -is [string]) {
    try {
        $requestBody = ConvertFrom-Json -InputObject $requestBody -Depth 10 -AsHashtable -NoEnumerate
    }
    catch {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Failed to parse request body as JSON' -Inner $_.Exception
    }
}

# Normalize once after the transport-specific parsing. No property access or string
# coercion should turn a malformed envelope into an apparently valid request.
try {
    $requestBody = ConvertTo-CertLCRequestMap -Value $requestBody
}
catch {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message $_.Exception.Message -InnerException $_.Exception
}
$requestEventId = $requestBody['id']
$requestEventSource = [string]$requestBody['source']
# Only the explicit JSON input path contributes event correlation. Webhook IDs can still
# be shown in the request diagnostic below without becoming the correlation field.
$hasRequestEventId = $requestEventId -is [string] -and -not [string]::IsNullOrWhiteSpace($requestEventId)
if ($usesJsonRequestBody -and $hasRequestEventId) {
    $script:CertLCCorrelationId = $requestEventId
}

# Now that the payload identity is known, validation and operation logs share correlation.

# Establish correlation before reporting envelope/data validation failures.
try {
    Assert-CertLCRequestFields -Data $requestBody -RequiredStrings 'specversion', 'type' -Prefix ''
    $requestData = ConvertTo-CertLCRequestMap -Value $requestBody['data'] -Label 'data'
}
catch {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message $_.Exception.Message -InnerException $_.Exception
}
if ($requestBody.specversion -ne $CloudEventSpecVersion) {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "The CloudEvents specversion specified in the request, $($requestBody.specversion), does not match the supported specversion $CloudEventSpecVersion!"
}
else {
    Write-CertLCLog -Section 'Dispatcher' -Message "specversion: $($requestBody.specversion)"
}

Write-CertLCLog -Section 'Dispatcher' -Message "request type: $($requestBody.type)"

if (-not $hasRequestEventId) {
    Write-CertLCLog -Section 'Dispatcher' -Message "request id: (not provided)" -Level 'Warning'
}
else {
    # The logger adds jobId; webhook request diagnostics do not opt into correlation.
    Write-CertLCLog -Section 'Dispatcher' -Message "request id: $requestEventId" -Context @{ eventSource = $requestEventSource }
}

# Process requests based on type

switch ($requestBody.type) {

    #region ### DISPATCHER.RENEWAL ###

    'Microsoft.KeyVault.CertificateNearExpiry' {

        ######################
        # DISPATCHER.RENEWAL #
        ######################

        # get parameters
        $VaultName = $requestData['VaultName']
        $CertificateName = $requestData['ObjectName']
        # Seed error-notification context from the event immediately, then enrich it only after
        # Key Vault and Active Directory values have been retrieved and validated.
        $script:CertificateNotificationContext = [ordered]@{
            Operation          = 'Renewal'
            # The shared renderer adds the Correlation ID row for every email type.
            'Request ID'       = $requestData['Id']
            'Key Vault'        = $VaultName
            'Certificate name' = $CertificateName
        }

        # Validate the event's local fields before retrieving certificate metadata.
        try {
            Assert-CertLCRequestFields -Data $requestData -RequiredStrings 'VaultName', 'ObjectName'
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message $_.Exception.Message -InnerException $_.Exception
        }

        # before processing the request, we need to obtain the other certificate details, such as template, subject, and DNS names
        Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "Getting additional certificate details for $CertificateName from key vault $VaultName..."
        $cert = $null
        try {
            $cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Error getting certificate details for $CertificateName from vault $VaultName" -Inner $_.Exception
        }
        if ($null -eq $cert) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Error getting certificate details for $CertificateName from vault $($VaultName): empty response! Certificate may not exist in the vault."
        }

        # If the latest version of this certificate was previously revoked by the runbook, the
        # CertLC revocation flow tagged it with Revoked=true and set it to disabled. Auto-renewal
        # in that situation would silently re-issue the certificate (new version, new serial) and
        # effectively "un-revoke" the certificate name on the CA side. Skip the renewal in this
        # case and require an explicit operator action (e.g. issue a brand new certificate or
        # clear the Revoked tag manually).
        $latestRevokedTag = $null
        if ($null -ne $cert.Tags -and $cert.Tags.ContainsKey('Revoked')) {
            $latestRevokedTag = [string]$cert.Tags['Revoked']
        }
        if ($latestRevokedTag -and $latestRevokedTag.Trim().ToLowerInvariant() -eq 'true') {
            $revokedAt = if ($cert.Tags.ContainsKey('RevokedAt')) { [string]$cert.Tags['RevokedAt'] } else { '<unknown>' }
            $revokedReason = if ($cert.Tags.ContainsKey('RevocationReason')) { [string]$cert.Tags['RevocationReason'] } else { '<unknown>' }
            Write-CertLCLog -Section 'Dispatcher.Renewal' -Level 'Warning' -Message "Skipping auto-renewal of certificate $CertificateName in vault $($VaultName): the latest version is tagged as revoked (RevokedAt=$revokedAt, RevocationReason=$revokedReason). Issue a new certificate explicitly or clear the Revoked tag to resume auto-renewal."
            return
        }

        # get NotifyTo from the certificate tags (optional)
        $rawNotifyTo = $cert.Tags['NotifyTo']
        if ([string]::IsNullOrWhiteSpace($rawNotifyTo)) {
            $notifyTo = $null
            Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "No NotifyTo addresses found for certificate $CertificateName in vault $VaultName."
        }
        else {
            Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "NotifyTo addresses found for certificate $CertificateName in vault ${VaultName}: $rawNotifyTo"
            $notifyTo = ConvertFrom-CertLCNotifyToTag -TagValue $rawNotifyTo
        }

        # Certificate subject
        $CertificateSubject = $cert.Certificate.Subject

        # The DNS names from the certificate
        $CertificateDnsNames = $null
        $san = $cert.Certificate.Extensions['2.5.29.17']
        if ($null -ne $san) {
            # Decode by OID and ASN.1 type, independent of localized display names or formatting.
            # CopyFrom also supports generic X509Extension instances; only DNS entries are renewed.
            $sanExtension = [System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]::new()
            $sanExtension.CopyFrom($san)
            $CertificateDnsNames = @($sanExtension.EnumerateDnsNames())
        }

        # Decode the template's numeric OID directly from DER, independent of worker locale.
        try {
            $oid = Get-CertLCTemplateOid -Certificate $cert.Certificate
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message 'Error decoding certificate template information.' -InnerException $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }

        # lookup the template name using the OID
        try {
            Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "Looking up template name for OID: $oid"
            $certificateTemplateName = Find-TemplateName -cnOrDisplayNameOrOid $oid
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Error resolving template name for OID $oid" -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }
        if ([string]::IsNullOrEmpty($certificateTemplateName)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Error resolving template name for OID $($oid): template not found in AD." -NotifyTo $NotifyTo @smtpArgs
        }
        Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "Template name found for OID $($oid) is: $certificateTemplateName"

        # Hostname from the certificate tags
        $Hostname = $cert.Tags['Hostname']
        if ([string]::IsNullOrWhiteSpace($Hostname)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Missing mandatory Hostname tag on certificate $CertificateName in vault $VaultName." -NotifyTo $NotifyTo @smtpArgs
        }
        Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "Hostname: $Hostname"

        # PfxProtectTo from the certificate tags
        $rawPfxProtectTo = $cert.Tags['PfxProtectTo']
        $PfxProtectTo = Convert-PfxProtectToFromTag -TagValue $rawPfxProtectTo
        # After normalization functions, simply checking truthiness is enough; avoid .Count under StrictMode on potential scalars
        if (-not $PfxProtectTo) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Missing mandatory PfxProtectTo tag on certificate $CertificateName in vault $VaultName." -NotifyTo $NotifyTo @smtpArgs
        }
        Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "PfxProtectTo principals: $($PfxProtectTo -join ', ')"

        # These values are now authoritative and safe to include if any later renewal step fails.
        $script:CertificateNotificationContext['Template'] = $certificateTemplateName
        $script:CertificateNotificationContext['Subject'] = $CertificateSubject
        $script:CertificateNotificationContext['DNS names'] = $CertificateDnsNames
        $script:CertificateNotificationContext['Hostname'] = $Hostname
        $script:CertificateNotificationContext['PFX protection principals'] = $PfxProtectTo

        if ($null -eq $CertificateDnsNames) {
            Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "Certificate $CertificateName details: Subject: $CertificateSubject, Template: $certificateTemplateName ($oid), no DNS names."
        }
        else {
            Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "Certificate $CertificateName details: Subject: $CertificateSubject, Template: $certificateTemplateName ($oid), DNS names: $($CertificateDnsNames -join ', ')"
        }

        # Now we have all the details to create the renew request.
        # Renew actually uses same code as New-CertificateCreationRequest, so we can reuse it.
        # Exceptions will be caught directly in the main section of the script
        Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "Got all required information to process the certificate renewal request for $CertificateName in vault $VaultName"
        Write-CertLCLog -Section 'Dispatcher.Renewal' -Message 'The operation will now continue as a new certificate creation request. See next log entries for details.'

        $creationResult = $null
        try {
            # Keep renewal audit metadata and the reference result explicit in the call contract.
            $creationParameters = @{
                VaultName               = $VaultName
                CertificateName         = $CertificateName
                CertificateTemplateName = $certificateTemplateName
                CertificateSubject      = $CertificateSubject
                # Retain array-shaped request inputs and the explicit CA/export context.
                CertificateDnsNames     = $CertificateDnsNames
                CA                      = $CA
                Hostname                = $Hostname
                PfxProtectTo            = $PfxProtectTo
                NotifyTo                = $NotifyTo
                # Renewal audit identity is distinct from the reference used for returned metadata.
                RenewedJobId            = $jobId
                Result                  = ([ref]$creationResult)
                PfxRootFolder           = $PfxRootFolder
            }
            New-CertificateCreationRequest @creationParameters
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message 'Error processing certificate creation request' -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }

        # Success details come from the completed operation result rather than the original event,
        # so the email reports the certificate and PFX artifacts that were actually committed.
        $notificationDetails = New-CertLCCreationNotificationDetails `
            -OperationResult $creationResult -Operation 'Renewal' -RequestId $requestData['Id']
        # send notification email if requested and SMTP is configured
        Send-SuccessNotification -Section 'Dispatcher.Renewal' `
            -Subject "Certificate $CertificateName renewed successfully" `
            -Summary "A new version of certificate $CertificateName has been issued, stored in Key Vault, and exported as a protected PFX." `
            -Details $notificationDetails `
            -JobId $jobId `
            -NotifyTo $NotifyTo @smtpArgs

        # confirm renewal
        Write-CertLCLog -Section 'Dispatcher.Renewal' -Message "Certificate $CertificateName was successfully renewed."
    }

    #endregion

    #region ### DISPATCHER.CREATION ###

    'CertLC.NewCertificateRequest' {

        #######################
        # DISPATCHER.CREATION #
        #######################

        # get parameters
        $VaultName = $requestData['VaultName']
        $CertificateName = $requestData['ObjectName']
        $CertificateTemplate = $requestData['CertificateTemplate']
        $CertificateSubject = $requestData['CertificateSubject']
        $CertificateDnsNames = $requestData['CertificateDnsNames']
        $Hostname = $requestData['Hostname']
        $PfxProtectTo = $requestData['PfxProtectTo']
        $NotifyTo = $requestData['NotifyTo']
        # Preserve raw request context early enough for validation failures to produce a useful
        # error email. Normalized values replace selected fields as validation succeeds below.
        $script:CertificateNotificationContext = [ordered]@{
            Operation          = 'Creation'
            # The shared renderer adds the Correlation ID row for every email type.
            'Request ID'       = $requestData['Id']
            'Key Vault'        = $VaultName
            'Certificate name' = $CertificateName
            Template           = $CertificateTemplate
            Subject            = $CertificateSubject
            'DNS names'        = $CertificateDnsNames
            Hostname           = $Hostname
        }

        # Reject malformed recipients before they can be passed to an error notification.
        try {
            Assert-CertLCRequestFields -Data $requestData -OptionalArrays 'NotifyTo'
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message $_.Exception.Message -InnerException $_.Exception
        }
        try {
            Assert-CertLCRequestFields -Data $requestData `
                -RequiredStrings 'VaultName', 'ObjectName', 'CertificateTemplate', 'CertificateSubject', 'Hostname' `
                -OptionalArrays 'CertificateDnsNames'
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message $_.Exception.Message -InnerException $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }

        # Finish local domain validation before any Key Vault or AD lookup.
        $Hostname = $Hostname.Trim().ToLowerInvariant()
        if ($Hostname -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253})$') {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Hostname '$Hostname' is not valid!" -NotifyTo $NotifyTo @smtpArgs
        }
        if (-not $PfxProtectTo) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Missing mandatory parameter 'PfxProtectTo'!" -NotifyTo $NotifyTo @smtpArgs
        }
        $PfxProtectTo = Format-PfxProtectTo -InputValue $PfxProtectTo
        if (-not $PfxProtectTo) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message 'PfxProtectTo list is empty after normalization!' -NotifyTo $NotifyTo @smtpArgs
        }
        $script:CertificateNotificationContext['Hostname'] = $Hostname
        $script:CertificateNotificationContext['PFX protection principals'] = $PfxProtectTo

        # CertificateName: check whether it is soft-deleted before attempting issuance.
        try {
            $deletedCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -InRemovedState
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message 'Error checking for deleted certificate' -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }
        if (($null -ne $deletedCert) -and ($null -ne $deletedCert.DeletedDate)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Certificate $CertificateName is deleted since $($deletedCert.DeletedDate). Purge it or use a different name." -NotifyTo $NotifyTo @smtpArgs
        }

        # CertificateTemplate: check if the template exists in AD; caller may have specified the template name (CN) or the display name or the OID. We need the 'name' attribute
        try {
            $CertificateTemplateName = Find-TemplateName -cnOrDisplayNameOrOid $CertificateTemplate
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message 'Error resolving template name' -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }
        if ([string]::IsNullOrEmpty($CertificateTemplateName)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Certificate template $CertificateTemplate not found in Active Directory!" -NotifyTo $NotifyTo @smtpArgs
        }

        # Replace the requested template with the authoritative AD name for later failures.
        $script:CertificateNotificationContext['Template'] = $CertificateTemplateName

        # end of validation. Now process the new certificate request

        if ($null -ne $CertificateDnsNames) {
            Write-CertLCLog -Section 'Dispatcher.Creation' -Message "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplateName, subject $CertificateSubject, DNS names $($CertificateDnsNames -join ', '), Hostname $Hostname, PfxProtectTo $($PfxProtectTo -join ', ')..."
        }
        else {
            Write-CertLCLog -Section 'Dispatcher.Creation' -Message "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplateName, subject $CertificateSubject, Hostname $Hostname, PfxProtectTo $($PfxProtectTo -join ', ')..."
        }

        $creationResult = $null
        try {
            # A new request uses the same explicit inputs without renewal-only audit metadata.
            $creationParameters = @{
                VaultName               = $VaultName
                CertificateName         = $CertificateName
                CertificateTemplateName = $CertificateTemplateName
                CertificateSubject      = $CertificateSubject
                # Preserve the optional DNS/notification arguments even when their values are null.
                CertificateDnsNames     = $CertificateDnsNames
                CA                      = $CA
                Hostname                = $Hostname
                PfxProtectTo            = $PfxProtectTo
                NotifyTo                = $NotifyTo
                # Preserve the separate metadata return while structured logs stay visible.
                Result                  = ([ref]$creationResult)
                PfxRootFolder           = $PfxRootFolder
            }
            New-CertificateCreationRequest @creationParameters
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message 'Error processing new certificate request' -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }

        # Build the success email from the operation result: it reflects the issued certificate,
        # stored Key Vault version, and verified PFX rather than merely echoing requested values.
        $notificationDetails = New-CertLCCreationNotificationDetails `
            -OperationResult $creationResult -Operation 'Creation' -RequestId $requestData['Id']
        # send notification email if requested and SMTP is configured
        Send-SuccessNotification -Section 'Dispatcher.Creation' `
            -Subject "Certificate $CertificateName created successfully" `
            -Summary "Certificate $CertificateName has been issued, stored in Key Vault, and exported as a protected PFX." `
            -Details $notificationDetails `
            -JobId $jobId `
            -NotifyTo $NotifyTo @smtpArgs

        # confirm creation
        Write-CertLCLog -Section 'Dispatcher.Creation' -Message "Certificate $CertificateName was successfully created."
    }

    #endregion

    #region ### DISPATCHER.REVOCATION ###

    'CertLC.CertificateRevocationRequest' {

        #########################
        # DISPATCHER.REVOCATION #
        #########################

        # get required parameters
        $VaultName = $requestData['VaultName']
        $CertificateThumbprint = $requestData['CertificateThumbprint']
        $RevocationReasonString = $requestData['RevocationReason']
        # Begin with request fields available before certificate lookup so early validation and
        # lookup failures retain enough context for an actionable error notification.
        $script:CertificateNotificationContext = [ordered]@{
            Operation                = 'Revocation'
            # The shared renderer adds the Correlation ID row for every email type.
            'Request ID'             = $requestData['Id']
            'Key Vault'              = $VaultName
            Thumbprint               = $CertificateThumbprint
            'Revocation reason code' = $RevocationReasonString
        }

        # Reason is intentionally not a required string: numeric zero is a valid code.
        try {
            Assert-CertLCRequestFields -Data $requestData -RequiredStrings 'VaultName', 'CertificateThumbprint'
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message $_.Exception.Message -InnerException $_.Exception
        }

        # RevocationReason: presence and integer check
        $RevocationReason = $null
        if (-not [string]::IsNullOrEmpty($RevocationReasonString)) {
            # try to convert to integer
            try {
                $RevocationReason = [Int64]::Parse($RevocationReasonString)
            }
            catch { Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message "Invalid integer value for 'data.RevocationReason' in request body!" -Inner $_.Exception }
        }
        else {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message "Missing or empty mandatory string parameter: 'data.RevocationReason' in request body!"
        }

        # RevocationReason: see https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-revokecertificate
        # 0 = CRL_REASON_UNSPECIFIED,
        # 1 = CRL_REASON_KEY_COMPROMISE,
        # 2 = CRL_REASON_CA_COMPROMISE,
        # 3 = CRL_REASON_AFFILIATION_CHANGED,
        # 4 = CRL_REASON_SUPERSEDED,
        # 5 = CRL_REASON_CESSATION_OF_OPERATION,
        # 6 = CRL_REASON_CERTIFICATE_HOLD

        if ($RevocationReason -notin 0, 1, 2, 3, 4, 5, 6) { Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "Revocation request validation: Invalid integer value for 'data.RevocationReason'. Supported: 0-6." }

        # before processing the request, we need to find the matching certificate version by thumbprint
        Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "Searching for certificate version with thumbprint $CertificateThumbprint in key vault $VaultName..."
        $match = $null
        try {
            $match = Get-CertificateByThumbprint -VaultName $VaultName -Thumbprint $CertificateThumbprint
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message "Error finding certificate with thumbprint $CertificateThumbprint in vault $VaultName" -Inner $_.Exception
        }
        if ($null -eq $match) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message "No certificate version found with thumbprint $CertificateThumbprint in vault $VaultName."
        }
        $CertificateName = $match.Name
        $CertificateVersion = $match.Version
        $IsLatestVersion = [bool]$match.IsLatest
        # Enrich the same context only after the thumbprint has resolved to a specific version.
        $script:CertificateNotificationContext['Certificate name'] = $CertificateName
        $script:CertificateNotificationContext['Key Vault version'] = $CertificateVersion
        $script:CertificateNotificationContext['Latest version'] = $IsLatestVersion
        Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "Found certificate '$CertificateName' version '$CertificateVersion' (IsLatest=$IsLatestVersion) matching thumbprint $CertificateThumbprint in vault $VaultName."

        # Get the matched certificate version to retrieve its tags (NotifyTo is read from the specific version,
        # so older versions that carry their own NotifyTo are honored).
        $cert = $null
        $revocationResult = $null
        try {
            $cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -Version $CertificateVersion
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message "Error getting certificate details for $CertificateName version $CertificateVersion from vault $VaultName" -Inner $_.Exception
        }
        if ($null -eq $cert) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message "Error getting certificate details for $CertificateName version $CertificateVersion from vault $($VaultName): empty response!"
        }

        # get NotifyTo from the certificate version tags (optional)
        $rawNotifyTo = $cert.Tags['NotifyTo']
        if ([string]::IsNullOrWhiteSpace($rawNotifyTo)) {
            $notifyTo = $null
            Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "No NotifyTo addresses found for certificate $CertificateName version $CertificateVersion in vault $VaultName."
        }
        else {
            Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "NotifyTo addresses found for certificate $CertificateName version $CertificateVersion in vault ${VaultName}: $rawNotifyTo"
            $notifyTo = ConvertFrom-CertLCNotifyToTag -TagValue $rawNotifyTo
        }

        $revokedTag = if ($cert.Tags -and $cert.Tags.ContainsKey('Revoked')) { [string]$cert.Tags['Revoked'] } else { $null }
        if ($revokedTag -and $revokedTag.Trim().ToLowerInvariant() -eq 'true') {
            $revokedAt = if ($cert.Tags.ContainsKey('RevokedAt')) { [string]$cert.Tags['RevokedAt'] }        else { '<unknown>' }
            $revokedReason = if ($cert.Tags.ContainsKey('RevocationReason')) { [string]$cert.Tags['RevocationReason'] } else { '<unknown>' }
            $revokedJobId = if ($cert.Tags.ContainsKey('RevokedJobId')) { [string]$cert.Tags['RevokedJobId'] }     else { '<unknown>' }
            # The requested end state already exists, so complete successfully and let the
            # Function acknowledge the queue message instead of scheduling another retry.
            Write-CertLCLog -Section 'Dispatcher.Revocation' -Level 'Warning' `
                -Message "Certificate '$CertificateName' version '$CertificateVersion' (thumbprint $CertificateThumbprint) is ALREADY REVOKED (RevokedAt=$revokedAt, RevocationReason=$revokedReason, RevokedJobId=$revokedJobId). Treating duplicate revocation request as idempotent success."
            return
        }

        # end of validation. Now process the certificate revocation request

        Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "Performing certificate revocation for certificate $CertificateName version $CertificateVersion in vault $VaultName with reason $RevocationReason..."
        try {
            # Retain the exact-version certificate, tags, and reference result from the lookup.
            $revocationParameters = @{
                VaultName          = $VaultName
                CertificateName    = $CertificateName
                CertificateVersion = $CertificateVersion
                RevocationReason   = $RevocationReason
                JobId              = $jobId
                # These objects identify the already-selected version; no latest-version lookup occurs here.
                ExistingTags       = $cert.Tags
                Certificate        = $cert.Certificate
                ExpectedThumbprint = $CertificateThumbprint
                Result             = ([ref]$revocationResult)
                CA                 = $CA
            }
            New-CertificateRevocationRequest @revocationParameters
        }
        catch {
            # Include the configured SMTP transport so a genuine CA or Key Vault revocation
            # failure can notify the recipients stored on this exact certificate version.
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message 'Error processing certificate revocation request' -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }

        # If the revoked version was the latest version of the certificate, warn the operator:
        # any consumer that requests this certificate without specifying a version will receive
        # a "disabled" error from Key Vault until either a new version is created (e.g. via the
        # renewal flow) or the version is manually re-enabled. Auto-renewal via the near-expiry
        # event is suppressed for revoked versions (see DISPATCHER.RENEWAL).
        if ($IsLatestVersion) {
            Write-CertLCLog -Section 'Dispatcher.Revocation' -Level 'Warning' -Message "The revoked version $CertificateVersion is the LATEST version of certificate $CertificateName in vault $VaultName. Consumers requesting this certificate without specifying a version will now receive an error from Key Vault until a new version is created."
        }

        $revocationReasonName = switch ($RevocationReason) {
            0 { 'Unspecified' }
            1 { 'Key compromise' }
            2 { 'CA compromise' }
            3 { 'Affiliation changed' }
            4 { 'Superseded' }
            5 { 'Cessation of operation' }
            6 { 'Certificate hold' }
        }
        # Use the post-revocation result for committed certificate and audit values; retain the
        # dispatcher lookup result only for whether the affected version was latest.
        $notificationDetails = [ordered]@{
            Operation           = 'Revocation'
            'Certificate name'  = $revocationResult.CertificateName
            Subject             = $revocationResult.Subject
            Thumbprint          = $revocationResult.Thumbprint
            'Serial number'     = $revocationResult.SerialNumber
            Issuer              = $revocationResult.Issuer
            'Valid from (UTC)'  = $revocationResult.NotBeforeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            'Valid until (UTC)' = $revocationResult.NotAfterUtc.ToString('yyyy-MM-dd HH:mm:ss')
            'Key Vault'         = $revocationResult.VaultName
            'Key Vault version' = $revocationResult.CertificateVersion
            'Latest version'    = $IsLatestVersion
            'Revocation reason' = "$revocationReasonName ($RevocationReason)"
            'Revoked at (UTC)'  = $revocationResult.RevokedAt
            # The shared renderer adds the Correlation ID row for every email type.
            'Request ID'        = $requestData['Id']
        }
        # send notification email if requested and SMTP is configured
        Send-SuccessNotification -Section 'Dispatcher.Revocation' `
            -Subject "Certificate $CertificateName version revoked successfully" `
            -Summary "Certificate $CertificateName version $CertificateVersion has been revoked at the CA and disabled in Key Vault. Other versions were not changed." `
            -Details $notificationDetails `
            -JobId $jobId `
            -NotifyTo $NotifyTo @smtpArgs

        # confirm revocation
        Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "Certificate $CertificateName version $CertificateVersion was successfully revoked (CA: serial revoked; KeyVault: version disabled and tagged)."
    }

    #endregion

    default {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "Unknown request type: $($requestBody.type). Supported values: Microsoft.KeyVault.CertificateNearExpiry, CertLC.NewCertificateRequest, CertLC.CertificateRevocationRequest."
    }
}

#endregion