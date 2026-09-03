#Requires -PSEdition Core
using module Az.Accounts
using module Az.KeyVault
using module Az.Storage
using module Az.Resources

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

You can also pass the RequestBody parameter explicitly, which must be a JSON string with the same structure as above.
In this case, use the Start-AzAutomationRunbook cmdlet to start the runbook, passing the jsonRequestBody parameter:

Start-AzAutomationRunbook -Name "certlc" -Parameters @{ 'jsonRequestBody'=$jsonRequestBody }

Where $jsonRequestBody is a JSON string containing the RequestBody (the same as WebhookData.RequestBody when the webhook is used).

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

$Version = '1.0'    # version of the script - must match specversion in the webhook body

<# Unified SMTP / Email templates
 There are two templates with a single placeholder: __CONTENT__
 1. $CertificateNotificationEmailBodyHtml -> generic (creation / renewal / revocation / info)
 2. $CertificateErrorEmailBodyHtml        -> error (distinct colors + icon)

 Usage (example):
   $fragment = "<p>Certificate <b>$name</b> renewed successfully.</p>"
   $body = $CertificateNotificationEmailBodyHtml.Replace('__CONTENT__',$fragment)
   Send-NotificationEmail -Body $body ...
#>

$CertificateNotificationEmailBodyHtml = @'
<html>
    <body style="margin:0;padding:24px;font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.45;background:#f5f7fa;">
        <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #d8e2ec;border-radius:10px;padding:24px;box-shadow:0 4px 14px -4px rgba(0,0,0,.08);">
            <h2 style="margin:0 0 16px;font-size:20px;font-weight:600;color:#0b5cab;">Certificate Notification</h2>
            <div style="margin:0 0 20px;">__CONTENT__</div>
            <hr style="border:0;border-top:1px solid #e2e8f0;margin:20px 0;" />
            <div style="font-size:11px;color:#5a6b7b;">Automated message • CERTLC</div>
        </div>
    </body>
</html>
'@

$CertificateErrorEmailBodyHtml = @'
<html>
    <body style="margin:0;padding:24px;font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.45;background:#1e293b;">
        <div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #fbbf24;border-left:6px solid #dc2626;border-radius:10px;padding:24px;box-shadow:0 6px 18px -6px rgba(0,0,0,.35);position:relative;overflow:hidden;">
            <div style="position:absolute;top:-40px;right:-40px;width:160px;height:160px;background:radial-gradient(circle at 30% 30%,rgba(220,38,38,0.45),transparent 70%);"></div>
            <div style="display:flex;align-items:center;gap:10px;margin:0 0 14px;">
                <div style="width:42px;height:42px;border-radius:50%;background:#dc2626;display:flex;align-items:center;justify-content:center;box-shadow:0 0 0 4px #fee2e2;">
                    <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 9v4" />
                        <path d="M12 17h.01" />
                        <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
                    </svg>
                </div>
                <h2 style="margin:0;font-size:20px;font-weight:600;color:#dc2626;">Certificate Error</h2>
            </div>
            <div style="background:#fef2f2;border:1px solid #fee2e2;border-radius:6px;padding:14px 16px;color:#7f1d1d;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;overflow:auto;max-height:320px;">__CONTENT__</div>
            <div style="margin-top:20px;font-size:11px;color:#475569;">Automated error notification • CERTLC</div>
        </div>
    </body>
</html>
'@

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
    An optional correlation ID to include in the log entry.

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
    - correlationId: optional correlation ID
    - additional fields from the Context hashtable, with keys prefixed with "ctx_" if they conflict with reserved keys

    Reserved keys that cannot be used in Context without prefixing: timestamp, level, message, section, correlationId

    If JSON serialization fails, an error log entry is emitted instead.

#>

function Write-CertLCLog {
    <#
        .SYNOPSIS
            Emit a structured JSON log entry
        .DESCRIPTION
            Writes a single-line JSON object with standard fields plus optional custom context.

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

    $reservedKeys = 'timestamp', 'level', 'message', 'section', 'correlationId'
    $entry = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        level     = $Level
        section   = $Section
        message   = $Message
    }
    if ($CorrelationId) {
        $entry.correlationId = $CorrelationId
    }

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
        $json = ([ordered]@{ timestamp = (Get-Date).ToString('o'); level = 'Error'; message = 'Failed to serialize log entry'; originalMessage = $Message; serializationError = $_.Exception.Message }) | ConvertTo-Json -Compress
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

        if ($null -eq $SmtpCredential) {
            # send without authentication
            Send-MailMessage -SmtpServer $SmtpServer -From $FromAddress -To $To -Subject $Subject -Body $Body -BodyAsHtml:$true -WarningAction:SilentlyContinue
        }
        else {
            # send with authentication
            Send-MailMessage -SmtpServer $SmtpServer -From $FromAddress -To $To -Subject $Subject -Body $Body -BodyAsHtml:$true -Credential $SmtpCredential -WarningAction:SilentlyContinue
        }

        Write-CertLCLog -Message "Notification email sent to: $($To -join ', ')" -Section 'Send-NotificationEmail'
    }
    catch {
        # don't throw if email sending fails, just log the error
        Write-CertLCLog -Level 'Warning' -Message "Error sending notification email to $($To -join ', '): $($_.Exception.Message)" -Section 'Send-NotificationEmail'
    }
}

#endregion

#region ### Send-SuccessNotification ###

#########################################
# FUNCTIONS - Send-SuccessNotification  #
#########################################

# Shared success-email helper used by the dispatcher success paths (creation/renewal/revocation).
# Returns silently if NotifyTo is empty. Logs a warning if NotifyTo is set but SmtpServer is not.
function Send-SuccessNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$BodyText,
        [Parameter()][string[]]$NotifyTo,
        [Parameter()][string]$SmtpServer,
        [Parameter()][string]$FromAddress,
        [Parameter()][pscredential]$SmtpCredential
    )

    if (-not $NotifyTo) { return }
    if ([string]::IsNullOrEmpty($SmtpServer)) {
        Write-CertLCLog -Section $Section -Level 'Warning' -Message 'Notification requested but SMTP is not configured. Skipping email notification.'
        return
    }

    $fragment = [System.Net.WebUtility]::HtmlEncode($BodyText)
    $body = $CertificateNotificationEmailBodyHtml -replace '__CONTENT__', $fragment
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
        An optional correlation ID to include in the log.

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

    $ctx = @{}
    if ($Context) { $ctx = @{} + $Context }
    if ($InnerException) { $ctx.exception = Convert-ExceptionToObject -Exception $InnerException }

    # Send email if needed. Note that we may not have the NotifyTo list in all cases.
    # For example, for a renewal, if the error occurs before we read the certificate details including the NotifyTo tag, we don't have the To list.
    # In this case, skip the email sending.
    # Also skip email sending if SMTP is not configured.

    if ($NotifyTo -and -not [string]::IsNullOrEmpty($SmtpServer)) {
        $subject = "Error in CERTLC runbook"
        $fragment = "An error occurred in section: $Section of the CERTLC runbook used to process certificate requests:<br>"
        $fragment += $message.Replace("`n", "`n<br/>").Replace("`r", '')

        # if we have an inner exception, include its message and type
        if ($InnerException) {
            $innerMsg = "Inner Exception: $($InnerException.GetType().FullName): $($InnerException.Message)"
            $fragment += "<br/>$innerMsg<br/><br/>See logs for more details."
        }

        $fragment = [System.Net.WebUtility]::HtmlEncode($fragment)
        $body = $CertificateErrorEmailBodyHtml -replace '__CONTENT__', $fragment
        Send-NotificationEmail -SmtpServer $SmtpServer -FromAddress $FromAddress -To $NotifyTo -Subject $subject -Body $body -SmtpCredential $SmtpCredential
    }
    elseif ($NotifyTo -and [string]::IsNullOrEmpty($SmtpServer)) {
        Write-CertLCLog -Level 'Warning' -Message "Error notification requested but SMTP is not configured. Skipping email notification." -Section $Section
    }

    Write-CertLCLog -Level 'Error' -Message $Message -Section $Section -CorrelationId $CorrelationId -Context $ctx

    # Throw a terminating exception
    if ($InnerException) {
        throw ([System.Exception]::new($Message, $InnerException))
    }
    throw ([System.Exception]::new($Message))
}

#endregion

#region ### Invoke-WithRetry ###

##############################
# FUNCTIONS - Invoke-WithRetry #
##############################

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
            $ex  = $err.Exception
            $isLastAttempt = ($attempt -ge $MaxAttempts)

            # Try to read an HTTP status code if this is an Invoke-RestMethod / Invoke-WebRequest failure.
            $statusCode  = $null
            $retryAfterMs = $null
            $respProp = $ex.PSObject.Properties['Response']
            if ($null -ne $respProp -and $null -ne $respProp.Value) {
                try { $statusCode = [int]$respProp.Value.StatusCode } catch { $statusCode = $null }
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

            if (-not $shouldRetry -or $isLastAttempt) {
                throw
            }

            # Backoff: Retry-After if present, otherwise exponential with jitter capped at 30s.
            if ($null -ne $retryAfterMs -and $retryAfterMs -gt 0) {
                $delayMs = [Math]::Min($retryAfterMs, 30000)
            }
            else {
                $delayMs = [Math]::Min(30000, $InitialDelayMs * [Math]::Pow(2, $attempt - 1))
                $delayMs += (Get-Random -Minimum 0 -Maximum $InitialDelayMs)
            }

            $statusInfo = if ($null -ne $statusCode) { "HTTP $statusCode" } else { $ex.GetType().Name }
            Write-CertLCLog -Section $Section -Level 'Warning' -Message "[$OperationName] Attempt $attempt of $($MaxAttempts) failed ($statusInfo): $($ex.Message). Retrying after $([int]$delayMs)ms..."
            Start-Sleep -Milliseconds ([int]$delayMs)
        }
    }
}

#endregion

#region ### Format-PfxProtectTo ###

####################################
# FUNCTIONS - Format-PfxProtectTo  #
####################################

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
    # Force array output even when single element to keep downstream .Count usage safe under StrictMode
    return @($out)
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

    if ([string]::IsNullOrWhiteSpace($TagValue)) { return @() }

    # Parse then normalize to keep parity with input handling
    $raw = $TagValue.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    return Format-PfxProtectTo -InputValue $raw
}

#endregion

#region ### Certificate chain helpers ###

#########################################
# FUNCTIONS - Certificate chain helpers #
#########################################

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
        $collection.Import($bytes)
    }
    catch {
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
    if ($leafCandidates.Count -ne 1) {
        throw [System.Exception]::new("Get-OrderedCertificateChain: Expected exactly one leaf certificate in $Source; found $($leafCandidates.Count).")
    }

    # Keep unconsumed certificates in a mutable list so each issuer can be used exactly once.
    $remaining = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    foreach ($certificate in $Certificates) {
        if ($certificate.Thumbprint -cne $leafCandidates[0].Thumbprint) {
            $remaining.Add($certificate)
        }
    }

    $ordered = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    $current = $leafCandidates[0]
    while ($null -ne $current) {
        $ordered.Add($current)
        if (Test-DistinguishedNameEqual -Left $current.SubjectName -Right $current.IssuerName) {
            break
        }

        # Encoded distinguished-name comparison avoids locale and formatting differences in
        # the display strings exposed by Subject and Issuer.
        $issuers = @($remaining | Where-Object {
            Test-DistinguishedNameEqual -Left $_.SubjectName -Right $current.IssuerName
        })
        if ($issuers.Count -ne 1) {
            throw [System.Exception]::new("Get-OrderedCertificateChain: Expected one issuer for '$($current.Subject)' in $Source; found $($issuers.Count).")
        }

        $current = $issuers[0]
        $null = $remaining.Remove($current)
    }

    if ($remaining.Count -gt 0) {
        throw [System.Exception]::new("Get-OrderedCertificateChain: $Source contains $($remaining.Count) certificate(s) outside the leaf's issuer chain.")
    }
    if (-not (Test-DistinguishedNameEqual -Left $ordered[$ordered.Count - 1].SubjectName -Right $ordered[$ordered.Count - 1].IssuerName)) {
        throw [System.Exception]::new("Get-OrderedCertificateChain: $Source does not terminate in a self-issued root certificate.")
    }

    if ($ExcludeRoot) {
        $ordered.RemoveAt($ordered.Count - 1)
        if ($ordered.Count -lt 2) {
            throw [System.Exception]::new("Get-OrderedCertificateChain: $Source contains no intermediate CA certificate after the root is excluded.")
        }
    }

    # Prevent output-pipeline enumeration so a one-item result remains an array for strict mode.
    Write-Output -NoEnumerate $ordered.ToArray()
}

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

#region ### Export-PfxWithGroupProtection ###

#############################################
# FUNCTIONS - Export-PfxWithGroupProtection #
#############################################

<#
.SYNOPSIS
    Export a PFX certificate from Azure Key Vault, protecting it to specified SIDs.

.DESCRIPTION
    This function exports a PFX certificate from Azure Key Vault, protecting it to specified SIDs.
    It does not use Export-PfxCertificate cmdlet, but instead uses native interop helpers to create a protection descriptor and export the PFX file.
    The exported PFX file can be protected to multiple SIDs (users or groups).

.PARAMETER Certificates
    One or more X509Certificate2 objects to include in the exported PFX. The leaf certificate
    carries the private key; issuer certificates contribute their public certificate material.

.PARAMETER ProtectTo
    An array of strings representing the users or groups (in domain\user or UPN format) to protect the PFX file to.

.PARAMETER PfxFile
    The path to the output PFX file.

.EXAMPLE
    $protectTo = @("DOMAIN\User1", "DOMAIN\Group1")
    $pfxFile = "C:\path\to\output.pfx"
    Export-PfxWithGroupProtection -Certificates @($cert) -ProtectTo $protectTo -PfxFile $pfxFile
#>
function Export-PfxWithGroupProtection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates,

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
    Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "Protection descriptor handle: $hDesc"

    try {

        # Create memory store
        $store = [Win32Native]::CertOpenStore('Memory', 0, [IntPtr]::Zero, 0x2000, [IntPtr]::Zero)
        if ($store -eq [IntPtr]::Zero) {
            throw 'Export-PfxWithGroupProtection: CertOpenStore failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "Memory store handle: $store"

        try {

            # Add every selected chain member to one memory store. Only the leaf is expected
            # to carry a private key; issuer certificates add their public material to the PFX.
            foreach ($certificate in $Certificates) {
                if (-not [Win32Native]::CertAddCertificateContextToStore($store, $certificate.Handle, 3, [IntPtr]::Zero)) {
                    throw "Export-PfxWithGroupProtection: CertAddCertificateContextToStore failed for '$($certificate.Subject)': $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
                }
            }
            Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "$($Certificates.Count) certificate(s) added to memory store."

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
                Write-CertLCLog -Section 'Export-PfxWithGroupProtection' -Message "PFX size will be: $($blob.cbData) bytes"

                # allocate memory for the PFX data (pass 2)
                $blob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($blob.cbData)

                # do export to the memory store
                try {
                    if (-not [Win32Native]::PFXExportCertStoreEx($store, [ref]$blob, $password, $pvPara, $flags)) {
                        throw ('Export-PfxWithGroupProtection: export to memory store failed: 0x{0:X}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
                    }
                    Write-CertLCLog -Section 'Export-PfxWithGroupProtection' 'Export to memory store successful.'

                    $password = $null  # clear the password variable to avoid keeping it in memory

                    # save the file
                    $bytes = New-Object byte[] $blob.cbData
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
            [Win32Native]::CertCloseStore($store, 0) | Out-Null
        }
    }
    finally {
        # free the protection descriptor handle
        [Win32Native]::NCryptCloseProtectionDescriptor($hDesc) | Out-Null
    }
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
    $templateName = Find-TemplateName -cnOrDisplayNameOrOid "WebServer
#>

function Find-TemplateName {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$cnOrDisplayNameOrOid
    )

    $rootDse = [ADSI]'LDAP://RootDSE'
    $configDN = $rootDse.configurationNamingContext
    $searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
    $entry = [ADSI]$searchRoot
    $searcher = New-Object DirectoryServices.DirectorySearcher $entry

    # S2: escape the search value per RFC 4515 before interpolation into the LDAP filter.
    # Defence-in-depth: today $cnOrDisplayNameOrOid comes from trusted sources (Event Grid
    # payload or CertEnroll OID), but escaping costs nothing and prevents future regressions
    # if the input ever becomes user-controlled. Escapes: \ * ( ) NUL -> \5c \2a \28 \29 \00.
    $escaped = $cnOrDisplayNameOrOid `
        -replace '\\', '\5c' `
        -replace '\*',  '\2a' `
        -replace '\(',  '\28' `
        -replace '\)',  '\29' `
        -replace "`0",  '\00'
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

#endregion

#region ### New-CertificateCreationRequest ###

##############################################
# FUNCTIONS - New-CertificateCreationRequest #
##############################################

<#
.SYNOPSIS
    Create a new certificate request in Azure Key Vault, submit it to the specified CA, export the issued certificate to a PFX file protected to specified users/groups.

.DESCRIPTION
    This function creates a new certificate request in Azure Key Vault and submits it to the specified Certificate Authority (CA) for issuance.
    It prepares the necessary tags, handles existing in-progress requests, and uses the Certificate Enrollment API to submit the request.
    The resulting certificate is then exported to a PFX file protected to the specified users/groups.

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

.PARAMETER NotifyTo
    An optional array of email addresses to notify about the certificate request status.

.EXAMPLE
    $result = New-CertificateCreationRequest -VaultName "MyKeyVault" -CertificateName "MyCertificate" -CertificateTemplateName "WebServer" -CertificateSubject "CN=www.example.com" -CertificateDnsNames @("www.example.com","example.com") -CA "MyCA\MyInstance" -Hostname "webserver01" -PfxProtectTo @("DOMAIN\User1", "DOMAIN\Group1") -NotifyTo @("admin@example.com")
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
        # R3: when this request is the second leg of an auto-renewal, the dispatcher
        # passes the current Automation job id; it is stamped on the new version's tags
        # for audit symmetry with RevokedJobId.
        [Parameter()][string]$RenewedJobId
    )

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
    $op  = $null
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
        if ($effectiveDns) {
            $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType 'application/x-pkcs12' -SubjectName $CertificateSubject -IssuerName 'Unknown' -DnsName $effectiveDns
        }
        else {
            $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType 'application/x-pkcs12' -SubjectName $CertificateSubject -IssuerName 'Unknown'
        }

        # create the request in the key vault
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

    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "CA: Sending request to the CA $CA using template $($CertificateTemplateName) for certificate $CertificateName..."
    $CertEncoded = $null
    try {
        $CertRequest = New-Object -ComObject CertificateAuthority.Request
        $CertRequestStatus = $CertRequest.Submit(0x1, $csr, "CertificateTemplate:$CertificateTemplateName", $CA)

        # ICertRequest::Submit disposition codes (see wincrypt.h)
        $CR_DISP_DENIED            = 2
        $CR_DISP_ISSUED            = 3
        $CR_DISP_UNDER_SUBMISSION  = 5

        switch ($CertRequestStatus) {
            $CR_DISP_DENIED {
                throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request was denied. Check the CA $CA for details.")
            }
            $CR_DISP_ISSUED {
                Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "CA: Certificate Request for $CertificateName submitted successfully."
                $CertEncoded = $CertRequest.GetCertificate(0x0)
                Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "Certificate received from CA $CA"
            }
            $CR_DISP_UNDER_SUBMISSION {
                throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request to $CA is pending. This runbook expects immediate issuance. Review template/CA configuration.")
            }
            default {
                throw [System.Exception]::new("New-CertificateCreationRequest: CA: Request to $CA failed with status $CertRequestStatus")
            }
        }
    }
    catch {
        throw [System.Exception]::new("New-CertificateCreationRequest: CA: Error submitting request to $CA", $_.Exception)
    }
    finally {
        if ($CertRequest) {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($CertRequest)
            $CertRequest = $null
        }
    }

    # we need to save the certificate in a temporary file because the Import-AzKeyVaultCertificate cmdlet does not accept a base64 string as input
    $CertEncodedFile = New-TemporaryFile
    Set-Content -Path $CertEncodedFile -Value $CertEncoded

    # import the certificate into the key vault
    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "KeyVault: Importing the certificate $CertificateName into the key vault $VaultName..."
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
    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "KeyVault: Certificate $CertificateName imported into the key vault $($VaultName)."

    # Create root folder if needed
    if (-not (Test-Path -Path $PfxRootFolder)) {
        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Creating the PFX root folder: $PfxRootFolder"
        New-Item -Path $PfxRootFolder -ItemType Directory -Force | Out-Null
    }
    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Root folder verified: $PfxRootFolder"

    $PfxTargetFolder = Join-Path -Path $PfxRootFolder -ChildPath $Hostname

    if (-not (Test-Path -Path $PfxTargetFolder)) {
        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Creating the target folder for PFX: $PfxTargetFolder"
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
        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: ACL set on target folder (inheritance disabled, custom ACEs only): $PfxTargetFolder"
    }
    catch {
        throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Error setting permissions on $PfxTargetFolder", $_.Exception)
    }

    $pfxFile = Join-Path -Path $PfxTargetFolder -ChildPath "$($CertificateName).pfx"
    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Export path: $pfxFile"

    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Retrieving secret for $CertificateName from vault $VaultName..."
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
        Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Removing existing file $pfxFile"
        try {
            Remove-Item -Path $pfxFile -Force
        }
        catch {
            $x509Cert = $null; throw [System.Exception]::new("New-CertificateCreationRequest: PFX: Cannot remove existing file $pfxFile", $_.Exception)
        }
    }

    try {
        # Keep the current leaf-only behavior explicit until the creation path supplies
        # the validated Key Vault chain in a later, separately reviewed change.
        Export-PfxWithGroupProtection -Certificates @($x509Cert) -ProtectTo $PfxProtectTo -PfxFile $pfxFile
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

    Write-CertLCLog -Section 'New-CertificateCreationRequest' -Message "PFX: Certificate $CertificateName exported to $pfxFile"
}

#endregion

#region ### Get-CertificateByThumbprint ###

############################################
# FUNCTIONS - Get-CertificateByThumbprint  #
############################################

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

    # Normalize the input thumbprint (remove spaces, dashes, colons; convert to uppercase)
    $normalizedThumbprint = ($Thumbprint -replace '[^a-fA-F0-9]', '').ToUpper()

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
        return ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
    }

    # Helper: Extract the last URL segment (certificate name or version) from a KV resource id
    $lastSegment = {
        param([string]$id)
        return ($id -split '/')[-1]
    }

    # Helper: Invoke Key Vault REST API
    # S1 fix: fetch the access token ONCE at function entry (not per page) and pass it to
    # Invoke-RestMethod as a SecureString via -Authentication Bearer -Token. PowerShell 7 then
    # builds the Authorization header internally without ever materializing the token into a
    # managed (immutable, GC-bound) plaintext String. The previous implementation called
    # PtrToStringBSTR(SecureStringToBSTR(...)) on every page, both materializing the token and
    # leaking the BSTR buffer (no ZeroFreeBSTR).
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
    $certificateNames = New-Object 'System.Collections.Generic.List[string]'
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
      1. Loads the secret of the specific version to extract the X.509 serial number.
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

.EXAMPLE
    New-CertificateRevocationRequest -VaultName 'MyKeyVault' -CertificateName 'MyCertificate' -CertificateVersion 'abc123...' -RevocationReason 1 -JobId $jobId

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
        [System.Collections.IDictionary]$ExistingTags
    )

    # get the specific version of the certificate from the key vault, to extract its serial number
    Write-CertLCLog -Section 'New-CertificateRevocationRequest' -Message "KeyVault: Certificate $($CertificateName) version $($CertificateVersion): getting the version secret from key vault $VaultName to obtain details..."
    try {
        $certBase64 = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertificateName -Version $CertificateVersion -AsPlainText
    }
    catch {
        throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Error getting certificate $CertificateName version $CertificateVersion from key vault $VaultName", $_.Exception)
    }
    if ([string]::IsNullOrEmpty($certBase64)) {
        throw [System.Exception]::new("New-CertificateRevocationRequest: KeyVault: Certificate $CertificateName version $CertificateVersion secret is empty in key vault $VaultName")
    }

    # convert the base64 string to a byte array and create an X509Certificate2 object
    $certBytes = [Convert]::FromBase64String($certBase64)
    $certBase64 = $null
    $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes, [string]::Empty, 'Exportable')

    # save the serial number of this specific version
    $serialNumber = $x509Cert.SerialNumber

    # cleanup objects that are no longer needed
    $x509Cert = $null
    $certBytes = $null

    Write-CertLCLog -Section 'New-CertificateRevocationRequest' -Message "CA: Sending revocation request for certificate $CertificateName version $CertificateVersion (serial $serialNumber) to the CA $CA using reason $($RevocationReason)..."

    try {
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
        $CertAdmin.RevokeCertificate($CA, $serialNumber, $RevocationReason, 0)
    }
    catch {
        throw [System.Exception]::new("New-CertificateRevocationRequest: CA: Error revoking certificate $CertificateName version $CertificateVersion (serial $serialNumber) in CA $CA", $_.Exception)
    }
    finally {
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
    else {
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
    $mergedTags['Revoked']          = 'true'
    $mergedTags['RevokedAt']        = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
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
}

#endregion

###############
# DISPATCHER  #
###############

# Connect to Azure using the Automation Account's identity.
# Ensures we do not inherit an AzContext, since we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process
Write-CertLCLog -Section 'Dispatcher' -Message 'Connecting to Azure using default identity...'
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'There is no system-assigned user identity.' -Inner $_.Exception
}

# set context
Set-AzContext -SubscriptionId $AzureConnection.Subscription.Id -DefaultProfile $AzureConnection | Out-Null

# Check if the script is running on Azure or on hybrid worker; assign jobId accordingly.
# https://rakhesh.com/azure/azure-automation-powershell-variables/
# TODO: decide if we want to use $jobId as correlation id in the logs

if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation/') {
    # Hybrid Runbook Worker. Collect every place the job id might live, then pick the first
    # candidate that parses as a real GUID. This bypasses all the per-worker quirks
    # (env var holding "System.Collections.Hashtable", $PSPrivateMetadata exposing the JobId
    # as a nested @{Guid='...'} hashtable, $PSCommandPath sometimes not being the <jobId>.ps1
    # script, etc.). We log every candidate so the diagnostic is always visible.
    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrEmpty($PSCommandPath)) {
        $candidates.Add([System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath))
    }
    $meta = Get-Variable -Name 'PSPrivateMetadata' -ErrorAction Ignore
    if ($null -ne $meta -and $meta.Value -is [System.Collections.IDictionary] -and $meta.Value.Contains('JobId')) {
        $j = $meta.Value['JobId']
        $candidates.Add("$j")
        if ($j -is [System.Collections.IDictionary] -and $j.Contains('Guid')) { $candidates.Add("$($j['Guid'])") }
    }
    if (-not [string]::IsNullOrEmpty($env:PSPrivateMetadata)) {
        $candidates.Add($env:PSPrivateMetadata)
    }
    $jobId = ''
    foreach ($c in $candidates) {
        $g = [Guid]::Empty
        if ([Guid]::TryParse($c, [ref]$g)) { $jobId = $g.Guid; break }
    }
    Write-CertLCLog -Section 'Dispatcher' -Message "Runbook running with job id '$jobId' on hybrid worker $($env:COMPUTERNAME). JobId candidates: [$($candidates -join ' | ')]."
}
elseif ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
    # Azure Automation sandbox: not supported (we require the hybrid worker for CA access).
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Runbook running in Azure Automation sandbox. This runbook must be executed by a hybrid worker instead!'
}
else {
    # We are in a local environment - not supported anymore because we cannot get the encrypted variables from the automation account in this case
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Runbook running in a local environment. This runbook must be executed by a hybrid worker instead!'
}

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
            @{ Name = 'certlc-smtpfrom';     Value = $FromAddress },
            @{ Name = 'certlc-smtpuser';     Value = $SmtpUser },
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
if ([string]::IsNullOrEmpty($jsonRequestBody)) {

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

        Write-CertLCLog -Level Warning -Section 'Dispatcher' -Message 'Cannot parse WebhookData as JSON. Attempting to extract RequestBody using regex instead...'

        if ($WebhookData -match '"?RequestBody"?\s*:\s*((?:{([^{}]|(?<open>{)|(?<-open>}))*(?(open)(?!))})|(?:\[([^\[\]]|(?<open>\[)|(?<-open>\]))*(?(open)(?!))\]))') {
            $jsonRequestBody = $matches[1]
            Write-CertLCLog -Section 'Dispatcher' -Message "Regex extracted RequestBody: $jsonRequestBody"
            try {
                $RequestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10
            }
            catch {
                # The extracted body may contain literal escape sequences (e.g. \r\n, \") from callers that
                # double-serialized the JSON (sent an already-escaped string as the HTTP body).
                # Try unescaping those sequences and parsing again before giving up.
                Write-CertLCLog -Level Warning -Section 'Dispatcher' -Message "First parse attempt failed: $($_.Exception.Message). Attempting to unescape literal \r\n and \`" sequences and retry..."
                $jsonRequestBody = $jsonRequestBody -replace '\\r\\n', "`r`n" -replace '\\"', '"'
                Write-CertLCLog -Section 'Dispatcher' -Message "Unescaped RequestBody: $jsonRequestBody"
                try {
                    $RequestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10
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
        $requestBody = ConvertFrom-Json -InputObject $jsonRequestBody -Depth 10
    }
    catch {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message 'Failed to parse jsonRequestBody parameter as JSON' -Inner $_.Exception
    }
}

# now that we have a valid requestBody object, check some fields and detect request type

# check version
if ([string]::IsNullOrEmpty($requestBody.specversion)) {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "Missing or empty mandatory string parameter: 'specversion' in request body!"
}
if ($requestBody.specversion -ne $Version) {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "The version specified in the request, $($requestBody.specversion), does not match the script version $Version!"
}
else {
    Write-CertLCLog -Section 'Dispatcher' -Message "specversion: $($requestBody.specversion)"
}

if ([string]::IsNullOrEmpty($requestBody.type)) {
    Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "Missing or empty mandatory string parameter: 'type' in request body!"
}
else {
    Write-CertLCLog -Section 'Dispatcher' -Message "request type: $($requestBody.type)"
}

if ([string]::IsNullOrEmpty($requestBody.id)) {
    Write-CertLCLog -Section 'Dispatcher' -Message "request id: (not provided)" -Level 'Warning'
}
else {
    Write-CertLCLog -Section 'Dispatcher' -Message "request id: $($requestBody.id)"
}

# Process requests based on type

switch ($requestBody.type) {

    #region ### DISPATCHER.RENEWAL ###

    'Microsoft.KeyVault.CertificateNearExpiry' {

        ######################
        # DISPATCHER.RENEWAL #
        ######################

        # get parameters
        $VaultName = $requestBody.data.VaultName
        $CertificateName = $requestBody.data.ObjectName

        # start formal validation of mandatory parameters:

        # VaultName: presence and non-empty check
        if ([string]::IsNullOrEmpty($VaultName)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Missing or empty mandatory string parameter: 'VaultName'!"
        }

        # CertificateName: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateName)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Missing or empty mandatory string parameter: 'ObjectName'!"
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
            $notifyTo = $rawNotifyTo.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        }

        # Certificate subject
        $CertificateSubject = $cert.Certificate.Subject

        # The DNS names from the certificate
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
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message 'Error getting template information from certificate: the Certificate Template Information extension was not found.' -NotifyTo $NotifyTo @smtpArgs
        }
        # $templateExtension.Format($false) returns a string like:
        # - Template=Flab-ShortWebServer(1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736), Major Version Number=100, Minor Version Number=5
        # - Template=1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736, Major Version Number=100, Minor Version Number=5
        $asn = $templateExtension.Format($false)

        # extract the OID using a regex working for both cases
        $regex = [regex]'(?<=Template=(?:[^\(]*\()?)(\d+(?:\.\d+)+)'
        if (-not $regex.IsMatch($asn)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message "Error getting OID from certificate: Template OID not found in string: $asn" -NotifyTo $NotifyTo @smtpArgs
        }
        $oid = $regex.Match($asn).Value

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

        try {
            New-CertificateCreationRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplateName $certificateTemplateName -CertificateSubject $CertificateSubject -CertificateDnsNames $CertificateDnsNames -CA $CA -Hostname $Hostname -PfxProtectTo $PfxProtectTo -NotifyTo $NotifyTo -RenewedJobId $jobId
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Renewal' -Message 'Error processing certificate creation request' -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }

        # send notification email if requested and SMTP is configured
        Send-SuccessNotification -Section 'Dispatcher.Renewal' `
            -Subject "Certificate $CertificateName renewed successfully" `
            -BodyText "A new version of certificate $CertificateName has been successfully renewed in the Key Vault $VaultName." `
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
        $VaultName = $requestBody.data.VaultName
        $CertificateName = $requestBody.data.ObjectName
        $CertificateTemplate = $requestBody.data.CertificateTemplate
        $CertificateSubject = $requestBody.data.CertificateSubject
        $CertificateDnsNames = $requestBody.data.CertificateDnsNames
        $Hostname = $requestBody.data.Hostname
        $PfxProtectTo = $requestBody.data.PfxProtectTo
        $NotifyTo = $requestBody.data.NotifyTo

        # start formal validation of mandatory parameters:

        # NotifyTo (optional, but if specified, must be an array)
        if ($NotifyTo -and $NotifyTo -isnot [array]) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Parameter 'NotifyTo' is not an array!"
        }

        # VaultName: presence and non-empty check
        if ([string]::IsNullOrEmpty($VaultName)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Missing or empty mandatory string parameter: 'data.VaultName' in request body!" -NotifyTo $NotifyTo @smtpArgs
        }

        # CertificateName: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateName)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Missing or empty mandatory string parameter: 'data.ObjectName' in request body!" -NotifyTo $NotifyTo @smtpArgs
        }

        # CertificateName: check if the certificate already exists in the key vault
        try {
            $deletedCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -InRemovedState
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message 'Error checking for deleted certificate' -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }
        if (($null -ne $deletedCert) -and ($null -ne $deletedCert.DeletedDate)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Certificate $CertificateName is deleted since $($deletedCert.DeletedDate). Purge it or use a different name." -NotifyTo $NotifyTo @smtpArgs
        }

        # CertificateTemplate: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateTemplate)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Missing or empty mandatory string parameter: 'data.CertificateTemplate' in request body!" -NotifyTo $NotifyTo @smtpArgs
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

        # CertificateSubject: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateSubject)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Missing or empty mandatory string parameter: 'data.CertificateSubject' in request body!" -NotifyTo $NotifyTo @smtpArgs
        }

        # DnsNames (optional, but if specified, must be an array)
        if ($CertificateDnsNames -and $CertificateDnsNames -isnot [array]) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Parameter 'CertificateDnsNames' is not an array!" -NotifyTo $NotifyTo @smtpArgs
        }

        # Hostname
        if ([string]::IsNullOrWhiteSpace($Hostname)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Missing or empty mandatory string parameter: 'data.Hostname' in request body!" -NotifyTo $NotifyTo @smtpArgs
        }
        $Hostname = $Hostname.Trim().ToLower()
        if ($Hostname -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253})$') {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Hostname '$Hostname' is not valid!" -NotifyTo $NotifyTo @smtpArgs
        }

        # PfxProtectTo
        if (-not $PfxProtectTo) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message "Missing mandatory parameter 'PfxProtectTo'!" -NotifyTo $NotifyTo @smtpArgs
        }
        $PfxProtectTo = Format-PfxProtectTo -InputValue $PfxProtectTo
        # Avoid .Count: Format-PfxProtectTo guarantees array; empty array evaluates to $false
        if (-not $PfxProtectTo) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message 'PfxProtectTo list is empty after normalization!' -NotifyTo $NotifyTo @smtpArgs
        }

        # end of validation. Now process the new certificate request

        if ($null -ne $CertificateDnsNames) {
            Write-CertLCLog -Section 'Dispatcher.Creation' -Message "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplateName, subject $CertificateSubject, DNS names $($CertificateDnsNames -join ', '), Hostname $Hostname, PfxProtectTo $($PfxProtectTo -join ', ')..."
        }
        else {
            Write-CertLCLog -Section 'Dispatcher.Creation' -Message "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplateName, subject $CertificateSubject, Hostname $Hostname, PfxProtectTo $($PfxProtectTo -join ', ')..."
        }

        try {
            New-CertificateCreationRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplateName $CertificateTemplateName -CertificateSubject $CertificateSubject -CertificateDnsNames $CertificateDnsNames -CA $CA -Hostname $Hostname -PfxProtectTo $PfxProtectTo -NotifyTo $NotifyTo
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Creation' -Message 'Error processing new certificate request' -Inner $_.Exception -NotifyTo $NotifyTo @smtpArgs
        }

        # send notification email if requested and SMTP is configured
        Send-SuccessNotification -Section 'Dispatcher.Creation' `
            -Subject "Certificate $CertificateName created successfully" `
            -BodyText "A new certificate $CertificateName has been successfully created in the Key Vault $VaultName." `
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
        $VaultName = $requestBody.data.VaultName
        $CertificateThumbprint = $requestBody.data.CertificateThumbprint
        $RevocationReasonString = $requestBody.data.RevocationReason

        # VaultName: presence and non-empty check
        if ([string]::IsNullOrEmpty($VaultName)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message "Missing or empty mandatory string parameter: 'data.VaultName' in request body!"
        }

        # CertificateThumbprint: presence and non-empty check
        if ([string]::IsNullOrEmpty($CertificateThumbprint)) {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message "Missing or empty mandatory string parameter: 'data.CertificateThumbprint' in request body!"
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
        $CertificateName    = $match.Name
        $CertificateVersion = $match.Version
        $IsLatestVersion    = [bool]$match.IsLatest
        Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "Found certificate '$CertificateName' version '$CertificateVersion' (IsLatest=$IsLatestVersion) matching thumbprint $CertificateThumbprint in vault $VaultName."

        # Get the matched certificate version to retrieve its tags (NotifyTo is read from the specific version,
        # so older versions that carry their own NotifyTo are honored).
        $cert = $null
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
            $notifyTo = $rawNotifyTo.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        }

        # Idempotency guard: if this version is already marked as revoked, exit cleanly with a
        # clear message instead of attempting the revocation again. Without this check the flow
        # would proceed and fail later inside New-CertificateRevocationRequest at the
        # Get-AzKeyVaultSecret call (Key Vault refuses to release the secret material of a
        # disabled version), producing a misleading "Error getting certificate from key vault"
        # log line. Mirrors the renewal-side check that skips auto-renewal of revoked versions.
        $revokedTag = if ($cert.Tags -and $cert.Tags.ContainsKey('Revoked')) { [string]$cert.Tags['Revoked'] } else { $null }
        if ($revokedTag -and $revokedTag.Trim().ToLowerInvariant() -eq 'true') {
            $revokedAt     = if ($cert.Tags.ContainsKey('RevokedAt'))        { [string]$cert.Tags['RevokedAt'] }        else { '<unknown>' }
            $revokedReason = if ($cert.Tags.ContainsKey('RevocationReason')) { [string]$cert.Tags['RevocationReason'] } else { '<unknown>' }
            $revokedJobId  = if ($cert.Tags.ContainsKey('RevokedJobId'))     { [string]$cert.Tags['RevokedJobId'] }     else { '<unknown>' }
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' `
                -Message "Certificate '$CertificateName' version '$CertificateVersion' (thumbprint $CertificateThumbprint) is ALREADY REVOKED (RevokedAt=$revokedAt, RevocationReason=$revokedReason, RevokedJobId=$revokedJobId). Ignoring duplicate revocation request." `
                -NotifyTo $notifyTo @smtpArgs
        }

        # end of validation. Now process the certificate revocation request

        Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "Performing certificate revocation for certificate $CertificateName version $CertificateVersion in vault $VaultName with reason $RevocationReason..."
        try {
            # Pass the already-fetched version tags so New-CertificateRevocationRequest does not
            # need a second Get-AzKeyVaultCertificate round-trip just to merge them.
            New-CertificateRevocationRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateVersion $CertificateVersion -RevocationReason $RevocationReason -JobId $jobId -ExistingTags $cert.Tags
        }
        catch {
            Write-CertLCLogAndThrow -Section 'Dispatcher.Revocation' -Message 'Error processing certificate revocation request' -Inner $_.Exception -NotifyTo $NotifyTo
        }

        # If the revoked version was the latest version of the certificate, warn the operator:
        # any consumer that requests this certificate without specifying a version will receive
        # a "disabled" error from Key Vault until either a new version is created (e.g. via the
        # renewal flow) or the version is manually re-enabled. Auto-renewal via the near-expiry
        # event is suppressed for revoked versions (see DISPATCHER.RENEWAL).
        if ($IsLatestVersion) {
            Write-CertLCLog -Section 'Dispatcher.Revocation' -Level 'Warning' -Message "The revoked version $CertificateVersion is the LATEST version of certificate $CertificateName in vault $VaultName. Consumers requesting this certificate without specifying a version will now receive an error from Key Vault until a new version is created."
        }

        # send notification email if requested and SMTP is configured
        Send-SuccessNotification -Section 'Dispatcher.Revocation' `
            -Subject "Certificate $CertificateName version revoked successfully" `
            -BodyText "The version $CertificateVersion of certificate $CertificateName has been revoked at the CA and disabled in Key Vault $VaultName. The certificate object remains in the vault for audit purposes; other versions (if any) are unaffected." `
            -NotifyTo $NotifyTo @smtpArgs

        # confirm revocation
        Write-CertLCLog -Section 'Dispatcher.Revocation' -Message "Certificate $CertificateName version $CertificateVersion was successfully revoked (CA: serial revoked; KeyVault: version disabled and tagged)."
    }

    #endregion

    default {
        Write-CertLCLogAndThrow -Section 'Dispatcher' -Message "Unknown request type: $($requestBody.type). Supported values: Microsoft.KeyVault.CertificateNearExpiry, CertLC.NewCertificateRequest, CertLC.CertificateRevocationRequest."
    }
}