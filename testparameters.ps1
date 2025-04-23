param
(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData
)

# force the runbook to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

# the WebhookData is documented here: https://learn.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal

if ($null -eq $WebhookData)
{
    Write-Error "Webhook data missing! Ensure the runbook is called from a webhook!"
    return
}

try {
    $payload = ConvertFrom-Json -InputObject $WebhookData.RequestBody
} catch {
    Write-Error "Failed to parse webhook data as JSON. Error: $_"
    return
}

if ($null -eq $payload)
{
    Write-Error "Webhook data is not valid JSON!"
    return
}

$subject = $payload.subject
$template = $payload.template
$san = $payload.san

if ([string]::IsNullOrWhiteSpace($subject)) {
    Write-Error "Missing or empty mandatory parameter: 'subject'"
    return
}
if ([string]::IsNullOrWhiteSpace($template)) {
    Write-Error "Missing or empty mandatory parameter: 'template'"
    return
}

# Validate SAN is an array of strings (if provided)
if ($san -and -not ($san -is [System.Collections.IEnumerable])) {
    Write-Error "'san' must be an array if provided."
    return
}

Write-Output "Webhook data is valid JSON!"
Write-Output "Subject: $subject"
Write-Output "Template: $template"
if ($san) {
    Write-Output "SAN: $($san -join ', ')"
}