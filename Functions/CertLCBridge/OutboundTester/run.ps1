<#
.SYNOPSIS
  HTTP test / utility function for the CertLC function app.

.DESCRIPTION
  Accepts GET or POST. If POST with JSON, the body is parsed.
  Returns a JSON payload echoing key request details and a UTC timestamp.

  Extend this to perform outbound calls, diagnostics, or to enqueue test messages.

  Local tests:
  func start --script-root Functions\CertLCBridge    then:
  Invoke-RestMethod -Method GET -Uri "http://localhost:7071/api/OutboundTester",   or
  Invoke-RestMethod -Method POST -Uri "http://localhost:7071/api/OutboundTester" -Body (@{ test = "value"; enqueue = $true } | ConvertTo-Json) -ContentType 'application/json'

  Once published to Azure, you can test with:
    Invoke-RestMethod -Method GET -Uri "https://<your-functionapp>.azurewebsites.net/api/OutboundTester?code=<your-function-key>"
    Invoke-RestMethod -Method POST -Uri "https://<your-functionapp>.azurewebsites.net/api/OutboundTester?code=<your-function-key>" -Body (@{ test = "value"; enqueue = $true } | ConvertTo-Json) -ContentType 'application/json'

.INPUTS
  - GET query parameters (optional)
  - POST JSON body (optional)

.OUTPUTS
  HTTP 200 with JSON describing the received request, unless an error occurs.

#>

param(
    $Request,
    $TriggerMetadata
)

# Strict / fail fast
Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

# Basic correlation info
$invocationId = $TriggerMetadata.InvocationId
$utcNow = (Get-Date).ToUniversalTime()

# Helper: attempt to parse body if raw string was provided
function Convert-ToJsonObject {
    param([Parameter(Mandatory)][string] $Raw)
    try {
        if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
        return $Raw | ConvertFrom-Json -Depth 50
    }
    catch {
        Write-Warning "Body was not valid JSON: $_"
        return $Raw  # fall back to original raw content
    }
}

# Extract method, headers, query, body (varies depending on Functions runtime shaping)
$method = $Request.Method
$headers = $Request.Headers
$query = $Request.Query
$rawBody = $null
$bodyObj = $null

if ($Request.Body) {
    if ($Request.Body -is [string]) {
        $rawBody = $Request.Body
        $bodyObj = Convert-ToJsonObject -Raw $rawBody
    }
    else {
        # If runtime already parsed JSON, we might have a hashtable / PSCustomObject
        $bodyObj = $Request.Body
    }
}

Write-Information ('OutboundTester invocation {0} method={1}' -f $invocationId, $method)

# Get my local IP addresses
$myLocalIps = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
  Where-Object AddressFamily -eq InterNetwork |
  Select-Object -ExpandProperty IPAddressToString
Write-Information "OutboundTester: local IPs $myLocalIps"

# Get public IP
$myPublicIp = $null
$myPublicIpError = $null
try {
    $myPublicIp = (Invoke-RestMethod -Uri 'http://ifconfig.me/ip' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop).ToString().Trim()
    Write-Information "OutboundTester: public IP $myPublicIp"
}
catch {
    $myPublicIpError = $_.Exception.Message
    Write-Warning "OutboundTester: $myPublicIpError"
}

# construct the response payload including ip and notes
$responsePayload = [PSCustomObject]@{
    invocationId    = $invocationId
    timestampUtc    = $utcNow
    method          = $method
    headers         = $headers
    query           = $query
    body            = $bodyObj
    rawBody         = $rawBody
    myLocalIps      = $myLocalIps
    myPublicIp      = $myPublicIp
    myPublicIpError = $myPublicIpError
    notes           = @()
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = 200
        Body       = $responsePayload | ConvertTo-Json -Depth 10
    })