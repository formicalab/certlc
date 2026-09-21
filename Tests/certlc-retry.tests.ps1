Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$tokens = $null
$parseErrors = $null
$sourcePath = Join-Path $PSScriptRoot '../Runbooks/certlc.ps1'
$sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$definition = $sourceAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-WithRetry'
}, $true)
if ($null -eq $definition) { throw 'Missing Invoke-WithRetry function.' }
. ([scriptblock]::Create($definition.Extent.Text))

function Start-Sleep { param($Milliseconds) $script:delays.Add([int]$Milliseconds) }
function Get-Random { param($Minimum, $Maximum) $Maximum - 1 }
function Write-CertLCLog { param($Section, $Level, $Message) $script:logs.Add($Message) }

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
}

function New-HttpFailure {
    param([int]$Status, [string]$RetryAfter, [switch]$Direct)
    if ($Direct) {
        return [System.Net.Http.HttpRequestException]::new('HTTP failure', $null, [System.Net.HttpStatusCode]$Status)
    }
    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$Status)
    if ($RetryAfter) { $null = $response.Headers.TryAddWithoutValidation('Retry-After', $RetryAfter) }
    $failure = [System.Net.Http.HttpRequestException]::new('HTTP failure')
    $failure | Add-Member -NotePropertyName Response -NotePropertyValue $response
    return $failure
}

function Test-RetryCase {
    param(
        [string]$Name,
        [System.Exception]$Failure,
        [int]$ExpectedAttempts,
        [int]$MinimumDelay = 0,
        [int]$MaximumDelay = 30000,
        [hashtable]$Parameters = @{},
        [switch]$AlwaysFail,
        [switch]$Invalid
    )
    $script:attempts = 0
    $script:delays = [System.Collections.Generic.List[int]]::new()
    $script:logs = [System.Collections.Generic.List[string]]::new()
    $caught = $null
    $result = $null
    try {
        $result = Invoke-WithRetry -OperationName $Name @Parameters -ScriptBlock {
            $script:attempts++
            if ($null -ne $Failure -and ($AlwaysFail -or $script:attempts -eq 1)) { throw $Failure }
            'completed'
        }
    }
    catch { $caught = $_.Exception }
    Assert-True ($script:attempts -eq $ExpectedAttempts) "$Name attempts: $script:attempts"
    if ($Invalid) {
        Assert-True ($caught -is [System.Management.Automation.ParameterBindingException]) "$Name parameter validation"
    }
    elseif ($AlwaysFail -or ($null -ne $Failure -and $ExpectedAttempts -eq 1)) {
        Assert-True ([object]::ReferenceEquals($caught, $Failure)) "$Name preserves original exception"
    }
    else {
        Assert-True ($null -eq $caught -and $result -ceq 'completed') "$Name returns success only"
    }
    $expectedSleeps = [Math]::Max(0, $ExpectedAttempts - 1)
    Assert-True ($script:delays.Count -eq $expectedSleeps) "$Name sleep count"
    Assert-True ($script:logs.Count -eq $expectedSleeps) "$Name log count"
    foreach ($delay in $script:delays) {
        Assert-True ($delay -ge $MinimumDelay -and $delay -le $MaximumDelay) "$Name delay: $delay"
    }
    if ($null -ne $Failure -and $null -ne $Failure.PSObject.Properties['Response'] -and $null -ne $Failure.Response) { $Failure.Response.Dispose() }
    Write-Output "PASS: $Name"
}

Test-RetryCase -Name Success -ExpectedAttempts 1
foreach ($status in 400, 401, 403, 404, 501) {
    Test-RetryCase -Name "Response$status" -Failure (New-HttpFailure -Status $status) -ExpectedAttempts 1
    Test-RetryCase -Name "Direct$status" -Failure (New-HttpFailure -Status $status -Direct) -ExpectedAttempts 1
}
foreach ($status in 408, 429, 500, 502, 503, 504) {
    Test-RetryCase -Name "Transient$status" -Failure (New-HttpFailure -Status $status) -ExpectedAttempts 2 -MinimumDelay 999 -MaximumDelay 999
}
Test-RetryCase -Name Direct429 -Failure (New-HttpFailure -Status 429 -Direct) -ExpectedAttempts 2
foreach ($failure in @(
    [System.Net.Http.HttpRequestException]::new('Network failure'),
    [System.TimeoutException]::new('Timeout'),
    [System.IO.IOException]::new('IO failure'),
    [System.Net.WebException]::new('Network failure'),
    [System.Runtime.InteropServices.COMException]::new('COM failure')
)) {
    Test-RetryCase -Name $failure.GetType().Name -Failure $failure -ExpectedAttempts 2
}
Test-RetryCase -Name NonTransient -Failure ([System.InvalidOperationException]::new('Invalid')) -ExpectedAttempts 1
Test-RetryCase -Name Delta -Failure (New-HttpFailure -Status 429 -RetryAfter '2') -ExpectedAttempts 2 -MinimumDelay 2000 -MaximumDelay 2000
Test-RetryCase -Name ZeroDelta -Failure (New-HttpFailure -Status 429 -RetryAfter '0') -ExpectedAttempts 2 -MaximumDelay 0
Test-RetryCase -Name LargeDelta -Failure (New-HttpFailure -Status 429 -RetryAfter '2147483647') -ExpectedAttempts 2 -MinimumDelay 30000
Test-RetryCase -Name FutureDate -Failure (New-HttpFailure -Status 503 -RetryAfter ([DateTimeOffset]::UtcNow.AddSeconds(20).ToString('r'))) -ExpectedAttempts 2 -MinimumDelay 10000 -MaximumDelay 20000
Test-RetryCase -Name FarFutureDate -Failure (New-HttpFailure -Status 503 -RetryAfter ([DateTimeOffset]::UtcNow.AddDays(60).ToString('r'))) -ExpectedAttempts 2 -MinimumDelay 30000
Test-RetryCase -Name PastDate -Failure (New-HttpFailure -Status 503 -RetryAfter ([DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('r'))) -ExpectedAttempts 2 -MaximumDelay 0
Test-RetryCase -Name MalformedHeader -Failure (New-HttpFailure -Status 429 -RetryAfter 'invalid') -ExpectedAttempts 2 -MinimumDelay 999 -MaximumDelay 999
Test-RetryCase -Name Exhaustion -Failure ([System.TimeoutException]::new('Timeout')) -ExpectedAttempts 4 -AlwaysFail
Test-RetryCase -Name SingleAttempt -Failure ([System.TimeoutException]::new('Timeout')) -ExpectedAttempts 1 -AlwaysFail -Parameters @{ MaxAttempts = 1 }
Test-RetryCase -Name DelayCap -Failure ([System.TimeoutException]::new('Timeout')) -ExpectedAttempts 2 -Parameters @{ InitialDelayMs = 30000 } -MinimumDelay 30000
Test-RetryCase -Name MinimumDelay -Failure ([System.TimeoutException]::new('Timeout')) -ExpectedAttempts 2 -Parameters @{ InitialDelayMs = 1 } -MinimumDelay 1 -MaximumDelay 1
foreach ($parameters in @(
    @{ MaxAttempts = 0 }, @{ MaxAttempts = -1 },
    @{ InitialDelayMs = 0 }, @{ InitialDelayMs = -1 }, @{ InitialDelayMs = 30001 }
)) {
    Test-RetryCase -Name ($parameters | ConvertTo-Json -Compress) -ExpectedAttempts 0 -Parameters $parameters -Invalid
}