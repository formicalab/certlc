[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$runbookPath = Join-Path $repositoryRoot 'Runbooks\certlc.ps1'
$normalTemplatePath = Join-Path $repositoryRoot 'Runbooks\normalnotification.html'
$errorTemplatePath = Join-Path $repositoryRoot 'Runbooks\errornotification.html'

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $runbookPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw "Runbook parse failed: $($parseErrors.Message -join '; ')"
}

function Assert-Equal {
    param([object]$Actual, [object]$Expected, [string]$Message)
    if ([string]$Actual -cne [string]$Expected) {
        throw "$Message`nExpected: $Expected`nActual: $Actual"
    }
}

function Assert-Contains {
    param([string]$Value, [string]$Expected, [string]$Message)
    if (-not $Value.Contains($Expected)) {
        throw "$Message`nMissing: $Expected"
    }
}

function Assert-NotContains {
    param([string]$Value, [string]$Unexpected, [string]$Message)
    if ($Value.Contains($Unexpected)) {
        throw "$Message`nUnexpected: $Unexpected"
    }
}

$templateVariables = @(
    'CertificateNotificationEmailBodyHtml',
    'CertificateErrorEmailBodyHtml'
)
$rendererFunctions = @(
    'ConvertTo-CertLCHtmlText',
    'New-CertLCNotificationDetailsHtml',
    'New-CertLCNotificationBody'
)

$assignmentTexts = foreach ($variableName in $templateVariables) {
    $assignment = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -ceq $variableName
        }, $true) | Select-Object -First 1
    if ($null -eq $assignment) { throw "Template assignment not found: $variableName" }
    $assignment.Extent.Text
}

$functionTexts = foreach ($functionName in $rendererFunctions) {
    $function = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
        }, $true) | Select-Object -First 1
    if ($null -eq $function) { throw "Renderer function not found: $functionName" }
    $function.Extent.Text
}

. ([scriptblock]::Create(($assignmentTexts + $functionTexts) -join "`n`n"))

$normalFile = (Get-Content -Raw $normalTemplatePath).TrimEnd("`r", "`n") -replace "`r`n", "`n"
$errorFile = (Get-Content -Raw $errorTemplatePath).TrimEnd("`r", "`n") -replace "`r`n", "`n"
Assert-Equal ($CertificateNotificationEmailBodyHtml -replace "`r`n", "`n") $normalFile 'Normal template mirror differs from the embedded runbook template.'
Assert-Equal ($CertificateErrorEmailBodyHtml -replace "`r`n", "`n") $errorFile 'Error template mirror differs from the embedded runbook template.'

$details = [ordered]@{
    Certificate = 'web<prod>&"'
    'DNS names' = @('one.example.test', 'two.example.test')
    Optional = ''
}
$successBody = New-CertLCNotificationBody -Title 'Created <now>' -Summary 'Done & verified' -Details $details -JobId 'job-123'
Assert-Contains $successBody 'Created &lt;now&gt;' 'Title was not HTML encoded.'
Assert-Contains $successBody 'Done &amp; verified' 'Summary was not HTML encoded.'
Assert-Contains $successBody 'web&lt;prod&gt;&amp;&quot;' 'Detail value was not HTML encoded.'
Assert-Contains $successBody 'one.example.test<br />two.example.test' 'Array details were not rendered on separate lines.'
Assert-Contains $successBody 'Job job-123' 'Job ID was not rendered.'
Assert-NotContains $successBody '>Optional<' 'Blank optional detail was not omitted.'

$errorBody = New-CertLCNotificationBody -Title 'Failure' -Summary 'Could not finish' -Details ([ordered]@{ Stage = 'Issuance' }) -ErrorDetails "Bad <value>`nSecond line"
Assert-Contains $errorBody 'Bad &lt;value&gt;<br />Second line' 'Error text was not safely encoded with visible line breaks.'

foreach ($body in @($successBody, $errorBody)) {
    if ($body -match '__[A-Z_]+__') { throw "Rendered body contains unresolved placeholder: $($matches[0])" }
    Assert-NotContains $body '<script' 'Rendered body contains executable script markup.'
    Assert-NotContains $body 'PRIVATE KEY' 'Rendered body leaked private-key material.'
}

Write-Output 'Notification template tests passed.'