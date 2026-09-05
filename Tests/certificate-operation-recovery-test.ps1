[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$runbookPath = Join-Path $repositoryRoot 'Runbooks\certlc.ps1'
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

$creationFunctionAst = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'New-CertificateCreationRequest'
    }, $true) | Select-Object -First 1
if ($null -eq $creationFunctionAst) { throw 'Function not found: New-CertificateCreationRequest' }

$directResultAssignments = @($creationFunctionAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -ieq 'Result'
        }, $true))
if ($directResultAssignments.Count -gt 0) {
    throw "The typed [ref] Result parameter is overwritten by a case-insensitive local assignment: $($directResultAssignments[0].Extent.Text)"
}

$functionName = 'Get-RecoverableKeyVaultCertificateOperation'
$functionAst = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq $functionName
    }, $true) | Select-Object -First 1
if ($null -eq $functionAst) { throw "Function not found: $functionName" }
. ([scriptblock]::Create($functionAst.Extent.Text))

$script:readAttempt = 0
$script:sleepCount = 0
function Write-CertLCLog { param([Parameter(ValueFromRemainingArguments)][object[]]$Arguments) }
function Start-Sleep { param([int]$Seconds) $script:sleepCount++ }
function Get-AzKeyVaultCertificateOperation {
    param([string]$VaultName, [string]$Name, [object]$ErrorAction)
    $script:readAttempt++
    if ($script:readAttempt -eq 1) { return $null }
    [pscustomobject]@{
        Status = 'inProgress'
        CertificateSigningRequest = 'recovered-csr'
    }
}

$result = Get-RecoverableKeyVaultCertificateOperation `
    -VaultName 'test-vault' `
    -CertificateName 'test-certificate' `
    -AttemptCount 3 `
    -DelaySeconds 1
if ($null -eq $result -or $result.CertificateSigningRequest -cne 'recovered-csr') {
    throw 'A pending operation was not recovered after an initially empty read.'
}
if ($script:readAttempt -ne 2 -or $script:sleepCount -ne 1) {
    throw "Unexpected retry behavior: reads=$script:readAttempt sleeps=$script:sleepCount"
}

$script:readAttempt = 0
$script:sleepCount = 0
function Get-AzKeyVaultCertificateOperation {
    param([string]$VaultName, [string]$Name, [object]$ErrorAction)
    $script:readAttempt++
    [pscustomobject]@{
        Status = 'completed'
        CertificateSigningRequest = 'stale-csr'
    }
}

$result = Get-RecoverableKeyVaultCertificateOperation `
    -VaultName 'test-vault' `
    -CertificateName 'test-certificate' `
    -AttemptCount 2 `
    -DelaySeconds 0
if ($null -ne $result) {
    throw 'A non-pending operation must not be treated as recoverable.'
}
if ($script:readAttempt -ne 2) {
    throw "Unexpected non-recoverable read count: $script:readAttempt"
}

Write-Output 'Certificate operation recovery tests passed.'