Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation/') {
    Write-Output "Hybrid Runbook Worker confirmed: $($env:COMPUTERNAME)."
}
elseif ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
    throw 'Runbook running in Azure Automation sandbox. This runbook must be executed by a hybrid worker instead!'
}
else {
    throw 'Runbook running in a local environment. This runbook must be executed by a hybrid worker instead!'
}

if ($PSVersionTable.PSVersion -lt [version]'7.6') {
    throw 'This diagnostic requires PowerShell 7.6 or later.'
}

$parsedJobId = [guid]::Empty
$jobIdSource = 'EnvironmentMetadata'
if (-not [guid]::TryParse($env:PSPrivateMetadata, [ref]$parsedJobId) -or $parsedJobId -eq [guid]::Empty) {
    $tracePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'diags\trace.log'
    $jobIdPattern = '(?i)\bjobId\s*=\s*(?<JobId>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![0-9a-f-])'
    $traceJobIds = @(Get-Content -LiteralPath $tracePath -ErrorAction Stop | ForEach-Object {
        foreach ($jobMatch in [regex]::Matches($_, $jobIdPattern)) {
            [guid]$jobMatch.Groups['JobId'].Value
        }
    } | Sort-Object -Unique)

    if ($traceJobIds.Count -ne 1 -or $traceJobIds[0] -eq [guid]::Empty) {
        throw "Cannot determine the Automation job ID: expected one distinct non-empty jobId in the current sandbox trace; found $($traceJobIds.Count)."
    }

    $parsedJobId = $traceJobIds[0]
    $jobIdSource = 'SandboxTrace'
}

$jobId = $parsedJobId.ToString('D')
Write-Output "Automation Job ID: $jobId"
[ordered]@{
    JobId = $jobId
    JobIdSource = $jobIdSource
    Worker = $env:COMPUTERNAME
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    HostEnvironment = $env:AZUREPS_HOST_ENVIRONMENT
} | ConvertTo-Json -Compress | Write-Output