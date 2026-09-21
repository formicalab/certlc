param(
    [string]$WhatIfResultPath,
    [string]$BaselineWhatIfResultPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    Write-Output "PASS: $Message"
}

function Assert-Equivalent($Expected, $Actual, [string]$Path = '$', [switch]$EscapedArmLiterals) {
    if ($Expected -is [System.Collections.IDictionary]) {
        if ($Actual -isnot [System.Collections.IDictionary] -or $Expected.Count -ne $Actual.Count) {
            throw "Object mismatch at $Path"
        }
        foreach ($key in $Expected.Keys) {
            if (-not $Actual.Contains($key)) { throw "Missing property at $Path.$key" }
            Assert-Equivalent $Expected[$key] $Actual[$key] "$Path.$key" -EscapedArmLiterals:$EscapedArmLiterals
        }
    }
    elseif ($Expected -is [array]) {
        if ($Actual -isnot [array] -or $Expected.Count -ne $Actual.Count) { throw "Array mismatch at $Path" }
        for ($i = 0; $i -lt $Expected.Count; $i++) {
            Assert-Equivalent $Expected[$i] $Actual[$i] "$Path[$i]" -EscapedArmLiterals:$EscapedArmLiterals
        }
    }
    else {
        # Bicep escapes leading '[' in ARM literals; ARM removes that escape at evaluation.
        if ($EscapedArmLiterals -and $Expected -is [string] -and $Expected.StartsWith('[')) {
            $Expected = '[' + $Expected
        }
        if ($Expected -cne $Actual) { throw "Value mismatch at $Path" }
    }
}

function Replace-Tokens([string]$Content, [System.Collections.IDictionary]$Replacements, [switch]$CheckLimit) {
    foreach ($token in $Replacements.Keys) {
        if ($CheckLimit -and $Content.Length -ge 131072) { throw 'Workbook section exceeds ARM string limit.' }
        $Content = $Content.Replace($token, $Replacements[$token])
    }
    if ($CheckLimit -and $Content.Length -ge 131072) { throw 'Expanded workbook section exceeds ARM string limit.' }
    return $Content
}

$root = Split-Path $PSScriptRoot -Parent
$source = Get-Content -LiteralPath (Join-Path $root 'Workbooks\certlcstats.workbook') -Raw | ConvertFrom-Json -AsHashtable -Depth 100
$compiledPath = Join-Path ([System.IO.Path]::GetTempPath()) ("certlc-workbook-{0}.json" -f [guid]::NewGuid())
try {
    & az bicep build --file (Join-Path $root 'Setup\modules\workbook.bicep') --outfile $compiledPath --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'Workbook Bicep compilation failed.' }
    $compiled = Get-Content -LiteralPath $compiledPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    $embedded = @($compiled.variables.Values | Where-Object {
        $_ -is [System.Collections.IDictionary] -and $_.Contains('items') -and $_.Contains('version')
    })
    Assert-True ($embedded.Count -eq 1) 'Compiled template embeds one authoritative workbook object'
    Assert-Equivalent $source $embedded[0] -EscapedArmLiterals
    Assert-True ($compiled.variables.workbookItems.StartsWith('[map(') -and $compiled.variables.workbookItems.Contains('reduce(')) 'Compiled item replacement is section-based'
    Assert-True ($compiled.variables.workbookMetadata.Contains('shallowMerge(')) 'Metadata replacement excludes workbook items'
    Assert-True ($compiled.variables.workbookContent.StartsWith('[string(shallowMerge(')) 'Final serialization preserves arrays without another replacement pass'
    Assert-True ($compiled.resources[0].properties.serializedData -ceq "[variables('workbookContent')]") 'Workbook resource uses the assembled content'

    $replacements = [ordered]@{}
    foreach ($token in $compiled.variables.workbookReplacements.Keys) {
        $replacements[$token] = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Test/resources/$token".Replace('__', '')
    }
    $sourceJson = ConvertTo-Json -InputObject $source -Depth 100 -Compress
    $sourceTokens = @([regex]::Matches($sourceJson, '__[A-Z_]+__').Value | Sort-Object -Unique)
    Assert-True ($sourceTokens.Count -eq 9 -and $replacements.Count -eq 9) 'All nine workbook resource tokens are represented'
    foreach ($token in $sourceTokens) {
        Assert-True ($replacements.Contains($token)) "Replacement exists for $token"
    }

    # Include duplicate items and extra metadata to guard against deep-merge array deduplication.
    $fixture = [ordered]@{
        version = 'Notebook/1.0'
        items = @(
            @{ content = ('x' * 60000) + '__MAIN_RUNBOOK_ID__'; text = "Quotes: `"text`"`nBackslash: \\" }
            @{ content = ('x' * 60000) + '__MAIN_RUNBOOK_ID__'; text = "Quotes: `"text`"`nBackslash: \\" }
            @{ content = ('y' * 60000) + '__QUEUE_SERVICE_ID__' }
        )
        fallbackResourceIds = @('__LOG_ANALYTICS_WORKSPACE_ID__')
        extra = @{ id = '__FUNCTION_APP_ID__'; enabled = $false; empty = @(); nullable = $null }
    }
    foreach ($workbook in @($source, $fixture)) {
        $wholeJson = ConvertTo-Json -InputObject $workbook -Depth 100 -Compress
        $expected = Replace-Tokens $wholeJson $replacements | ConvertFrom-Json -AsHashtable -Depth 100
        $metadata = [ordered]@{}
        foreach ($key in $workbook.Keys) { $metadata[$key] = $workbook[$key] }
        $metadata.items = @()
        $actual = Replace-Tokens (ConvertTo-Json -InputObject $metadata -Depth 100 -Compress) $replacements -CheckLimit | ConvertFrom-Json -AsHashtable -Depth 100
        $actual.items = @(
            foreach ($item in $workbook.items) {
                Replace-Tokens (ConvertTo-Json -InputObject $item -Depth 100 -Compress) $replacements -CheckLimit | ConvertFrom-Json -AsHashtable -Depth 100
            }
        )
        Assert-Equivalent $expected $actual
        Assert-True ($true) 'Section replacement preserves the whole-document result, metadata, item order and duplicates'
    }

    if ($WhatIfResultPath) {
        $preview = Get-Content -LiteralPath $WhatIfResultPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
        Assert-True ($preview.status -eq 'Succeeded' -and $null -eq $preview.error) 'Azure what-if succeeded'
        $workbooks = @($preview.changes | Where-Object { $_.resourceId -like '*/Microsoft.Insights/workbooks/*' -and $null -ne $_.after })
        Assert-True ($workbooks.Count -eq 1) 'Azure rendered one workbook'
        $rendered = $workbooks[0].after.properties.serializedData | ConvertFrom-Json -AsHashtable -Depth 100
        $parameters = @{}
        $parameters.logAnalyticsWorkspaceId = $workbooks[0].after.properties.sourceId
        $resourceTypes = @{
            automationAccountId = 'Microsoft.Automation/automationAccounts'
            functionAppId = 'Microsoft.Web/sites'
            eventGridSystemTopicId = 'Microsoft.EventGrid/systemTopics'
            eventGridSourceId = 'Microsoft.KeyVault/vaults'
            queueStorageAccountId = 'Microsoft.Storage/storageAccounts'
        }
        foreach ($name in $resourceTypes.Keys) {
            $resources = @($preview.changes | Where-Object { $null -ne $_.after -and $_.after.type -eq $resourceTypes[$name] })
            Assert-True ($resources.Count -eq 1) "Azure preview identifies $name"
            $parameters[$name] = $resources[0].resourceId
        }
        $runbooks = @($preview.changes | Where-Object {
            $null -ne $_.after -and $_.after.type -eq 'Microsoft.Automation/automationAccounts/runbooks' -and $_.resourceId -notlike '*/certlcstats'
        })
        Assert-True ($runbooks.Count -eq 1) 'Azure preview identifies the main runbook'
        $parameters.runbookName = $runbooks[0].resourceId.Split('/')[-1]
        $liveReplacements = [ordered]@{
            __LOG_ANALYTICS_WORKSPACE_ID__ = $parameters.logAnalyticsWorkspaceId
            __AUTOMATION_ACCOUNT_ID__ = $parameters.automationAccountId
            __MAIN_RUNBOOK_ID__ = "$($parameters.automationAccountId)/runbooks/$($parameters.runbookName)"
            __STATS_RUNBOOK_ID__ = "$($parameters.automationAccountId)/runbooks/certlcstats"
            __FUNCTION_APP_ID__ = $parameters.functionAppId
            __EVENT_GRID_TOPIC_ID__ = $parameters.eventGridSystemTopicId
            __EVENT_GRID_SOURCE_ID__ = $parameters.eventGridSourceId
            __QUEUE_STORAGE_ACCOUNT_ID__ = $parameters.queueStorageAccountId
            __QUEUE_SERVICE_ID__ = "$($parameters.queueStorageAccountId)/queueServices/default"
        }
        $expectedJson = $sourceJson
        if ($BaselineWhatIfResultPath) {
            # An unsubstituted baseline isolates what-if's Unicode normalization from module changes.
            $baseline = Get-Content -LiteralPath $BaselineWhatIfResultPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
            Assert-True ($baseline.status -eq 'Succeeded' -and $null -eq $baseline.error) 'Original serialization baseline succeeded'
            $baselineWorkbooks = @($baseline.changes | Where-Object { $_.resourceId -eq $workbooks[0].resourceId -and $null -ne $_.after })
            Assert-True ($baselineWorkbooks.Count -eq 1) 'Baseline identifies the same workbook'
            $expectedJson = $baselineWorkbooks[0].after.properties.serializedData
            $baselineContent = $expectedJson | ConvertFrom-Json -AsHashtable -Depth 100
            Assert-Equivalent (($sourceJson -creplace '[^\x00-\x7F]', '') | ConvertFrom-Json -AsHashtable -Depth 100) $baselineContent
            Write-Warning 'Azure baseline preview omits Unicode symbols; local equivalence checks retain and verify the original Unicode content.'
        }
        $expected = Replace-Tokens $expectedJson $liveReplacements | ConvertFrom-Json -AsHashtable -Depth 100
        Assert-Equivalent $expected $rendered
        Assert-True ($true) 'Azure-rendered workbook matches whole-document token substitution of the comparison source'
    }
}
finally {
    if (Test-Path -LiteralPath $compiledPath) { Remove-Item -LiteralPath $compiledPath }
}
