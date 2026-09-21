Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$tokens = $null
$parseErrors = $null
$sourcePath = Join-Path $PSScriptRoot '../Runbooks/certlc.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    Write-Output "PASS: $Message"
}

function Get-Definition([string]$Name) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
    }, $true)
    if ($null -eq $definition) { throw "Missing function $Name" }
    return $definition
}

$creation = Get-Definition 'New-CertificateCreationRequest'
$revocation = Get-Definition 'New-CertificateRevocationRequest'
$notification = Get-Definition 'Send-SuccessNotification'
$errorNotification = Get-Definition 'Write-CertLCLogAndThrow'
. ([scriptblock]::Create($creation.Extent.Text))
. ([scriptblock]::Create($notification.Extent.Text))
. ([scriptblock]::Create($errorNotification.Extent.Text))
# Replace only native COM release so a managed CA double can exercise the actual helper.
$releaseCall = '[Runtime.InteropServices.Marshal]::ReleaseComObject($CertAdmin)'
Assert-True ($revocation.Extent.Text.Contains($releaseCall)) 'Native release boundary located'
. ([scriptblock]::Create($revocation.Extent.Text.Replace($releaseCall, '(Release-TestComObject $CertAdmin)')))

foreach ($name in 'New-CertificateCreationRequest', 'New-CertificateRevocationRequest') {
    $command = Get-Command $name
    Assert-True ([bool]($command.Parameters['Result'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory })) "$name requires Result"
}
foreach ($name in 'Certificate', 'ExistingTags', 'ExpectedThumbprint') {
    $parameter = (Get-Command New-CertificateRevocationRequest).Parameters[$name]
    Assert-True ([bool]($parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory })) "Revocation requires $name"
}
Assert-True ((Get-Command Send-SuccessNotification).Parameters['Summary'].Aliases -notcontains 'BodyText') 'Obsolete alias removed'
Assert-True (-not $creation.Extent.Text.Contains('$privateKeyProbe')) 'Passwordless export probe removed'
Assert-True (-not $revocation.Extent.Text.Contains('Get-AzKeyVaultCertificate')) 'Revocation has no fallback certificate reads'

function Write-CertLCLog { param($Section, $Message, $Level, $CorrelationId, $Context) @{ section = $Section; message = $Message } | ConvertTo-Json -Compress }
function New-CertLCNotificationBody {
    param($Title, $Summary, $Details, $ErrorDetails, $JobId, $CorrelationId)
    $script:capturedErrorDetails = $ErrorDetails
    return 'notification body'
}
function Send-NotificationEmail {
    param($SmtpServer, $FromAddress, $To, $Subject, $Body, $SmtpCredential)
    $script:capturedErrorSubject = $Subject
}
function Get-AzKeyVaultCertificate { throw 'Unexpected fallback read' }
function New-Object {
    param($ComObject)
    if ($ComObject -ne 'CertificateAuthority.Admin') { throw 'Unexpected COM activation' }
    $admin = [pscustomobject]@{}
    $admin | Add-Member -MemberType ScriptMethod -Name RevokeCertificate -Value {
        param($Authority, $Serial, $Reason, $Date)
        $script:caCalls.Add(@{ CA = $Authority; Serial = $Serial; Reason = $Reason })
    }
    return $admin
}
function Release-TestComObject { param($Admin) $script:releaseCount++; return 0 }
function Update-AzKeyVaultCertificate {
    param($VaultName, $Name, $Version, $Enable, $Tag, [switch]$PassThru, $ErrorAction)
    $script:patches.Add(@{ Vault = $VaultName; Name = $Name; Version = $Version; Enable = $Enable; Tags = $Tag })
}

$key = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=contract-test', $key, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddDays(1))
$testFolder = Join-Path ([System.IO.Path]::GetTempPath()) ('certlc-contract-' + [guid]::NewGuid().ToString('N'))
$null = [System.IO.Directory]::CreateDirectory($testFolder)
try {
    foreach ($scenario in 'Tagged', 'Untagged', 'Mismatch') {
        $script:caCalls = [System.Collections.Generic.List[object]]::new()
        $script:patches = [System.Collections.Generic.List[object]]::new()
        $script:releaseCount = 0
        $tags = if ($scenario -eq 'Untagged') { $null } else { @{ NotifyTo = 'owner@example.test'; Revoked = 'false' } }
        $revocationResult = $null
        $expected = if ($scenario -eq 'Mismatch') { 'WRONG' } else { $certificate.Thumbprint.ToLowerInvariant() }
        $failure = $null
        $logs = @()
        try {
            $logs = @(New-CertificateRevocationRequest -VaultName 'test-vault' -CertificateName 'test-cert' -CertificateVersion 'exact-version' -RevocationReason 1 -JobId 'test-job' -ExistingTags $tags -Certificate $certificate -ExpectedThumbprint $expected -CA 'test-ca' -Result ([ref]$revocationResult))
        }
        catch { $failure = $_.Exception }
        if ($scenario -eq 'Mismatch') {
            Assert-True ($null -ne $failure -and $failure.Message -like '*thumbprint does not match*' -and $script:caCalls.Count -eq 0 -and $script:patches.Count -eq 0 -and $null -eq $revocationResult) 'Thumbprint mismatch fails before mutation'
            continue
        }
        Assert-True ($null -eq $failure -and $script:caCalls.Count -eq 1 -and $script:patches.Count -eq 1 -and $script:releaseCount -eq 1) "$scenario performs one revocation and one patch"
        $patch = $script:patches[0]
        Assert-True ($patch.Version -eq 'exact-version' -and -not $patch.Enable -and $patch.Tags.Revoked -eq 'true' -and $patch.Tags.RevokedJobId -eq 'test-job') "$scenario updates only the selected version"
        Assert-True ($revocationResult.Thumbprint -eq $certificate.Thumbprint -and $logs.Count -gt 0 -and @($logs | Where-Object { $_ -isnot [string] }).Count -eq 0) "$scenario returns metadata through reference and logs through Output"
        if ($null -ne $tags) {
            Assert-True ($tags.Revoked -eq 'false' -and $patch.Tags.NotifyTo -eq $tags.NotifyTo) 'Tag snapshot preserved without caller mutation'
        }
    }

    $script:CertificateNotificationContext = [ordered]@{
        Operation = 'Revocation'
        'Certificate name' = 'test-cert'
    }
    $script:capturedErrorDetails = $null
    $script:capturedErrorSubject = $null
    $accessDenied = [System.UnauthorizedAccessException]::new(
        'CCertAdmin::RevokeCertificate: Access is denied. 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)'
    )
    $caFailure = [System.Exception]::new('CA: Error revoking certificate test-cert', $accessDenied)
    $failure = $null
    try {
        Write-CertLCLogAndThrow `
            -Section 'Dispatcher.Revocation' `
            -Message 'Error processing certificate revocation request' `
            -InnerException $caFailure `
            -NotifyTo 'owner@example.test' `
            -SmtpServer 'smtp.example.test' `
            -FromAddress 'certlc@example.test'
    }
    catch {
        $failure = $_.Exception
    }
    Assert-True ($null -ne $failure) 'Error notification preserves terminating behavior'
    Assert-True ($script:capturedErrorDetails -like '*System.Exception*CA: Error revoking certificate test-cert*') 'Error notification includes CA exception'
    Assert-True ($script:capturedErrorDetails -like '*System.UnauthorizedAccessException*Access is denied*ERROR_ACCESS_DENIED*') 'Error notification includes nested authorization exception'
    Assert-True ($script:capturedErrorDetails -like '*0x80070005*') 'Error notification includes nested exception HRESULT'
    Assert-True ($script:capturedErrorSubject -ceq 'Certificate test-cert revocation failed') 'Error notification uses an operation-specific subject'

    # Execute the actual post-merge export block; issuance and native SID export stay mocked.
    $exportBlock = @($creation.Body.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.TryStatementAst] -and $_.Extent.Text.Contains('All remaining PFX work')
    })
    Assert-True ($exportBlock.Count -eq 1) 'Post-merge export block located'
    $resultAssignment = $creation.Body.EndBlock.Statements[-1].Extent.Text
    Assert-True ($resultAssignment -eq '$Result.Value = $operationResult') 'Creation has a single reference result assignment'
    function Initialize-PfxExportTarget {
        param($PfxRootFolder, $Hostname, $ProtectTo)
        @{ TargetFolder = $testFolder; ProtectionSids = @() }
    }
    function Export-PfxWithGroupProtection {
        param($Certificates, $ProtectionSids, $PfxFile)
        $script:exportCalls++
        [System.IO.File]::WriteAllBytes($PfxFile, [byte[]](1, 2, 3))
        if ($scenario -eq 'ExportFailure') { throw [System.Security.Cryptography.CryptographicException]::new('Private key is not exportable') }
    }
    foreach ($scenario in 'ExportSuccess', 'ExportFailure') {
        $script:exportCalls = 0
        $CertificateName = 'test-cert'
        $VaultName = 'test-vault'
        $certificateVersion = 'exact-version'
        $CertificateTemplateName = 'test-template'
        $CertificateDnsNames = @('test.example')
        $Hostname = 'test-host'
        $PfxRootFolder = $testFolder
        $PfxProtectTo = @('TEST\Readers')
        $keyVaultCertificates = @()
        $exportChain = @($certificate)
        $creationResult = $null
        $Result = [ref]$creationResult
        $targetFile = Join-Path $testFolder 'test-cert.pfx'
        [System.IO.File]::WriteAllBytes($targetFile, [byte[]](9, 8, 7))
        $failure = $null
        try { $logs = @(. ([scriptblock]::Create($exportBlock[0].Extent.Text + "`n" + $resultAssignment))) }
        catch { $failure = $_.Exception }
        Assert-True ($script:exportCalls -eq 1) "$scenario invokes the real export boundary once"
        if ($scenario -eq 'ExportFailure') {
            Assert-True ($null -ne $failure -and $failure.Message -like '*PFX: Export failure*' -and $null -eq $creationResult -and ([System.IO.File]::ReadAllBytes($targetFile) -join ',') -eq '9,8,7') 'Export failure preserves existing PFX and leaves result unset'
        }
        else {
            Assert-True ($null -eq $failure -and $creationResult.CertificateVersion -eq 'exact-version' -and $creationResult.PfxSizeBytes -eq 3 -and ([System.IO.File]::ReadAllBytes($targetFile) -join ',') -eq '1,2,3') 'Export success publishes PFX and returns exact-version metadata'
            Assert-True (@($logs | Where-Object { $_ -isnot [string] }).Count -eq 0) 'Creation Output contains logs only'
        }
        Assert-True (@(Get-ChildItem -LiteralPath $testFolder -Filter '*.tmp' -Force).Count -eq 0) "$scenario cleans temporary export files"
    }
    Assert-True ($certificate.SerialNumber.Length -gt 0) 'Caller retains certificate ownership'
}
finally {
    $certificate.Dispose()
    $key.Dispose()
    Remove-Item -LiteralPath $testFolder -Recurse -Force
}