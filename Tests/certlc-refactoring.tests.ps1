# Run directly with PowerShell 7.6+. Only AST-selected helpers execute; no Azure login,
# dispatcher, CA operation, or real SMTP call is allowed in this regression suite.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test doubles retain production signatures but only inspect relevant arguments.')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'New-* test doubles and certificate fixtures are in-memory operations, not production mutations.')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Mock helper names match the production API; Assert-Throws names the exception assertion.')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'The local Send-MailMessage mock must intercept all delivery attempts in this script scope.')]
[CmdletBinding()]
param()

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '../Runbooks/certlc.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }

function Import-TestFunction([string]$Name) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
    }, $true)
    if ($null -eq $definition) { throw "Missing function: $Name" }
    # Install only the selected function body into this test script's scope.
    Set-Item -Path "Function:script:$Name" -Value ([scriptblock]::Create($definition.Body.Extent.Text.TrimStart('{').TrimEnd('}')))
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
}

function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    $caught = $null
    try { & $Action } catch { $caught = $_ }
    Assert-True ($null -ne $caught) "Expected exception matching $Pattern"
    Assert-True ($caught.Exception.Message -like $Pattern) "Unexpected exception: $($caught.Exception.Message)"
}

function Write-CertLCLog { param($Message, $Section, $Level) }
function Send-MailMessage {
    [CmdletBinding()]
    param($SmtpServer, $From, $To, $Subject, $Body, [switch]$BodyAsHtml, [pscredential]$Credential)
    $script:capturedMail = $PSBoundParameters
}

Import-TestFunction 'Send-NotificationEmail'
Import-TestFunction 'Format-PfxProtectTo'
Import-TestFunction 'Convert-PfxProtectToFromTag'

$mail = @{ SmtpServer = 'relay'; FromAddress = 'from@example.test'; To = @('to@example.test'); Subject = 'Subject'; Body = '<p>Body</p>' }
Send-NotificationEmail @mail
Assert-True (-not $capturedMail.ContainsKey('Credential')) 'Anonymous SMTP omits credentials'
Assert-True ($capturedMail.BodyAsHtml -and $capturedMail.WarningAction -eq 'SilentlyContinue') 'SMTP flags preserved'
Assert-True ($capturedMail.From -eq $mail.FromAddress -and $capturedMail.Body -eq $mail.Body) 'SMTP content preserved'
# An empty synthetic credential exercises argument forwarding without storing a password.
$credential = [pscredential]::new('test', [securestring]::new())
Send-NotificationEmail @mail -SmtpCredential $credential
Assert-True ([object]::ReferenceEquals($capturedMail.Credential, $credential)) 'Authenticated SMTP uses supplied credentials'
$credential.Password.Dispose()

$principals = Convert-PfxProtectToFromTag ' DOMAIN\\Group ; ; domain\group ; DOMAIN\User '
Assert-True ($principals -is [array] -and $principals.Count -eq 2) 'Principal array shape and deduplication'
Assert-True (($principals -join ';') -ceq 'DOMAIN\Group;DOMAIN\User') 'Principal order and normalization'
$single = Convert-PfxProtectToFromTag ' DOMAIN\Group '
Assert-True ($single -is [array] -and $single.Count -eq 1) 'Single principal remains an array'
Write-Output 'PASS: SMTP and protection-tag regression checks'

Import-TestFunction 'ConvertTo-CertLCRequestMap'
Import-TestFunction 'Assert-CertLCRequestFields'
foreach ($inputObject in @(
    (ConvertFrom-Json '{"VaultName":"vault","NotifyTo":["to@example.test"]}'),
    (ConvertFrom-Json -AsHashtable -InputObject '{"VaultName":"vault","NotifyTo":["to@example.test"]}')
)) {
    $map = ConvertTo-CertLCRequestMap $inputObject
    Assert-True ($map['vaultname'] -eq 'vault') 'Case-insensitive request fields'
    Assert-True ($null -eq $map['CertificateDnsNames']) 'Omitted optional fields return null'
    Assert-True ($map['NotifyTo'] -is [array] -and $map['NotifyTo'].Count -eq 1) 'Preserve singleton arrays'
    Assert-CertLCRequestFields $map -RequiredStrings 'VaultName' -OptionalArrays 'NotifyTo', 'CertificateDnsNames'
}
foreach ($invalidShape in @($null, 'text', 1, @(@{}))) {
    Assert-Throws { ConvertTo-CertLCRequestMap -Value $invalidShape } '*single object*'
}
$duplicateKeys = ConvertFrom-Json -AsHashtable -InputObject '{"Name":"one","name":"two"}'
Assert-Throws { ConvertTo-CertLCRequestMap $duplicateKeys } '*duplicate field*'
foreach ($invalidString in @($null, '', ' ', 42, @('vault'))) {
    Assert-Throws { Assert-CertLCRequestFields @{ VaultName = $invalidString } -RequiredStrings 'VaultName' } '*data.VaultName*'
}
foreach ($invalidArray in @('', 'recipient', 0, $false)) {
    Assert-Throws { Assert-CertLCRequestFields @{ NotifyTo = $invalidArray } -OptionalArrays 'NotifyTo' } '*not an array*'
}
Assert-CertLCRequestFields @{ NotifyTo = $null; CertificateDnsNames = @() } -OptionalArrays 'NotifyTo', 'CertificateDnsNames'
Write-Output 'PASS: request map and field validation checks'

# Execute only the request-handling tail of the dispatcher. Every external operation
# is replaced by a local test double, so validation order and routing can be exercised.
$source = [IO.File]::ReadAllText($sourcePath)
$requestOffset = $source.IndexOf('$usesJsonRequestBody =', [StringComparison]::Ordinal)
Assert-True ($requestOffset -gt 0) 'Locate request dispatcher boundary'
$requestStatements = $ast.EndBlock.Statements | Where-Object { $_.Extent.StartOffset -ge $requestOffset }
$requestDispatcher = [scriptblock]::Create(($requestStatements.Extent.Text -join "`n"))

function Write-CertLCLogAndThrow {
    param($Section, $Message, [Alias('Inner')]$InnerException, $NotifyTo, $SmtpServer, $FromAddress, [pscredential]$SmtpCredential)
    $script:lastFailure = @{ Section = $Section; NotifyTo = $NotifyTo; Context = $script:CertificateNotificationContext }
    throw $Message
}
function Get-AzKeyVaultCertificate {
    param($VaultName, $Name, [switch]$InRemovedState, $Version)
    $script:remoteReads++
    if ($InRemovedState) { return $null }
    if ($null -ne $script:certificateFixture) { return $script:certificateFixture }
    throw 'Unexpected certificate read in creation test'
}
function Find-TemplateName {
    param($cnOrDisplayNameOrOid)
    $script:remoteReads++
    $script:templateLookup = $cnOrDisplayNameOrOid
    return 'ResolvedTemplate'
}
function New-CertificateCreationRequest {
    param($VaultName, $CertificateName, $CertificateTemplateName, $CertificateSubject,
        $CertificateDnsNames, $CA, $Hostname, $PfxProtectTo, $NotifyTo, $RenewedJobId,
        [ref]$Result, $PfxRootFolder)
    $script:creationCall = $PSBoundParameters
    $Result.Value = [pscustomobject]@{ CertificateName = $CertificateName }
}
function New-CertLCCreationNotificationDetails {
    param($OperationResult, $Operation, $RequestId)
    $script:notificationRequestId = $RequestId
    return [ordered]@{ Operation = $Operation }
}
function Send-SuccessNotification {
    param($Section, $Subject, $Summary, $Details, $JobId, $NotifyTo, $SmtpServer, $FromAddress, [pscredential]$SmtpCredential)
    $script:notificationCall = $PSBoundParameters
}
function Invoke-TestRequest {
    # These locals are the explicit environment for the AST-extracted dispatcher below.
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Locals are consumed by the extracted dispatcher scriptblock.')]
    [CmdletBinding()]
    param($Json, $Webhook)
    $script:CertLCCorrelationId = ''
    $script:CertificateNotificationContext = [ordered]@{}
    $script:remoteReads = 0
    $script:creationCall = $null
    $script:revocationCall = $null
    $script:notificationRequestId = $null
    $script:lastFailure = $null
    $jsonRequestBody = $Json
    $WebhookData = $Webhook
    $CloudEventSpecVersion = '1.0'
    $smtpArgs = @{ SmtpServer = 'relay'; FromAddress = 'from@example.test'; SmtpCredential = $null }
    $CA = 'test-ca'
    $PfxRootFolder = 'test-root'
    $jobId = 'test-job'
    & $requestDispatcher
}

$script:certificateFixture = $null
$validCreation = @{
    specversion = '1.0'; type = 'CertLC.NewCertificateRequest'; id = 'event-id'; source = 'test-source'
    data = @{ VaultName = 'vault'; ObjectName = 'certificate'; CertificateTemplate = 'template'
        CertificateSubject = 'CN=test'; Hostname = ' HOST.EXAMPLE '; PfxProtectTo = @(' DOMAIN\Group ') }
}
$creationJson = ConvertTo-Json -InputObject $validCreation -Depth 10 -Compress
Invoke-TestRequest -Json $creationJson
Assert-True ($creationCall.Hostname -ceq 'host.example') 'Dispatcher normalizes hostname'
Assert-True ($null -eq $creationCall.NotifyTo -and $null -eq $creationCall.CertificateDnsNames) 'Omitted optional creation fields accepted'
Assert-True ($null -eq $notificationRequestId) 'Omitted data.Id does not fall back to event ID'
Assert-True ($script:CertLCCorrelationId -ceq 'event-id') 'Explicit JSON preserves log correlation'
Assert-True (-not $creationCall.ContainsKey('RenewedJobId')) 'Creation has no renewal audit ID'

$webhooks = @(
    [pscustomobject]@{ RequestBody = $creationJson },
    [pscustomobject]@{ RequestBody = (ConvertFrom-Json $creationJson) },
    @{ RequestBody = $validCreation },
    (ConvertTo-Json @{ RequestBody = $creationJson } -Compress),
    ('{WebhookName:certlc,RequestBody:' + $creationJson + ',RequestHeader:{}}'),
    ('{WebhookName:certlc,RequestBody:' + $creationJson.Replace('"', '\"') + ',RequestHeader:{}}')
)
foreach ($webhook in $webhooks) {
    Invoke-TestRequest -Webhook $webhook
    Assert-True ($null -ne $creationCall) 'Webhook input reaches creation'
    Assert-True ($script:CertLCCorrelationId -ceq '') 'Webhook input never opts into log correlation'
}

foreach ($optionalValue in @($null, @(), @('one.example'))) {
    $candidate = ConvertFrom-Json -AsHashtable -InputObject $creationJson
    $candidate.data.NotifyTo = $optionalValue
    $candidate.data.CertificateDnsNames = $optionalValue
    Invoke-TestRequest -Json (ConvertTo-Json $candidate -Depth 10 -Compress)
    Assert-True ($null -ne $creationCall) 'Null, empty and singleton arrays reach creation'
}
foreach ($invalidField in @('VaultName', 'ObjectName', 'CertificateTemplate', 'CertificateSubject', 'Hostname', 'PfxProtectTo')) {
    $candidate = ConvertFrom-Json -AsHashtable -InputObject $creationJson
    $candidate.data.Remove($invalidField)
    Assert-Throws { Invoke-TestRequest -Json (ConvertTo-Json $candidate -Depth 10 -Compress) } "*$invalidField*"
    Assert-True ($remoteReads -eq 0) "Missing $invalidField rejected before external reads"
}
$candidate = ConvertFrom-Json -AsHashtable -InputObject $creationJson
$candidate.data.NotifyTo = 'invalid-scalar'
Assert-Throws { Invoke-TestRequest -Json (ConvertTo-Json $candidate -Depth 10 -Compress) } '*NotifyTo*not an array*'
Assert-True ($remoteReads -eq 0 -and $null -eq $lastFailure.NotifyTo) 'Malformed recipients never reach notification transport'
$candidate.data.NotifyTo = @('to@example.test')
$candidate.data.CertificateDnsNames = 'invalid-scalar'
Assert-Throws { Invoke-TestRequest -Json (ConvertTo-Json $candidate -Depth 10 -Compress) } '*CertificateDnsNames*not an array*'
Assert-True ($remoteReads -eq 0 -and $lastFailure.NotifyTo[0] -eq 'to@example.test') 'Validated recipients retained on later failures'

foreach ($badBody in @('[]', ('[' + $creationJson + ']'), 'null', '42', '{"specversion":"1.0","type":"CertLC.NewCertificateRequest"}')) {
    Assert-Throws { Invoke-TestRequest -Json $badBody } '*single object*'
    Assert-True ($remoteReads -eq 0) 'Malformed envelope or data rejected before external reads'
}
# String bodies retain the existing second JSON parse used for serialized webhook bodies.
Assert-Throws { Invoke-TestRequest -Json '"text"' } '*Failed to parse request body as JSON*'
Assert-True ($remoteReads -eq 0) 'Invalid serialized body rejected before external reads'
$candidate = ConvertFrom-Json -AsHashtable -InputObject $creationJson
$candidate.id = 42
Invoke-TestRequest -Json (ConvertTo-Json $candidate -Depth 10 -Compress)
Assert-True ($script:CertLCCorrelationId -ceq '') 'Numeric event ID is not coerced into correlation'
Write-Output 'PASS: request dispatcher and transport regression checks'

Import-TestFunction 'Get-CertLCTemplateOid'

# Generate public test certificates in memory. Nothing is installed in a certificate
# store, sent to a CA, or exported to disk; each certificate and key is disposed below.
function New-TestTemplateCertificate([byte[]]$RawData) {
    $key = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=CertLC test', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if ($null -ne $RawData) {
            $extension = [System.Security.Cryptography.X509Certificates.X509Extension]::new(
                '1.3.6.1.4.1.311.21.7', $RawData, $false)
            $request.CertificateExtensions.Add($extension)
        }
        return $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
    }
    finally { $key.Dispose() }
}
function New-TestTemplateEncoding([int[]]$Versions = @()) {
    $writer = [System.Formats.Asn1.AsnWriter]::new([System.Formats.Asn1.AsnEncodingRules]::DER)
    # PushSequence returns a scope token; keep it off the encoded-byte output stream.
    $null = $writer.PushSequence()
    $writer.WriteObjectIdentifier('1.3.6.1.4.1.311.21.8.123.456')
    foreach ($version in $Versions) { $writer.WriteInteger([long]$version) }
    $writer.PopSequence()
    return ,$writer.Encode()
}
foreach ($versions in @(@(), @(100), @(100, 5))) {
    $certificate = New-TestTemplateCertificate (New-TestTemplateEncoding -Versions $versions)
    try {
        $certificate.Extensions['1.3.6.1.4.1.311.21.7'].Oid.FriendlyName = 'Unrelated display name'
        Assert-True ((Get-CertLCTemplateOid $certificate) -ceq '1.3.6.1.4.1.311.21.8.123.456') 'ASN.1 template OID independent of display name and optional versions'
    }
    finally { $certificate.Dispose() }
}
$invalidEncodings = @(
    [byte[]]@(0x30, 0x00),
    [byte[]]@(0x30, 0x03, 0x06, 0x01),
    (New-TestTemplateEncoding -Versions @(-1)),
    (New-TestTemplateEncoding -Versions @(1, 2, 3)),
    [byte[]]((New-TestTemplateEncoding) + @(0x05, 0x00))
)
foreach ($encoding in $invalidEncodings) {
    $certificate = New-TestTemplateCertificate $encoding
    try { Assert-Throws { Get-CertLCTemplateOid $certificate } '*' }
    finally { $certificate.Dispose() }
}
$certificate = New-TestTemplateCertificate $null
try { Assert-Throws { Get-CertLCTemplateOid $certificate } '*extension was not found*' }
finally { $certificate.Dispose() }
Write-Output 'PASS: ASN.1 certificate template decoding checks'

Import-TestFunction 'ConvertFrom-CertLCNotifyToTag'
foreach ($tag in @($null, '', '  ')) {
    $addresses = ConvertFrom-CertLCNotifyToTag $tag
    Assert-True ($addresses -is [array] -and $addresses.Count -eq 0) 'Empty notification tag stays array-shaped'
}
$addresses = ConvertFrom-CertLCNotifyToTag ' First@example.test ; ; Second@example.test;First@example.test '
Assert-True (($addresses -join ';') -ceq 'First@example.test;Second@example.test;First@example.test') 'Recipient order, casing and duplicates preserved'
$addresses = ConvertFrom-CertLCNotifyToTag ' One@example.test '
Assert-True ($addresses -is [array] -and $addresses.Count -eq 1) 'One recipient remains an array'

# Import only the literal HTML assignments, never the runbook's initialization or dispatcher.
foreach ($name in 'CertificateNotificationEmailBodyHtml', 'CertificateErrorEmailSectionHtml') {
    $assignment = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq "`$$name"
    }, $true)
    Assert-True ($null -ne $assignment) "Find $name template"
    Set-Variable -Name $name -Value $assignment.Right.Expression.Value -Scope Script
}
Import-TestFunction 'ConvertTo-CertLCHtmlText'
Import-TestFunction 'New-CertLCNotificationDetailsHtml'
Import-TestFunction 'New-CertLCNotificationBody'
$script:CertLCCorrelationId = 'event-id'
$render = @{ Title = '<Title>'; Summary = 'A & B'; Details = [ordered]@{ Name = '<script>'; List = @('one', 'two'); Empty = $null }; JobId = 'job-id' }
$normalHtml = New-CertLCNotificationBody @render
$errorHtml = New-CertLCNotificationBody @render -ErrorDetails "<error>`nsecond line"
Assert-True ($normalHtml.Contains('background:#0b5cab') -and $normalHtml.Contains('border:1px solid #ccd6e0')) 'Success colors retained'
Assert-True ($normalHtml.Contains('padding:10px 24px 24px;') -and -not $normalHtml.Contains('background:#fff1f0')) 'Success spacing and no error section'
Assert-True ($errorHtml.Contains('background:#b42318') -and $errorHtml.Contains('border:1px solid #e1b4b4')) 'Error colors retained'
Assert-True ($errorHtml.Contains('padding:10px 24px 16px;') -and $errorHtml.Contains('&lt;error&gt;<br />second line')) 'Error spacing and escaped multiline details'
foreach ($html in $normalHtml, $errorHtml) {
    Assert-True ($html.Contains('&lt;Title&gt;') -and $html.Contains('A &amp; B') -and $html.Contains('&lt;script&gt;')) 'Dynamic text HTML encoded'
    Assert-True ($html.Contains('one<br />two') -and $html.Contains('event-id') -and $html.Contains('job-id')) 'Collections and distinct identities retained'
    Assert-True ($html -notmatch '__[A-Z_]+__') 'No unexpanded template tokens'
}
Assert-True ((New-CertLCNotificationBody @render -ErrorDetails ' ') -ceq $normalHtml) 'Whitespace error details select success'
Write-Output 'PASS: shared notification parser and HTML layout checks'

function Get-CertificateByThumbprint {
    param($VaultName, $Thumbprint)
    $script:remoteReads++
    return [pscustomobject]@{ Name = 'certificate'; Version = 'exact-version'; IsLatest = $true }
}
function New-CertificateRevocationRequest {
    param($VaultName, $CertificateName, $CertificateVersion, $RevocationReason, $JobId,
        $ExistingTags, $Certificate, $ExpectedThumbprint, [ref]$Result, $CA)
    $script:revocationCall = $PSBoundParameters
    $Result.Value = [pscustomobject]@{
        CertificateName = $CertificateName; Subject = $Certificate.Subject; Thumbprint = $Certificate.Thumbprint
        SerialNumber = $Certificate.SerialNumber; Issuer = $Certificate.Issuer
        NotBeforeUtc = $Certificate.NotBefore.ToUniversalTime(); NotAfterUtc = $Certificate.NotAfter.ToUniversalTime()
        VaultName = $VaultName; CertificateVersion = $CertificateVersion; RevokedAt = '2026-01-01T00:00:00Z'
    }
}

# Exercise the real renewal decoder and recipient parser together with both dispatcher
# branches, while keeping all CA, filesystem, Key Vault, and notification writes mocked.
$certificate = New-TestTemplateCertificate (New-TestTemplateEncoding -Versions @(100, 5))
try {
    $script:certificateFixture = [pscustomobject]@{
        Certificate = $certificate
        Tags = @{ Hostname = 'host.example'; PfxProtectTo = ' DOMAIN\Group '; NotifyTo = ' one@example.test ; ; two@example.test ' }
    }
    $renewal = @{ specversion = '1.0'; type = 'Microsoft.KeyVault.CertificateNearExpiry'; id = 'renewal-event'
        data = @{ VaultName = 'vault'; ObjectName = 'certificate' } }
    Invoke-TestRequest -Json (ConvertTo-Json $renewal -Depth 10)
    Assert-True ($creationCall.RenewedJobId -ceq 'test-job') 'Renewal retains its separate execution audit identity'
    Assert-True ($templateLookup -ceq '1.3.6.1.4.1.311.21.8.123.456') 'Renewal resolves the decoded numeric template OID'
    Assert-True (($creationCall.NotifyTo -join ';') -ceq 'one@example.test;two@example.test') 'Renewal uses shared recipient parser'
    Assert-True ($null -eq $notificationRequestId -and $script:CertLCCorrelationId -ceq 'renewal-event') 'Renewal accepts omitted data.Id without changing event correlation'

    $script:certificateFixture.Tags.Revoked = 'true'
    Invoke-TestRequest -Json (ConvertTo-Json $renewal -Depth 10)
    Assert-True ($null -eq $creationCall) 'Revoked latest certificate still skips renewal'
    $script:certificateFixture.Tags.Remove('Revoked')

    $revocation = @{ specversion = '1.0'; type = 'CertLC.CertificateRevocationRequest'; id = 'revocation-event'
        data = @{ VaultName = 'vault'; CertificateThumbprint = $certificate.Thumbprint; RevocationReason = 0 } }
    foreach ($reason in @(0, '0', 6, '6')) {
        $revocation.data.RevocationReason = $reason
        Invoke-TestRequest -Json (ConvertTo-Json $revocation -Depth 10)
        Assert-True ($revocationCall.RevocationReason -eq [int]$reason) 'Numeric and string reason codes including zero accepted'
        Assert-True ($revocationCall.CertificateVersion -ceq 'exact-version') 'Revocation remains pinned to matched version'
        Assert-True ([object]::ReferenceEquals($revocationCall.Certificate, $certificate)) 'Revocation uses the matched certificate'
        Assert-True ($revocationCall.ExpectedThumbprint -ceq $certificate.Thumbprint) 'Thumbprint guard remains explicit'
        Assert-True (($notificationCall.NotifyTo -join ';') -ceq 'one@example.test;two@example.test') 'Revocation uses shared recipient parser'
        Assert-True ($null -eq $notificationCall.Details['Request ID']) 'Revocation accepts omitted data.Id'
    }
    foreach ($reason in @($null, '', 'invalid', -1, 7)) {
        $revocation.data.RevocationReason = $reason
        Assert-Throws { Invoke-TestRequest -Json (ConvertTo-Json $revocation -Depth 10) } '*RevocationReason*'
        Assert-True ($remoteReads -eq 0 -and $null -eq $revocationCall) 'Invalid reason rejected before external reads'
    }
    $revocation.data.RevocationReason = 0
    $script:certificateFixture.Tags.Revoked = 'true'
    Invoke-TestRequest -Json (ConvertTo-Json $revocation -Depth 10)
    Assert-True ($null -eq $revocationCall) 'Duplicate revocation remains idempotent success'
}
finally {
    $script:certificateFixture = $null
    $certificate.Dispose()
}
Write-Output 'PASS: renewal and revocation dispatcher regression checks'