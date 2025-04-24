##########
# CERTLC #
##########

# CERTLC is a PowerShell runbook that automates the process of obtaining or renewing certificates from an AD CA, integrated with Azure Key Vault.
# The key vault is used to generate all requests, storing the private keys safely.

# The script is designed to be run using PowerShell 5.1 in an Azure Automation hybrid worker environment.
# Requires the following modules:
# - Az
# - PSPKI

# Based on certlc solution https://learn.microsoft.com/en-us/azure/architecture/example-scenario/certificate-lifecycle/


param
(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData
)

# the WebhookData is documented here: https://learn.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal
# Contains:
# - WebhookData.WebhookName: the name of the webhook that triggered the runbook
# - WebhookData.RequestHeaders: the headers of the request that triggered the runbook
# - WebhookData.RequestBody: the body of the request that triggered the runbook

# We assume to use the followng JSON structure for the webhook body:

# for NEW CERTIFICATES:
# {
#   "CertLCVersion": "1.0",                     # version tag
#   "Action": "New"                             # action to perform
#   "VautName": "string"                        # key vault name
#   "CertificateName": "string",                # name of the certificate to create or renew
#   "CertificateTemplate": "string",            # name of the certificate template to use
#   "CertificateSubject": "string",             # subject of the certificate to create or renew
#   "CertificateDNSNames": array of strings     # optional, certificate DNS names
# }

# for RENEWALS:
# {
#   "CertLCVersion": "1.0",                     # version tag
#   "Action": "Renew"                           # action to perform
#   "VaultName": "string",                      # key vault name
#   "CertificateName": "string",                # name of the certificate to renew (it will have the same subject, DNS names, template, and a new private key)
# }

# Note: RENEWALS can be triggered by event grid events, for example when the certificate is about to expire.
# In this case, the webhook body will not contain the above structure.
# A missing 'CertLCVersion' field will be used to identify the webhook as an autorenewal. CertificateName and VaultName will be fetched from the queue message.


# force the runbook to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

###################
# STATIC SETTINGS #
###################

# TODO: can be automation variables instead (see renewcertviakv.ps1)

$Version = "1.0"                        # version of the script - must match the version in the webhook body

$IngestionUrl = "https://dce-certlc-itn-001-ws3i.italynorth-1.ingest.monitor.azure.com"     # Log Analytics Ingestion: ingestion URL
$DcrImmutableId = "dcr-0af8254b18bf4c06a6d2952f9f040938"                                    # Log Analytics Ingestion: Data Collection Rule (DCR) immutable ID
$Table = "certlc_CL"                                                                        # Log Analytics Ingestion: custom table name (must include also the _CL suffix)

$AutomationAccountName = "aa-shared-neu-001"
$AutomationAccountRG = "rg-shared-neu-001"

$QueueStorageAccountName = "flazstsharedneu001"     # name of the storage account where the queue is located
$QueueName = "certlc"                               # name of the queue to use for autorenewals
$QueueAttempts = 10                                 # number of attempts to check the queue
$QueueWait = 5                                      # seconds to wait between attempts
$QueueInvisibilityTimeout = [System.TimeSpan]::FromSeconds(30) # seconds to wait for the message to be invisible in the queue when it is being processed

$CAServer = "flazdc03.formicalab.casa"  # CA server name
$PFXFolder = "C:\Temp"                  # folder where the PFX file will be downloaded

# Note: some settings might be set in the Automation Account variables instead. Fetch as follows:
#$QueueStorageAccountName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-storageaccount").Value
#$QueueName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-queue").Value
#$CAServer = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-ca").Value

####################
# GLOBAL VARIABLES #
####################

$Progress = 0                                   # progress of the script
$LAToken = $null                                # token using to send logs to Log Analytics
$CorrelationId = [guid]::NewGuid().ToString()   # correlation ID for the log entry

#########################
# FUNCTIONS - Write-Log #
#########################

# Write-Log: send log to Log Analytics workspace (if token is available) and to output
function Write-Log {
    param (
        [Parameter()]
        [string]$Description,
        [Parameter()]
        [string]$Level = "Information"
    )

    # send log to Log Analytics workspace (if token is available)
    if ($null -ne $LAToken) {
        $log_entry = @{
            CorrelationId = $CorrelationId
            Status        = $Level
            Progress      = $Progress
            Description   = $Description
        }
        $body = $log_entry | ConvertTo-Json -Depth 10
        # put the json body into an array [] - PowerShell 5.1 does support the -AsArray switch for ConvertTo-Json
        $body = "[$body]"
        $headers = @{"Authorization" = "Bearer $LAToken"; "Content-Type" = "application/json" };
        $uri = "$IngestionUrl/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table" + "?api-version=2023-01-01";
        Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers | Out-Null
    }

    # write to output
    if ($Level -eq "Error") {
        Write-Error "$(get-date): $($Level): [$(('{0:D3}' -f $Progress))] $Description"
    }
    elseif ($Level -eq "Warning") {
        Write-Warning "$(get-date): $($Level): [$(('{0:D3}' -f $Progress))] $Description"
    }
    else {
        Write-Output "$(get-date): $($Level): [$(('{0:D3}' -f $Progress))] $Description"
    }
}

######################################
# FUNCTIONS - New-CertificateRequest #
######################################

# New-CertificateRequest: create a new certificate request

function New-CertificateRequest {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        [Parameter(Mandatory = $true)]
        [string]$CertificateName,
        [Parameter(Mandatory = $true)]
        [string]$CertificateTemplate,
        [Parameter(Mandatory = $true)]
        [string]$CertificateSubject,
        [Parameter(Mandatory = $false)]
        [array]$CertificateDNSNames,
        [Parameter(Mandatory = $false)]
        [string]$CAServer,
        [Parameter(Mandatory = $false)]
        [string]$PfxFolder
    )

    # create certificate - if a previous request is in progress, reuse it
    $csr = $null
    try {
        $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertificateName | Where-Object { $_.Status -eq "inProgress" }
        if ($null -ne $op) {
            Write-Log "Certificate request is already in progress for this certificate: $CertificateName; reusing the existing request."
            $csr = $op.CertificateSigningRequest
        }
        else {
            Write-Log "Creating a new CSR for certificate $CertificateName in key vault $VaultName..."
            if ($null -ne $CertificateDnsNames) {
                # create a new CSR with the DNS names
                $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $CertificateSubject -IssuerName "Unknown" -DnsName $CertificateDnsNames
            }
            else {
                # create a new CSR without DNS names
                $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $CertificateSubject -IssuerName "Unknown"
            }
            $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -CertificatePolicy $Policy
            $csr = $result.CertificateSigningRequest
        }
    }
    catch {
        Write-Log "Error generating CSR in Key Vault: $_" -Level "Error"
        return
    }
    $Progress++

    # Write the CSR content to a temporary file
    $csrFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertificateName.csr"
    Set-Content -Path $csrFile -Value $csr
    Write-Log "CSR file created: $csrFile"
    $Progress++

    # Send request to the CA and remove the CSR file
    Write-Log "Sending request to the CA..."
    try {
        $certificateRequest = Submit-CertificateRequest -CA $ca -Path $csrFile -Attribute "CertificateTemplate:$($CertificateTemplate)"    
    }
    catch {
        Write-Log "Error sending request to the CA: $_" -Level "Error"
        return
    }
    finally {
        # remove the CSR file
        Remove-Item -Path $csrFile -Force -ErrorAction SilentlyContinue
    }
    if ($null -eq $certificateRequest) {
        Write-Log "Error sending request to the CA: empty response returned!" -Level "Error"
        return
    }
    $certificate = $certificateRequest.Certificate
    if ($null -eq $certificate) {
        Write-Log "Error getting certificate from the CA: no X.509 certificate returned!" -Level "Error"
        return
    }
    $Progress++

    # write the returned signed certificate to a temporary file
    Write-Log "Exporting the signed certificate to a temporary file..."
    $certFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertificateName.p7b"
    try {
        Export-Certificate -Cert $certificate -FilePath $certFile -Type P7B | Out-Null    
    }
    catch {
        Write-Log "Error exporting certificate to file: $_" -Level "Error"
        return
    }
    Write-Log "Certificate file created: $certFile"
    $Progress++

    # use certutil -encode to convert the certificate to base64 - this is required to import a p7b file into the key vault
    # (https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#formats-of-merge-csr-we-support)
    Write-Log "Converting the certificate to base64..."
    $certFileBase64 = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertificateName.b64"
    $process = Start-Process -FilePath "certutil.exe" -ArgumentList "-encode", $certFile, $certFileBase64 -NoNewWindow -Wait -PassThru
    Remove-Item -Path $certFile -Force -ErrorAction SilentlyContinue
    if ($process.ExitCode -ne 0) {
        Write-Log "certutil.exe failed with exit code $($process.ExitCode)" -Level "Error"
        return
    }
    $Progress++

    # import the certificate into the key vault
    Write-Log "Importing the certificate $CertificateName into the key vault $VaultName..."
    try {
        $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -FilePath $certFileBase64 
    }
    catch {
        Write-Log "Error importing certificate into the key vault: $_" -Level "Error"
        return
    }
    finally {
        Remove-Item -Path $certFileBase64 -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Certificate imported into the key vault."
    $Progress++

    # if required, download the certificate to a local file in the pfx folder
    if ($null -ne $pfxFolder) {

        # get the password for the PFX file from the key vault
        Write-Log "Retrieving the certificate password from Key Vault..."
        try {
            $CertPassword = (Get-AzKeyVaultSecret -VaultName $VaultName -Name "CertPassword").SecretValueText
        }
        catch {
            Write-Log "Failed to retrieve certificate password from Key Vault: $_" -Level "Error"
            return
        }
        $Progress++

        # create the folder if it does not exist
        if (-not (Test-Path -Path $pfxFolder)) {
            Write-Log "Creating the PFX folder: $pfxFolder"
            New-Item -Path $pfxFolder -ItemType Directory -Force | Out-Null
        }
        Write-Log "PFX folder verified: $pfxFolder"
        $Progress++

        # download the certificate to a local file in the pfx folder
        $pfxFile = Join-Path -Path $pfxFolder -ChildPath "$($CertificateName).pfx"
        Write-Log "Exporting the $CertificateName certificate to PFX file: $pfxFile"
        try {
            $CertBase64 = Get-AzKeyVaultSecret -VaultName $vaultName -Name $CertificateName -AsPlainText
            $CertBytes = [Convert]::FromBase64String($CertBase64)
            $x509Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($certBytes, $null, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            $pfxFileByte = $x509Cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPassword)
            [IO.File]::WriteAllBytes($pfxFile, $pfxFileByte)
        }
        catch {
            Write-Log "Error exporting certificate to PFX: $_" -Level "Error"
            return
        }
        Write-Log "Certificate exported to PFX file: $pfxFile"
        $Progress++
    }
}

################
# MAIN - 00-19 #
################

# see if Az module is installed
Write-Log "Checking if Az module is installed..."
if (-not (Get-InstalledModule -Name Az)) {
    Write-Log "Az module not installed!" -Level "Error"
    return
}
$Progress++

# Connect to azure

# Ensures you do not inherit an AzContext, since we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
Write-Log "Connecting to Azure using default identity..."
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    Write-Log "There is no system-assigned user identity." -Level "Error"
    return
}
$Progress++

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection

# get a token for the ingestion endpoint
Write-Log "Getting token for ingestion endpoint..."
$secureToken = (Get-AzAccessToken -ResourceUrl "https://monitor.azure.com//.default"-AsSecureString ).Token
$LAToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))
$Progress++

# Check if the script is running on Azure or on hybrid worker
Write-Log "Script started, checking worker..."
$envVars = Get-ChildItem env:
$HybridWorker = ($envVars | Where-Object { $_.name -like 'Fabric_*' } ).count -eq 0
if (-not $HybridWorker) {
    Write-Log "This workbook must be executed by a hybrid worker!" -Level "Error"
    return
}
$worker = $env:COMPUTERNAME
Write-Log "Running on $worker"
$Progress++

# see if PSPKI module is installed
Write-Log "Check if PSPKI module is installed..."
if (-not (Get-InstalledModule -Name PSPKI)) {
    Write-Log "PSPKI module not installed!" -Level "Error"
    return
}
import-module PSPKI
$Progress++

# get CA details
Write-Log "Getting the CA details for $CAServer..."
$ca = Get-CertificationAuthority -ComputerName $CAServer
if ($null -eq $ca) {
    Write-Log "Error getting CA details: $CAServer not found" -Level "Error"
    return
}
$Progress++

# Parse the webhook data
Write-Log "Parsing webhook data..."
if (($null -eq $WebhookData) -or ($null -eq $WebhookData.RequestBody)) {
    Write-Log "Webhook data missing! Ensure the runbook is called from a webhook!" -Level "Error"
    return
}
try {
    $requestBody = ConvertFrom-Json -InputObject $WebhookData.RequestBody
}
catch {
    Write-Log "Failed to parse WebhookData.RequestBody as JSON. Error: $_" -Level "Error"
    return
}
$Progress++

$CertLCVersion = $requestBody.CertLCVersion
$Action = $requestBody.Action
$VaultName = $requestBody.VaultName
$CertificateName = $requestBody.CertificateName
$CertificateTemplate = $requestBody.CertificateTemplate
$CertificateSubject = $requestBody.CertificateSubject
$CertificateDNSNames = $requestBody.CertificateDNSNames

if ($null -eq $CertLCVersion) {
    Write-Log "CertLCVersion is missing: assuming this is an automatic renewal request triggered by Event Grid"
    $Action = "autorenew"

    # write all the static and parsed parameters to the log
    Write-Log "Action: $Action"
    Write-Log "VaultName: will get from the queue message"
    Write-Log "CertificateName: will get from the queue message"    
}
else {
    if ($CertLCVersion -ne $Version) {
        Write-Log "CertLCVersion $CertLCVersion does not match the script version $Version!" -Level "Error"
        return
    }
    if ([string]::IsNullOrWhiteSpace($Action)) {
        Write-Log "Missing or empty mandatory parameter: 'Action'" -Level "Error"
        return
    }
    $Action = $Action.ToLower()
    if ($Action -ne "new" -and $Action -ne "renew") {
        Write-Log "Invalid value for 'Action': $Action. Must be 'New' or 'Renew'!" -Level "Error"
        return
    }
    if ([string]::IsNullOrWhiteSpace($VaultName)) {
        Write-Log "Missing or empty mandatory parameter: 'VaultName'" -Level "Error"
        return
    }
    if ([string]::IsNullOrWhiteSpace($CertificateName)) {
        Write-Log "Missing or empty mandatory parameter: 'CertificateName'" -Level "Error"
        return
    }

    # check if there is a deleted certificate with the same name in the key vault
    Write-Log "Checking if there is a deleted certificate with the same name in the key vault..."
    try {
        $deletedCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -InRemovedState
        if (($null -ne $deletedCert) -and ($null -ne $deletedCert.DeletedDate)) {
            Write-Log "Certificate $CertificateName is already in the key vault and in deleted state since $($deletedCert.DeletedDate). It must be purged before creating a new one; otherwise specify a different certificate name." -Level "Error"
            return
        }  
    }
    catch {
        Write-Log "Error checking for deleted certificate: $_" -Level "Error"
        return
    }

    # the following parameters are only required for new certificates
    if ($Action -eq "new") {
        if ([string]::IsNullOrWhiteSpace($CertificateTemplate)) {
            Write-Log "Missing or empty mandatory parameter: 'CertificateTemplate'" -Level "Error"
            return
        }

        # check if the template exists in AD
        Write-Log "Checking if the template $CertificateTemplate exists in AD..."
        $tmpl = Get-CertificateTemplate -Name $CertificateTemplate -ErrorAction SilentlyContinue
        if ($null -eq $tmpl) {
            Write-Log "Template $($CertificateTemplate) not found in AD! Check its name." -Level "Error"
            return
        }
        $Progress++

        if ([string]::IsNullOrWhiteSpace($CertificateSubject)) {
            Write-Log "Missing or empty mandatory parameter: 'CertificateSubject'" -Level "Error"
            return
        }
        if ($CertificateDnsNames -and $CertificateDNSNames -isnot [array]) {
            Write-Log "'CertificateDNSNames' parameter is not an array!" -Level "Error"
            return
        }
    }

    # write the parsed parameters to the log
    Write-Log "CertLCVersion: $CertLCVersion"
    Write-Log "Action: $Action"
    Write-Log "VaultName: $VaultName"
    Write-Log "CertificateName: $CertificateName"
    if ($null -ne $CertificateTemplate) {
        Write-Log "CertificateTemplate: $CertificateTemplate"
    }
    else {
        Write-Log "CertificateTemplate: N/A"
    }
    if ($null -ne $CertificateSubject) {
        Write-Log "CertificateSubject: $CertificateSubject"
    }
    else {
        Write-Log "CertificateSubject: N/A"
    }
    if ($null -ne $CertificateDNSNames) {
        Write-Log "CertificateDNSNames: $($CertificateDNSNames -join ', ')"
    }
    else {
        Write-Log "CertificateDNSNames: N/A"
    }
}

Write-Log "Runbook parameters parsed successfully."

##########################
# MAIN - 20+ (AUTORENEW) #
##########################

if ($Action -eq "autorenew") {

    $Progress = 20
    Write-Log "Starting autorenewal process..."

    Write-Log "Creating context to work with storage account..."
    $ctx = New-AzStorageContext -StorageAccountName $QueueStorageAccountName -UseConnectedAccount
    $Progress++

    # check the queue for messages for a maximum of $queueAttempts times
    try {
        for ($i = 0; $i -lt $queueAttempts; $i++) {
            Write-Log "Checking the queue (attempt $($i+1) of $queueAttempts)..."
            $queue = Get-AzStorageQueue -Name $queueName -Context $ctx
            Write-Log ("Queued messages " + $queue.ApproximateMessageCount)
    
            if ($queue.ApproximateMessageCount -gt 0) {
                break
            }
            else {
                Write-Log "Queue is empty: going to sleep for $queueWait seconds before checking again..." -Level "Warning"
                Start-Sleep -Seconds $queueWait
            }
        }
        if ($i -eq $queueAttempts) {
            Write-Log "No messages in the queue after $queueAttempts attempts. Exiting." -Level "Error"
            return
        }        
    }
    catch {
        Write-Log "Error getting the queue: $_" -Level "Error"
        return
    }
    $Progress++

    # process the messages in the queue
    for ($i = 1; $i -le $queue.ApproximateMessageCount; $i++ ) {
        Write-Log "Processing message $i of $($queue.ApproximateMessageCount)..."

        # get the message from the queue    
        try {
            $queueMessage = $queue.QueueClient.ReceiveMessage($queueInvisibilityTimeout)
            if ($null -eq $queueMessage.Value) {
                Write-Log "No message value found, skipping." -Level "Warning"
                continue
            }            
        }
        catch {
            Write-Log "Error getting message from the queue: $_" -Level "Error"
            return
        }
        $Progress++

        # decode body of the message from base64
        $messageText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($queueMessage.value.MessageText))   
        Write-Log "JSON Message fetched from the queue: $($messageText)"

        # parse the message
        try {
            $message = ConvertFrom-Json -InputObject $messageText
        }
        catch {
            Write-Log "Failed to parse message body as JSON. Error: $_" -Level "Error"
            return
        }
        $Progress++

        $VaultName = $message.data.VaultName
        $CertificateName = $message.data.ObjectName

        # before processing the request, we need to obtain the other certificate details, such as template, subject, and DNS names
        Write-Log "Getting remaining certificate details from the key vault..."

        Write-Log "Getting certificate details for $CertificateName from vault $VaultName..."
        $cert = $null
        try {
            $cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $CertificateName
        }
        catch {
            Write-Log "Error getting certificate details for $CertificateName from vault: $_" -Level "Error"
            return
        }
        if ($null -eq $cert) {
            Write-Log "Cannot get certificate details for $CertificateName from vault: empty response! It is possible that the certificate was deleted before the renewal process started. This request will be ignored and removed from the queue" -Level "Warning"
        }

        else {
            Write-Log "Certificate $CertificateName found in vault $VaultName."
            $Progress++
        
            $CertificateSubject = $cert.Certificate.Subject
            Write-Log "Certificate Subject: $SubjectName"

            # get the DNS names from the certificate
            $CertificateDnsNames = $null
            $san = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            if ($null -ne $san) {
                # $DNS.Format(0) returns a string like: DNS Name=server01.contoso.com, DNS Name=server01.litware.com.
                # Transform it into an array of DNS names using regex; remove the "DNS Name=" prefix and split by comma
                $CertificateDnsNames = ($san.Format(0) -replace 'DNS Name=', '').Split(',').Trim() | Where-Object { $_ -ne "" }
                Write-Log "Certificate DNS Names: $($CertificateDnsNames -join ', ')"
            }
            else {
                Write-Log "Certificate DNS Names: N/A"
            }
            $Progress++

            # get the OID of the Certificate Template
            $oid = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Certificate Template Information" }
            if ($null -eq $oid) {
                Write-Log "Error getting OID from certificate: Certificate Template Information not found" -Level "Error"
                return
            }
            # convert in a string like:
            # Template=Flab-ShortWebServer(1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736), Major Version Number=100, Minor Version Number=5
            $oid = $oid.Format(0)

            # extract the template name and the ASN.1 values using regex
            $CertificateTemplate = $oid -replace '.*Template=(.*)\(.*\).*', '$1'
            $CertificateTemplateASN = $oid -replace '.*\((.*)\).*', '$1'
            Write-Log "Certificate Template: $CertificateTemplate ($CertificateTemplateASN)"
            $Progress++

            # Now we have all the details to create the new certificate request.
            # We can use the same code as for new certificates
            New-CertificateRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplate $CertificateTemplate -CertificateSubject $CertificateSubject -CertificateDNSNames $CertificateDnsNames -CAServer $CAServer -PfxFolder $PFXFolder 
        }

        # delete the message from the queue
        Write-Log "Deleting message from the queue..."
        try {
            $queue.QueueClient.DeleteMessage($queueMessage.value.MessageId, $queueMessage.value.PopReceipt) | Out-Null        
        }
        catch {
            Write-Log "Error deleting message from the queue: $_" -Level "Error"
            return
        }
    }
}

#####################
# MAIN - 40+ (REEW) #
#####################

elseif ($Action -eq "renew" ) {

    $Progress = 40
    Write-Log "Starting the '$Action' process..."

    # before processing the request, we need to obtain the other certificate details, such as template, subject, and DNS names
    Write-Log "Getting remaining certificate details from the key vault..."

    Write-Log "Getting certificate $CertificateName from vault $VaultName..."
    $cert = $null
    try {
        $cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $CertificateName
    }
    catch {
        Write-Log "Error getting certificate from vault: $_" -Level "Error"
        return
    }
    if ($null -eq $cert) {
        Write-Log "Error getting certificate $CertificateName from vault: empty response! It is possible that the certificate was deleted before the renewal process started." -Level "Error"
        return
    }
    $Progress++
        
    $CertificateSubject = $cert.Certificate.Subject
    Write-Log "Certificate Subject: $SubjectName"

    # get the DNS names from the certificate
    $CertificateDnsNames = $null
    $san = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
    if ($null -ne $san) {
        # $DNS.Format(0) returns a string like: DNS Name=server01.contoso.com, DNS Name=server01.litware.com.
        # Transform it into an array of DNS names using regex; remove the "DNS Name=" prefix and split by comma
        $CertificateDnsNames = ($san.Format(0) -replace 'DNS Name=', '').Split(',').Trim() | Where-Object { $_ -ne "" }
        Write-Log "Certificate DNS Names: $($CertificateDnsNames -join ', ')"
    }
    else {
        Write-Log "Certificate DNS Names: N/A"
    }
    $Progress++

    # get the OID of the Certificate Template
    $oid = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Certificate Template Information" }
    if ($null -eq $oid) {
        Write-Log "Error getting OID from certificate: Certificate Template Information not found" -Level "Error"
        return
    }
    # convert in a string like:
    # Template=Flab-ShortWebServer(1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736), Major Version Number=100, Minor Version Number=5
    $oid = $oid.Format(0)

    # extract the template name and the ASN.1 values using regex
    $CertificateTemplate = $oid -replace '.*Template=(.*)\(.*\).*', '$1'
    $CertificateTemplateASN = $oid -replace '.*\((.*)\).*', '$1'
    Write-Log "Certificate Template: $CertificateTemplate ($CertificateTemplateASN)"
    $Progress++

    New-CertificateRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplate $CertificateTemplate -CertificateSubject $CertificateSubject -CertificateDNSNames $CertificateDnsNames -CAServer $CAServer -PfxFolder $PFXFolder 
}

####################
# MAIN - 60+ (new) #
####################

else {

    $Progress = 60
    Write-Log "Starting the '$Action' process..."

    # check if a certificate with the same name already exists in the key vault
    Write-Log "Checking if a certificate with the same name already exists in the key vault..."
    try {
        $cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $CertificateName
        if ($null -ne $cert) {
            Write-Log "Certificate $CertificateName already exists in the key vault. Please use a different name or use the Renew action to create a new version." -Level "Error"
            return
        }
    }
    catch {
        Write-Log "Error checking for existing certificate: $_" -Level "Error"
        return
    }
    $Progress++

    # we already have all the parameters from the webhook body, so we can create the new certificate request
    New-CertificateRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplate $CertificateTemplate -CertificateSubject $CertificateSubject -CertificateDNSNames $CertificateDNSNames -CAServer $CAServer -PfxFolder $PFXFolder
}

##############
# MAIN - end #
##############

$Progress = 100
Write-Log "Runbook completed successfully."

