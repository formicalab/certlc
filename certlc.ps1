#Requires -PSEdition Core
using module Az.Accounts
using module Az.KeyVault
using module Az.Storage
using module Az.Resources

##########
# CERTLC #
##########

# CERTLC is a PowerShell runbook that automates the process of obtaining or renewing certificates from an AD CA, integrated with Azure Key Vault.
# The key vault is used to generate all requests, storing the private keys safely.

# The script is designed to be run using PowerShell 7.x in an Azure Automation hybrid worker environment.
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

# Note: using Powershell 7.x, the WebhookData is passed not as a structure but as a string with a wrongly formatted JSON.
# See the code in Main section for details and workaround.

# We assume to use the followng JSON structure for the RequestBody:

# for NEW CERTIFICATES:
# {
#   "CertLCVersion": "1.0",                     # version tag
#   "Action": "New"                             # action to perform
#   "VaultName": "string"                       # key vault name
#   "CertificateName": "string",                # name of the certificate to create or renew
#   "CertificateTemplate": "string",            # name of the certificate template to use
#   "CertificateSubject": "string",             # subject of the certificate to create or renew
#   "CertificateDnsNames": array of strings     # optional, certificate DNS names
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

# Prohibits references to uninitialized variables
Set-StrictMode -Version 1.0

###################
# STATIC SETTINGS #
###################

$Version = "1.0"                        # version of the script - must match the version in the webhook body

$LAEnabled = $true                                                                                  # enable Log Analytics ingestion
$LAIngestionUrl = "https://dce-certlc-shared-itn-001-luwu.italynorth-1.ingest.monitor.azure.com"    # Log Analytics Ingestion: ingestion URL
$LADCRImmutableId = "dcr-748535390f2943c683e85e12dbda98a1"                                          # Log Analytics Ingestion: Data Collection Rule (DCR) immutable ID
$LATable = "certlc_CL"                                                                              # Log Analytics Ingestion: custom table name (must include also the _CL suffix)

$AutomationAccountName = "aa-shared-neu-001"        # automation account used to run the script and to store the variables
$AutomationAccountRG = "rg-shared-neu-001"          # resource group of the automation account

$QueueStorageAccount = "flazstsharedneu001"         # name of the storage account where the queue is located
$QueueName = "certlc"                               # name of the queue to use for autorenewals
$QueueAttempts = 10                                 # number of attempts to check the queue
$QueueWait = 5                                      # seconds to wait between attempts
$QueueInvisibilityTimeout = [System.TimeSpan]::FromSeconds(30) # seconds to wait for the message to be invisible in the queue when it is being processed

$CA = "flazdc03.formicalab.casa\SubCA"  # Issuing CA server (must be in the form <servername>\<CAname>)
$PfxFolder = "C:\Temp"                  # folder where the PFX file will be downloaded
$CertPswSecretName = "CertPassword"     # name of the secret in the key vault that contains the password for the PFX file

# TODO: where possible, use automation variables instead (see renewcertviakv.ps1). Sample usage:
#$QueueStorageAccount = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-storageaccount").Value
#$QueueName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-queue").Value
#$CA = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-ca").Value

####################
# GLOBAL VARIABLES #
####################

$LAToken = $null                                # token using to send logs to Log Analytics
$CorrelationId = [guid]::NewGuid().ToString()   # correlation ID for the log entry

#########################
# FUNCTIONS - Write-Log #
#########################

# Write-Log: send log to Log Analytics workspace (if token is available) and to output
function Write-Log {
    param (
        [Parameter()]
        [string]$Message,
        [Parameter()]
        [string]$Level = "Information"
    )

    # send log to Log Analytics workspace (if token is available and output to LA is enabled)
    if ($LAEnabled -and ($null -ne $LAToken)) {
        $log_entry = @{
            TimeGenerated = (Get-Date).ToUniversalTime()
            CorrelationId = $CorrelationId
            Status        = $Level
            Message       = $Message
        }
        $body = $log_entry | ConvertTo-Json -AsArray
        $headers = @{"Authorization" = "Bearer $LAToken"; "Content-Type" = "application/json" };
        $uri = "$LAIngestionUrl/dataCollectionRules/$LADCRImmutableId/streams/Custom-$LATable" + "?api-version=2023-01-01";
        Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers | Out-Null
    }

    # write to output
    switch ($Level) {
        "Error" {
            Write-Output "$(get-date): $($Level): $Message"
        }
        "Warning" {
            Write-Warning "$(get-date): $($Level): $Message"
        }
        default {
            Write-Output "$(get-date): $($Level): $Message"
        }
    }
}

#############################################
# FUNCTIONS - New-CertificateRenewalRequest #
#############################################

function New-CertificateRenewalRequest {
    param (

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CA,

        [Parameter(Mandatory = $false)]
        [string]$PfxFolder,

        [Parameter(Mandatory = $false)]
        [string]$CertPswSecretName
    )

    # before processing the request, we need to obtain the other certificate details, such as template, subject, and DNS names
    Write-Log "Getting certificate details for $CertificateName from key vault $VaultName..."
    $cert = $null
    try {
        $cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
    }
    catch {
        throw "Error getting certificate details for $CertificateName from vault: $_"
    }

    if ($null -eq $cert) {
        throw "Error getting certificate details for $CertificateName from vault: empty response! It is possible that the certificate was deleted before the renewal process started."
    }

    # get the certificate subject
    $CertificateSubject = $cert.Certificate.Subject

    # get the DNS names from the certificate
    $CertificateDnsNames = $null
    $san = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
    if ($null -ne $san) {
        # $DNS.Format(0) returns a string like: DNS Name=server01.contoso.com, DNS Name=server01.litware.com.
        # Transform it into an array of DNS names using regex; remove the "DNS Name=" prefix and split by comma
        $CertificateDnsNames = ($san.Format(0) -replace 'DNS Name=', '').Split(',').Trim() | Where-Object { $_ -ne "" }
    }
        
    # get the OID of the Certificate Template
    $oid = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Certificate Template Information" }
    if ($null -eq $oid) {
        throw "Error getting OID from certificate: Certificate Template Information not found"
    }
    # convert in a string like:
    # Template=Flab-ShortWebServer(1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736), Major Version Number=100, Minor Version Number=5
    $oid = $oid.Format(0)
    
    # extract the template name and the ASN.1 values using regex
    $CertificateTemplate = $oid -replace '.*Template=(.*)\(.*\).*', '$1'
    $CertificateTemplateASN = $oid -replace '.*\((.*)\).*', '$1'

    Write-Log "Certificate $CertificateName found in vault $($VaultName): Subject: $CertificateSubject, Template: $CertificateTemplate ($CertificateTemplateASN)"
    if ($null -eq $CertificateDnsNames) {
        Write-Log "Certificate DNS Names: N/A"
    }
    else {
        Write-Log "Certificate DNS Names: $($CertificateDnsNames -join ', ')"
    }
    
    # Now we have all the details to create the new certificate request.
    # We can use the same code as for new certificates
    
    try {
        New-CertificateRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplate $CertificateTemplate -CertificateSubject $CertificateSubject -CertificateDnsNames $CertificateDnsNames -CA $CA -PfxFolder $PfxFolder -CertPswSecretName $CertPswSecretName            
    }
    catch {
        throw "Error creating certificate request: $_"
    }   
}

######################################
# FUNCTIONS - New-CertificateRequest #
######################################

# New-CertificateRequest: create a new certificate request

function New-CertificateRequest {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateTemplate,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateSubject,

        [Parameter(Mandatory = $false)]
        [string[]]$CertificateDnsNames,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CA,

        [Parameter(Mandatory = $false)]
        [string]$PfxFolder,

        [Parameter(Mandatory = $false)]
        [string]$CertPswSecretName

    )

    # check if the template exists in AD
    Write-Log "Checking if the template $CertificateTemplate exists in AD..."
    $tmpl = Get-CertificateTemplate -Name $CertificateTemplate -ErrorAction SilentlyContinue
    if ($null -eq $tmpl) {
        throw "Template $($CertificateTemplate) not found in AD! Check its name."
    }
    
    # check if there is a deleted certificate with the same name in the key vault
    Write-Log "Checking if there is a deleted certificate with the same name in the key vault..."
    try {
        $deletedCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -InRemovedState
    }
    catch {
        throw "Error checking for deleted certificate: $_"
    }  
    if (($null -ne $deletedCert) -and ($null -ne $deletedCert.DeletedDate)) {
        throw "Certificate $CertificateName is already in the key vault and in deleted state since $($deletedCert.DeletedDate). It must be purged before creating a new one; otherwise specify a different certificate name."
    }  

    # create certificate - if a previous request is in progress, reuse it
    $csr = $null
    try {
        $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertificateName | Where-Object { $_.Status -eq "inProgress" }
        if ($null -ne $op) {
            Write-Log "Certificate request is already in progress for this certificate: $CertificateName; reusing the existing request." -Level "Warning"
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
        throw "Error generating CSR in Key Vault: $_"
    }
    
    # see https://www.sysadmins.lv/blog-en/introducing-to-certificate-enrollment-apis-part-3-certificate-request-submission-and-response-installation.aspx
    
    # CR_IN_BASE64HEADER = 0x0,
    # CR_IN_BASE64 = 0x1,
    # CR_IN_BINARY = 0x2,
    # CR_IN_ENCODEANY = 0xff,
    # CR_OUT_BASE64HEADER = 0x0,
    # CR_OUT_BASE64 = 0x1,
    # CR_OUT_BINARY = 0x2

    Write-Log "Sending request to the CA..."
    try {
        $CertRequest = New-Object -ComObject CertificateAuthority.Request
        $CertRequestStatus = $CertRequest.Submit(0x1, $csr, "CertificateTemplate:$($CertificateTemplate)", $CA)
        
        # status is described in https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/c084a3e3-4df3-4a28-9a3b-6b08487b04f3?redirectedfrom=MSDN

        switch ($CertRequestStatus) {
            2 {
                throw "Request was denied. Check the CA for details."
            }
            3 {
                Write-Log "Certificate Request submitted successfully."
                # https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-getcertificate?redirectedfrom=MSDN
                # 0 = CR_OUT_BASE64HEADER (BASE64 format with begin/end header - this is how the key vault expects the certificate in order to perform a merge)
                $CertEncoded = $CertRequest.GetCertificate(0x0)   
                Write-Log "Certificate received from CA."
            }
            5 {
                throw "Request is pending. This is not expected since this runbook can only process completed requests. Review the certiicate template and CA configuration to ensure that certificates are immediately issued."
            }
            Default {
                throw "Request failed with status $($CertRequestStatus). Check codes in https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/c084a3e3-4df3-4a28-9a3b-6b08487b04f3?redirectedfrom=MSDN"
            }
        }

    }
    catch {
        throw "Error submitting request to the CA: $_"
    }

    # we need to save the certificate in a temporary file because the Import-AzKeyVaultCertificate cmdlet does not accept a base64 string as input
    $CertEncodedFile = New-TemporaryFile
    Set-Content -Path $CertEncodedFile -Value $CertEncoded

    # import the certificate into the key vault
    Write-Log "Importing the certificate $CertificateName into the key vault $VaultName..."
    try {
        $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -FilePath $CertEncodedFile
        if ($null -eq $newCert) {
            throw "Error importing certificate into the key vault: Import-AzKeyVaultCertificate returned null!"
        }
    }
    catch {
        throw "Error importing certificate into the key vault: $_"
    }
    finally {
        Remove-Item -Path $CertEncodedFile -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Certificate imported into the key vault."
    
    # if required, download the certificate to a local file in the pfx folder
    if ($null -ne $PfxFolder) {

        # create the folder if it does not exist
        if (-not (Test-Path -Path $PfxFolder)) {
            Write-Log "Creating the PFX folder: $PfxFolder"
            New-Item -Path $PfxFolder -ItemType Directory -Force | Out-Null
        }
        $pfxFile = Join-Path -Path $PfxFolder -ChildPath "$($CertificateName).pfx"
        Write-Log "PFX folder verified: $PfxFolder"
        
        # get the password for the PFX file from the key vault
        Write-Log "Retrieving the certificate password from Key Vault $VaultName, secret $($CertPswSecretName)..."
        try {
            $SecCertPassword = (Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertPswSecretName).SecretValue
        }
        catch {
            throw "Failed to retrieve certificate password from secret $CertPswSecretName in Key Vault $($VaultName): $_"
        }
        
        # download the certificate to a local file in the pfx folder
        Write-Log "Exporting the $CertificateName certificate to PFX file: $pfxFile"
        try {
            $CertBase64 = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertificateName -AsPlainText
            $CertBytes = [Convert]::FromBase64String($CertBase64)
            $x509Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($certBytes, $null, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

            # get clear text password from the secure string and clear it as soon as possible
            $CertPassword = ConvertFrom-SecureString -SecureString $SecCertPassword -AsPlainText

            # export the certificate to a PFX file
            $pfxFileByte = $x509Cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPassword)
            [IO.File]::WriteAllBytes($pfxFile, $pfxFileByte)
        }
        catch {
            throw "Error exporting certificate to PFX: $_"
        }
        finally {
            $CertPassword = $null
            $CertBase64 = $null
            $pfxFileByte = $null
            $x509Cert = $null
            $SecCertPassword = $null
        }
        Write-Log "Certificate exported to PFX file: $pfxFile"
    }
}

#################################
# MAIN - modules and parameters #
#################################

# Connect to Azure. Ensures we do not inherit an AzContext, since we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
Write-Log "Connecting to Azure using default identity..."
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    $msg = "There is no system-assigned user identity."
    Write-Log $msg -Level "Error"
    throw $msg
}

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection

# get a token for the ingestion endpoint if Log Analytics ingestion is enabled
if ($LAEnabled) {
    Write-Log "Getting token for ingestion endpoint..."
    $secureToken = (Get-AzAccessToken -ResourceUrl "https://monitor.azure.com//.default"-AsSecureString ).Token
    $LAToken = ConvertFrom-SecureString -SecureString $secureToken -AsPlainText
    $secureToken = $null
}

# Check if the script is running on Azure or on hybrid worker
$envVars = Get-ChildItem env:
$HybridWorker = ($envVars | Where-Object { $_.name -like 'Fabric_*' } ).count -eq 0
if (-not $HybridWorker) {
    $msg = "This workbook must be executed by a hybrid worker!"
    Write-Log $msg -Level "Error"
    throw $msg
}
Write-Log "Runbook running on hybrid worker $($env:COMPUTERNAME)."

# Parse the webhook data
# We have different cases:
# - WebhookData is null or empty: the runbook is not called from a webhook but it was started manually. In this case we assume action is 'autorenew', so that we can check if there are requests pending in the queue
# - WebhookData is not null or empty: the runbook is called from a webhook. We need to parse the request body and extract the parameters.

if ([string]::IsNullOrEmpty($WebhookData)) {
    Write-Log "WebhookData missing or empty! Assuming autorenew action and checking the queue for messages..."
    $Action = "autorenew"
}

else
{
    # using Powershell 7.x, the WebhookData is passed not as a structure but as a string with a wrongly formatted JSON...
    # (see https://learn.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal#create-a-webhook)
    # such as: 
    # {WebhookName:certlc,RequestBody:{"CertLCVersion":"1.0","Action":"renew","VaultName":"<vaultname>","CertificateName":"<certificatename>"},RequestHeader:{Accept-Encoding:gzip,Host:<webhook uri>,User-Agent:Mozilla/5.0,x-ms-request-id:<guid>}}
    #
    # The problem is that WebhookName, RequestBody and RequestHeader are not enclosed in double quotes.
    # We try to extract the RequestBody via regex and convert it from JSON to object.
    # The following regex matches these cases:
    # - RequestBody is enclosed in double quotes (valid case):   "RequestBody":"{...}"
    # - RequestBody is not enclosed in double quotes (invalid case):   RequestBody:{...}
    # - After RequestBody there is an array:  RequestBody:[{...}] or "RequestBody":[{...},{...}]

    if ($WebhookData -match '\"?RequestBody\"?\s*:\s*(\{.*?\}|\[.*?\])') {
        $jsonRequestBody = $matches[1]
    }
    else {
        $msg = "WebhookData.RequestBody not found! WebhookData structure received is: $($WebhookData)"
        Write-Log $msg -Level "Error"
        throw $msg
    }

    # we now have a RequestBody, convert from JSON to object
    try {
        $requestBody = ConvertFrom-Json -InputObject $jsonRequestBody
    }
    catch {
        $msg = "Failed to parse WebhookData.RequestBody as JSON. WebhookData structure received is: $($WebhookData). Error: $_"
        Write-Log $msg -Level "Error"
        throw $msg
    }
    if ([string]::IsNullOrEmpty($requestBody)) {
        $msg = "WebhookData.RequestBody is empty! Ensure the runbook is called from a webhook! WebhookData structure received is: $($WebhookData)"
        Write-Log $msg -Level "Error"
        throw $msg
    }

    # in case the request arrives from Event Grid, the body has a structure like this:
    # [{"id":"1af41fa2-54b2-4b03-ba46-f5088ba709c7","topic":"/subscriptions/<guid>/resourceGroups/<rgname>/providers/Microsoft.KeyVault/vaults/<vaultname>","subject":"<certificatename>","eventType":"Microsoft.KeyVault.CertificateNearExpiry","data":{"Id":"https://<vaultname>.vault.azure.net/certificates/<certificatename>/<versionid>","VaultName":"<vaultname>","ObjectType":"Certificate","ObjectName":"<certificatename>","Version":"<versionid>","NBF":1745695048,"EXP":1745702248},"dataVersion":"1","metadataVersion":"1","eventTime":"2025-04-26T19:29:34.4197223Z"}]
    if ($requestBody.eventType -eq "Microsoft.KeyVault.CertificateNearExpiry") {

        # if we have an eventType field with a value of Microsoft.KeyVault.CertificateNearExpiry, we need to extract the VaultName and ObjectName from the data field
        # and set the Action to autorenew. The CertLCVersion is not present in this case.

        $Action = "autorenew"
        $VaultName = $requestBody.data.VaultName            # we preset this, but it will be overwritten by the queue message since we need to process the queue in any case
        $CertificateName = $requestBody.data.ObjectName     # we preset this, but it will be overwritten by the queue message since we need to process the queue in any case
        Write-Log "WebhookData is an Event Grid event. Setting Action to 'autorenew' for certificate $($CertificateName) in vault $($VaultName)..."
    }
    else {

        # otherwise, it is a new or renew request invoked explicitly from the webhook. We need to extract the parameters from the request body.

        $CertLCVersion = $requestBody.CertLCVersion
        $Action = $requestBody.Action
        $VaultName = $requestBody.VaultName
        $CertificateName = $requestBody.CertificateName
        $CertificateTemplate = $requestBody.CertificateTemplate
        $CertificateSubject = $requestBody.CertificateSubject
        $CertificateDnsNames = $requestBody.CertificateDnsNames

        # check version
        if ($CertLCVersion -ne $Version) {
            $msg = "CertLCVersion $CertLCVersion does not match the script version $Version!"
            Write-Log $msg -Level "Error"
            throw $msg
        }
        else {
            Write-Log "CertLCVersion: $CertLCVersion"
        }

        if ([string]::IsNullOrEmpty($Action)) {
            $msg = "Missing or empty mandatory parameter: 'Action'"
            Write-Log $msg -Level "Error"
            throw $msg
        }
        $Action = $Action.ToLower()
        if ($Action -ne "new" -and $Action -ne "renew") {
            $msg = "Invalid value for 'Action': $Action. Must be 'New' or 'Renew'!"
            Write-Log $msg -Level "Error"
            throw $msg
        }

        # check mandatory parameters for both new and renew requests
        if ([string]::IsNullOrEmpty($VaultName)) {
            $msg = "Missing or empty mandatory parameter: 'VaultName'"
            Write-Log $msg -Level "Error"
            throw $msg
        }
        if ([string]::IsNullOrEmpty($CertificateName)) {
            $msg = "Missing or empty mandatory parameter: 'CertificateName'"
            Write-Log $msg -Level "Error"
            throw $msg
        }
    }
}

####################
# MAIN - AUTORENEW #
####################

if ($Action -eq "autorenew") {

    try {
        $ctx = New-AzStorageContext -StorageAccountName $QueueStorageAccount -UseConnectedAccount        
    }
    catch {
        $msg = "Error creating a context to work with storage account $($QueueStorageAccount): $_"
        Write-Log $msg -Level "Error"
        throw $msg
    }
    
    # wait until the queue has messages for a maximum of $QueueAttempts
    Write-Log "Performing autorenew: waiting for messages in the queue $QueueName..."
    try {
        for ($i = 0; $i -lt $QueueAttempts; $i++) {
            Write-Log "Checking the queue (attempt $($i+1) of $QueueAttempts)..."
            $queue = Get-AzStorageQueue -Name $QueueName -Context $ctx
            Write-Log ("Queued messages: " + $queue.ApproximateMessageCount)
    
            if ($queue.ApproximateMessageCount -gt 0) {
                break
            }
            else {
                Write-Log "Queue is empty: going to sleep for $QueueWait seconds before checking again..." -Level "Warning"
                Start-Sleep -Seconds $QueueWait
            }
        }
        if ($i -eq $QueueAttempts) {
            $msg = "No messages in the queue after $QueueAttempts attempts. Exiting."
            Write-Log $msg -Level "Error"
            throw $msg
        }        
    }
    catch {
        $msg = "Error getting the queue: $_"
        Write-Log $msg -Level "Error"
        throw $msg
    }
    
    # process the messages in the queue
    while ($queueMessage = $queue.QueueClient.ReceiveMessage($QueueInvisibilityTimeout)) {

        if (-not $queueMessage.Value) {
            Write-Log "No more messages in the queue. Exiting."
            break
        }
    
        try {
            # decode body of the message from base64 and parse the message
            $messageText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($queueMessage.value.MessageText))   
            $message = ConvertFrom-Json -InputObject $messageText
        
            $VaultName = $message.data.VaultName
            $CertificateName = $message.data.ObjectName
            
            New-CertificateRenewalRequest -VaultName $VaultName -CertificateName $CertificateName -CA $CA -PfxFolder $PfxFolder -CertPswSecretName $CertPswSecretName
        }
        catch {
            Write-Log "Error processing message: $_" -Level "Warning"
            continue    # continue to the next message in the queue
        }
        finally {
            # Make sure the message is deleted from the queue even if there is an error
            # If the message is not deleted, it will be visible again after the invisibility timeout
            Write-Log "Deleting message from the queue..."
            $queue.QueueClient.DeleteMessage($queueMessage.Value.MessageId, $queueMessage.Value.PopReceipt) | Out-Null
        }
    }
}

##################
# MAIN - (RENEW) #
##################

elseif ($Action -eq "renew" ) {

    # process the renewal request
    Write-Log "Performing certificate renew request for $CertificateName using $VaultName..."
    try {
        New-CertificateRenewalRequest -VaultName $VaultName -CertificateName $CertificateName -CA $CA -PfxFolder $PfxFolder -CertPswSecretName $CertPswSecretName            
    }
    catch {
        $msg = "Error processing renewal request: $_"
        Write-Log $msg -Level "Error"
        throw $msg
    }
}

################
# MAIN - (NEW) #
################

else {

    # check additional required parameters for new certificate requests: template
    if ([string]::IsNullOrEmpty($CertificateTemplate)) {
        $msg = "Missing or empty mandatory parameter: 'CertificateTemplate'"
        Write-Log $msg -Level "Error"
        throw $msg
    }   
    # subject
    if ([string]::IsNullOrEmpty($CertificateSubject)) {
        $msg = "Missing or empty mandatory parameter: 'CertificateSubject'"
        Write-Log $msg -Level "Error"
        throw $msg
    }
    # DnsNames (optional, but if specified, must be an array)
    if ($CertificateDnsNames -and $CertificateDnsNames -isnot [array]) {
        $msg = "Parameter 'CertificateDnsNames' is not an array!"
        Write-Log $msg -Level "Error"
        throw $msg
    }
    if ($null -ne $CertificateDnsNames) {
        Write-Log "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplate, subject $CertificateSubject, DNS names $($CertificateDnsNames -join ', ')..."
    }
    else {
        Write-Log "Performing new certificate request for certificate $CertificateName using vault $VaultName, template $CertificateTemplate, subject $CertificateSubject..."
    }

    # process the new certificate request
    try {
        New-CertificateRequest -VaultName $VaultName -CertificateName $CertificateName -CertificateTemplate $CertificateTemplate -CertificateSubject $CertificateSubject -CertificateDnsNames $CertificateDnsNames -CA $CA -PfxFolder $PfxFolder -CertPswSecretName $CertPswSecretName     
        
    }
    catch {
        $msg = "Error processing new request: $_"
        Write-Log $msg -Level "Error"
        throw $msg
    }
}

##############
# MAIN - end #
##############

Write-Log "Runbook completed successfully."