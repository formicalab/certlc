# Generates a CSR for a certificate in Azure Key Vault, sends it to a CA, and imports the signed certificate back into the Key Vault.
# This script is designed to be run as an Azure Automation Runbook on a hybrid worker.

param
(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData   # the WebhookData is documented here: https://learn.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal
)

# force the runbook to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

###################
# STATIC SETTINGS #
###################

$automationAccountName = "aa-shared-neu-001"
$automationAccountRG = "rg-shared-neu-001"
$queueAttempts = 10     # number of attempts to check the queue
$queueWait = 5          # seconds to wait between attempts
$queueInvisibilityTimeout = [System.TimeSpan]::FromSeconds(30) # seconds to wait for the message to be invisible in the queue when it is being processed

$IngestionUrl = "https://dce-certlc-itn-001-ws3i.italynorth-1.ingest.monitor.azure.com"
$DcrImmutableId = "dcr-0af8254b18bf4c06a6d2952f9f040938"
$Table = "certlc_CL"  # the name of the custom log table, including "_CL" suffix

####################
# GLOBAL VARIABLES #
####################

$Progress = 0                                   # progress of the script
$LAToken = $null                                # token using to send logs to Log Analytics
$CorrelationId = [guid]::NewGuid().ToString()   # correlation ID for the log entry

#################
### FUNCTIONS ###
#################

# logger: send log to Log Analytics workspace (if token is available) and to output
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
    } elseif ($Level -eq "Warning") {
        Write-Warning "$(get-date): $($Level): [$(('{0:D3}' -f $Progress))] $Description"
    } else {
        Write-Output "$(get-date): $($Level): [$(('{0:D3}' -f $Progress))] $Description"
    }
}

function certlcworkflow {
    param (
        [Parameter(Mandatory = $true)]
        [string] $jsonMessage,
        [Parameter(Mandatory = $true)]
        [object] $ca
    )

    # decode the message from JSON
    $message = $jsonMessage | ConvertFrom-Json
    if ($null -eq $message) {
        Write-Log "Error decoding message from JSON: $jsonMessage" -Level "Error"
        return
    }

    $vaultName = $message.data.VaultName
    $CertificateName = $message.data.ObjectName

    Write-Log "VaultName = $VaultName"
    Write-Log "ObjectName = $CertificateName"

    # get the certificate from the vault
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
        Write-Log "Error getting certificate from vault: $CertificateName not found!" -Level "Error"
        return
    }

    $SubjectName = $cert.Certificate.Subject
    Write-Log "SubjectName = $SubjectName"

    $IssuerName = $cert.Certificate.Issuer
    Write-Log "IssuerName = $IssuerName"

    # get the DNS names from the certificate
    $dnsNames = $null
    $san = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
    if ($null -ne $san) {
        # $DNS.Format(0) returns a string like: DNS Name=server01.contoso.com, DNS Name=server01.litware.com.
        # Transform it into an array of DNS names using regex; remove the "DNS Name=" prefix and split by comma
        $dnsNames = ($san.Format(0) -replace 'DNS Name=', '').Split(',').Trim() | Where-Object { $_ -ne "" }
        Write-Log "DNS Names: $($dnsNames -join ', ')"
    }

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
    $templateName = $oid -replace '.*Template=(.*)\(.*\).*', '$1'
    $templateASN = $oid -replace '.*\((.*)\).*', '$1'

    Write-Log "Template Name: $templateName"

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
            if ($null -ne $dnsNames) {
                # create a new CSR with the DNS names
                $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $SubjectName -IssuerName "Unknown" -DnsName $dnsNames
            }
            else {
                # create a new CSR without DNS names
                $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $SubjectName -IssuerName "Unknown"
            }
            $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -CertificatePolicy $Policy
            $csr = $result.CertificateSigningRequest
        }
    }
    catch {
        Write-Log "Error generating CSR in Key Vault: $_" -Level "Error"
        return
    }
    
    # Write the CSR content to a temporary file
    $csrFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertificateName.csr"
    Set-Content -Path $csrFile -Value $csr
    Write-Log "CSR file created: $csrFile"

    # Send request to the CA
    Write-Log "Sending request to the CA..."
    try {
        $certificateRequest = Submit-CertificateRequest -CA $ca -Path $csrFile -Attribute "CertificateTemplate:$($templateName)"        
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
}

############
### MAIN ###
############

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

# see if Az module is installed
Write-Log "Checking if Az module is installed..."
if (-not (Get-InstalledModule -Name Az)) {
    Write-Log "Az module not installed!" -Level "Error"
    return
}
$Progress++

# Connect to azure

# Ensures you do not inherit an AzContext, snce we are using a system-assigned identity for login
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

# see if PSPKI module is installed
Write-Log "Check if PSPKI module is installed..."
if (-not (Get-InstalledModule -Name PSPKI)) {
    Write-Log "PSPKI module not installed!" -Level "Error"
    return
}
import-module PSPKI
$Progress++

# get the automation variables
Write-Log "Getting automation variables..."
$storageAccountName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-storageaccount").Value
$queueName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-queue").Value
$CAServer = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-ca").Value

# check that all variables are set
if ($null -eq $storageAccountName) {
    Write-Log "Storage account name is not set. Exiting." -Level "Error"
    return
}
if ($null -eq $queueName) {
    Write-Log "Queue name is not set. Exiting." -Level "Error"
    return
}
if ($null -eq $CAServer) {
    Write-Log "Certification authority is not set. Exiting." -Level "Error"
    return
}

# write the parameters to the log
Write-Log "Storage account is: $storageAccountName"
Write-Log "Queue name is: $queueName"
Write-Log "Certification authority is: $CAServer"
$Progress++

# get CA details
Write-Log "Getting the CA details for $CAServer..."
$ca = Get-CertificationAuthority -ComputerName $CAServer
if ($null -eq $ca) {
    Write-Log "Error getting CA details: $CAServer not found" -Level "Error"
    return
}
$Progress++

Write-Log "Creating context to work with storage account..."
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount
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

    # decode body of the message from base64
    $jsonMessage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($queueMessage.value.MessageText))
    
    # process the message
    Write-Log "JSON Message fetched from the queue: $($jsonMessage)"
    certlcworkflow -jsonMessage $jsonMessage -ca $ca
    
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

$Progress = 100
Write-Log "All done!"