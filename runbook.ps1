# Generates a CSR for a certificate in Azure Key Vault, sends it to a CA, and imports the signed certificate back into the Key Vault.
# This script is designed to be run as an Azure Automation Runbook on a hybrid worker.

param
(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData
)

# force the runbook to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

#################
# CONFIGURATION #
#################

$automationAccountName = "aa-shared-neu-001"
$automationAccountRG = "rg-shared-neu-001"
$queueAttempts = 10     # number of attempts to check the queue
$queueWait = 5          # seconds to wait between attempts
$queueInvisibilityTimeout = [System.TimeSpan]::FromSeconds(30) # seconds to wait for the message to be invisible in the queue when it is being processed

#################
### FUNCTIONS ###
#################

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
        Write-Error "Error decoding message from JSON: $jsonMessage"
        return
    }

    $vaultName = $message.data.VaultName
    $CertName = $message.data.ObjectName

    Write-Output "VaultName = $VaultName"
    Write-Output "ObjectName = $CertName"

    # get the certificate from the vault
    $cert = $null
    try {
        $cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $CertName
    }
    catch {
        Write-Error "Error getting certificate from vault: $_"
        return
    }

    if ($null -eq $cert) {
        Write-Error "Error getting certificate from vault: $CertName not found!"
        return
    }

    $SubjectName = $cert.Certificate.Subject
    Write-Output "SubjectName = $SubjectName"

    $IssuerName = $cert.Certificate.Issuer
    Write-Output "IssuerName = $IssuerName"

    # get the DNS names from the certificate
    $dnsNames = $null
    $san = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
    if ($null -ne $san) {
        # $DNS.Format(0) returns a string like: DNS Name=server01.contoso.com, DNS Name=server01.litware.com.
        # Transform it into an array of DNS names using regex; remove the "DNS Name=" prefix and split by comma
        $dnsNames = ($san.Format(0) -replace 'DNS Name=', '').Split(',').Trim() | Where-Object { $_ -ne "" }
        Write-Output "DNS Names: $($dnsNames -join ', ')"
    }

    # get the OID of the Certificate Template
    $oid = $cert.Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Certificate Template Information" }
    if ($null -eq $oid) {
        Write-Error "Error getting OID from certificate: Certificate Template Information not found"
        return
    }
    # convert in a string like:
    # Template=Flab-ShortWebServer(1.3.6.1.4.1.311.21.8.15431357.2613787.6440092.16459852.14380503.11.12399345.16691736), Major Version Number=100, Minor Version Number=5
    $oid = $oid.Format(0)

    # extract the template name and the ASN.1 values using regex
    $templateName = $oid -replace '.*Template=(.*)\(.*\).*', '$1'
    $templateASN = $oid -replace '.*\((.*)\).*', '$1'

    Write-Output "Template Name: $templateName"

    # create certificate - if a previous request is in progress, reuse it
    $csr = $null
    try {
        $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertName | Where-Object { $_.Status -eq "inProgress" }
        if ($null -ne $op) {
            Write-Output "Certificate request is already in progress for this certificate: $CertName; reusing the existing request."
            $csr = $op.CertificateSigningRequest
        }
        else {
            Write-Output "Creating a new CSR for certificate $CertName in key vault $VaultName..."
            if ($null -ne $dnsNames) {
                # create a new CSR with the DNS names
                $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $SubjectName -IssuerName "Unknown" -DnsName $dnsNames
            }
            else {
                # create a new CSR without DNS names
                $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $SubjectName -IssuerName "Unknown"
            }
            $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificatePolicy $Policy
            $csr = $result.CertificateSigningRequest
        }
    }
    catch {
        Write-Error "Error generating CSR in Key Vault: $_"
        return
    }
    

    # Write the CSR content to a temporary file
    $csrFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertName.csr"
    Set-Content -Path $csrFile -Value $csr
    Write-Output "CSR file created: $csrFile"

    # Send request to the CA
    Write-Output "Sending request to the CA..."
    $certificateRequest = Submit-CertificateRequest -CA $ca -Path $csrFile -Attribute "CertificateTemplate:$($templateName)"
    Remove-Item -Path $csrFile -Force -ErrorAction SilentlyContinue
    if ($null -eq $certificateRequest) {
        Write-Error "Error sending request to the CA."
        return
    }
    Write-Output "Retrieving signed certificate from the CA..."
    $certificate = $certificateRequest.Certificate
    if ($null -eq $certificate) {
        Write-Error "Error getting certificate from the CA."
        return
    }

    # write the returned signed certificate to a temporary file
    $certFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertName.p7b"
    try {
        Export-Certificate -Cert $certificate -FilePath $certFile -Type P7B | Out-Null    
    }
    catch {
        Write-Error "Error exporting certificate to file: $_"
        return
    }
    Write-Output "Certificate file created: $certFile"

    # use certutil -encode to convert the certificate to base64 - this is required to import a p7b file into the key vault
    # (https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#formats-of-merge-csr-we-support)
    Write-Output "Converting the certificate to base64..."
    $certFileBase64 = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$CertName.b64"
    $process = Start-Process -FilePath "certutil.exe" -ArgumentList "-encode", $certFile, $certFileBase64 -NoNewWindow -Wait -PassThru
    Remove-Item -Path $certFile -Force -ErrorAction SilentlyContinue
    if ($process.ExitCode -ne 0) {
        Write-Error "certutil.exe failed with exit code $($process.ExitCode)"
        return
    }

    # import the certificate into the key vault
    Write-Output "Importing the certificate $CertName into the key vault $VaultName..."
    try {
        $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -FilePath $certFileBase64 
    }
    catch {
        Write-Error "Error importing certificate into the key vault: $_"
        return
    }
    finally {
        Remove-Item -Path $certFileBase64 -Force -ErrorAction SilentlyContinue
    }
    Write-Output "Certificate imported into the key vault."
}

############
### MAIN ###
############

# Check if the script is running on Azure or on hybrid worker
$envVars = Get-ChildItem env:
$HybridWorker = ($envVars | Where-Object { $_.name -like 'Fabric_*' } ).count -eq 0
if (-not $HybridWorker) {
    Write-Error "This workbook must be executed by a hybrid worker!"
    return
}

# get the automation variables
$storageAccountName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-storageaccount").Value
$queueName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-queue").Value
$CAServer = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-ca").Value

# check that all variables are set
if ($null -eq $storageAccountName) {
    Write-Error "Storage account name is not set. Exiting."
    return
}
if ($null -eq $queueName) {
    Write-Error "Queue name is not set. Exiting."
    return
}
if ($null -eq $CAServer) {
    Write-Error "Certification authority is not set. Exiting."
    return
}

$worker = $env:COMPUTERNAME
Write-Output "Script started at $(Get-Date), running on $worker"
Write-Output "Storage account is: $storageAccountName"
Write-Output "Queue name is: $queueName"
Write-Output "Certification authority is: $CAServer"
Write-Output ""

# see if Az module is installed
Write-Output "Checking if Az module is installed..."
if (-not (Get-InstalledModule -Name Az)) {
    Write-Error "Az module not installed!"
    return
}

# see if PSPKI module is installed
Write-Output "Checking if PSPKI module is installed..."
if (-not (Get-InstalledModule -Name PSPKI)) {
    Write-Error "PSPKI module not installed!"
    return
}

# Connect to azure

# Ensures you do not inherit an AzContext, snce we are using a system-assigned identity for login
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
Write-Output "Connecting to Azure using default identity..."
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    Write-Error "There is no system-assigned user identity. Aborting." 
    return
}

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection

# import other modules if needed
import-module PSPKI

# get CA details
Write-Output "Getting the CA details for $CAServer..."
$ca = Get-CertificationAuthority -ComputerName $CAServer
if ($null -eq $ca) {
    Write-Error "Error getting CA details: $CAServer not found"
    return
}

Write-Output "Creating context to work with storage account..."
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount

# check the queue for messages for a maximum of $queueAttempts times
try {
    for ($i = 0; $i -lt $queueAttempts; $i++) {
        Write-Output "Checking the queue (attempt $($i+1) of $queueAttempts)..."
        $queue = Get-AzStorageQueue -Name $queueName -Context $ctx
        Write-Output ("Queued messages " + $queue.ApproximateMessageCount)
    
        if ($queue.ApproximateMessageCount -gt 0) {
            break
        }
        else {
            Write-Output "Queue is empty: going to sleep for $queueWait seconds before checking again..."
            Start-Sleep -Seconds $queueWait
        }
    }
    if ($i -eq $queueAttempts) {
        Write-Error "No messages in the queue after $queueAttempts attempts. Exiting."
        return
    }        
}
catch {
    Write-Error "Error getting the queue: $_"
    return
}

# process the messages in the queue
for ($i = 1; $i -le $queue.ApproximateMessageCount; $i++ ) {
    Write-Output "Processing message $i of $($queue.ApproximateMessageCount)..."
    # get the message from the queue

    try {
        $queueMessage = $queue.QueueClient.ReceiveMessage($queueInvisibilityTimeout)
        if ($null -eq $queueMessage.Value) {
            Write-Output "No message value found, skipping."
            continue
        }            
    }
    catch {
        Write-Error "Error getting message from the queue: $_"
        return
    }

    # decode body of the message from base64
    $jsonMessage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($queueMessage.value.MessageText))
    
    # process the message
    Write-Output "JSON Message: $($jsonMessage)"
    certlcworkflow -jsonMessage $jsonMessage -ca $ca
    
    # delete the message from the queue
    Write-Output "Deleting message from the queue..."
    try {
        $queue.QueueClient.DeleteMessage($queueMessage.value.MessageId, $queueMessage.value.PopReceipt) | Out-Null        
    }
    catch {
        Write-Error "Error deleting message from the queue: $_"
        return
    }
}

Write-Output "All done - $(get-date)."