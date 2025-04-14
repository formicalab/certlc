param
(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData
)

# force the runbook to stop also on a non-terminating error
$ErrorActionPreference = 'Stop'
# ensure that all variables are set
Set-StrictMode -Version 1.0

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
        [object] $certificationAuthority
    )

    # decode the message from JSON
    $message = $jsonMessage | ConvertFrom-Json
    if ($null -eq $message) {
        Write-Error "Error decoding message from JSON: $jsonMessage"
        return
    }

    $vaultName = $message.data.VaultName
    $ObjectName = $message.data.ObjectName

    Write-Output "VaultName = $VaultName"
    Write-Output "ObjectName = $ObjectName"

    # get the certificate from the vault
    $cert = $null
    try {
        $cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $ObjectName
    }
    catch {
        Write-Error "Error getting certificate from vault: $_"
        return
    }

    if ($null -eq $cert) {
        Write-Error "Error getting certificate from vault: $ObjectName not found!"
        return
    }

    $SubjectName = $cert.Certificate.Subject
    $IssuerName = $cert.Certificate.Issuer

    write-output "SubjectName = $SubjectName"
    write-output "IssuerName = $IssuerName"

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
    
    # check if an existing CSR is present in the vault
    $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $ObjectName | where {$_.Status -eq "inProgress"}
    if ($null -ne $op) {
        Write-Output "Certificate request is already in progress for this certificate: $ObjectName; reusing the existing request."
        $csr = $op.CertificateSigningRequest
    }
    else {
        try {
            Write-Output "Creating a new CSR for the certificate: $ObjectName"
            $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $SubjectName -IssuerName "Unknown"
            $result = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $ObjectName -CertificatePolicy $Policy
            $csr = $result.CertificateSigningRequest
        }
        catch {
            Write-Error "Error generating CSR in Key Vault: $_"
            return
        }
    }

    # Write the CSR content to a temporary file
    $csrFile = [System.IO.Path]::GetTempFileName()
    $csrFile = [System.IO.Path]::ChangeExtension($csrFile, ".csr")
    Set-Content -Path $csrFile -Value $csr
    Write-Output "CSR file created: $csrFile"

    # Send request to the CA
    Write-Output "Sending request to the CA..."
    $certificateRequest = Submit-CertificateRequest -CA $certificationAuthority -Path $csrFile -Attribute "CertificateTemplate:$($templateName)"
    if ($null -eq $certificateRequest) {
        Write-Error "Error sending request to the CA."
        return
    }
    $certificate = $certificateRequest.Certificate
    if ($null -eq $certificate) {
        Write-Error "Error getting certificate from the CA."
        return
    }

    # write the certificate to a temporary file
    $certFile = [System.IO.Path]::GetTempFileName()
    $certFile = [System.IO.Path]::ChangeExtension($certFile, ".p7b")
    Export-Certificate -Cert $certificate -FilePath $certFile -Type P7B
    Write-Output "Certificate file created: $certFile"

    # use certutil -encode to convert the certificate to base64
    # (https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios#formats-of-merge-csr-we-support)
    Write-Output "Converting the certificate to base64..."
    $certFileBase64 = [System.IO.Path]::ChangeExtension($certFile, ".b64")
    Start-Process -FilePath "certutil.exe" -ArgumentList "-encode", $certFile, $certFileBase64 -NoNewWindow -Wait

    # import the certificate into the key vault
    Write-Output "Importing the certificate into the key vault..."
    try {
        $newCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $ObjectName -FilePath $certFileBase64 
    }
    catch {
        Write-Error "Error importing certificate into the key vault: $_"
        return
    }
    Write-Output "Certificate imported into the key vault: $($newCert.Name)"

    # cleanup temporary files
    Remove-Item -Path $csrFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $certFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $certFileBase64 -Force -ErrorAction SilentlyContinue
    Write-Output "Temporary files deleted."
}

############
### MAIN ###
############

# Check if the script is running on Azure or on hybrid worker
$envVars = Get-ChildItem env:
$HybridWorker = ($envVars | Where-Object { $_.name -like 'Fabric_*' } ).count -eq 0
if (-not $HybridWorker) {
    Write-Error "This workbook must be executed by a hybrid worker!"
    #Write-Output $envVars
    exit 1
}

$worker = $env:COMPUTERNAME
Write-Output "Runbook started at $(Get-Date), running on hybrid worker $worker"

# Connect to azure

# Ensures you do not inherit an AzContext in your runbook
$null = Disable-AzContextAutosave -Scope Process

# Connect using a Managed Service Identity
Write-output "Connecting to Azure..."
try {
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch {
    Write-Output "There is no system-assigned user identity. Aborting." 
    exit 1
}

# import other modules if needed
import-module PSPKI

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection
Write-Output "Connection done."

# get the automation variables
$storageAccountName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-storageaccount").Value
$queueName = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-queue").Value
$certificationAuthority = (Get-AzAutomationVariable -ResourceGroupName $automationAccountRG -AutomationAccountName $automationAccountName -name "certlc-ca").Value

# check that all variables are set
if ($null -eq $storageAccountName) {
    Write-Error "Storage account name is not set. Exiting."
    exit 1
}
if ($null -eq $queueName) {
    Write-Error "Queue name is not set. Exiting."
    exit 1
}
if ($null -eq $certificationAuthority) {
    Write-Error "Certification authority is not set. Exiting."
    exit 1
}

write-output "Storage account is: $storageAccountName"
write-output "Queue name is: $queueName"
write-output "Certification authority is: $certificationAuthority"

Write-Output "Getting the CA details for $certificationAuthority..."
$ca = Get-CertificationAuthority -ComputerName $certificationAuthority
if ($null -eq $ca) {
    Write-Error "Error getting CA details: $certificationAuthority not found"
    return
}

write-output "Creating context to work with storage account..."
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount


# check the queue for messages for a maximum of $queueAttempts times
for ($i = 0; $i -lt $queueAttempts; $i++) {
    write-output "Checking the queue..."
    $queue = Get-AzStorageQueue -Name $queueName -Context $ctx
    write-output ("Queued messages " + $queue.ApproximateMessageCount)

    if ($queue.ApproximateMessageCount -gt 0) {
        break
    }
    else {
        write-output "Sleeping for $queueWait seconds..."
        Start-Sleep -Seconds $queueWait
    }
}
if ($i -eq $queueAttempts) {
    Write-Error "No messages in the queue after $queueAttempts attempts. Exiting."
    exit 1
}

# process the messages in the queue
for ($i = 1; $i -le $queue.ApproximateMessageCount; $i++ ) {
    write-output "Processing message $i of $($queue.ApproximateMessageCount)..."
    # get the message from the queue
    $queueMessage = $queue.QueueClient.ReceiveMessage($queueInvisibilityTimeout)
    if ($null -eq $queueMessage.Value) {
        write-output "No message value found, skipping."
        continue
    }
    # decode body of the message from base64
    $jsonMessage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($queueMessage.value.MessageText))
    # process the message
    write-output "JSON Message: $($jsonMessage)"
    certlcworkflow -jsonMessage $jsonMessage -certificationAuthority $ca
    # delete the message from the queue
    write-output "Deleting message from the queue..."
    $queue.QueueClient.DeleteMessage($queueMessage.value.MessageId, $queueMessage.value.PopReceipt)
}

write-output "DONE."