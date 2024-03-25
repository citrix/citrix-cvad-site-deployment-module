# Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.
<#
.SYNOPSIS
    Enable the TLS/DTLS listeners on the VDA

.DESCRIPTION
    Enable the TLS/DTLS listeners on the VDA. 
    Optionally, the TLS/DTLS certificate, port, version and cipher suite to use can be specified.

.PARAMETER SSLPort
    Specifies the port to use. Default is port 443.
.PARAMETER SSLMinVersion
    Specifies the minimum TLS/DTLS version to use (allowed values are SSL_3.0, TLS_1.0, TLS_1.1, TLS_1.2 and TLS_1.3).
    Default is TLS_1.2. 
.PARAMETER SSLCipherSuite
    Specifies the cipher suite to use (allowed values are GOV, COM and ALL). Default is ALL.
.PARAMETER CertificateThumbPrint
    Specifies the certificate thumbprint to identify the certificate to use

.EXAMPLE
    To enable the TLS/DTLS listeners
    Enable-VdaSSL -Enable -CertificateThumbprint "373641446CCA0343D1D5C77EB263492180B3E0FD"
.EXAMPLE
    To enable the TLS/DTLS listeners on port 4000
    Enable-VdaSSL -Enable -SSLPort 4000 -CertificateThumbprint "373641446CCA0343D1D5C77EB263492180B3E0FD"
.EXAMPLE
    To enable the TLS/DTLS listeners using TLS 1.2 with the GOV cipher suite
    Enable-VdaSSL -Enable -SSLMinVersion "TLS_1.2" -SSLCipherSuite "GOV" -CertificateThumbprint "373641446CCA0343D1D5C77EB263492180B3E0FD"
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $True)]
    [string]$CertificateThumbPrintFilePath,

    [Parameter(Mandatory = $True)]
    [string]$LogFilePath,

    [Parameter(Mandatory = $False)]
    [int] $SSLPort = 443,

    [Parameter(Mandatory = $False)]
    [ValidateSet("SSL_3.0", "TLS_1.0", "TLS_1.1", "TLS_1.2", "TLS_1.3")]
    [String] $SSLMinVersion = "TLS_1.2",

    [Parameter(Mandatory = $False)]
    [ValidateSet("GOV", "COM", "ALL")]
    [String] $SSLCipherSuite = "ALL"
)

Set-StrictMode -Version 2.0
$erroractionpreference = "Stop"

# Registry path constants 
$ICA_LISTENER_PATH = 'HKLM:\system\CurrentControlSet\Control\Terminal Server\Wds\icawd'
$ICA_CIPHER_SUITE = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'
$DHEnabled = 'Enabled'
$BACK_DHEnabled = 'Back_Enabled'
$ENABLE_SSL_KEY = 'SSLEnabled'
$SSL_CERT_HASH_KEY = 'SSLThumbprint'
$SSL_PORT_KEY = 'SSLPort'
$SSL_MINVERSION_KEY = 'SSLMinVersion'
$SSL_CIPHERSUITE_KEY = 'SSLCipherSuite'

$POLICIES_PATH = 'HKLM:\SOFTWARE\Policies\Citrix\ICAPolicies'
$ICA_LISTENER_PORT_KEY = 'IcaListenerPortNumber'
$SESSION_RELIABILITY_PORT_KEY = 'SessionReliabilityPort'
$WEBSOCKET_PORT_KEY = 'WebSocketPort'

#Read ICA, CGP and HTML5 ports from the registry
try {
    $IcaPort = (Get-ItemProperty -Path $POLICIES_PATH -Name $ICA_LISTENER_PORT_KEY).IcaListenerPortNumber
}
catch {
    $IcaPort = 1494
}

try {
    $CgpPort = (Get-ItemProperty -Path $POLICIES_PATH -Name $SESSION_RELIABILITY_PORT_KEY).SessionReliabilityPort
}
catch {
    $CgpPort = 2598
}

try {
    $Html5Port = (Get-ItemProperty -Path $POLICIES_PATH -Name $WEBSOCKET_PORT_KEY).WebSocketPort
}
catch {
    $Html5Port = 8008
}

if (!$IcaPort) {
    $IcaPort = 1494
}
if (!$CgpPort) {
    $CgpPort = 2598
}
if (!$Html5Port) {
    $Html5Port = 8008
}

# Determine the name of the ICA Session Manager
if (Get-Service | Where-Object { $_.Name -eq 'porticaservice' }) {
    $username = 'NT SERVICE\PorticaService'
    $serviceName = 'PortIcaService'
}
else {
    $username = 'NT SERVICE\TermService'
    $serviceName = 'TermService'
}

$RegistryKeysSet = $ACLsSet = $FirewallConfigured = $False

$Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
$Store.Open("ReadOnly")

$CertificateThumbPrint = Get-Content $CertificateThumbPrintFilePath -Tail 1
$Certificate = $Store.Certificates | Where-Object { $_.GetCertHashString() -eq $CertificateThumbPrint }
if (!$Certificate) {
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Enabling SSL to VDA failed: No certificate found in the certificate store with thumbprint $CertificateThumbPrint"
    $Store.Close()
    break
}

#Validate expiration date
$ValidTo = [DateTime]::Parse($Certificate.GetExpirationDateString())
if ($ValidTo -lt [DateTime]::UtcNow) {
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Enabling SSL to VDA failed: The certificate is expired. Please install a valid certificate and try again."
    $Store.Close()
    break
}

#Check certificate trust
if (!$Certificate.Verify()) {
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Enabling SSL to VDA failed: Verification of the certificate failed. Please install a valid certificate and try again."
    $Store.Close()
    break
}

#Check private key availability
try {
    $PrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    # both legacy CSP and new KSP certificate PrivateKey object obtained as above is of type RSACng
    # the Key.UniqueName returned for CSP certificate is actually the CspKeyContainerInfo.UniqueKeyContainerName
    $UniqueName = $PrivateKey.Key.UniqueName 
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] RSA CNG unique key name : $UniqueName"
}
catch {
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Enabling SSL to VDA failed: Unable to access the Private Key of the Certificate or one of its fields."
    $Store.Close()
    break
}

if (!$PrivateKey -or !$UniqueName) {
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Enabling SSL to VDA failed: Unable to access the Private Key of the Certificate or one of its fields."
    $Store.Close()
    break
}


[System.Security.Cryptography.AsymmetricAlgorithm] $PrivateKey = $Certificate.PrivateKey
if ($PrivateKey) {
    # Legacy CSP Certificate
    $unique_name = $PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    $dir = $env:ProgramData + '\Microsoft\Crypto\RSA\MachineKeys\'
}
else {
    # KSP Certificate
    $PrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    $unique_name = $PrivateKey.Key.UniqueName
    $dir = $env:ProgramData + '\Microsoft\Crypto\Keys\'
}

$keypath = $dir + $unique_name
Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] keypath: $keypath"
icacls $keypath /grant `"$username`"`:RX | Out-Null

Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] ACLs set."
$ACLsSet = $True

#Delete any existing rules for the SSLPort
netsh advfirewall firewall delete rule name=all protocol=tcp localport=$SSLPort | Out-Null

#Delete any existing rules for the DTLSPort
netsh advfirewall firewall delete rule name=all protocol=udp localport=$SSLPort | Out-Null
                        
#Delete any existing rules for Citrix SSL Service
netsh advfirewall firewall delete rule name="Citrix SSL Service" | Out-Null

#Delete any existing rules for Citrix DTLS Service
netsh advfirewall firewall delete rule name="Citrix DTLS Service" | Out-Null
                        
#Creating firewall rule for Citrix SSL Service
netsh advfirewall firewall add rule name="Citrix SSL Service"  dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$SSLPort | Out-Null

#Creating firewall rule for Citrix DTLS Service
netsh advfirewall firewall add rule name="Citrix DTLS Service" dir=in action=allow service=$serviceName profile=any protocol=udp localport=$SSLPort | Out-Null

#Disable any existing rules for ICA, CGP and HTML5 ports
netsh advfirewall firewall set rule name="Citrix ICA Service"        protocol=tcp localport=$IcaPort new enable=no | Out-Null
netsh advfirewall firewall set rule name="Citrix CGP Server Service" protocol=tcp localport=$CgpPort new enable=no | Out-Null
netsh advfirewall firewall set rule name="Citrix Websocket Service"  protocol=tcp localport=$Html5Port new enable=no | Out-Null

#Disable existing rules for UDP-ICA, UDP-CGP
netsh advfirewall firewall set rule name="Citrix ICA UDP" protocol=udp localport=$IcaPort new enable=no | Out-Null          
netsh advfirewall firewall set rule name="Citrix CGP UDP" protocol=udp localport=$CgpPort new enable=no | Out-Null

Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Firewall configured."
$FirewallConfigured = $True

# Create registry keys to enable SSL to the VDA
Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Setting registry keys..."
Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CERT_HASH_KEY -Value $Certificate.GetCertHash() -Type Binary -Confirm:$False 
switch ($SSLMinVersion) {
    "SSL_3.0" {
        Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 1 -Type DWord -Confirm:$False
    }
    "TLS_1.0" {
        Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 2 -Type DWord -Confirm:$False
    }
    "TLS_1.1" {
        Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 3 -Type DWord -Confirm:$False
    }
    "TLS_1.2" {
        Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 4 -Type DWord -Confirm:$False
    }
    "TLS_1.3" {
        #check if this OS support TLS 1.3 or not
                    
        $osVersion = (Get-WMIObject win32_operatingsystem) | Select-Object Version | Out-String
        $osVersion = $osVersion.trim()
        $buildNum = [int]$osVersion.Split(".")[2]
        if ($buildNum -lt 20348) {
            Write-Output "Enabling SSL to VDA failed. TLS 1.3 is only supported in Windows 2k22 / Windows 11 and above."
            $Store.Close()
            Exit
        }

        Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 5 -Type DWord -Confirm:$False
    }
}

switch ($SSLCipherSuite) {
    "GOV" {
        Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 1 -Type DWord -Confirm:$False
    }    
    "COM" {
        Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 2 -Type DWord -Confirm:$False
    }
    "ALL" { 
        Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 3 -Type DWord -Confirm:$False
    }
}

Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_PORT_KEY -Value $SSLPort -Type DWord -Confirm:$False

#Backup DH Cipher Suite and set Enabled:0 if SSL is enabled
if (!(Test-Path $ICA_CIPHER_SUITE)) {
    New-Item -Path $ICA_CIPHER_SUITE -Force | Out-Null
    New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value 1 -PropertyType DWORD -Force | Out-Null
}
else {
    $back_enabled_exists = Get-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -ErrorAction SilentlyContinue
    if ($null -eq $back_enabled_exists) {
        $exists = Get-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -ErrorAction SilentlyContinue
        if ($null -ne $exists) {
            New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value $exists.Enabled -PropertyType DWORD -Force | Out-Null
            Set-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0
        }
        else {
            New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value 1 -PropertyType DWORD -Force | Out-Null
        }
    }
}

# NOTE: This must be the last thing done when enabling SSL as the Citrix Service
#       will use this as a signal to try and start the Citrix SSL Listener!!!!
Set-ItemProperty -Path $ICA_LISTENER_PATH -name $ENABLE_SSL_KEY -Value 1 -Type DWord -Confirm:$False
        
Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Registry keys set."
$RegistryKeysSet = $True

$Store.Close()

if ($RegistryKeysSet -and $ACLsSet -and $FirewallConfigured) {
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] SSL to VDA enabled.`n"
}
else {
    if (!$RegistryKeysSet) {
        Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Configure registry manually or re-run the script to complete enabling SSL to VDA."
    }

    if (!$ACLsSet) {
        Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Configure ACLs manually or re-run the script to complete enabling SSL to VDA."
    }
                    
    if (!$FirewallConfigured) {
        Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Enable-VdaSSL] Configure firewall manually or re-run the script to complete enabling SSL to VDA."
    }
}
