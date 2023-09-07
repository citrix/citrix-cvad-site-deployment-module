<#
.Synopsis
    Request a Certificate from a CA
.Description
    Request a Certificate from a CA
.Parameter LogFilePath
    Specifies the path of the file where log entries will be added
.Parameter CertStoreLocation
    Specifies the location where requested certificate stored
.Parameter Subject
    Specifies the subject name for requesting certificate
.Parameter CAServer
    Specifies the name of the CA Server
.Parameter CAName
    Specifies the name of the CA
.Parameter FriendlyName
    Specifies the friendly name of the requested certificate
.Parameter SAN
    Specifies the content of the Subject Alternative Name (SAN)
.Parameter KeyLength
    Specifies the length of encryption key to be used
.Parameter ExportThumbprint
    Switch parameter that indicates whether Thumbprint will be exported to a file
.Parameter ThumbprintFilePath
    Specifies the path of the file to export the requested certificate thumbprint
.Example
    Request-CertificateFromCA.ps1 -CertStoreLocation 'Cert:\LocalMachine\My' -Template 'Machine' -FriendlyName 'Test'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $LogFilePath,

    [Parameter(Mandatory = $true)]
    [string]$Subject,

    [Parameter(Mandatory = $true)]
    [string]$CAServer,

    [Parameter(Mandatory = $true)]
    [string]$CAName,

    [Parameter(Mandatory = $true)]
    [string] $FriendlyName,

    [Parameter(Mandatory = $true)]
    [string] $SAN,

    [Parameter(Mandatory = $false)]
    [string]$KeyLength = "2048",

    [Parameter(Mandatory = $false)]
    [string] $Template = 'WebServer',

    [Parameter(Mandatory = $false)]
    [string] $CertStoreLocation = "Cert:\LocalMachine\My",

    [Parameter(Mandatory = $false)]
    [switch] $ExportThumbprint,

    [Parameter(Mandatory = $false)]
    [string] $ThumbprintFilePath,

    [Parameter(Mandatory = $false)]
    [int] $TimeoutSecond = 120
)

$ErrorActionPreference = "Stop"
Set-PSDebug -Trace 0 
Set-StrictMode -Version 2
$workingDir = Split-Path -Path $($MyInvocation.MyCommand.Source) -Parent

function New-InfFileFromTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateFile,

        [Parameter(Mandatory = $false)]
        [hashtable]$attrs,

        [Parameter(Mandatory = $false)]
        [string]$OutFile
    )
    if (-not (Test-Path $OutFile)) {
        Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Creating the $OutFile"
        New-Item -Type File $OutFile
    }
    $templateContent = Get-Content $TemplateFile
    if ($null -eq $templateContent) {
        Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] The template file $TemplateFile is empty"
        exit 1
    }

    $each = $attrs.GetEnumerator()
    while ($each.movenext()) {
        $current = $each.current
        $templateContent = $templateContent | ForEach-Object { $_.replace(";[%$($current.key)%]", "$($current.value)") }                
    }
    $templateContent | Out-File $OutFile
}

$dtBegin = Get-Date
Add-Content $LogFilePath -value ("$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Test-DesktopSessionStatusOnClient: Start at " + $dtBegin)
$dtTimeout = $dtBegin.addseconds($TimeoutSecond)

while ($dtTimeout -gt (Get-Date)) {
    if (-not (Test-Path "$workingDir\RequestTemplate.inf")) {
        Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Did not find the required RequestTemplate.inf file. "
        exit 1
    }
    Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Generating the attribute hashtable"
    $attrs = [system.collections.hashtable] @{}
    if (-not [string]::isnullorempty($Subject)) {
        $attrs.add("SUBJECT", "Subject =`"CN=$Subject`"")
    }
    if (-not [string]::isnullorempty($Template)) {
        $attrs.add("TEMPLATE", "CertificateTemplate = $Template")
    }
    if (-not [string]::isnullorempty($FriendlyName)) {
        $attrs.add("FRIENDLYNAME", "FriendlyName = $FriendlyName")
    }
    if (-not [string]::isnullorempty($FriendlyName)) {
        $attrs.add("KEYLENGTH", "KeyLength = $KeyLength")
    }
    if (-not [string]::isnullorempty($SAN)) {
        $attrs.add("SAN", "2.5.29.17 = `"{text}`"`n_continue_ = `"$SAN&`"")
    }
    Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Generating the request inf file"
    New-InfFileFromTemplate -TemplateFile "$workingDir\RequestTemplate.inf" -attrs $attrs -OutFile "$workingDir\request.inf" -verbose

    Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Generating the request template req file from request inf file"
    certreq.exe -new -f "$workingDir\request.inf" "$workingDir\RequestTemplate.req"

    Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Acquiring the request file information"
    certutil -dump "$workingDir\RequestTemplate.req"

    Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Requesting the certificate from Certificate Authority $CAServer\$CAName"
    certreq -submit -config "$CAServer\$CAName" -f "$workingDir\RequestTemplate.req" "$workingDir\Certificate.cer"

    if (-not (Test-Path "$workingDir\Certificate.cer")) {
        Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Failed to request a certificate from CA"
        exit 1
    }

    Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Certificate acquired from CA is valid and will be stored in $CertStoreLocation"
    certreq -accept "$workingDir\Certificate.cer"
    $store = Get-Item $CertStoreLocation
    $store.open("ReadWrite")

    $cert = $store.certificates | Where-Object { $_.FriendlyName -eq $FriendlyName }
    if ($null -eq $cert) {
        Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Certificate not found in $CertStoreLocation"
        exit 1
    }
    if ($cert.verify()) {
        $store.close()  
        Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] The certificate has been installed and configured successfully in $CertStoreLocation"          
           
    }
    else {
        Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Failed to verify certificate"
        $store.Remove($cert)
        $store.close()
    }
    Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] The Certificate has been installed and configured successfully"
    # Get and export certificate thumbprint
    $Thumbprint = (Get-ChildItem -path cert:\localMachine\My | Where-Object { $_.Subject -eq "CN=$Subject" }).Thumbprint
    if ($ExportThumbprint) {
        if ([string]::isnullorempty($ThumbprintFilePath)) {
            $compSys = Get-WmiObject Win32_ComputerSystem
            $ThumbprintFilePath = "$workingDir\$($compSys.Name + '.' + $compSys.Domain)"
        }
        # Export the Thumbprint to a thumbprint file.
        Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Export the Thumbprint to $ThumbprintFilePath ..."                
        try { 
            $Thumbprint | Out-File $ThumbprintFilePath
        }
        catch {
            Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Failed to export Thumbprint."
            $error
            exit 1
        }
    }
    exit 0
}
Add-Content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Request-CertificateFromCA] Failed to request certificate: Timeout after $($TimeoutSecond) seconds"
exit 1