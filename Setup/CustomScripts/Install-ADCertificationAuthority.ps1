<#
    .Synopsis
        Installs Active Directory Certificate Services role on local computer.
    .Description
        Installs Active Directory Certificate Services (AD CS) role on local computer.    
        The command supports Windows Server 2008 R2 Server Core installations.
    .Parameter CAName
        Specifies a custom CA certificate name/subject. If not passed, a '<ComputerName>-CA'
        form is used for workgroup CAs and '<DomainName>-<ComputerName-CA>' form is used for domain CAs.
    .Parameter CADomainNameSuffix
        Specifies a Domain Name suffix to provide some additional information. For example, company name, country, city, etc. DN suffix is empty for
        workgroup CAs and includes current domain distinguished name (for example, DC=domain,DC=com). 
    .Parameter CAType
        Specifies CA type:
        
        Standalone Root,
        Standalone Subordinate,
        Enterprise Root,
        Enterprise Subordinate.
    .Parameter CSP
        Specifies a custom cryptographic service provider. By default 'RSA#Microsoft Software Key Storage Provider' is used (in most cases
        just use default CSP). 

        The full list of supportable and available "by default" CSPs for Windows Server 2008+ is:

        Microsoft Base Cryptographic Provider v1.0
        Microsoft Base DSS Cryptographic Provider
        Microsoft Base Smart Card Crypto Provider
        Microsoft Enhanced Cryptographic Provider v1.0
        Microsoft Strong Cryptographic Provider
        RSA#Microsoft Software Key Storage Provider
        DSA#Microsoft Software Key Storage Provider
        ECDSA_P256#Microsoft Software Key Storage Provider
        ECDSA_P384#Microsoft Software Key Storage Provider
        ECDSA_P521#Microsoft Software Key Storage Provider
        RSA#Microsoft Smart Card Key Storage Provider
        ECDSA_P256#Microsoft Smart Card Key Storage Provider
        ECDSA_P384#Microsoft Smart Card Key Storage Provider
        ECDSA_P521#Microsoft Smart Card Key Storage Provider
    .Parameter KeyLength
        This parameter specifies the key length. If not specified, a 2048-bit key will be generated.
    .Parameter HashAlgorithm
        This parameter specifies hash algorithm that will be used for CA certificate/request hashing. Note that this is important for root
        CA installations. Subordinate CA certificates are hashed and signed by the parent CA with it's own settings. By default 'SHA1' is
        used.
    .Parameter ValidForYears
        Specifies the validity for root CA installations. By default root CA certificates are valid for 5 years. You can increase this value
        to 10, 20, 50, whatever. This parameter accepts integer values, assuming that the value is specified in years.
    .PARAMETER LogFilePath
        Path to the log file to record installation progress
    .Example
        PS > Install-CertificationAuthority -CAName "My Root CA" -CADomainNameSuffix "DC=test, DC=com" `
        -CAType "Standalone Root" -ValidForYears 10


        In this scenario, just setup a new Standalone Root CA with "CN=My Root CA, DC=test, DC=com" subject, that will be valid
        for 10 years. The CA will use default paths to CA database and log files and certificate will use 'RSA#Microsoft Software Key Storage Provider'
        CSP with 2048-bit key and SHA1 hashing algorithm.
    #>
param(
    [Parameter(Mandatory = $true)]
    [string]$LogFilePath,

    [Parameter(Mandatory = $false)]
    [string]$CAName,

    [Parameter(Mandatory = $false)]
    [string]$CADomainNameSuffix,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Standalone Root", "Standalone Subordinate", "Enterprise Root", "Enterprise Subordinate")]
    [string]$CAType,

    [Parameter(Mandatory = $false)]
    [string]$CSP,

    [Parameter(Mandatory = $false)]
    [int]$KeyLength,

    [Parameter(Mandatory = $false)]
    [string]$HashAlgorithm,

    [Parameter(Mandatory = $false)]
    [int]$ValidForYears = 5
)

#region Binaries checking and installation if necessary
if ([Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 0) {
    $null = cmd /c "servermanagercmd -install AD-Certificate 2> null"
} 
else {
    try {
        Import-Module ServerManager -ErrorAction Stop
    }
    catch {
        $null = ocsetup 'ServerManager-PSH-Cmdlets' /quiet 
        Start-Sleep 1
        Import-Module ServerManager -ErrorAction Stop
    }
    $status = (Get-WindowsFeature -Name AD-Certificate).Installed
    # if still no, install binaries, otherwise do nothing
    if (!$status) {
        $retn = Add-WindowsFeature -Name AD-Certificate -ErrorAction Stop
        if (!$retn.Success) {
            Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] Unable to install ADCS installation packages due of the following error: $($retn.breakCode)"
            exit 1
        }
    }
}
try {
    $CASetup = New-Object -ComObject CertOCM.CertSrvSetup.1
}
catch {
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] Unable to load necessary interfaces. Your Windows Server operating system is not supported!"
    exit 1
}
    
# initialize setup binaries
try {
    $CASetup.InitializeDefaults($true, $false)
}
catch {
    Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] Cannot initialize setup binaries!"
    exit 1
}
#endregion

#region Property enums
$CATypesByName = @{"Enterprise Root" = 0; "Enterprise Subordinate" = 1; "Standalone Root" = 3; "Standalone Subordinate" = 4 }
$CATypesByVal = @{}
$CATypesByName.keys | ForEach-Object { $CATypesByVal.Add($CATypesByName[$_], $_) }
$CAPRopertyByName = @{"CAType" = 0; "CAKeyInfo" = 1; "Interactive" = 2; "ValidityPeriodUnits" = 5;
    "ValidityPeriod" = 6; "ExpirationDate" = 7; "PreserveDataBase" = 8; "DBDirectory" = 9; "Logdirectory" = 10;
    "ParentCAMachine" = 12; "ParentCAName" = 13; "RequestFile" = 14; "WebCAMachine" = 15; "WebCAName" = 16
}
$CAPRopertyByVal = @{}
$CAPRopertyByName.keys | ForEach-Object { $CAPRopertyByVal.Add($CAPRopertyByName[$_], $_) }
#endregion
    
#region Key set processing 
$CAKey = $CASetup.GetCASetupProperty(1)
if ($CSP -ne "") {
    if ($CASetup.GetProviderNameList() -notcontains $CSP) {
        Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] Specified CSP '$($CSP)' is not valid!"
        exit 1
    } 
    else {
        $CAKey.ProviderName = $CSP
    }
} 
else {
    $CAKey.ProviderName = "RSA#Microsoft Software Key Storage Provider"
}
if ($KeyLength -ne 0) {
    if ($CASetup.GetKeyLengthList($CSP).Length -eq 1) {
        $CAKey.Length = $CASetup.GetKeyLengthList($CSP)[0]
    } 
    else {
        if ($CASetup.GetKeyLengthList($CSP) -notcontains $KeyLength) {
            Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] The specified key length '$($KeyLength)' is not supported by the selected CSP '$($CSP)' The following key lengths are supported by this CSP: $($CASetup.GetKeyLengthList($CSP))"
            exit 1
        }
        $CAKey.Length = $KeyLength
    }
}
if ($HashAlgorithm -ne "") {
    if ($CASetup.GetHashAlgorithmList($CSP) -notcontains $HashAlgorithm) {
        Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] The specified hash algorithm $($HashAlgorithm) is not supported by the selected CSP '$($CSP)' The following hash algorithms are supported by this CSP: $($CASetup.GetHashAlgorithmList($CSP))"
        exit 1
    }
    $CAKey.HashAlgorithm = $HashAlgorithm
}
$CASetup.SetCASetupProperty(1, $CAKey)
#endregion

#region Setting CA type
if (-not [string]::IsNullOrEmpty($CAType)) {
    $SupportedTypes = $CASetup.GetSupportedCATypes()
    $SelectedType = $CATypesByName[$CAType]
    if ($SupportedTypes -notcontains $CATypesByName[$CAType]) {
        Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] Selected CA type: '$($CAType)' is not supported by current Windows Server installation.The following CA types are supported by this installation: $([int[]]$CASetup.GetSupportedCATypes() | ForEach-Object{$CATypesByVal[$_]})"
        exit 1
    } 
    else {
        $CASetup.SetCASetupProperty($CAPRopertyByName.CAType, $SelectedType)
    }
}
#endregion

#region setting CA certificate validity
if ($SelectedType -eq 0 -or $SelectedType -eq 3 -and $ValidForYears -ne 0) {
    try {
        $CASetup.SetCASetupProperty(6, $ValidForYears)
    }
    catch {
        Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] The specified CA certificate validity period '$($ValidForYears)' is invalid."
        exit 1
    }
}
#endregion

#region setting CA name
if ($CAName -ne "") {
    if ($CADomainNameSuffix -ne "") {
        $Subject = "CN=$CAName" + ",$CADomainNameSuffix"
    } 
    else {
        $Subject = "CN=$CAName"
    }
    $DN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    # validate X500 name format
    try {
        $DN.Encode($Subject, 0x0)
    }
    catch {
        Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] Specified CA name or CA name suffix is not correct X.500 Distinguished Name."
        exit 1
    }
    $CASetup.SetCADistinguishedName($Subject, $true, $true, $true)
}
#endregion   
Add-content $LogFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Install-ADCertificationAuthority] Installing Certification Authority role on $env:computername ..."
        
$CASetup.Install()
        
Remove-Module ServerManager -ErrorAction SilentlyContinue