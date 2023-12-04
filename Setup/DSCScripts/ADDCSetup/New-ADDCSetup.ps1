Configuration New-ADDCSetup {

    <#
    .SYNOPSIS
        Setup AD Domain Controller VM
        
        Copyright (c) Citrix Systems, Inc. All Rights Reserved.
        
    .DESCRIPTION
        Configure AD Domain Controller VM and add mock users
    
    .PARAMETER OUName
        Organizational Unit name to be setup for the new users
    .PARAMETER UserGroupName
        Group name for the new users
    .PARAMETER AdDomainFQDN
        Domain FQDN of Active Directory
    .PARAMETER AdDomainAdminPassword
        AD domain admin password
    .PARAMETER AdDefaultUserPassword
        Default password for the new users
    .PARAMETER CitrixModulesPath
        Path to the temp file directory for AD configuration
    .PARAMETER CASetupScriptUrl
        Certification Authority setup script download URL
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string] $OUName,
        [Parameter(Mandatory = $true)]
        [string] $UserGroupName,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainFQDN,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainUsername,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainAdminPassword,
        [Parameter(Mandatory = $true)]
        [string] $AdDefaultUserPassword,
        [Parameter(Mandatory = $true)]
        [string] $CitrixModulesPath,
        [Parameter(Mandatory = $true)]
        [string] $CASetupScriptUrl,
        [Parameter(Mandatory = $true)]
        [string] $CACommonName
    )
    
    Import-DSCResource -ModuleName PSDesiredStateConfiguration

    $CADomainNameSuffixArray = New-Object Collections.Generic.List[String]
    foreach ($dc in ($AdDomainFQDN).Split(".")) {
        $CADomainNameSuffixArray.Add("DC=$dc")
    }
    $CADomainNameSuffix = $CADomainNameSuffixArray -join ","

    $CASetupScriptPath = "$CitrixModulesPath\Install-ADCertificationAuthority.ps1"
    $logFilePath = "$($CitrixModulesPath)\ActiveDirectorySetup.log"

    $ADCredentials = New-Object pscredential -ArgumentList ([pscustomobject]@{
            UserName = "$ADDomainFQDN\$ADDomainUsername"
            Password = (ConvertTo-SecureString "$($AdDomainAdminPassword)" -AsPlainText -Force)[0]
        })
    
    Node localhost {
        LocalConfigurationManager {
            ActionAfterReboot  = "ContinueConfiguration"
            RefreshMode        = "Push"
            RebootNodeIfNeeded = $true
            ConfigurationMode  = "ApplyOnly"
        }
    
        #region Setup Pre-requisite for Domain Controller
        Registry DisableAllowNT4Crypto {
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            ValueName = "AllowNT4Crypto"
            ValueData = "0"
        }

        File CitrixModules {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = $CitrixModulesPath
        }

        Script DownloadCASetupScript {
            GetScript  = {
            }

            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DownloadCASetupScript] Downloading the $($using:CASetupScriptPath)."

                try {
                    Invoke-WebRequest -Uri $using:CASetupScriptUrl -OutFile $using:CASetupScriptPath
                }
                catch {
                    Remove-Item $using:CASetupScriptPath -Force
                }
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadCASetupScript] Check if the $($using:CASetupScriptPath) is already downloaded."
                Test-Path -Path $using:CASetupScriptPath
            }
        }

        #region Make the AD Domain Controller discoverable on VNet and Domain
        Script EnableNetworkDiscovery {   
            GetScript  = {
            }
    
            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnableNetworkDiscovery] Enabling Network Discovery for Private and Domain Networks"
                netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
            }
    
            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnableNetworkDiscovery] Checking if Network Discovery has been enabled"
                (Get-NetFirewallRule -DisplayGroup 'Network Discovery' -Enabled False -ErrorAction SilentlyContinue).Count -EQ 0
            }
        }
        #endregion
        
        #endregion

        #region Install AD Domain Services and Management Tools
        WindowsFeatureSet ADDSInstall {
            DependsOn = @("[Registry]DisableAllowNT4Crypto", "[File]CitrixModules", "[Script]DownloadCASetupScript", "[Script]EnableNetworkDiscovery")

            Name      = @("AD-Domain-Services", "GPMC", "RSAT-AD-AdminCenter", "RSAT-ADDS", "RSAT-ADDS-Tools")
            Ensure    = "Present"
        }
        #endregion
    
        #region Install AD Domain Service Forest, setup AD domain, and AD Domain Admin
        Script SetupAdDomain {
            DependsOn  = "[WindowsFeatureSet]ADDSInstall"
    
            GetScript  = {
            }
    
            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetupAdDomain] Setting up Active Directory Domain Service Forest."
                Install-ADDSForest -SkipPreChecks -DomainName $using:AdDomainFQDN -InstallDNS -Force -SafeModeAdministratorPassword (ConvertTo-SecureString "$($using:AdDomainAdminPassword)" -AsPlainText -Force)[0]
                Restart-Computer -Force
                # Add 120 seconds padding to complete restart
                Start-Sleep 120
            }
    
            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-SetupAdDomain] Testing if Active Directory Domain Service Forest has already been setup."
                return [boolean](Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")
            }
        }
        #endregion

        #region Ensure ADWS is up and running
        Script EnsureADWSRunning {
            DependsOn            = "[Script]SetupAdDomain"
            
            PsDscRunAsCredential = $ADCredentials
        
            GetScript            = {
            }
            
            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnsureADWSRunning] Check if Active Directory Web Service is up and running."
                Start-Service -Name ADWS 
                $adwsRunning = $false
                $retryCount = 0
                while ((-not $adwsRunning) -and $retryCount -le 5) {
                    try {
                        Get-ADForest
                        $adwsRunning = $true
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnsureADWSRunning] Active Directory Web Service is not up and running yet. Retry count: $retryCount"
                        Start-Sleep -Seconds 120
                    }
                    finally {
                        $retryCount++
                    }
                }

                if ($adwsRunning){
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnsureADWSRunning] Active Directory Web Service is up and running now."
                }
            }
            
            TestScript           = {
                return $false
            }
        }
        #endregion

        #region Configure Active Directory Certification Service  
        Script InstallCertAuthority {
            DependsOn  = "[Script]EnsureADWSRunning"
        
            GetScript  = {
            }
            
            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallCertAuthority] Running $($using:CASetupScriptPath) script to setup AD Certification Service."
                $argumentList = @(
                    "-file $($using:CASetupScriptPath)",
                    "-CAName $($using:CACommonName)",
                    "-CADomainNameSuffix $($using:CADomainNameSuffix)",
                    "-CAType `"Enterprise Root`"",
                    "-LogFilePath $($using:logFilePath)"
                )
                Start-Process powershell.exe -ArgumentList $argumentList -Wait
            }
            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallCertAuthority] Checking if AD Certification Service has already been setup in the Active Directory Domain Controller."
        
                $CertConfig = New-Object -ComObject CertificateAuthority.Config
                try {
                    $ExistingDetected = $CertConfig.GetConfig(3)
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallCertAuthority] The CA has not been installed, start install CA."
                    return $false
                }   
                if ($ExistingDetected) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallCertAuthority] Certificate Services are already installed on this computer. Only one Certification Authority instance per computer is supported."
                    return $true
                }
            }
        }
        #endregion

        #region Add AD Domain Users
        # Delivery Group user assignment will depend on the custom script extension

        Script AddDomainUsers {
            DependsOn            = "[Script]InstallCertAuthority"
    
            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }
    
            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddDomainUsers] Creating new users in the Active Directory Domain."
                1..10 | ForEach-Object { $_.ToString().Padleft(4, '0') } | ForEach-Object { New-ADUser -Name "user$_" -ChangePasswordAtLogon $false -Enabled $true -PasswordNeverExpires $true -AccountPassword (ConvertTo-SecureString "$($using:AdDefaultUserPassword)" -AsPlainText -Force) -UserPrincipalName "user$($_)@$($using:AdDomainFQDN)" }
            }
    
            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddDomainUsers] Check if new users are already added to the Active Directory Domain."
                $adUserNames = (Get-ADUser -Filter 'Name -like "user*"').Name
                if ($null -eq $adUserNames) {
                    return $false
                }
                $allDesiredUsernames = 1..10 | ForEach-Object { $_.ToString().Padleft(4, '0') } | ForEach-Object { "user$_" }
                return ($null -eq (Compare-Object $allDesiredUsernames $adUserNames | Where-Object { $_.sideindicator -eq "<=" }))
            }
        }

        Script AddOrganizationalUnit {
            DependsOn            = "[Script]InstallCertAuthority"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }
            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddOrganizationalUnit] Adding new Organizational Unit and User Group."
                New-ADOrganizationalUnit -Name $using:OUName -Path $using:CADomainNameSuffix

            }
            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddOrganizationalUnit] Check if the desired Organizational Unit is already added."
                try {
                    Get-ADOrganizationalUnit -Identity "OU=$using:OUName,$using:CADomainNameSuffix"
                    return $true
                }
                catch {
                    return $false
                }
            }
        }

        Script AddUserGroup {
            DependsOn            = @("[Script]AddDomainUsers", "[Script]AddOrganizationalUnit")

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }
            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddUserGroup] Adding new User Group $($using:UserGroupName)."
                New-ADGroup -Name $using:UserGroupName -GroupCategory Security -GroupScope Global -DisplayName $using:UserGroupName -Path "OU=$using:OUName,$using:CADomainNameSuffix"  
            }
            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddUserGroup] Check if the desired User Group is already added."
                try {
                    $adGroup = Get-ADGroup -Identity $using:UserGroupName
                    if ($null -eq $adGroup) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddUserGroup] User group returned is null, will create the desired user group $($using:UserGroupName)."
                        return $false
                    }
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddUserGroup] User group $($using:UserGroupName) already exists."
                    return $true
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddUserGroup] Error encountered when checking if the desired User Group is already added: $($_)"
                    return $false
                }
            }
        }

        Script AddUsersToUserGroup {
            DependsOn            = "[Script]AddUserGroup"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }
            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddUsersToUserGroup] Adding users to the User Group $($using:UserGroupName)."
                5..10 | ForEach-Object { $_.ToString().Padleft(4, '0') } | ForEach-Object { Add-ADGroupMember -Identity $using:UserGroupName -Members "user$_" }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddUsersToUserGroup] Completed adding users to the User Group $($using:UserGroupName)."
            }
            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddUsersToUserGroup] Check if users are added to the desired User Group."
                try {
                    $allDesiredUsernames = 5..10 | ForEach-Object { $_.ToString().Padleft(4, '0') } | ForEach-Object { "user$_" }
                    $members = Get-ADGroupMember -Identity $using:UserGroupName -Recursive | Select-Object -ExpandProperty Name
                    foreach ($user in $allDesiredUsernames) {
                        if (-not ($members -contains $user)) {
                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddUsersToUserGroup] Found an user not added to user group, will proceed to add action"
                            return $false
                        }
                    }
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddUsersToUserGroup] All specified users are added to the desired User Group."
                    return $true
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddUsersToUserGroup] Issue encountered when checking if users are added to the desired User Group: $($_)"
                    return $false
                }
            }
        }
        #endregion
    }
}

