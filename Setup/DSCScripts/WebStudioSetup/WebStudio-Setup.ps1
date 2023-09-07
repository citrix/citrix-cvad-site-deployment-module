Configuration WebStudioSetup
{
    param (
        [Parameter(Mandatory = $true)]
        [string] $ADDomainFQDN,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainUsername,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainPassword,
        [Parameter(Mandatory = $true)]
        [string] $CVADInstallerDownloadUrl,
        [Parameter(Mandatory = $true)]
        [string] $CVADInstallerMd5Hash,
        [Parameter(Mandatory = $true)]
        [string] $DDCDNSName,
        [Parameter(Mandatory = $true)]
        [string] $CitrixModulesPath,
        [Parameter(Mandatory = $true)]
        [string] $CAServerHostName,
        [Parameter(Mandatory = $true)]
        [string] $CACommonName,
        [Parameter(Mandatory = $true)]
        [string] $RequestCertFromCAScriptUrl,
        [Parameter(Mandatory = $true)]
        [string] $RequestCertTemplateUrl

    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    $logFilePath = "$($CitrixModulesPath)\WebStudio_Installation.log"
    $cvadInstallerOutputPath = "$($CitrixModulesPath)\CVAD_Installer.iso"
    $xenDesktopServerSetupPath = "$($CitrixModulesPath)\x64\XenDesktop Setup\XenDesktopServerSetup.exe"
    $registryPath_CvadAutomation = "HKLM:\SOFTWARE\Citrix\Automation\"
    $registryKey_CvadIsoFileHash = "IsoFileHash"

    # Credential Object for Active Directory Admin
    $ADCredentials = New-Object pscredential -ArgumentList ([pscustomobject]@{
        UserName = "$ADDomainFQDN\$ADDomainUsername"
        Password = (ConvertTo-SecureString $ADDomainPassword -AsPlainText -Force)[0]
    })
    # SSL Certificate Setup
    $RequestCertFromCAScriptPath = "$CitrixModulesPath\Request-CertificateFromCA.ps1"
    $RequestCertTemplatePath = "$CitrixModulesPath\RequestTemplate.inf"
    $IISCertThumbprintFilePath = "$CitrixModulesPath\IISCertThumbprint"
    
    Node localhost {

        LocalConfigurationManager {
            ActionAfterReboot  = "ContinueConfiguration"
            RefreshMode        = "Push"  
            RebootNodeIfNeeded = $true
            ConfigurationMode  = "ApplyOnly" #TODO: Changing to ApplyAndMonitor or ApplyAndAutocorrect will expose secret in mof file
        }

        #region Initial Setup and Domain Join
        WindowsFeature IISInstall {
            Ensure = "Present"
            Name   = "Web-Server" 
        }
        
        File CitrixModules {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = $CitrixModulesPath
        }

        Registry EnsureCvadDownloadRegistryPresents {
            Key       = $registryPath_CvadDownload
            ValueName = $registryKey_CvadIsoFileHash
            ValueType = "String"
            Ensure    = "Present"
        }

        #region Make the AD Domain Controller discoverable on VNet and Domain
        Script EnableNetworkDiscovery {
            DependsOn            = "[File]CitrixModules"
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

        Script DomainJoin {
            DependsOn  = @("[WindowsFeature]IISInstall", "[File]CitrixModules", "[Registry]EnsureCvadDownloadRegistryPresents", "[Script]EnableNetworkDiscovery")

            GetScript  = {
            }

            SetScript  = {
                $cred = New-Object pscredential -ArgumentList ([pscustomobject]@{
                        UserName = "$using:ADDomainFQDN\$using:ADDomainUsername"
                        Password = (ConvertTo-SecureString $using:ADDomainPassword -AsPlainText -Force)[0]
                    })
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DomainJoin] Joining VM to domain $($using:ADDomainFQDN)"
                Add-Computer -DomainName $using:ADDomainFQDN -Credential $cred
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DomainJoin] Domain Join Complete"
                Restart-Computer -Force
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DomainJoin] Testing if VM is joined to domain $($using:ADDomainFQDN)"
                try {
                    Test-ComputerSecureChannel -Server $using:ADDomainFQDN
                    return $true
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DomainJoin] VM is not joined to domain $($using:ADDomainFQDN). Attempting to join."
                    return $false
                }
            }
        }
        #endregion
        
        #region CVAD Core Component Installation
        Script CVADDownload {
            DependsOn            = "[Script]DomainJoin"

            GetScript            = {
            }

            SetScript            = {
                $retryCount = 0
                while ($retryCount -lt 3) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] Downloading CVAD ISO File"
                    Start-BitsTransfer -Source $using:CVADInstallerDownloadUrl -Destination $using:cvadInstallerOutputPath

                    # Checking MD5 hash of the downloaded ISO file
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] Calculating MD5 hash for downloaded CVAD ISO File"
                    $generatedHash = Get-FileHash -Algorithm MD5 -Path $using:cvadInstallerOutputPath
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] CVAD ISO File MD5 Hash calculation completed with hash value $($generatedHash.Hash). Expected hash value: $($using:CVADInstallerMd5Hash)"
                    if ($generatedHash.Hash -eq $using:CVADInstallerMd5Hash) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] Sucessfully downloaded CVAD ISO File. IsoFileHash registry key is set with value $($generatedHash.Hash)"
                        Set-ItemProperty -Path $using:registryPath_CvadAutomation -Name $using:registryKey_CvadIsoFileHash -Value $generatedHash.Hash
                        break;
                    }
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] CVAD ISO file hash did not match. Next Retry Count: $($retryCount + 1)"
                    Remove-Item -Path $using:cvadInstallerOutputPath -Force
                    $retryCount++
                }
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] Checking if CVAD ISO File was successfully downloaded"
                if (Test-Path -Path $using:cvadInstallerOutputPath) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] A registry key already exists for the hash calculation of the CVAD ISO file $($using:cvadInstallerOutputPath)."
                    $storedHashValue = Get-ItemPropertyValue $using:registryPath_CvadAutomation -Name $using:registryKey_CvadIsoFileHash
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] CVAD ISO file hash calculation registry key has value $($storedHashValue). Expected MD5 hash: $($using:CVADInstallerMd5Hash)"
                    if ($storedHashValue -eq $using:CVADInstallerMd5Hash) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] Stored hash matches expected hash, continuing to the next step."
                        return $true
                    }
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] CVAD ISO file hash calculation registry value does not match expected MD5 hash."
                    # Remove the downloaded file and return false
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] Generated hash does not match expected hash, removing downloaded CVAD ISO File."
                    Remove-Item -Path $using:cvadInstallerOutputPath -Force
                }
                return $false
            }
        }

        Script MountISO {
            DependsOn            = '[Script]CVADDownload'

            GetScript            = {
            }

            SetScript            = {
                
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-MountISO] Mounting the CVAD ISO File to a drive"
                $mountResult = Mount-DiskImage -ImagePath $using:cvadInstallerOutputPath -PassThru 
                $driveLetter = ($mountResult | Get-Volume).DriveLetter

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-MountISO] Copying files to the CitrixModules directory"
                Copy-Item -Path "${driveLetter}:\*" -Destination "$($using:CitrixModulesPath)\" -recurse -Force
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-MountISO] Checking if XenDesktopServerSetup.exe is present within Citrix Modules"
                Test-Path -Path $using:xenDesktopServerSetupPath  
            }
        }

        #region WebStudio Installation
        Script InstallWebStudio {
            DependsOn            = '[Script]MountISO'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallWebStudio] Starting web studio"
                Start-Process -FilePath $using:xenDesktopServerSetupPath -ArgumentList "/components WEBSTUDIO /controllers $using:ddcDNSName /ignore_hw_check_failure /no_remote_assistance /noreboot /configure_firewall /passive" -Wait
                Restart-Computer
            }

            TestScript           = {
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallWebStudio] Checking if Web Studio have been installed"
                    Get-Item 'HKLM:SOFTWARE\Citrix\MetaInstall\' -ErrorAction Stop | Get-ItemPropertyValue -Name ExitCode | ForEach-Object { $_ -eq 0 } 

                    $regKeyResult = Get-Item "HKLM:SOFTWARE\Citrix\WebStudio\" -ErrorAction SilentlyContinue
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallWebStudio] Reg Key test result: $($regKeyResult)"
                    return  ($null -ne $regKeyResult)
                }
                catch {
                    return $false
                }  
            }
        }
        #endregion

        #region Configure IIS SSL Encryption
        Script DownloadCertificateRequestScript {
            DependsOn  = '[Script]InstallWebStudio'

            GetScript  = {
            }

            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DownloadCertificateRequestScript] Downloading Request-CertificateFromCA.ps1 file"
                Invoke-WebRequest -Uri $using:RequestCertFromCAScriptUrl -OutFile $using:RequestCertFromCAScriptPath
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadCertificateRequestScript] Checking if Request-CertificateFromCA.ps1 file already exists"
                Test-Path -Path $using:RequestCertFromCAScriptPath
            }
        }

        Script DownloadCertificateRequestTemplate {
            DependsOn  = '[Script]DownloadCertificateRequestScript'

            GetScript  = {
            }

            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DownloadCertificateRequestTemplate] Downloading RequestTemplate.inf file"
                Invoke-WebRequest -Uri $using:RequestCertTemplateUrl -OutFile $using:RequestCertTemplatePath
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadCertificateRequestTemplate] Checking if RequestTemplate.inf file already exists"
                Test-Path -Path $using:RequestCertTemplatePath
            }
        }

        Script RequestCertificateFromCA {
            DependsOn            = '[Script]DownloadCertificateRequestTemplate'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-RequestCertificateFromCA] Requesting domain certificate from certification authority"

                $argumentList = @(
                    "-File `"$($using:RequestCertFromCAScriptPath)`"",
                    "-FriendlyName `"*.$($using:ADDomainFQDN)`"",
                    "-Subject `"*.$($using:ADDomainFQDN)`"",
                    "-CAServer `"$($using:CAServerHostName).$($using:ADDomainFQDN)`"",
                    "-CAName `"$($using:CACommonName)`"",
                    "-SAN `"DNS=*.$($using:ADDomainFQDN)`"",
                    "-ExportThumbprint",
                    "-ThumbprintFilePath `"$($using:IISCertThumbprintFilePath)`"",
                    "-LogFilePath `"$($using:logFilePath)`""
                )

                Start-Process powershell.exe -ArgumentList $argumentList -Wait
               
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-RequestCertificateFromCA] Checking if certificate request from certification authority is already completed"
                Test-Path -Path $using:IISCertThumbprintFilePath
            }
        }

        Script BindRequestedCertToIIS {
            DependsOn            = '[Script]RequestCertificateFromCA'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Remove-Module IISAdministration -ErrorAction SilentlyContinue
                Remove-Module WebAdministration -ErrorAction SilentlyContinue

                Import-Module IISAdministration -ErrorAction SilentlyContinue

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-BindRequestedCertToIIS] Remove existing https port 443 binding"
                Remove-IISSiteBinding -Name "Default Web Site" -Protocol "https" -BindingInformation "*:443:" -Confirm:$False -ErrorAction SilentlyContinue

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-BindRequestedCertToIIS] Read requested certificate thumbprint value from file"
                $thumbprint = Get-Content $using:IISCertThumbprintFilePath -Tail 1

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-BindRequestedCertToIIS] Bind certificate to IIS with protocol https port 443"
                New-IISSiteBinding -Name "Default Web Site" -Protocol "https" -BindingInformation "*:443:" -CertificateThumbPrint $thumbprint -CertStoreLocation "Cert:\LocalMachine\My"

                Stop-IISSite -Name "Default Web Site" -Confirm:$False
                Start-IISSite -Name "Default Web Site"

                Remove-Module IISAdministration -ErrorAction SilentlyContinue
            }

            TestScript           = {
                Remove-Module IISAdministration -ErrorAction SilentlyContinue
                Remove-Module WebAdministration -ErrorAction SilentlyContinue

                Import-Module WebAdministration -ErrorAction SilentlyContinue

                $sites = Get-ChildItem IIS:SSLBindings | Where-Object { ($_.Sites -eq "Default Web Site") -and ($_.Port -eq 443) }
                Remove-Module WebAdministration -ErrorAction SilentlyContinue
                if ((-not $sites) -or (-not $sites.Thumbprint)) {
                    return $false
                }
                if (($sites[0].Thumbprint -ne (Get-Content $using:IISCertThumbprintFilePath))) {
                    return $false
                }
                return $true
            }
        }
        #endregion

        #region Disable and Remove local users
        Script DisableAndRemoveLocalUser {
            DependsOn            = "[Script]BindRequestedCertToIIS"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DisableAndRemoveLocalUser] Disabling and removing local users"
                    $EnabledLocalUsers = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled }
                    $EnabledLocalUsers | ForEach-Object { Disable-LocalUser -InputObject $_ -ErrorAction SilentlyContinue }
                    $EnabledLocalUsers | ForEach-Object { Remove-LocalUser -InputObject $_ -ErrorAction SilentlyContinue }
                }
                catch { }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DisableAndRemoveLocalUser] Local users disabled and removed"
            }

            TestScript           = {
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DisableAndRemoveLocalUser] Checking if there is any local user to be removed"
                    $EnabledLocalUsers = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled }
                    return (-not $EnabledLocalUsers)
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DisableAndRemoveLocalUser] No local user found"
                }
            }
        }
        #endregion
    }
}