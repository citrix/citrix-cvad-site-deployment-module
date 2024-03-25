# Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.
Configuration CVADInstallation
{
    param (
        #region General Settings for DSC script
        [Parameter(Mandatory = $true)]
        [string] $CitrixModulesPath,
        [Parameter(Mandatory = $false)]
        [string] $RemoveCitrixModuleAfterSetup = "true",
        #endregion

        #region CVAD Installation Parameters
        [Parameter(Mandatory = $false)]
        [string] $ComponentList = "", #Comma separated list of cvad component to be installed in ddc vm
        [Parameter(Mandatory = $true)]
        [string] $CVADInstallerDownloadUrl,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $CVADInstallerMd5Hash,
        [Parameter(Mandatory = $true)]
        [string] $DefaultControllerName,
        #endregion CVAD Installation Parameters

        #region AD Domain Join Parameters
        [Parameter(Mandatory = $true)]
        [string] $AdDomainControllerPrivateIp,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainFQDN,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainUsername,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainPassword,
        #endregion AD Domain Join Parameters

        #region Certificate Request Parameters
        [Parameter(Mandatory = $true)]
        [string] $CAServerHostName,
        [Parameter(Mandatory = $true)]
        [string] $CACommonName,
        [Parameter(Mandatory = $true)]
        [string] $RequestCertFromCAScriptUrl,
        [Parameter(Mandatory = $true)]
        [string] $RequestCertTemplateUrl,
        # Used for License Server setup
        [Parameter(Mandatory = $false)]
        [string] $LicenseCertPassword,
        #endregion Certificate Request Parameters

        #region Controller and Site Setup Parameters
        [Parameter(Mandatory = $false)]
        [string] $SiteName,
        [Parameter(Mandatory = $false)]
        [string] $SetupIndependentSqlVM = "false",
        [Parameter(Mandatory = $false)]
        [string] $DatabaseServerName,
        #endregion Controller and Site Setup Parameters

        #region CVAD Licensing Parameters
        [Parameter(Mandatory = $false)]
        [string] $LicenseServerAddress,
        [Parameter(Mandatory = $false)]
        [string] $LicenseServerPort,
        [Parameter(Mandatory = $false)]
        [string] $ProductCode,
        [Parameter(Mandatory = $false)]
        [string] $ProductEdition,
        # Optional License File
        [Parameter(Mandatory = $false)]
        [string] $LicenseFileUri = "",
        #endregion CVAD Licensing Parameters

        #region StoreFront Setup Parameters
        [Parameter(Mandatory = $false)]
        [string] $IncludeStoreFront = "false",
        [Parameter(Mandatory = $false)]
        [string] $StoreFrontHostBaseAddress,
        [Parameter(Mandatory = $false)]
        [string] $StoreVirtualPath,
        [Parameter(Mandatory = $false)]
        [string] $SFDeliveryControllerPort, 
        [Parameter(Mandatory = $false)]
        [string] $FarmType,
        [Parameter(Mandatory = $false)]
        [string] $FarmName,
        [Parameter(Mandatory = $false)]
        [string] $AreDDCServersLoadBalanced,
        [Parameter(Mandatory = $false)]
        [string] $SFStoreFriendlyName
        #endregion StoreFront Setup Parameters
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    # Registries
    $registryPath_CvadAutomation = "HKLM:\SOFTWARE\Citrix\Automation\"
    $registryKey_CvadIsoFileHash = "IsoFileHash"

    $registryPath_SqlServerModuleInstallation = "HKLM:SOFTWARE\Citrix\SqlServerModuleInstallation"
    $registryEntry_SqlServerModuleRetries = "SystemRebootCount"

    $registryPath_CvadDeliveryServices = "HKLM:\SOFTWARE\Citrix\DeliveryServices"

    # CVAD Component Variables
    $cvadInstallerOutputPath = "$($CitrixModulesPath)\CVAD_Installer.iso"
    $logFilePath = "$($CitrixModulesPath)\CVAD_Installation.log"
    $xenDesktopServerSetupPath = "$($CitrixModulesPath)\x64\XenDesktop Setup\XenDesktopServerSetup.exe"
    $componentsToInstall = $ComponentList.Split(",")
    $LicenseFileDownloadPath = "$CitrixModulesPath\CVAD_License.lic"
    $WebStudioConfiguratorPath = "C:\Program Files\Citrix\Web Studio\Tool\StudioConfig.exe"
    $ControllerHostName = "$($DefaultControllerName).$($ADDomainFQDN)"
    
    # Storefront
    $InstallStoreFront = [System.Convert]::ToBoolean($IncludeStoreFront)
    $authenticationVirtualPath = "$($StoreVirtualPath.TrimEnd('/'))Auth"
    $receiverVirtualPath = "$($StoreVirtualPath.TrimEnd('/'))Web"
    $storeFrontModules = @("Citrix.StoreFront", "Citrix.StoreFront.Stores", "Citrix.StoreFront.Authentication", "Citrix.StoreFront.WebReceiver")

    # MS SQL Database
    $setupIndependentSqlVM = [System.Convert]::ToBoolean($SetupIndependentSqlVM)
    $databaseConnectionStringPrefix = "Server=$($DatabaseServerName);Integrated Security=True;Encrypt=True;TrustServerCertificate=True;Database="
    $masterDatabaseName = "master"
    $siteDatabaseName = "Citrix$($SiteName)Site"
    $loggingDatabaseName = "Citrix$($SiteName)Logging"
    $monitoringDatabaseName = "Citrix$($SiteName)Monitoring"

    # Credential Object for Active Directory Admin
    $ADCredentials = New-Object pscredential -ArgumentList ([pscustomobject]@{
            UserName = "$ADDomainFQDN\$ADDomainUsername"
            Password = (ConvertTo-SecureString "$($ADDomainPassword)" -AsPlainText -Force)[0]
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
            ConfigurationMode  = "ApplyOnly"
        }

        #region Initialization
        File CitrixModules {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = $CitrixModulesPath
        }

        Registry EnsureCvadDownloadRegistryPresents {
            Key       = $registryPath_CvadAutomation
            ValueName = $registryKey_CvadIsoFileHash
            ValueType = "String"
            Ensure    = "Present"
        }

        # Adding registry key to track retry attempt for Sql Server module installtion
        Script CreateSqlServerModuleRegistryKey {
            GetScript  = {
            }

            TestScript = {
                Test-Path -Path $using:registryPath_SqlServerModuleInstallation
            }

            SetScript  = {
                # SQL module is only required if Controller component will be installed on the machine
                if ($using:componentsToInstall -contains "controller") {
                    New-Item -Path $using:registryPath_SqlServerModuleInstallation -Force
                    New-ItemProperty -Path $using:registryPath_SqlServerModuleInstallation -Name $using:registryEntry_SqlServerModuleRetries -Value 0
                }
                else {
                    return $true
                }
            }
        }

        Script EnsureDomainControllerReachability {
            DependsOn  = '[Script]CreateSqlServerModuleRegistryKey'

            GetScript  = {
            }

            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnsureDomainControllerReachability] Domain controller reachability test failed."
                throw "Unable to reach Active Directory Domain Controller"
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnsureDomainControllerReachability] Checking if Domain Controller is reachable."
                $connectivityResult = $false
                $retryCount = 0
                $maxRetryCount = 5
                while (($retryCount -lt $maxRetryCount) -and (-not $connectivityResult)) {
                    $connectivityResult = Test-Connection $using:AdDomainControllerPrivateIp -Count 1 -Quiet
                    Start-Sleep -Seconds 30
                    $retryCount++
                }
                return $connectivityResult
            }
        }

        Script DomainJoin {
            DependsOn  = '[Script]EnsureDomainControllerReachability'

            GetScript  = {
            }

            SetScript  = {
                $cred = New-Object pscredential -ArgumentList ([pscustomobject]@{
                        UserName = "$using:ADDomainFQDN\$using:ADDomainUsername"
                        Password = (ConvertTo-SecureString "$($using:ADDomainPassword)" -AsPlainText -Force)[0]
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

        Script EnableNetworkDiscovery {
            DependsOn  = @("[Registry]EnsureCvadDownloadRegistryPresents", "[Script]DomainJoin")
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
        #endregion Initialization
        
        #region CVAD download and component installation
        Script CVADDownload {
            DependsOn  = "[Script]EnableNetworkDiscovery"

            GetScript  = {
            }

            SetScript  = {
                $retryCount = 0
                while ($retryCount -lt 3) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] Downloading CVAD ISO File"
                    Start-BitsTransfer -Source $using:CVADInstallerDownloadUrl -Destination $using:cvadInstallerOutputPath

                    # Checking MD5 hash of the downloaded ISO file
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] Calculating MD5 hash for downloaded CVAD ISO File"
                    $generatedHash = Get-FileHash -Algorithm MD5 -Path $using:cvadInstallerOutputPath
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] CVAD ISO File MD5 Hash calculation completed with hash value $($generatedHash.Hash). Expected hash value: $($using:CVADInstallerMd5Hash)"
                    if (-not $using:CVADInstallerMd5Hash) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CVADDownload] Sucessfully downloaded CVAD ISO File. MD5 value not provided. IsoFileHash registry key is set with value $($generatedHash.Hash)"
                        break;
                    }
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

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] Checking if CVAD ISO File was successfully downloaded"
                if (Test-Path -Path $using:cvadInstallerOutputPath) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] A registry key already exists for the hash calculation of the CVAD ISO file $($using:cvadInstallerOutputPath)."
                    $storedHashValue = Get-ItemPropertyValue $using:registryPath_CvadAutomation -Name $using:registryKey_CvadIsoFileHash
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] CVAD ISO file hash calculation registry key has value $($storedHashValue). Expected MD5 hash: $($using:CVADInstallerMd5Hash)"
                    if (-not $using:CVADInstallerMd5Hash) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CVADDownload] CVAD installer ISO file detected. MD5 value not provided. Skip verification..."
                        return $true
                    }
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
            DependsOn  = '[Script]CVADDownload'

            GetScript  = {
            }

            SetScript  = {
                
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-MountISO] Mounting the CVAD ISO File to a drive"
                $mountResult = Mount-DiskImage -ImagePath $using:cvadInstallerOutputPath -PassThru 
                $driveLetter = ($mountResult | Get-Volume).DriveLetter

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-MountISO] Copying files to the CitrixModules directory"
                Copy-Item -Path "${driveLetter}:\*" -Destination "$($using:CitrixModulesPath)\" -recurse -Force
                Get-Volume -DriveLetter $driveLetter | Get-DiskImage | Dismount-DiskImage
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-MountISO] Checking if XenDesktopServerSetup.exe is present within Citrix Modules"
                Test-Path -Path $using:xenDesktopServerSetupPath  
            }
        }

        Script InstallNetFramework48 {
            DependsOn  = '[Script]MountISO'

            GetScript  = {
            }

            SetScript  = {
                $installerPath = "$($using:CitrixModulesPath)\Support\DotNet48\ndp48-x86-x64-allos-enu.exe"

                # execute file
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallNetFramework48] Installing .Net Framework"
                Start-Process -FilePath $installerPath -ArgumentList "/quiet /log $($using:CitrixModulesPath)\net_framework_installation.log" -Wait
                Start-Sleep -Seconds 30
            }

            TestScript = {
                if ($using:componentsToInstall -notcontains "licenseserver") {
                    return $true
                }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallNetFramework48] Checking if .Net Framework 4.8 is already installed"
                Get-ChildItem 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' |
                Get-ItemPropertyValue -Name Release |
                ForEach-Object { $_ -ge 528049 } 
            }
        }

        Script InstallCVADComponents {
            DependsOn            = "[Script]InstallNetFramework48"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallCVADComponents] Running the CVAD Installer"
                $cvadInstallationArgs = "/components $using:ComponentList /ignore_hw_check_failure /configure_firewall /no_remote_assistance /noreboot /noresume /passive"
                if ($using:setupIndependentSqlVM -eq $true) {
                    $cvadInstallationArgs += " /nosql"
                }
                
                if ($using:componentsToInstall -notcontains "controller") {
                    $cvadInstallationArgs += " /controllers $using:ControllerHostName"
                }
                
                Start-Process -FilePath $using:xenDesktopServerSetupPath -ArgumentList $cvadInstallationArgs -Wait
                
                Restart-Computer  # We don't want to add the -Force argument as CVAD installer will try to restart the computer. Duplicated restart request could fail the DSC script
            }

            TestScript           = {
                if (-not $using:ComponentList) {
                    return $true
                }
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallCVADComponents] Checking if CVAD components have been installed"
                    Get-Item 'HKLM:SOFTWARE\Citrix\MetaInstall\' -ErrorAction Stop | Get-ItemPropertyValue -Name ExitCode | ForEach-Object { $_ -eq 0 } 
                }
                catch {
                    return $false
                }
            }
        }
        #endregion CVAD download and component installation

        #region Controller Configuration and Site Setup
        Script ImportSqlServer {
            DependsOn            = @("[Script]CreateSqlServerModuleRegistryKey", "[Script]InstallCVADComponents")

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $retryCount = 0
                $maxRetryCount = 3
                while ($retryCount -lt $maxRetryCount) {
                    try {
                        try {
                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] Checking if SQLServer module has already been installed."
                            Get-InstalledModule -Name SqlServer -ErrorAction Stop
                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] SqlServer module found. Skipping installation."
                        }
                        catch {
                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] Uninstalling SQLPS Module"
                            Uninstall-Module SQLPS -Force -ErrorAction SilentlyContinue

                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] Set PSGallery with Trusted Installation Policy"
                            Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] Installing SqlServer module with retry $($retryCount)"
                            Install-Module "SqlServer" -AllowClobber -Force -ErrorAction Stop -Scope CurrentUser
                        }
                        finally {
                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] Importing SqlServer module into scope with retry $($retryCount)"
                            Import-Module "SqlServer" -Force
                        }
                        break
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] Inside catch block with error. Increasing retry count. Error: $($_)"
                        $retryCount++
                    }
                }
                if ($retryCount -eq $maxRetryCount) {
                    try {
                        # Get registry key for reboot attempts. If it reaches 3 throw error
                        $rebootAttempts = Get-Item $using:registryPath_SqlServerModuleInstallation -ErrorAction Stop | Get-ItemPropertyValue -Name $using:registryEntry_SqlServerModuleRetries -ErrorAction Stop
                        if ($rebootAttempts -ge 3) {
                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] SqlServer module failed to be imported after $($rebootAttempts) reboot attempts"
                            throw "[Set-ImportSqlServer] Failed to import SqlServer module after $($rebootAttempts) reboot attempts."
                        }
                        else {
                            # Increment the registry key value and restart the system
                            $rebootAttempts += 1

                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] Setting $($using:registryEntry_SqlServerModuleRetries) to $($rebootAttempts)"
                            Set-ItemProperty -Path $using:registryPath_SqlServerModuleInstallation -Name $using:registryEntry_SqlServerModuleRetries -Value $rebootAttempts

                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] $($using:registryEntry_SqlServerModuleRetries) successfully updated. Restarting the system."
                            Restart-Computer -Force
                        }
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportSqlServer] Could not get/update value for registry entry: $($using:registryEntry_SqlServerModuleRetries). Error: $($_)"
                        throw "[Set-ImportSqlServer] Could not get/update value for registry entry: $($using:registryEntry_SqlServerModuleRetries). Error: $($_)"
                    }  
                }
            }

            TestScript           = {
                # Add padding time between SQL module import and CVAD installation to avoid pending restart causing issue
                Start-Sleep -Seconds 30
                if ($using:componentsToInstall -notcontains "controller") {
                    return $true
                }
                
                # SQL module is only required if Controller is installed and expected to be configured
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportSqlServer] Checking to see if SqlServer module has already been imported"
                $getSqlPsModuleResult = Get-InstalledModule SQLPS -ErrorAction SilentlyContinue
                return ((-not $getSqlPsModuleResult) -and ((Get-Module -Name "SqlServer" -ErrorAction SilentlyContinue | Measure-Object).Count -NE 0))

            }
        }

        Script ImportXenDesktopModule {
            DependsOn            = '[Script]ImportSqlServer'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportXenDesktopModule] Importing Citrix.XenDesktop.Admin module into scope"
                Import-Module "Citrix.XenDesktop.Admin" -Force
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "controller") {
                    return $true
                }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportXenDesktopModule] Checking to see if Citrix.XenDesktop.Admin module has already been imported"
                return (Get-Module -Name "Citrix.XenDesktop.Admin" | Measure-Object).Count -NE 0
            }
        }

        Script CheckSqlExpressConnectivity {
            DependsOn            = '[Script]ImportSqlServer'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $retryCount = 0
                $maxRetryCount = 5
                $connectionCheckInterval = 120
                while ($retryCount -lt $maxRetryCount) {
                    try {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CheckSqlExpressConnectivity] Checking connectivity to SQLExpress Server. Retry attempt: $($retryCount)"
                        $connectionString = $using:databaseConnectionStringPrefix + $using:masterDatabaseName
                        $sqlServerStatus = (Get-SqlDatabase -ConnectionString $connectionString -ErrorAction Stop | Measure-Object).Count -NE 0
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CheckSqlExpressConnectivity] Connectivity to SQLExpress Server returned with status $($sqlServerStatus)"
                        break
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CheckSqlExpressConnectivity] Could not connect to SQLExpress Server with error. Will Sleep for $($connectionCheckInterval) seconds and try again. Error: $($_)"
                        $retryCount++
                        Start-Sleep -seconds $connectionCheckInterval
                    }
                }
                if ($retryCount -eq $maxRetryCount) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CheckSqlExpressConnectivity] Failed to connect to SQLExpress datbase after $($retryCount) attempts. Continue to the next step."
                }
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "controller") {
                    return $true
                }
                
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CheckSqlExpressConnectivity] Checking connectivity to SQLExpress Server"
                $connectionString = $using:databaseConnectionStringPrefix + $using:masterDatabaseName
                try {
                    return (Get-SqlDatabase -ConnectionString $connectionString -ErrorAction Stop | Measure-Object).Count -NE 0
                }
                catch {
                    return $false
                }
            }
        }

        Script CreateSiteDatabase {
            DependsOn            = @('[Script]CheckSqlExpressConnectivity', '[Script]ImportXenDesktopModule')

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateSiteDatabase] Creating database: $($using:siteDatabaseName) on MS Sql Server"
                New-XDDatabase -AdminAddress $using:ControllerHostName -SiteName $using:SiteName -Datastore Site -DatabaseServer $using:DatabaseServerName -DatabaseName $using:siteDatabaseName
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "controller") {
                    return $true
                }

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateSiteDatabase] Checking if database: $($using:siteDatabaseName) already exists in the MS Sql Server"
                $connectionString = $using:databaseConnectionStringPrefix + $using:siteDatabaseName
                return (Get-SqlDatabase -ConnectionString $connectionString | Measure-Object).Count -NE 0
            }
        }

        Script CreateLoggingDatabase {
            DependsOn            = @('[Script]CheckSqlExpressConnectivity', '[Script]ImportXenDesktopModule')

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateLoggingDatabase] Creating database: $($using:loggingDatabaseName) on MS Sql Server"
                New-XDDatabase -AdminAddress $using:ControllerHostName -SiteName $using:SiteName -Datastore Logging -DatabaseServer $using:DatabaseServerName -DatabaseName $using:loggingDatabaseName
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "controller") {
                    return $true
                }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateLoggingDatabase] Checking if database: $($using:loggingDatabaseName) already exists in the MS Sql Server"
                $connectionString = $using:databaseConnectionStringPrefix + $using:loggingDatabaseName
                return (Get-SqlDatabase -ConnectionString $connectionString | Measure-Object).Count -NE 0
            }
        }

        Script CreateMonitoringDatabase {
            DependsOn            = @('[Script]CheckSqlExpressConnectivity', '[Script]ImportXenDesktopModule')

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateMonitoringDatabase] Creating database: $($using:monitoringDatabaseName) on MS Sql Server"
                New-XDDatabase -AdminAddress $using:ControllerHostName -SiteName $using:SiteName -Datastore Monitor -DatabaseServer $using:DatabaseServerName -DatabaseName $using:monitoringDatabaseName
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "controller") {
                    return $true
                }

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateMonitoringDatabase] Checking if database: $($using:monitoringDatabaseName) already exists in the MS Sql Server"
                $connectionString = $using:databaseConnectionStringPrefix + $using:monitoringDatabaseName
                return (Get-SqlDatabase -ConnectionString $connectionString | Measure-Object).Count -NE 0
            }
        }

        Script EnsureCitrixHostServiceRunning {
            DependsOn            = @('[Script]CreateSiteDatabase', '[Script]CreateLoggingDatabase', '[Script]CreateMonitoringDatabase')

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Start-Service CitrixHostService -ErrorAction SilentlyContinue
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "controller") {
                    return $true
                }

                return (Get-Service CitrixHostService -ErrorAction SilentlyContinue).Status -eq "Running"
            }
        }

        Script SetupSite {
            DependsOn            = "[Script]EnsureCitrixHostServiceRunning"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetupSite] Setting up Site"
                $newXdSiteRetryCount = 0
                $newXdSiteResult = $false
                while (($newXdSiteRetryCount -le 5) -and (-not $newXdSiteResult)){
                    try {
                        # If Get-XDSite found the existing site
                        try {
                            $site = Get-XDSite -AdminAddress $using:ControllerHostName
                            if ($site) {
                                $newXdSiteResult = $true
                                break
                            }
                        }
                        catch {
                            Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetupSite] Site has not been setup yet..."
                        }

                        New-XDSite -DatabaseServer $using:DatabaseServerName -LoggingDatabaseName $using:loggingDatabaseName -MonitorDatabaseName $using:monitoringDatabaseName -SiteDatabaseName $using:siteDatabaseName -SiteName $using:SiteName
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetupSite] Failed to setup XD Site, retry count: $newXdSiteRetryCount"
                        Start-Sleep -Seconds 90
                        $newXdSiteRetryCount++
                        continue
                    }
                    $newXdSiteResult = $true
                }
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "controller") {
                    return $true
                }
                    
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-SetupSite] Checking if Site has already been set up"
                try {
                    Get-XDSite -AdminAddress $using:ControllerHostName
                    return $true
                }
                catch {
                    return $false
                }
            }
        }

        Script ConfigureWebStudio {
            DependsOn            = '[Script]SetupSite'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureWebStudio] Configuring WebStudio"
                    Start-Process -FilePath $using:WebStudioConfiguratorPath -ArgumentList "/server $($using:ControllerHostName)" -Wait
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureWebStudio] Failed to configure WebStudio FQDN: $($_)"
                }
            }

            TestScript           = {
                if ($using:componentsToInstall -contains "webstudio") {
                    return $false
                }
                else {
                    return $true
                }
            }
        }
        #endregion Controller Configuration and SiteSetup

        #region Request cert from CA
        Script DownloadCertificateRequestScript {
            DependsOn  = '[Script]ConfigureWebStudio'
        
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
        
                certutil -pulse
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
        
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-RequestCertificateFromCA] Argument List: $($argumentList)"
                Start-Process powershell.exe -ArgumentList $argumentList -Wait
            }
        
            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-RequestCertificateFromCA] Checking if certificate request from certification authority is already completed"
                Test-Path -Path $using:IISCertThumbprintFilePath
            }
        }
        #endregion Request cert from CA

        #region Licensing Configuration in Desktop Studio
        Script ImportLicensingModule {
            DependsOn            = '[Script]RequestCertificateFromCA'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportLicensingModule] Importing Citrix.Licensing.Admin.V1 module into scope"
                Import-Module "Citrix.Licensing.Admin.V1" -Force
            }

            TestScript           = {
                if ($using:componentsToInstall -contains "desktopstudio") {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportLicensingModule] Checking to see if Citrix.Licensing.Admin.V1 module has already been imported"
                    return (Get-Module -Name "Citrix.Licensing.Admin.V1" | Measure-Object).Count -NE 0
                }
                else {
                    return $true
                }
            }
        }

        Script InstallChocolatey {
            DependsOn            = '[Script]RequestCertificateFromCA'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallChocolatey] Installing Chocolatey"
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                $chocoInstallRetries = 0
                $chocoInstallResult = $false
                while (($chocoInstallRetries -le 5) -and (-not $chocoInstallResult)) {
                    try {
                        Invoke-WebRequest -Uri "https://community.chocolatey.org/install.ps1" -OutFile "$($using:CitrixModulesPath)\choco-install.ps1"
                        Invoke-Expression "$($using:CitrixModulesPath)\choco-install.ps1"
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallChocolatey] Failed to install chocolatey, retrying..."
                        $chocoInstallRetries++
                        Start-Sleep -Seconds 15
                        continue
                    }
                    $chocoInstallResult = $true
                }
                Import-Module $env:ChocolateyInstall\helpers\chocolateyProfile.psm1 -Force
            }

            TestScript           = {
                if (($using:componentsToInstall -notcontains "licenseserver") -and ($using:componentsToInstall -notcontains "desktopstudio")) {
                    return $true
                }
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallChocolatey] Checking if Chocolatey has been installed."
                    choco -v
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallChocolatey] Chocolatey is already installed on this system, skip set."
                    return $true
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallChocolatey] Chocolatey has not been installed yet."
                    return $false
                }
            }
        }

        Script RefreshPowershellEnvironment {
            DependsOn            = '[Script]InstallChocolatey'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-RefreshPowershellEnvironment] Refreshing environment."
                refreshenv
            }

            TestScript           = {
                if (($using:componentsToInstall -notcontains "licenseserver") -and ($using:componentsToInstall -notcontains "desktopstudio")) {
                    return $true
                }
                return $false
            }
        }

        
        Script InstallOpenSSL {
            DependsOn            = '[Script]RefreshPowershellEnvironment'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallOpenSSL] Installing OpenSSL package with Chocolatey."
                choco install openssl -y
                refreshenv
            }

            TestScript           = {
                if (($using:componentsToInstall -notcontains "licenseserver") -and ($using:componentsToInstall -notcontains "desktopstudio")) {
                    return $true
                }
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallOpenSSL] Checking if OpenSSL package has been installed."
                    openssl version
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallOpenSSL] OpenSSL is already installed on this system, skip set."
                    return $true
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallOpenSSL] OpenSSL package has not been installed yet."
                    return $false
                }
            }
        }

        Script ExtractLicenseServerPfxFromCert {
            DependsOn            = @('[Script]ImportLicensingModule', '[Script]InstallOpenSSL')

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $certThumbprint = Get-Content $using:IISCertThumbprintFilePath -Tail 1
                $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$($certThumbprint)"
                $licenseCertPasswordSecureString = ConvertTo-SecureString -String "$($using:LicenseCertPassword)" -Force -AsPlainText

                $cert | Export-PfxCertificate -FilePath "$($using:CitrixModulesPath)\licenseServer.pfx" -Password $licenseCertPasswordSecureString
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "licenseserver") {
                    return $true
                }
                Test-Path -Path "$($using:CitrixModulesPath)\licenseServer.pfx"
            }
        }

        Script ExtractLicenseServerCrtFromPfx {
            DependsOn            = '[Script]ExtractLicenseServerPfxFromCert'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                openssl pkcs12 -in "$($using:CitrixModulesPath)\licenseServer.pfx" -out "$($using:CitrixModulesPath)\server.crt" -nokeys -password "pass:$($using:LicenseCertPassword)"
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "licenseserver") {
                    return $true
                }
                Test-Path -Path "$($using:CitrixModulesPath)\server.crt"
            }
        }

        Script ExtractLicenseServerKeyFromPfx {
            DependsOn            = '[Script]ExtractLicenseServerPfxFromCert'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                openssl pkcs12 -in "$($using:CitrixModulesPath)\licenseServer.pfx" -out "$($using:CitrixModulesPath)\server.key" -nocerts -nodes -password "pass:$($using:LicenseCertPassword)"
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "licenseserver") {
                    return $true
                }
                Test-Path -Path "$($using:CitrixModulesPath)\server.key"
            }
        }
        
        Script ImportLicenseServerCert {
            DependsOn            = @('[Script]ExtractLicenseServerCrtFromPfx', '[Script]ExtractLicenseServerKeyFromPfx')

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportLicenseServerCert] Importing CVAD license server certificates"
                Stop-Service -Name "Citrix Web Services for Licensing" -ErrorAction SilentlyContinue
                Stop-Service -Name "Citrix Licensing" -ErrorAction SilentlyContinue
                
                # Configure SSL encryption for Citrix Licensing service
                Copy-Item -Path "$($using:CitrixModulesPath)\server.crt" -Destination "C:\Program Files (x86)\Citrix\Licensing\LS\conf\server.crt" -Force
                Copy-Item -Path "$($using:CitrixModulesPath)\server.key" -Destination "C:\Program Files (x86)\Citrix\Licensing\LS\conf\server.key" -Force
                
                # Configure SSL encryption for Citrix Web Services for Licensing
                Copy-Item -Path "$($using:CitrixModulesPath)\server.crt" -Destination "C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\server.crt" -Force
                Copy-Item -Path "$($using:CitrixModulesPath)\server.key" -Destination "C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\server.key" -Force

                Start-Service -Name "Citrix Licensing" -ErrorAction SilentlyContinue
                Start-Service -Name "Citrix Web Services for Licensing" -ErrorAction SilentlyContinue
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "licenseserver") {
                    return $true
                }
                return $false
            }
        }

        Script EnsureCvadLicServerRunning {
            DependsOn            = '[Script]ImportLicenseServerCert'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnsureCvadLicServerRunning] Check if Citrix Licensing service is presented with running status."
                Start-Service -Name "Citrix Licensing" 
                $ctxLicensingStatus = (Get-Service -Name "Citrix Licensing" -ErrorAction SilentlyContinue).Status
                $retryCount = 0
                while (($ctxLicensingStatus -ne "Running") -and $retryCount -le 3) {
                    $ctxLicensingStatus = (Get-Service -Name "Citrix Licensing" -ErrorAction SilentlyContinue).Status
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnsureCvadLicServerRunning] Citrix Licensing service has status $($ctxLicensingStatus). Retry count: $retryCount"
                    
                    Start-Sleep -Seconds 60
                    $retryCount++
                }

                if ($ctxLicensingStatus -eq "Running") {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnsureCvadLicServerRunning] Citrix Licensing service has started."
                }
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "licenseserver") {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnsureCvadLicServerRunning] License server is not installed in this machine, skip [licensing service status check."
                    return $true
                }

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnsureCvadLicServerRunning] Check if Citrix Licensing service is presented with running status."
                $ctxLicensingStatus = (Get-Service -Name "CitrixLicensing" -ErrorAction SilentlyContinue).Status
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnsureCvadLicServerRunning] Citrix licensing service has status $($ctxLicensingStatus)."
                return ($ctxLicensingStatus -eq "Running")
            }
        }

        Script DownloadCvadLicense {
            DependsOn            = '[Script]EnsureCvadLicServerRunning'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DownloadCvadLicense] Downloading CVAD license"
                try {
                    Invoke-WebRequest -Uri $using:LicenseFileUri -OutFile $using:LicenseFileDownloadPath
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DownloadCvadLicense] Failed to download CVAD license, cleaning up and retrying"
                    Remove-Item $using:LicenseFileDownloadPath -Force
                }
            }

            TestScript           = {
                if ($using:componentsToInstall -contains "desktopstudio") {
                    if (-not $using:LicenseFileUri) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadCvadLicense] Skip CVAD license download because license file is not provided"
                        return $true
                    }
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadCvadLicense] Checking if CVAD License exists"
                    return (Test-Path -Path $using:LicenseFileDownloadPath)
                }
                else {
                    return $true
                }
            }
        }

        Script ImportCvadLicense {
            DependsOn            = "[Script]DownloadCvadLicense"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportCvadLicense] Importing CVAD license file to license server"
                $licenseCertHash = (Get-LicCertificate -AdminAddress $using:LicenseServerAddress).certhash
                Import-LicLicenseFile -AdminAddress $using:LicenseServerAddress -FileName $using:LicenseFileDownloadPath -CertHash $licenseCertHash -Overwrite
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportCvadLicense] CVAD license file imported to license server"
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "desktopstudio") {
                    return $true
                }
                if (-not $using:LicenseFileUri) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportCvadLicense] Skip CVAD license Import because license file is not provided"
                    return $true
                }
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportCvadLicense] Checking if CVAD license server has the license file for desired product edition"
                    $licenseCertHash = (Get-LicCertificate -AdminAddress $using:LicenseServerAddress).certhash
                    $allLic = Get-LicInventory -AdminAddress $using:LicenseServerAddress -CertHash $licenseCertHash
                    $productCodeResult = $allLic.LicenseProductName -contains $using:ProductCode
                    $productEditionResult = $allLic.LicenseEdition -contains $using:ProductEdition
                    return ($productCodeResult -and $productEditionResult)
                }
                catch {
                    # Add catch block with logged information as Get-LicInventory could throw exceptions mentioned in https://developer-docs.citrix.com/projects/citrix-virtual-apps-desktops-sdk/en/1808/Licensing/Get-LicInventory/#notes
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportCvadLicense] CVAD license check failed with exception, returning false. Exception: $($_)"
                    return $false
                }
            }
        }

        Script ImportLicenseServerCertToStudio {
            DependsOn            = "[Script]ImportCvadLicense"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportLicenseServerCertToStudio] Importing CVAD license server certificates"
                (Get-LicCertificate -AdminAddress $using:LicenseServerAddress).Certificate | Export-Certificate -FilePath "$($using:CitrixModulesPath)\LicenseServerCert.cer"
                Import-Certificate -FilePath "$($using:CitrixModulesPath)\LicenseServerCert.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
                refreshenv
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "desktopstudio") {
                    return $true
                }
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportLicenseServerCertToStudio] Checking if CVAD license server certificates have been imported"
                    $allRootCerts = Get-ChildItem -Path Cert:\LocalMachine\Root
                    $licenseCert = (Get-LicCertificate -AdminAddress $using:LicenseServerAddress).Certificate
                    return ($allRootCerts.Subject -contains $licenseCert.Subject) -and ($allRootCerts.Thumbprint -contains $licenseCert.Thumbprint)
                }
                catch {
                    # The following exceptions could happened for Get-LicCertificate command: https://developer-docs.citrix.com/projects/citrix-virtual-apps-desktops-sdk/en/1808/Licensing/Get-LicCertificate/#notes
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportLicenseServerCertToStudio] CVAD license server certificate check failed with exception, returning false. Exception: $($_)"
                    return $false
                }
            }
        }

        Script SetSiteCertificateHash {
            DependsOn            = "[Script]ImportLicenseServerCertToStudio"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $certSHA512Fingerprint = (openssl x509 -noout -fingerprint -sha512 -in "C:\CitrixModules\LicenseServerCert.cer").Replace("sha512 Fingerprint=", "").Replace(":", "")
                $certFingerprintArray = $certSHA512Fingerprint -split '([A-F0-9]{2})' | ForEach-Object { if ($_) {[System.Convert]::ToByte($_,16)}}
                $CertificateHash = [System.Convert]::ToBase64String($certFingerprintArray)
                Set-XDSiteMetadata -DataName "CertificateHash" -DataValue $CertificateHash
                refreshenv
            }

            TestScript           = {
                if ($using:componentsToInstall -notcontains "desktopstudio") {
                    return $true
                }
                try {
                    $certHashMetadata = ((Get-ConfigSite).MetadataMap).CertificateHash
                    return (-not (-not $certHashMetadata))
                }
                catch {
                    return $false
                }
            }
        }

        Script SetLicenseServerForSite {
            DependsOn            = '[Script]SetSiteCertificateHash'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetLicenseServerForSite] Setting License Server information for site on controller"
                Set-XDLicensing -AdminAddress $using:ControllerHostName -LicenseServerAddress $using:LicenseServerAddress -LicenseServerPort $using:LicenseServerPort -ProductCode $using:ProductCode -ProductEdition $using:ProductEdition
            }

            TestScript           = {
                if ($using:componentsToInstall -contains "controller") {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-SetLicenseServerForSite] Checking if License Server parameters has already been set for site"
                    try {
                        return (Get-XDLicensing -AdminAddress $using:ControllerHostName).LicenseServer -eq $using:LicenseServerAddress
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-SetLicenseServerForSite] Failed to check license server settings of Site with exception, returning false. Exception: $($_)"
                        return $false
                    }
                }
                else {
                    return $true
                }
            }
        }
        #endregion Licensing Configuration in Desktop Studio

        #region StoreFront Configruation
        Script InstallStoreFront {
            DependsOn            = '[Script]SetLicenseServerForSite'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Start-Process -FilePath "$($using:CitrixModulesPath)\x64\Storefront\CitrixStoreFront-x64.exe" -ArgumentList "-silent" -Wait
                Restart-Computer -Force
            }

            TestScript           = {
                if ($using:InstallStoreFront) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallStoreFront] Checking if Store Front service has already been installed"
                    $psModuleResult = Test-Path -Path "C:\Program Files\Citrix\Receiver StoreFront\PowerShellSDK\Modules"
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallStoreFront] SF Path test result: $($psModuleResult)"
                    $regKeyResult = Get-Item $using:registryPath_CvadDeliveryServices -ErrorAction SilentlyContinue
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallStoreFront] Reg Key test result: $($regKeyResult)"
                    return ($psModuleResult -and $regKeyResult)
                }
                else {
                    return $true
                }
            }
        }

        Script ImportStoreFrontModules {
            DependsOn            = '[Script]InstallStoreFront'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                # Add padding between SF module import and SF installation
                Start-Sleep -Seconds 60

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportStoreFrontModules] Importing StoreFront Modules"
                Import-Module -Name $using:storeFrontModules -Force
            }

            TestScript           = {
                if ($using:InstallStoreFront) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportStoreFrontModules] Checking if StoreFront Modules have already been imported"
                    return (Get-Module -Name $using:storeFrontModules | Measure-Object).Count -EQ $using:storeFrontModules.length
                }
                else {
                    return $true
                }
            }
        }

        Script AddStoreFrontDeployment {
            DependsOn            = '[Script]ImportStoreFrontModules'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $iis_site = Get-IISSite "Default Web Site"
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontDeployment] Creating a StoreFront Deployment"
                Add-STFDeployment -HostBaseUrl $using:StoreFrontHostBaseAddress -SiteId $iis_site.Id -Confirm:$false
            }

            TestScript           = {
                if ($using:InstallStoreFront) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontDeployment] Checking if a StoreFront deployment already exists"
                    $existingDeployment = Get-STFDeployment
                    if (-not $existingDeployment) {
                        return $false
                    }
                    return $true
                }
                else {
                    return $true
                }
            }
        }

        Script AddStoreFrontAuthenticationService {
            DependsOn            = '[Script]AddStoreFrontDeployment'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontAuthenticationService] Adding Authentication Service"
                Add-STFAuthenticationService $using:authenticationVirtualPath
            }

            TestScript           = {
                if ($using:InstallStoreFront) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontAuthenticationService] Checking if Authentication Service at the specifiec virtual path already exists"
                    $authentication = Get-STFAuthenticationService -VirtualPath $using:authenticationVirtualPath
                    if (-not $authentication) {
                        return $false
                    }
                    return $true
                }
                else {
                    return $true
                }
            }
        }

        Script AddStoreFrontStoreService {
            DependsOn            = '[Script]AddStoreFrontAuthenticationService'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontStoreService] Adding a StoreFront Store that uses the new Authentication Service"
                $authentication = Get-STFAuthenticationService -VirtualPath $using:authenticationVirtualPath

                $transportType = switch ($using:SFDeliveryControllerPort) {
                    "80" { "HTTP" }
                    "443" { "HTTPS" }
                }

                $loadBalance = [System.Convert]::ToBoolean($using:AreDDCServersLoadBalanced)
                Add-STFStoreService -VirtualPath $using:StoreVirtualPath -AuthenticationService $authentication -FarmName $using:FarmName -FarmType $using:Farmtype -Servers $using:ControllerHostName -LoadBalance $loadBalance -Port $using:SFDeliveryControllerPort -FriendlyName $using:SFStoreFriendlyName -TransportType $transportType
            }

            TestScript           = {
                if ($using:InstallStoreFront) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontStoreService] Checking if Store Service at the specified Virtual Path already exists"
                    $store = Get-STFStoreService -VirtualPath $using:StoreVirtualPath
                    if (-not $store) {
                        return $false
                    }
                    return $true
                }
                else {
                    return $true
                }
            }
        }

        Script AddStoreFrontWebReceiverService {
            DependsOn            = '[Script]AddStoreFrontStoreService'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontWebReceiverService] Adding a StoreFront web receiver"
                $store = Get-STFStoreService -VirtualPath $using:StoreVirtualPath
                Add-STFWebReceiverService -VirtualPath $using:receiverVirtualPath -StoreService $store
            }

            TestScript           = {
                if ($using:InstallStoreFront) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontWebReceiverService] Checking if StoreFront receiver already exists"
                    $receiver = Get-STFWebReceiverService -VirtualPath $using:receiverVirtualPath
                    if (-not $receiver) {
                        return $false
                    }
                    return $true
                }
                else {
                    return $true
                }
            }
        }

        Script EnableSFStorePna {
            DependsOn            = '[Script]AddStoreFrontWebReceiverService'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnableSFStorePna] Enabling XenApp Service Url and make it the default store for PNAgent"
                $store = Get-STFStoreService -VirtualPath $using:StoreVirtualPath
                Enable-STFStorePna -StoreService $store -AllowUserPasswordChange -DefaultPnaService
            }

            TestScript           = {
                if ($using:InstallStoreFront) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnableSFStorePna] Checking if PNA is configured for store service"
                    $store = Get-STFStoreService -VirtualPath $using:StoreVirtualPath
                    $storePnaSettings = Get-STFStorePna -StoreService $store
                    if (-not $storePnaSettings.PnaEnabled) {
                        return $false
                    }
                    return $true
                }
                else {
                    return $true
                }
            }
        }

        Script EnableSFHtml5Fallback {
            DependsOn            = '[Script]EnableSFStorePna'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                # Documentation: https://github.com/citrix/storefront-sdk/blob/e629d255c6a10c7321820f08d97859d5fb3481d0/docs/Citrix.StoreFront.WebReceiver/Set-STFWebReceiverPluginAssistant.html
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnableSFHtml5Fallback] Enabling Receiver StoreFront HTML5 option with Fallback mode"
                $webReceiverService = Get-STFWebReceiverService
                Set-STFWebReceiverPluginAssistant -WebReceiverService $webReceiverService -Enabled $true -Html5Enabled "Fallback"
            }

            TestScript           = {
                if ($using:InstallStoreFront) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnableSFHtml5Fallback] Checking if HTML5 Receiver StoreFront Fallback option is enabled"
                    try {
                        $webReceiverService = Get-STFWebReceiverService
                        $html5Option = (Get-STFWebReceiverPluginAssistant -WebReceiverService $webReceiverService).Html5
                        return $html5Option.Enabled -eq "Fallback"
                    }
                    catch {
                        return $false
                    }
                }
                else {
                    return $true
                }
            }
        }

        Script AddStoreFrontToSite {
            DependsOn            = '[Script]EnableSFHtml5Fallback'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                try {
                    $configurationSlot = Get-BrokerConfigurationSlot -Name "RS"
                    $storefrontUrl = $using:StoreFrontHostBaseAddress + "$(($using:StoreVirtualPath).TrimEnd('/'))Web"
                    $configuration = New-BrokerStorefrontAddress -Description "Citrix Storefront Address" -Enabled $true -Name "Citrix StoreFront" -Url $storefrontUrl
                    New-BrokerMachineConfiguration -Policy $configuration -ConfigurationSlotUid $configurationSlot.Uid -Description "Citrix Storefront Address Configuration" -LeafName $using:SFStoreFriendlyName
                }
                catch {
                    $string_err = $_ | Out-String
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontToSite] Unable to add store front to site: $string_err"
                }
            }

            TestScript           = {
                if ($using:componentsToInstall -contains "controller") {
                    if (-not (Get-BrokerMachineConfiguration -LeafName $using:SFStoreFriendlyName)) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontToSite] StoreFront has not been added to site yet"
                        return $false
                    }
    
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontToSite] StoreFront has already been added to site"
                    return $true
                }
                else {
                    return $true
                }

            }
        }
        #endregion StoreFront Configuration

        #region Enable Site DNS Resolution
        Script EnableSiteDnsResolution {
            DependsOn            = '[Script]AddStoreFrontToSite'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnableSiteDnsResolution] Enabling DNS resolution on site"
                Set-BrokerSite -DnsResolutionEnabled 1
            }

            TestScript           = {
                if ($using:componentsToInstall -contains "controller") {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnableSiteDnsResolution] Checking if DNS Resolution for site is enabled"
                    return (Get-BrokerSite).DnsResolutionEnabled
                }
                else {
                    return $true
                }
            }
        }
        #endregion Enable Site DNS Resolution

        #region Bind cert to IIS
        Script BindRequestedCertToIIS {
            DependsOn            = '[Script]EnableSiteDnsResolution'

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
                if ((Get-WindowsFeature Web-Server).InstallState -ne "Installed") {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-BindRequestedCertToIIS] IIS is not installed on the machine, skipping cert binding"
                    return $true
                } 
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

        Script AddHttpRedirectRule {
            DependsOn            = '[Script]BindRequestedCertToIIS'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Remove-Module IISAdministration -ErrorAction SilentlyContinue
                Remove-Module WebAdministration -ErrorAction SilentlyContinue

                Import-Module IISAdministration -ErrorAction SilentlyContinue

                Start-IISCommitDelay
                $sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
                $siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name" = "Default Web Site" }
                $hstsElement = Get-IISConfigElement -ConfigElement $siteElement -ChildElementName "hsts"
                Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "enabled" -AttributeValue $true
                Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "max-age" -AttributeValue 31536000
                Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "redirectHttpToHttps" -AttributeValue $true
                Stop-IISCommitDelay

                Stop-IISSite -Name "Default Web Site" -Confirm:$False
                Start-IISSite -Name "Default Web Site"

                Remove-Module IISAdministration -ErrorAction SilentlyContinue
            }

            TestScript           = {
                if ((Get-WindowsFeature Web-Server).InstallState -ne "Installed") {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddHttpRedirectRule] IIS is not installed on the machine, skipping http redirect setting"
                    return $true
                } 

                Remove-Module IISAdministration -ErrorAction SilentlyContinue
                Remove-Module WebAdministration -ErrorAction SilentlyContinue

                Import-Module IISAdministration -ErrorAction SilentlyContinue

                Start-IISCommitDelay
                $sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
                $siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name" = "Default Web Site" }
                $hstsElement = Get-IISConfigElement -ConfigElement $siteElement -ChildElementName "hsts"
                $ruleCreated = Get-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "enabled"
                Stop-IISCommitDelay
                Remove-Module IISAdministration -ErrorAction SilentlyContinue
                if (-not $ruleCreated) {
                    return $false
                }
                return $true
            }
        }
        #endregion Bind cert to IIS

        #region Local User Cleanup
        Script DisableAndRemoveLocalUser {
            DependsOn            = "[Script]AddHttpRedirectRule"

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
        #endregion Local User Cleanup

        #region Citrix Module Files Cleanup
        Script RemoveCitrixModule {
            DependsOn            = "[Script]DisableAndRemoveLocalUser"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                try {
                    Get-ChildItem -Path $using:CitrixModulesPath -Include * -File -Recurse | ForEach-Object { $_.Delete()}
                }
                catch { }
            }

            TestScript           = {
                return (-not [System.Convert]::ToBoolean($using:RemoveCitrixModuleAfterSetup))
            }
        }
        #endregion
    }
}
