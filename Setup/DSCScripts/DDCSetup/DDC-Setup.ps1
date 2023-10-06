Configuration CVADComponentAndSiteSetup
{
    param (
        [Parameter(Mandatory = $true)]
        [string] $AdDomainControllerPrivateIp,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainFQDN,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainUsername,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainPassword,
        [Parameter(Mandatory = $true)]
        [string] $SiteName,
        [Parameter(Mandatory = $true)]
        [string] $SetupIndependentSqlVM,
        [Parameter(Mandatory = $true)]
        [string] $DatabaseServerName,
        [Parameter(Mandatory = $true)]
        [string] $CVADInstallerDownloadUrl,
        [Parameter(Mandatory = $true)]
        [string] $CVADInstallerMd5Hash,
        [Parameter(Mandatory = $true)]
        [string] $CitrixModulesPath,
        [Parameter(Mandatory = $true)]
        [string] $LicenseServerPort,
        [Parameter(Mandatory = $true)]
        [string] $ProductCode,
        [Parameter(Mandatory = $true)]
        [string] $ProductEdition,
        [Parameter(Mandatory = $true)]
        [string] $StoreVirtualPath,
        [Parameter(Mandatory = $true)]
        [string] $SFDeliveryControllerPort, 
        [Parameter(Mandatory = $true)]
        [string] $FarmType,
        [Parameter(Mandatory = $true)]
        [string] $FarmName,
        [Parameter(Mandatory = $true)]
        [string] $FarmServers, #Servers where Delivery Controller is running, FQDN is required
        [Parameter(Mandatory = $true)]
        [string] $AreDDCServersLoadBalanced,
        [Parameter(Mandatory = $true)]
        [string] $SFStoreFriendlyName,
        [Parameter(Mandatory = $true)]
        [string] $ComponentList, #Comma separated list of cvad component to be installed in ddc vm

        # Certificate Request Parameters
        [Parameter(Mandatory = $true)]
        [string] $CAServerHostName,
        [Parameter(Mandatory = $true)]
        [string] $CACommonName,
        [Parameter(Mandatory = $true)]
        [string] $RequestCertFromCAScriptUrl,
        [Parameter(Mandatory = $true)]
        [string] $RequestCertTemplateUrl,

        # Azure Hosting Connection Parameters
        [Parameter(Mandatory = $true)]
        [string] $AzureClientID,
        [Parameter(Mandatory = $true)]
        [string] $AzureClientSecret,
        [Parameter(Mandatory = $true)]
        [string] $AzureSubscriptionId,
        [Parameter(Mandatory = $true)]
        [string] $AzureTenantId,
        [Parameter(Mandatory = $true)]
        [string] $AzureRegion,

        [Parameter(Mandatory = $true)]
        [string] $AzureVNet,
        [Parameter(Mandatory = $true)]
        [string] $AzureSubnet,
        [Parameter(Mandatory = $true)]
        [string] $AzureVNetResourceGroup,
        
        [Parameter(Mandatory = $true)]
        [string] $AdNetBIOSName,
        [Parameter(Mandatory = $true)]
        [string] $CatalogName,
        [Parameter(Mandatory = $true)]
        [string] $SessionSupport,
        [Parameter(Mandatory = $true)]
        [string] $DeliveryGroupName,
        [Parameter(Mandatory = $true)]
        [string] $UserGroupName,
        [Parameter(Mandatory = $true)]
        [string] $DeliveryGroupAccessPolicyName,
        [Parameter(Mandatory = $true)]
        [string] $DesktopRuleName,
        [Parameter(Mandatory = $true)]
        [string] $HostingName,
        [Parameter(Mandatory = $true)]
        [string] $DesktopName,
        [Parameter (Mandatory = $true)]
        [string] $DefaultUsersInput,
        [Parameter(Mandatory = $false)]
        [boolean] $AreMachinesPowerManaged = $true,

        [Parameter(Mandatory = $false)]
        [string] $LicenseServerAddress = "",

        [Parameter(Mandatory = $false)]
        [string] $StoreFrontAddress = "",

        # Required only if license file is not provided
        [Parameter(Mandatory = $false)]
        [string] $ListOfVDAs = "",
        [Parameter(Mandatory = $false)]
        [string] $ConnectionName,
        [Parameter(Mandatory = $false)]
        [string] $VDAResourceGroup = "",

        # Optional License File
        [Parameter(Mandatory = $false)]
        [string] $LicenseFileUri = "",

        # Machine Catalog Optional Parameters
        [Parameter(Mandatory = $false)]
        [string] $AllocationType = "Random",
        [Parameter(Mandatory = $false)]
        [string] $PersistUserChanges = "Discard"

    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $registryPath_CvadAutomation = "HKLM:\SOFTWARE\Citrix\Automation\"
    $registryKey_CvadIsoFileHash = "IsoFileHash"

    $registryPath_SqlServerModuleInstallation = "HKLM:SOFTWARE\Citrix\SqlServerModuleInstallation"
    $registryEntry_SqlServerModuleRetries = "SystemRebootCount"

    $registryPath_CvadDeliveryServices = "HKLM:\SOFTWARE\Citrix\DeliveryServices"

    $logFilePath = "$($CitrixModulesPath)\CVAD_Installation.log"
    $xenDesktopServerSetupPath = "$($CitrixModulesPath)\x64\XenDesktop Setup\XenDesktopServerSetup.exe"
    $cvadInstallerOutputPath = "$($CitrixModulesPath)\CVAD_Installer.iso"

    # MS SQL Database
    $setupIndependentSqlVM = [System.Convert]::ToBoolean($SetupIndependentSqlVM)
    $databaseConnectionStringPrefix = "Server=$($DatabaseServerName);Integrated Security=True;Encrypt=True;TrustServerCertificate=True;Database="
    $masterDatabaseName = "master"
    $siteDatabaseName = "Citrix$($SiteName)Site"
    $loggingDatabaseName = "Citrix$($SiteName)Logging"
    $monitoringDatabaseName = "Citrix$($SiteName)Monitoring"

    # License Server
    $LicenseFileDownloadPath = "$CitrixModulesPath\CVAD_License.lic"

    # Web Studio
    $WebStudioConfiguratorPath = "C:\Program Files\Citrix\Web Studio\Tool\StudioConfig.exe"

    # Credential Object for Active Directory Admin
    $ADCredentials = New-Object pscredential -ArgumentList ([pscustomobject]@{
            UserName = "$ADDomainFQDN\$ADDomainUsername"
            Password = (ConvertTo-SecureString $ADDomainPassword -AsPlainText -Force)[0]
        })

    # Storefront 
    $authenticationVirtualPath = "$($StoreVirtualPath.TrimEnd('/'))Auth"
    $receiverVirtualPath = "$($StoreVirtualPath.TrimEnd('/'))Web"
    $storeFrontModules = @("Citrix.StoreFront", "Citrix.StoreFront.Stores", "Citrix.StoreFront.Authentication", "Citrix.StoreFront.WebReceiver")

    # SSL Certificate Setup
    $RequestCertFromCAScriptPath = "$CitrixModulesPath\Request-CertificateFromCA.ps1"
    $RequestCertTemplatePath = "$CitrixModulesPath\RequestTemplate.inf"
    $IISCertThumbprintFilePath = "$CitrixModulesPath\IISCertThumbprint"

    # Broker Objects Setup
    $DefaultUsers = $DefaultUsersInput.Split(",") | ForEach-Object { "$($_.ToString())@$($ADDomainFQDN)" }

    if (-not $LicenseServerAddress) {
        $LicenseServerAddress = "$env:COMPUTERNAME.$ADDomainFQDN"
    }
    
    Node localhost {

        LocalConfigurationManager {
            ActionAfterReboot  = "ContinueConfiguration"
            RefreshMode        = "Push"  
            RebootNodeIfNeeded = $true
            ConfigurationMode  = "ApplyOnly"
        }

        #region Initial Setup and Domain Join
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
                New-Item -Path $using:registryPath_SqlServerModuleInstallation -Force
                New-ItemProperty -Path $using:registryPath_SqlServerModuleInstallation -Name $using:registryEntry_SqlServerModuleRetries -Value 0
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

        #region Make the AD Domain Controller discoverable on VNet and Domain
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
        #endregion
        
        #region CVAD Core Component Installation
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
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-MountISO] Checking if XenDesktopServerSetup.exe is present within Citrix Modules"
                Test-Path -Path $using:xenDesktopServerSetupPath  
            }
        }

        Script InstallCVADComponents {
            DependsOn            = "[Script]MountISO"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallCVADComponents] Running the CVAD Installer"

                if ($using:setupIndependentSqlVM -eq $true) {
                    Start-Process -FilePath $using:xenDesktopServerSetupPath -ArgumentList "/components $using:ComponentList /ignore_hw_check_failure /configure_firewall /no_remote_assistance /nosql /noreboot /noresume /passive" -Wait
                }
                else {
                    Start-Process -FilePath $using:xenDesktopServerSetupPath -ArgumentList "/components $using:ComponentList /ignore_hw_check_failure /configure_firewall /no_remote_assistance /noreboot /noresume /passive" -Wait
                }
                
                Restart-Computer  # We don't want to add the -Force argument as CVAD installer will try to restart the computer. Duplicated restart request could fail the DSC script
            }

            TestScript           = {
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallCVADComponents] Checking if CVAD components have been installed"
                    Get-Item 'HKLM:SOFTWARE\Citrix\MetaInstall\' -ErrorAction Stop | Get-ItemPropertyValue -Name ExitCode | ForEach-Object { $_ -eq 0 } 
                }
                catch {
                    return $false
                }
            }
        }
        #endregion

        #region SQL Server Connection and Database Creation
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
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportXenDesktopModule] Checking to see if Citrix.XenDesktop.Admin module has already been imported"
                (Get-Module -Name "Citrix.XenDesktop.Admin" | Measure-Object).Count -NE 0
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
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CheckSqlExpressConnectivity] Checking connectivity to SQLExpress Server"
                $connectionString = $using:databaseConnectionStringPrefix + $using:masterDatabaseName
                try {
                    (Get-SqlDatabase -ConnectionString $connectionString -ErrorAction Stop | Measure-Object).Count -NE 0
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
                New-XDDatabase -AdminAddress $env:COMPUTERNAME -SiteName $using:SiteName -Datastore Site -DatabaseServer $using:DatabaseServerName -DatabaseName $using:siteDatabaseName
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateSiteDatabase] Checking if database: $($using:siteDatabaseName) already exists in the MS Sql Server"
                $connectionString = $using:databaseConnectionStringPrefix + $using:siteDatabaseName
                (Get-SqlDatabase -ConnectionString $connectionString | Measure-Object).Count -NE 0
            }
        }

        Script CreateLoggingDatabase {
            DependsOn            = @('[Script]CheckSqlExpressConnectivity', '[Script]ImportXenDesktopModule')

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateLoggingDatabase] Creating database: $($using:loggingDatabaseName) on MS Sql Server"
                New-XDDatabase -AdminAddress $env:COMPUTERNAME -SiteName $using:SiteName -Datastore Logging -DatabaseServer $using:DatabaseServerName -DatabaseName $using:loggingDatabaseName
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateLoggingDatabase] Checking if database: $($using:loggingDatabaseName) already exists in the MS Sql Server"
                $connectionString = $using:databaseConnectionStringPrefix + $using:loggingDatabaseName
                (Get-SqlDatabase -ConnectionString $connectionString | Measure-Object).Count -NE 0
            }
        }

        Script CreateMonitoringDatabase {
            DependsOn            = @('[Script]CheckSqlExpressConnectivity', '[Script]ImportXenDesktopModule')

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateMonitoringDatabase] Creating database: $($using:monitoringDatabaseName) on MS Sql Server"
                New-XDDatabase -AdminAddress $env:COMPUTERNAME -SiteName $using:SiteName -Datastore Monitor -DatabaseServer $using:DatabaseServerName -DatabaseName $using:monitoringDatabaseName
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateMonitoringDatabase] Checking if database: $($using:monitoringDatabaseName) already exists in the MS Sql Server"
                $connectionString = $using:databaseConnectionStringPrefix + $using:monitoringDatabaseName
                (Get-SqlDatabase -ConnectionString $connectionString | Measure-Object).Count -NE 0
            }
        }
        #endregion

        #region Ensure Citrix Host Service Running
        Script EnsureCitrixHostServiceRunning {
            DependsOn            = @('[Script]CreateSiteDatabase', '[Script]CreateLoggingDatabase', '[Script]CreateMonitoringDatabase')

            PsDscRunAsCredential = $ADCredentials

            GetScript = {
            }

            SetScript = {
                Start-Service CitrixHostService -ErrorAction SilentlyContinue
            }

            TestScript = {
                return (Get-Service CitrixHostService -ErrorAction SilentlyContinue).Status -eq "Running"
            }
        }
        #endregion

        #region Site Setup
        Script SetupSite {
            DependsOn            = "[Script]EnsureCitrixHostServiceRunning"

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetupSite] Setting up Site"
                New-XDSite -DatabaseServer $using:DatabaseServerName -LoggingDatabaseName $using:loggingDatabaseName -MonitorDatabaseName $using:monitoringDatabaseName -SiteDatabaseName $using:siteDatabaseName -SiteName $using:SiteName

                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetupSite] Configuring WebStudio"
                    Start-Process -FilePath $using:WebStudioConfiguratorPath -ArgumentList "/server '$($env:COMPUTERNAME).$($using:ADDomainFQDN)'" -Wait
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetupSite] Failed to configure WebStudio FQDN: $($_)"
                }
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-SetupSite] Checking if Site has already been set up"
                try {
                    Get-XDSite -AdminAddress $env:COMPUTERNAME
                    return $true
                }
                catch {
                    return $false
                }
            }
        }
        #endregion

        #region License Server Installation and Configuration
        Script SetupLicenseServer {
            DependsOn            = '[Script]SetupSite'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetupLicenseServer] Setting up License Server"
                Set-XDLicensing -AdminAddress "$env:COMPUTERNAME.$using:ADDomainFQDN" -LicenseServerAddress $using:LicenseServerAddress -LicenseServerPort $using:LicenseServerPort -ProductCode $using:ProductCode -ProductEdition $using:ProductEdition
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-SetupLicenseServer] Checking if License Server has already been set up"
                try {
                    (Get-XDLicensing -AdminAddress "$env:COMPUTERNAME.$using:ADDomainFQDN").LicenseServer -eq $using:LicenseServerAddress
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-SetupLicenseServer] Failed to check license server with exception, returning false. Exception: $($_)"
                    return $false
                }
            }
        }

        Script DownloadCvadLicense {
            DependsOn            = '[Script]SetupLicenseServer'

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
                if (-not $using:LicenseFileUri) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadCvadLicense] Skip CVAD license download because license file is not provided"
                    return $true
                }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadCvadLicense] Checking if CVAD License exists"
                Test-Path -Path $using:LicenseFileDownloadPath
            }
        }

        Script ImportLicensingModule {
            DependsOn            = '[Script]SetupLicenseServer'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportLicensingModule] Importing Citrix.Licensing.Admin.V1 module into scope"
                Import-Module "Citrix.Licensing.Admin.V1" -Force
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportLicensingModule] Checking to see if Citrix.Licensing.Admin.V1 module has already been imported"
                (Get-Module -Name "Citrix.Licensing.Admin.V1" | Measure-Object).Count -NE 0
            }
        }

        Script ImportLicenseServerCert {
            DependsOn            = '[Script]ImportLicensingModule'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportLicenseServerCert] Importing CVAD license server certificates"
                Import-Certificate -FilePath "C:\Program Files (x86)\Citrix\Licensing\LS\conf\server.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
                Import-Certificate -FilePath "C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\server.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
                Restart-Computer -Force
            }

            TestScript           = {
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportLicenseServerCert] Checking if CVAD license server certificates have been imported"
                    $allRootCerts = Get-ChildItem -Path Cert:\LocalMachine\Root
                    $licenseCert = (Get-LicCertificate -AdminAddress "$env:COMPUTERNAME.$using:ADDomainFQDN").Certificate
                    return ($allRootCerts.Subject -contains $licenseCert.Subject) -and ($allRootCerts.Thumbprint -contains $licenseCert.Thumbprint)
                }
                catch {
                    # The following exceptions could happened for Get-LicCertificate command: https://developer-docs.citrix.com/projects/citrix-virtual-apps-desktops-sdk/en/1808/Licensing/Get-LicCertificate/#notes
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportLicenseServerCert] CVAD license server certificate check failed with exception, returning false. Exception: $($_)"
                    return $false
                }
                
            }
        }

        Service EnsureCvadLicServerRunning {
            DependsOn   = '[Script]ImportLicenseServerCert'

            Name        = "Citrix Licensing"
            StartupType = "Automatic"
            State       = "Running"
            Ensure      = "Present"
        }

        Script ImportCvadLicense {
            DependsOn            = @("[Service]EnsureCvadLicServerRunning", "[Script]DownloadCvadLicense")

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportCvadLicense] Importing CVAD license file to license server"
                $licenseCertHash = (Get-LicCertificate -AdminAddress "$env:COMPUTERNAME").certhash
                Import-LicLicenseFile -AdminAddress "$env:COMPUTERNAME" -FileName $using:LicenseFileDownloadPath -CertHash $licenseCertHash -Overwrite
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ImportCvadLicense] CVAD license file imported to license server"
            }

            TestScript           = {
                if (-not $using:LicenseFileUri) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportCvadLicense] Skip CVAD license Import because license file is not provided"
                    return $true
                }
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportCvadLicense] Checking if CVAD license server has the license file for desired product edition"
                    $licenseCertHash = (Get-LicCertificate -AdminAddress "$env:COMPUTERNAME").certhash
                    $allLic = Get-LicInventory -AdminAddress "$env:COMPUTERNAME" -CertHash $licenseCertHash
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
        #endregion

        #region StoreFront Installation and Configuration
        Script InstallStoreFront {
            DependsOn            = '[Script]ImportCvadLicense'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Start-Process -FilePath "$($using:CitrixModulesPath)\x64\Storefront\CitrixStoreFront-x64.exe" -ArgumentList "-silent" -Wait
                Restart-Computer -Force
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallStoreFront] Checking if Store Front service has already been installed"
                $psModuleResult = Test-Path -Path "C:\Program Files\Citrix\Receiver StoreFront\PowerShellSDK\Modules"
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallStoreFront] SF Path test result: $($psModuleResult)"
                $regKeyResult = Get-Item $using:registryPath_CvadDeliveryServices -ErrorAction SilentlyContinue
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallStoreFront] Reg Key test result: $($regKeyResult)"
                return ($psModuleResult -and $regKeyResult)
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
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ImportStoreFrontModules] Checking if StoreFront Modules have already been imported"
                (Get-Module -Name $using:storeFrontModules | Measure-Object).Count -EQ $using:storeFrontModules.length
            }
        }

        Script AddStoreFrontDeployment {
            DependsOn            = '[Script]ImportStoreFrontModules'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $iis_site = Get-IISSite "Default Web Site" # ToDo: Check if this should be parameterized based on customer's setup
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontDeployment] Creating a StoreFront Deployment"
                Add-STFDeployment -HostBaseUrl "https://$env:COMPUTERNAME.$using:ADDomainFQDN" -SiteId $iis_site.Id -Confirm:$false
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontDeployment] Checking if a StoreFront deployment already exists"
                $existingDeployment = Get-STFDeployment
                if (-not $existingDeployment) {
                    return $false
                }
                return $true
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
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontAuthenticationService] Checking if Authentication Service at the specifiec virtual path already exists"
                $authentication = Get-STFAuthenticationService -VirtualPath $using:authenticationVirtualPath
                if (-not $authentication) {
                    return $false
                }
                return $true
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
                Add-STFStoreService -VirtualPath $using:StoreVirtualPath -AuthenticationService $authentication -FarmName $using:FarmName -FarmType $using:Farmtype -Servers $using:FarmServers -LoadBalance $loadBalance -Port $using:SFDeliveryControllerPort -FriendlyName $using:SFStoreFriendlyName -TransportType $transportType
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontStoreService] Checking if Store Service at the specified Virtual Path already exists"
                $store = Get-STFStoreService -VirtualPath $using:StoreVirtualPath
                if (-not $store) {
                    return $false
                }
                return $true
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
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontWebReceiverService] Checking if StoreFront receiver already exists"
                $receiver = Get-STFWebReceiverService -VirtualPath $using:receiverVirtualPath
                if (-not $receiver) {
                    return $false
                }
                return $true
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
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnableSFStorePna] Checking if PNA is configured for store service"
                $store = Get-STFStoreService -VirtualPath $using:StoreVirtualPath
                $storePnaSettings = Get-STFStorePna -StoreService $store
                if (-not $storePnaSettings.PnaEnabled) {
                    return $false
                }
                return $true
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
        }

        Script AddStoreFrontToSite {
            DependsOn            = '[Script]EnableSFHtml5Fallback'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                try {
                    $configurationSlot = Get-BrokerConfigurationSlot -Name "RS"
                    $storefrontUrl = $using:StoreFrontAddress + "$(($using:StoreVirtualPath).TrimEnd('/'))Web"
                    $configuration = New-BrokerStorefrontAddress -Description "Citrix Storefront Address" -Enabled $true -Name "Citrix StoreFront" -Url $storefrontUrl
                    New-BrokerMachineConfiguration -Policy $configuration -ConfigurationSlotUid $configurationSlot.Uid -Description "Citrix Storefront Address" -LeafName $using:SFStoreFriendlyName
                }
                catch {
                    $string_err = $_ | Out-String
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontToSite] Unable to add store front to site: $string_err"
                }
            }

            TestScript           = {
                if (-not (Get-BrokerMachineConfiguration -LeafName $using:SFStoreFriendlyName)){
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontToSite] StoreFront has not been added to site yet"
                    return $false
                }

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontToSite] StoreFront has already been added to site"
                return $true
            }
        }
        #endregion

        #region Enable Remote VDA Launch
        Script EnableRemoteVdaLaunch {
            DependsOn            = '[Script]AddStoreFrontToSite'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnableRemoteVdaLaunch] Enabling DNS resolution on Site"
                Set-BrokerSite -DnsResolutionEnabled 1
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnableRemoteVdaLaunch] Checking if DNS Resolution for Site is enabled"
                return (Get-BrokerSite).DnsResolutionEnabled
            }
        }
        #endregion

        #region Configure IIS SSL Encryption
        Script DownloadCertificateRequestScript {
            DependsOn  = '[Script]EnableRemoteVdaLaunch'

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

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-RequestCertificateFromCA] Argument List: $($argumentList)"
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
                $siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name"="Default Web Site"}
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
                Remove-Module IISAdministration -ErrorAction SilentlyContinue
                Remove-Module WebAdministration -ErrorAction SilentlyContinue

                Import-Module IISAdministration -ErrorAction SilentlyContinue

                Start-IISCommitDelay
                $sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
                $siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name"="Default Web Site"}
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
        #endregion

        #region Create Azure Hosting Connection
        Script AddCitrixPSSnapin {
            DependsOn            = '[Script]AddHttpRedirectRule'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddCitrixPSSnapin] Removing all the existing Citrix PS Snapins"
                Remove-PSSnapin -Name Citrix* -ErrorAction SilentlyContinue
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddCitrixPSSnapin] Adding all the available Citrix PS Snapins"
                Add-PSSnapin -Name Citrix* -ErrorAction SilentlyContinue
                if (-not (Get-PSSnapin -Name Citrix* -ErrorAction SilentlyContinue)) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddCitrixPSSnapin] Failed to add Citrix PSSnapin"
                    throw "Failed to add Citrix PSSnapin"
                }
            }

            TestScript           = {
                return $false
            }
        }

        Script CreateAzureHostingConnection {
            DependsOn            = '[Script]AddCitrixPSSnapIn'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateAzureHostingConnection] Configuring Azure Hosting Connection"
                Set-HypAdminConnection
                $connObject = New-Item -ConnectionType "Custom" -CustomProperties "<CustomProperties xmlns=`"http://schemas.citrix.com/2014/xd/machinecreation`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`"><Property xsi:type=`"StringProperty`" Name=`"SubscriptionId`" Value=`"$using:AzureSubscriptionId`" /><Property xsi:type=`"StringProperty`" Name=`"ManagementEndpoint`" Value=`"https://management.azure.com/`" /><Property xsi:type=`"StringProperty`" Name=`"AuthenticationAuthority`" Value=`"https://login.microsoftonline.com/`" /><Property xsi:type=`"StringProperty`" Name=`"StorageSuffix`" Value=`"core.windows.net`" /><Property xsi:type=`"StringProperty`" Name=`"TenantId`" Value=`"$using:AzureTenantId`" /></CustomProperties>" -HypervisorAddress @("https://management.azure.com/") -Path @("XDHyp:\Connections\$using:ConnectionName") -Persist -PluginId "AzureRmFactory" -Scope @() -SecurePassword  (ConvertTo-SecureString $using:AzureClientSecret -AsPlainText -Force) -UserName $using:AzureClientID -ZoneUid $configZone.Uid
                New-BrokerHypervisorConnection -HypHypervisorConnectionUid $connObject.HypervisorConnectionUid
                Set-HypAdminConnection
                New-Item -HypervisorConnectionName $using:ConnectionName -NetworkPath @("XDHyp:\Connections\$using:ConnectionName\$using:AzureRegion.region\virtualprivatecloud.folder\$using:AzureVnetResourceGroup.resourcegroup\$using:AzureVNet.virtualprivatecloud\$using:AzureSubnet.network") -Path @("XDHyp:\HostingUnits\$using:HostingName") -PersonalvDiskStoragePath @() -RootPath "XDHyp:\Connections\$using:ConnectionName\$using:AzureRegion.region" -StoragePath @()
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateAzureHostingConnection] Azure Hosting Connection Created"
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateAzureHostingConnection] Testing if Azure hosting connection already exists"
                $currentConnection = Get-ChildItem -LiteralPath @("XDHyp:\Connections\$using:ConnectionName") -ErrorAction SilentlyContinue
                return ($null -ne $currentConnection)
            }
        }

        Script WaitHostingConnectionToBeReady {
            DependsOn            = '[Script]CreateAzureHostingConnection'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                throw "[Set-WaitHostingConnectionToBeReady] Broker Hypervisor Connection is not ready"
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateAzureHostingConnection] Testing if Azure hosting connection already exists"
                $brokerHypervisorConnection = Get-BrokerHypervisorConnection -Name $using:ConnectionName
                $retryCount = 0
                $maxRetry = 5
                while ((-not $brokerHypervisorConnection.IsReady) -and ($retryCount -lt $maxRetry)) {
                    Start-Sleep -Seconds 60
                    $brokerHypervisorConnection = Get-BrokerHypervisorConnection -Name $using:ConnectionName
                    $retryCount++
                }
                if ($brokerHypervisorConnection.IsReady) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateAzureHostingConnection] Testing if Azure hosting connection already exists"
                    return $true
                }
                else {
                    return $false
                }
            }
        }
        #endregion

        #region Machine Catalog Setup
        Script CreateMachineCatalog {
            DependsOn            = '[Script]WaitHostingConnectionToBeReady'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateMachineCatalog] Creating $($using:SessionSupport) Power Managed Machine Catalog $($using:CatalogName)"
                New-BrokerCatalog -AllocationType $using:AllocationType -ProvisioningType "Manual" -SessionSupport $using:SessionSupport -PersistUserChanges $using:PersistUserChanges -Name $using:CatalogName -Description "$($using:SessionSupport) Catalog" -MachinesArePhysical $false

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateMachineCatalog] Machine Catalog $($using:CatalogName) is created successfully"
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateMachineCatalog] Testing if desired machine catalog $($using:CatalogName) already exists"
                $isCatalogNameAvailable = (Test-BrokerCatalogNameAvailable $using:CatalogName).Available
                if ($isCatalogNameAvailable) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateMachineCatalog] Desired machine catalog does not exist, creating a new machine catalog with name $($using:CatalogName)"
                    return $false
                }
                else {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateMachineCatalog] Desired machine catalog with name $($using:CatalogName) already exists"
                    return $true
                }
            }
        }

        Script AddVDAToMachineCatalog {
            DependsOn            = '[Script]CreateMachineCatalog'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $brokerCatalog = Get-BrokerCatalog -Name $using:CatalogName
                $hypervisorConnection = Get-BrokerHypervisorConnection -Name $using:ConnectionName

                foreach ($vdaToAdd in $($using:ListOfVDAs).Split(",")) {
                    try {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddVDAToMachineCatalog] Adding $($vdaToAdd) to machine catalog $($using:CatalogName)"
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddVDAToMachineCatalog] Machine will be power managed as the license file is provided"
                        New-BrokerMachine -MachineName (($using:AdNetBIOSName).ToUpper() + "\" + $vdaToAdd.ToUpper() + "$") -CatalogUid $brokerCatalog.Uid -HypervisorConnectionUid $hypervisorConnection.Uid -HostedMachineId ($using:VDAResourceGroup + "/" + $vdaToAdd)
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddVDAToMachineCatalog] $($vdaToAdd) is added to machine catalog $($using:CatalogName)"
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddVDAToMachineCatalog] Skip $($vdaToAdd): it cannot be added to machine catalog $($using:CatalogName): $($_)"
                    }
                }
            }

            TestScript           = {
                if (($using:ListOfVDAs).Split(",").Count -eq 0) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddVDAToMachineCatalog] No VDA available, will skip add machine to catalog action"
                    return $true
                }
                return $false
            }
        }
        #endregion

        #region Delivery Group Setup
        Script ForceRefreshBrokerCache {
            DependsOn            = '[Script]AddVDAToMachineCatalog'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ForceRefreshBrokerCache] Force refreshing the broker name cache for machines and users"
                Update-BrokerNameCache -Machines -Users
            }

            TestScript           = {
                return $false
            }
        }

        Script CreateNewDeliveryGroup {
            DependsOn            = '[Script]ForceRefreshBrokerCache'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateNewDeliveryGroup] Creating delivery group $($using:DeliveryGroupName)"
                $DeliveryGroupConfiguration = @{
                    InMaintenanceMode        = $False
                    IsRemotePC               = $False
                    DeliveryType             = 'DesktopsAndApps'
                    DesktopKind              = 'Shared'
                    MinimumFunctionalLevel   = 'L7_9'
                    Name                     = $using:DeliveryGroupName
                    OffPeakBufferSizePercent = 100
                    PeakBufferSizePercent    = 100
                    Scope                    = @()
                    SecureIcaRequired        = $False
                    SessionSupport           = $using:SessionSupport
                    ShutdownDesktopsAfterUse = $False
                    TimeZone                 = "Eastern Standard Time"
                }
                
                New-BrokerDesktopGroup @DeliveryGroupConfiguration
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-CreateNewDeliveryGroup] Delivery group $($using:DeliveryGroupName) creation completed"
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateNewDeliveryGroup] Testing if delivery group $($using:DeliveryGroupName) already exists"
                $isDeliveryGroupNameAvailable = (Test-BrokerDesktopGroupNameAvailable -Name $using:DeliveryGroupName).Available
                if ($isDeliveryGroupNameAvailable) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateNewDeliveryGroup] Delivery group $($using:DeliveryGroupName) does not exist and will be created"
                    return $false
                }
                else {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-CreateNewDeliveryGroup] Delivery group $($using:DeliveryGroupName) already exists"
                    return $true
                }
            }
        }

        Script AddStoreFrontToDeliveryGroup {
            DependsOn            = '[Script]CreateNewDeliveryGroup'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                try {
                    Add-BrokerMachineConfiguration -Name "RS\$($using:SFStoreFriendlyName)" -DesktopGroup $using:DeliveryGroupName
                }
                catch {
                    $string_err = $_ | Out-String
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontToDeliveryGroup] Unable to add store front to delivery group: $string_err"
                }
            }

            TestScript           = {
                $deliveryGroupUid = (Get-BrokerDesktopGroup -Name $using:DeliveryGroupName).Uid
                
                if (-not ((Get-BrokerMachineConfiguration -Name "RS\$($using:SFStoreFriendlyName)").DesktopGroupUids -contains $deliveryGroupUid)){
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontToDeliveryGroup] StoreFront has not been added to delivery group yet"
                    return $false
                }

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontToDeliveryGroup] StoreFront has already been added to delivery group"
                return $true
            }
        }

        Script AddMachinesToDeliveryGroup {
            DependsOn            = '[Script]AddStoreFrontToDeliveryGroup'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddMachinesToDeliveryGroup] Adding machines to delivery group $($using:DeliveryGroupName)"
                    $DeliveryGroupMachineAddRequest = @{
                        Catalog      = $using:CatalogName
                        Count        = ($using:ListOfVDAs).Split(",").Count
                        DesktopGroup = $using:DeliveryGroupName
                    }
                    Add-BrokerMachinesToDesktopGroup @DeliveryGroupMachineAddRequest
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddMachinesToDeliveryGroup] Finished adding machines to delivery group $($using:DeliveryGroupName)"
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddMachinesToDeliveryGroup] Failed to add machines to delivery group $($using:DeliveryGroupName): $($_)"
                }
            }

            TestScript           = {
                if (($using:ListOfVDAs).Split(",").Count -eq 0) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddMachinesToDeliveryGroup] No VDA provisioned, will not add VDA to delivery group"
                    return $true
                }
                return $false
            }
        }
        #endregion

        #region Configure Broker Rules
        Script ConfigureDeliveryGroupAGAccessPolicyRule {
            DependsOn            = '[Script]AddMachinesToDeliveryGroup'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $desktopGroup = Get-BrokerDesktopGroup -Name $using:DeliveryGroupName
                $agAccessPolicyRuleName = "$($using:DeliveryGroupName)_AG"
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureDeliveryGroupAGAccessPolicyRule] Adding broker delivery group AG access policy rule $($agAccessPolicyRuleName)"

                New-BrokerAccessPolicyRule -Name $agAccessPolicyRuleName -AllowRestart $true -AllowedConnections ViaAG -AllowedProtocols @('HDX', 'RDP') -AllowedUsers AnyAuthenticated -Enabled $true -DesktopGroupUid $desktopGroup.Uid
                Set-BrokerAccessPolicyRule -Name $agAccessPolicyRuleName -IncludedSmartAccessFilterEnabled $true -HdxSslEnabled $true
                
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureDeliveryGroupAGAccessPolicyRule] Broker delivery group AG access policy rule for $($agAccessPolicyRuleName) is added"
            }

            TestScript           = {
                $agAccessPolicyRuleName = "$($using:DeliveryGroupName)_AG"
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDeliveryGroupAGAccessPolicyRule] Testing if broker delivery group AG access policy rule $($agAccessPolicyRuleName) exists"
                
                $agAccessPolicyRule = Get-BrokerAccessPolicyRule -Name $agAccessPolicyRuleName -ErrorAction SilentlyContinue
                if (-not $agAccessPolicyRule) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDeliveryGroupAGAccessPolicyRule] Broker delivery group AG access policy rule $($agAccessPolicyRuleName) does not exist, will proceed to add operation"
                    return $false
                }
                
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDeliveryGroupAGAccessPolicyRule] Broker delivery group AG access policy rule $($agAccessPolicyRuleName) exists, skip add operation"
                return $true
            }
        }

        Script ConfigureDeliveryGroupDirectAccessPolicyRule {
            DependsOn            = '[Script]ConfigureDeliveryGroupAGAccessPolicyRule'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $desktopGroup = Get-BrokerDesktopGroup -Name $using:DeliveryGroupName
                $directAccessPolicyRuleName = "$($using:DeliveryGroupName)_Direct"
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureDeliveryGroupDirectAccessPolicyRule] Adding broker delivery group direct access policy rule $($directAccessPolicyRuleName)"
                
                $defaultDirectAccessPolicy = Get-BrokerAccessPolicyRule -Name $directAccessPolicyRuleName -ErrorAction SilentlyContinue
                if (-not $defaultDirectAccessPolicy){
                    New-BrokerAccessPolicyRule -Name $directAccessPolicyRuleName -AllowRestart $true -AllowedConnections NotViaAG -AllowedProtocols @('HDX', 'RDP') -AllowedUsers AnyAuthenticated -Enabled $true -DesktopGroupUid $desktopGroup.Uid
                    Set-BrokerAccessPolicyRule -Name $directAccessPolicyRuleName -IncludedSmartAccessFilterEnabled $true -HdxSslEnabled $true
                }
               
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureDeliveryGroupDirectAccessPolicyRule] Broker delivery group direct access policy rule for $($directAccessPolicyRuleName) is added"
            }

            TestScript           = {
                $directAccessPolicyRuleName = "$($using:DeliveryGroupName)_Direct"
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDeliveryGroupDirectAccessPolicyRule] Testing if broker delivery group direct access policy rule for $($directAccessPolicyRuleName) exists"
                $defaultDirectAccessPolicy = Get-BrokerAccessPolicyRule -Name $directAccessPolicyRuleName -ErrorAction SilentlyContinue
                if (-not $defaultDirectAccessPolicy){
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDeliveryGroupDirectAccessPolicyRule] Broker delivery group direct access policy rule for $($directAccessPolicyRuleName) does not exist, will proceed to add operation"
                    return $false
                }

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDeliveryGroupDirectAccessPolicyRule] Broker delivery group direct access policy rule for $($directAccessPolicyRuleName) exists, skip add operation"
                return $true
            }
        }

        Script ConfigureDesktopEntitlementPolicyRule {
            DependsOn            = '[Script]ConfigureDeliveryGroupDirectAccessPolicyRule'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                $desktop = Get-BrokerDesktopGroup -Name $using:DeliveryGroupName
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureDesktopEntitlementPolicyRule] Adding broker desktop entitlement policy rule $($using:DesktopRuleName)"
                New-BrokerEntitlementPolicyRule -Name $using:DesktopRuleName  -PublishedName $using:DesktopName -DesktopGroupUid $desktop.Uid -Enabled $True -ExcludedUserFilterEnabled $False -IncludedUserFilterEnabled $True -IncludedUsers ($using:DefaultUsers + @("$using:UserGroupName@$using:ADDomainFQDN"))
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureDesktopEntitlementPolicyRule] Broker desktop entitlement policy rule $($using:DesktopRuleName) is added"
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDesktopEntitlementPolicyRule] Testing if broker desktop entitlement policy rule $($using:DesktopRuleName) exists"
                $isBrokerEntitlementPolicyRuleNameAvailableForUsers = (Test-BrokerEntitlementPolicyRuleNameAvailable -Name $using:DesktopRuleName).Available
                if ($isBrokerEntitlementPolicyRuleNameAvailableForUsers) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDesktopEntitlementPolicyRule] Broker desktop entitlement policy rule $($using:DesktopRuleName) does not exist, will proceed to add operation"
                    return $false
                }
                else {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-ConfigureDesktopEntitlementPolicyRule] Broker desktop entitlement policy rule $($using:DesktopRuleName) exists, skip add operation"
                    return $true
                }
            }
        }
        #endregion

        #region Enable WebSocket Connection with Group Policy

        Script ConfigureWebSocketGroupPolicy {
            DependsOn            = '[Script]ConfigureDesktopEntitlementPolicyRule'

            PsDscRunAsCredential = $ADCredentials

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureWebSocketGroupPolicy] Enabling web socket connection"
                $retryCount = 0
                $maxRetry = 3
                Remove-Module Citrix.GroupPolicy.Commands -ErrorAction SilentlyContinue
                Remove-PsSnapin Citrix.Common.GroupPolicy -ErrorAction SilentlyContinue
                Remove-PSDrive GP -ErrorAction SilentlyContinue

                Import-Module Citrix.GroupPolicy.Commands -ErrorAction SilentlyContinue

                New-PsDrive -PsProvider CitrixGroupPolicy -Name GP -Root \ -Controller localhost
                do {
                    try {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureWebSocketGroupPolicy] Configuring WebSocket connection group policy"
                        $state = (Get-ItemProperty -Path "GP:\Computer\Unfiltered\Settings\ICA\WebSockets\AcceptWebSocketsConnections" -ErrorAction Stop).State
                        Set-ItemProperty -Path "GP:\Computer\Unfiltered\Settings\ICA\WebSockets\AcceptWebSocketsConnections" -Name State -Value Allowed -ErrorAction SilentlyContinue
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureWebSocketGroupPolicy] WebSocket connection group policy is set to Allowed"
                    }
                    catch {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-ConfigureWebSocketGroupPolicy] WebSocket connection enable end with exception $($_)"
                    }
                    finally {
                        $retryCount++
                    }
                } until (($state -eq "Allowed") -or ($retryCount -gt $maxRetry))
            }

            TestScript           = {
                return $false
            }
        }
        #endregion

        #region Disable and Remove local users
        Script DisableAndRemoveLocalUser {
            DependsOn            = "[Script]ConfigureWebSocketGroupPolicy"

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
