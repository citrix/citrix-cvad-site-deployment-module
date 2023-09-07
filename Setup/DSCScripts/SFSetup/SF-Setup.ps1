Configuration StoreFrontSetup
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
        [string] $CitrixModulesPath,
        [Parameter(Mandatory = $true)]
        [string] $StoreVirtualPath,
        [Parameter(Mandatory = $true)]
        [string] $SFDeliveryControllerPort, 
        [Parameter(Mandatory = $true)]
        [string] $FarmType,
        [Parameter(Mandatory = $true)]
        [string] $FarmName,
        [Parameter(Mandatory = $true)]
        [string] $FarmServers, 
        [Parameter(Mandatory = $true)]
        [string] $AreDDCServersLoadBalanced,
        [Parameter(Mandatory = $true)]
        [string] $SFStoreFriendlyName,
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

    $registryPath_CvadDeliveryServices = "HKLM:\SOFTWARE\Citrix\DeliveryServices"
    
    $logFilePath = "$($CitrixModulesPath)\StoreFront_Installation.log"
    $xenDesktopServerSetupPath = "$($CitrixModulesPath)\x64\Storefront\CitrixStoreFront-x64.exe"
    $cvadInstallerOutputPath = "$($CitrixModulesPath)\CVAD_Installer.iso"
    $registryPath_CvadAutomation = "HKLM:\SOFTWARE\Citrix\Automation\"
    $registryKey_CvadIsoFileHash = "IsoFileHash"

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

        Script DomainJoin {
            DependsOn  = @("[File]CitrixModules", "[Registry]EnsureCvadDownloadRegistryPresents", "[Script]EnableNetworkDiscovery")

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




        #region StoreFront Installation and Configuration
        Script InstallStoreFront {
            DependsOn            = '[Script]MountISO'

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
                try {
                    $iis_site = Get-IISSite "Default Web Site" # ToDo: Check if this should be parameterized based on customer's setup
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontDeployment] Creating a StoreFront Deployment with $env:COMPUTERNAME and  $using:ADDomainFQDN"
                    Add-STFDeployment -HostBaseUrl "https://$env:COMPUTERNAME.$using:ADDomainFQDN" -SiteId $iis_site.Id -Confirm:$false
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-AddStoreFrontDeployment] Creating a StoreFront Deployment Exception: $($_)"
                    return $false
                }
              
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-AddStoreFrontDeployment] Checking if a StoreFront deployment already exists for machineID: $env:ComputerName"
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
                Add-STFStoreService -VirtualPath $using:StoreVirtualPath -AuthenticationService $authentication -FarmName $using:FarmName -FarmType $using:Farmtype -Servers "$using:FarmServers.$using:ADDomainFQDN" -LoadBalance $loadBalance -Port $using:SFDeliveryControllerPort -FriendlyName $using:SFStoreFriendlyName -TransportType $transportType
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
        #endregion

        #region Configure IIS SSL Encryption
        Script DownloadCertificateRequestScript {
            DependsOn            = '[Script]EnableSFStorePna'

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DownloadCertificateRequestScript] Downloading Request-CertificateFromCA.ps1 file"
                Invoke-WebRequest -Uri $using:RequestCertFromCAScriptUrl -OutFile $using:RequestCertFromCAScriptPath
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadCertificateRequestScript] Checking if Request-CertificateFromCA.ps1 file already exists"
                Test-Path -Path $using:RequestCertFromCAScriptPath
            }
        }

        Script DownloadCertificateRequestTemplate {
            DependsOn            = '[Script]DownloadCertificateRequestScript'

            GetScript            = {
            }

            SetScript            = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DownloadCertificateRequestTemplate] Downloading RequestTemplate.inf file"
                Invoke-WebRequest -Uri $using:RequestCertTemplateUrl -OutFile $using:RequestCertTemplatePath
            }

            TestScript           = {
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

                $sites = Get-ChildItem IIS:SSLBindings | Where-Object {($_.Sites -eq "Default Web Site") -and ($_.Port -eq 443)}
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