# Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.
Configuration VdaSetup
{
    param (
        [Parameter(Mandatory = $true)]
        [string] $ADDomainFQDN,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainUsername,
        [Parameter(Mandatory = $true)]
        [string] $ADDomainPassword,
        [Parameter(Mandatory = $true)]
        [string] $DDCList,
        [Parameter(Mandatory = $true)]
        [string] $CAServerHostName,
        [Parameter(Mandatory = $true)]
        [string] $CACommonName,
        [Parameter(Mandatory = $true)]
        [string] $RequestCertFromCAScriptUrl,
        [Parameter(Mandatory = $true)]
        [string] $RequestCertTemplateUrl,
        [Parameter(Mandatory = $true)]
        [string] $EnableVdaSSLScriptUrl,
        [Parameter(Mandatory = $false)]
        [string] $CitrixModulesPath = "C:\CitrixModules"
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $registryPath_VirtualDesktopAgent = "HKLM:\Software\Citrix\VirtualDesktopAgent"

    $logFilePath = "$($CitrixModulesPath)\VDA_Installation.log"

    # SSL Certificate Setup
    $RequestCertFromCAScriptPath = "$CitrixModulesPath\Request-CertificateFromCA.ps1"
    $RequestCertTemplatePath = "$CitrixModulesPath\RequestTemplate.inf"
    $SslCertThumbprintFilePath = "$CitrixModulesPath\SslCertThumbprint"

    $EnableVdaSSLScriptPath = "$CitrixModulesPath\Enable-VdaSSL.ps1"

    # Credential Object for Active Directory Admin
    $ADCredentials = New-Object pscredential -ArgumentList ([pscustomobject]@{
            UserName = "$ADDomainFQDN\$ADDomainUsername"
            Password = (ConvertTo-SecureString "$($ADDomainPassword)" -AsPlainText -Force)[0]
        })

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
        #endregion

        #region Configure VDA SSL Encryption
        Script DownloadCertificateRequestScript {
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
            DependsOn            = @('[Script]DownloadCertificateRequestScript', '[Script]DownloadCertificateRequestTemplate')

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
                    "-ThumbprintFilePath `"$($using:SslCertThumbprintFilePath)`"",
                    "-LogFilePath `"$($using:logFilePath)`""
                )

                Start-Process powershell.exe -ArgumentList $argumentList -Wait -NoNewWindow
                       
            }

            TestScript           = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-RequestCertificateFromCA] Checking if certificate request from certification authority is already completed"
                Test-Path -Path $using:SslCertThumbprintFilePath
            }
        }
        #endregion

        # Set DDC List registry for VDA registration
        Script SetDDCListRegistry {
            DependsOn  = '[Script]RequestCertificateFromCA'

            GetScript  = {
            }

            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-SetDDCListRegistry] Setting DDC List Registry"
                Set-ItemProperty -Path $using:registryPath_VirtualDesktopAgent -Name ListOfDDCs -Value $using:DDCList
            }

            TestScript = {
                try {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-SetDDCListRegistry] Checking if DDC List registry key have been set"
                    $registryDDCList = Get-ItemPropertyValue -Path $using:registryPath_VirtualDesktopAgent -Name ListOfDDCs -ErrorAction Stop
                    return $registryDDCList -eq $using:DDCList
                }
                catch {
                    return $false
                }
            }
        }
        #endregion

        #region Disable and Remove local users
        Script DisableAndRemoveLocalUser {
            DependsOn            = "[Script]SetDDCListRegistry"

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

        #region Run Enable-VdaSSL script
        Script DownloadEnableVdaSSLScript {
            DependsOn  = '[Script]DisableAndRemoveLocalUser'

            GetScript  = {
            }

            SetScript  = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DownloadEnableVdaSSLScript] Downloading Enable-VdaSSL.ps1 file"
                Invoke-WebRequest -Uri $using:EnableVdaSSLScriptUrl -OutFile $using:EnableVdaSSLScriptPath
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DownloadEnableVdaSSLScript] Checking if Enable-VdaSSL.ps1 file already exists"
                Test-Path -Path $using:EnableVdaSSLScriptPath
            }
        }

        Script EnableVdaSSL {
            DependsOn  = '[Script]DownloadEnableVdaSSLScript'
            
            GetScript  = {
                
            }
            
            SetScript  = {
                $argumentList = @(
                    "-File `"$($using:EnableVdaSSLScriptPath)`"",
                    "-CertificateThumbPrintFilePath `"$($using:SslCertThumbprintFilePath)`"",
                    "-LogFilePath `"$($using:logFilePath)`""
                )

                Start-Process powershell.exe -ArgumentList $argumentList -Wait -NoNewWindow
            }

            TestScript = {
                return $false
            }
        }
        #endregion
    }
}
