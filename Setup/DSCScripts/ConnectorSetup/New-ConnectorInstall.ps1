Configuration New-ConnectorInstall {

<#
.SYNOPSIS
    Setup Citrix Cloud Connector
    
    Copyright (c) Citrix Systems, Inc. All Rights Reserved.
    
.DESCRIPTION
    Configure Connector VM

.Parameter AdDomainFQDN
    Domain FQDN of Active Directory

.Parameter AdDomainAdminName
    Domain admin username of Active Directory

.Parameter AdDomainAdminPassword
    AD domain admin password

.Parameter CustomerId
    Citrix Cloud Customer Id
.Parameter ClientId
    Citrix Cloud Customer API Client Id
.Parameter ClientSecret
    Citrix Cloud Customer API Client Secret
.Parameter ResourceLocationId
    Citrix Cloud Customer Resource Location for the Connector
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $tempDir,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainControllerPrivateIp,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainFQDN,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainAdminName,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainAdminPassword,
        [Parameter(Mandatory = $true)]
        [string] $CustomerId,
        [Parameter(Mandatory = $true)]
        [string] $ClientId,
        [Parameter(Mandatory = $true)]
        [string] $ClientSecret,
        [Parameter(Mandatory = $true)]
        [string] $ResourceLocationId,
        [Parameter(Mandatory = $true)]
        [bool] $IsJpCustomer
    )

    Import-DSCResource -ModuleName PSDesiredStateConfiguration
    $baseUrl = "cloud.com"
    if ($IsJpCustomer) {
        $baseUrl = "citrixcloud.jp"
    }

    $connectorPreReqFile = "$tempDir\cwcconnectorprerequisites.exe"
    $connectorPreReqDownloadUri = "https://downloads.$baseUrl/$CustomerId/connectorprerequisites/cwcconnectorprerequisites.exe"

    $connectorInstallerFile = "$tempDir\cwcconnector.exe"
    $connectorDownloadUri = "https://downloads.$baseUrl/$CustomerId/connector/cwcconnector.exe"
    $connectorInstallParamsFile = "$tempDir\cwcconnector_install_params.json"

    $logFilePath = "$($tempDir)\ConnectorSetup.log"

    Node localhost {
        LocalConfigurationManager {
            ActionAfterReboot   = "ContinueConfiguration"
            RefreshMode         = "Push"
            RebootNodeIfNeeded  = $true;
            ConfigurationMode   = "ApplyOnly"
        }

        Registry DisableUserIEESC {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            ValueName   = "IsInstalled"
            ValueData   = "0"
        }

        Registry DisableAdminIEESC {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            ValueName   = "IsInstalled"
            ValueData   = "0"
        }

        File SetupTempDir
        {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $tempDir
            Force = $true
        }

        Script EnsureDomainControllerReachability {
            DependsOn = @('[Registry]DisableUserIEESC','[Registry]DisableAdminIEESC','[File]SetupTempDir')

            GetScript = {
            }

            SetScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-EnsureDomainControllerReachability] Domain controller reachability test failed."
                throw "Unable to reach Active Directory Domain Controller"
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-EnsureDomainControllerReachability] Checking if Domain Controller $($using:AdDomainControllerPrivateIp) is reachable."
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

        Script DomainJoinVM {
            DependsOn = '[Script]EnsureDomainControllerReachability'
            GetScript = {
            }

            SetScript = {
                # Domain Join Credential Setup
                $adCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
                    UserName = "$using:AdDomainFQDN\$using:AdDomainAdminName"
                    Password = (ConvertTo-SecureString $using:AdDomainAdminPassword -AsPlainText -Force)[0]
                })
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-DomainJoinVM] Adding connector VM to domain."
                Add-Computer -DomainName $using:AdDomainFQDN -Credential $adCred
                Restart-Computer -Force
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DomainJoinVM] Checking whether connector VM has already domain joined."
                try {
                    Test-ComputerSecureChannel -Server $using:AdDomainFQDN
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DomainJoinVM] Connector VM has already domain joined."
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-DomainJoinVM] Connector VM has not join the provided domain."
                    return $false
                }
            }
        }
        
        Script InstallConnectorPreReq {
            DependsOn = @('[Script]DomainJoinVM')
            GetScript = {
            }

            SetScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallConnectorPreReq] Installing pre-requisites for connector."
                $retryCount = 0
                while ($retryCount -lt 3){
                    Invoke-WebRequest -Uri $using:connectorPreReqDownloadUri -OutFile $using:connectorPreReqFile

                    $proc = Start-Process -FilePath $using:connectorPreReqFile -ArgumentList "/quiet" -PassThru -Wait
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\CloudServices\Install\RegistryConfig" -Name "ConnectorPreReqInstallExitCode" -Value $proc.ExitCode -Force
                    
                    if ($proc.ExitCode -eq 0){
                        break;
                    }

                    Remove-Item -Path $using:connectorPreReqFile -Force
                    $retryCount++
                }
                Restart-Computer -Force
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallConnectorPreReq] Checking if connector pre-requisites are installed."
                try {
                    Get-Item "HKLM:\SOFTWARE\Citrix\CloudServices\Install\RegistryConfig\" -ErrorAction Stop | Get-ItemPropertyValue -Name ProductVersion | ForEach-Object {$null -ne $_}
                    Get-Item "HKLM:\SOFTWARE\Citrix\CloudServices\Install\RegistryConfig\" -ErrorAction Stop | Get-ItemPropertyValue -Name ConnectorPreReqInstallExitCode | ForEach-Object {$_ -eq 0}
                }
                catch {
                    return $false
                }
            }
        }

        Script InstallConnector {
            DependsOn = '[Script]InstallConnectorPreReq'
            GetScript = {
            }

            SetScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Set-InstallConnector] Install and configure connector software."

                # Passing /ClientSecret: on the command line would undo the protectedSettings boundary:
                # process command lines are readable locally and captured by command-line auditing.
                $paramsFilePath = $using:connectorInstallParamsFile

                try {
                    # Creating over an existing file would adopt its owner and explicit ACEs, leaving
                    # whoever planted it able to read the secret; this also clears a stranded file.
                    Remove-Item -Path $paramsFilePath -Force -ErrorAction SilentlyContinue

                    # Build the security descriptor from scratch rather than from the file, and apply it
                    # as the file is created, so the secret is never on disk under any other permissions.
                    # Well-known SIDs are used rather than account names because those names are localized.
                    $fileSecurity = New-Object System.Security.AccessControl.FileSecurity
                    $fileSecurity.SetAccessRuleProtection($true, $false)
                    foreach ($wellKnownSid in @("S-1-5-18", "S-1-5-32-544")) {
                        $fileSecurity.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            (New-Object System.Security.Principal.SecurityIdentifier($wellKnownSid)),
                            "FullControl",
                            "Allow"
                        )))
                    }

                    $installParams = @{
                        customerName         = $using:CustomerId
                        clientId             = $using:ClientId
                        clientSecret         = $using:ClientSecret
                        resourceLocationId   = $using:ResourceLocationId
                        acceptTermsOfService = "true"
                    }

                    # CreateNew fails rather than overwrites if the path still exists, so a file that
                    # could not be removed above stops the install instead of leaking into it.
                    # UTF8Encoding($false) so that no byte order mark is prepended to the JSON.
                    $paramsStream = New-Object System.IO.FileStream(
                        $paramsFilePath,
                        [System.IO.FileMode]::CreateNew,
                        [System.Security.AccessControl.FileSystemRights]::Write,
                        [System.IO.FileShare]::None,
                        4096,
                        [System.IO.FileOptions]::None,
                        $fileSecurity
                    )
                    try {
                        $paramsBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(($installParams | ConvertTo-Json))
                        $paramsStream.Write($paramsBytes, 0, $paramsBytes.Length)
                    }
                    finally {
                        $paramsStream.Dispose()
                    }

                    $retryCount = 0
                    while ($retryCount -lt 3){
                        Invoke-WebRequest -Uri $using:connectorDownloadUri -OutFile $using:connectorInstallerFile

                        $proc = Start-Process -FilePath $using:connectorInstallerFile -ArgumentList "/q /ParametersFilePath:`"$paramsFilePath`"" -PassThru -Wait
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\CloudServices\AgentFoundation" -Name "ConnectorInstallExitCode" -Value $proc.ExitCode -Force

                        if ($proc.ExitCode -eq 0){
                            break;
                        }

                        Remove-Item -Path $using:connectorInstallerFile -Force
                        $retryCount++
                    }
                }
                finally {
                    Remove-Item -Path $paramsFilePath -Force -ErrorAction SilentlyContinue
                }
            }

            TestScript = {
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') [Test-InstallConnector] Checking if connector software is installed and congfigured."
                try {
                    Get-Item "HKLM:\SOFTWARE\Citrix\CloudServices\AgentFoundation\" -ErrorAction Stop | Get-ItemPropertyValue -Name Configured | ForEach-Object {$_ -eq 1}
                    Get-Item "HKLM:\SOFTWARE\Citrix\CloudServices\AgentFoundation\" -ErrorAction Stop | Get-ItemPropertyValue -Name CustomerName | ForEach-Object {$_ -eq $using:CustomerId}
                    Get-Item "HKLM:\SOFTWARE\Citrix\CloudServices\AgentFoundation\" -ErrorAction Stop | Get-ItemPropertyValue -Name ConnectorInstallExitCode | ForEach-Object {$_ -eq 0}
                }
                catch {
                    return $false
                }
            }
        }
    }
}
