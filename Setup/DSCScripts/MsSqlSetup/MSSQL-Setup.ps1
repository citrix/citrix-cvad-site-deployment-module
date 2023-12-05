# Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.
Configuration MSSQL-Setup {
    <#
.SYNOPSIS
    Setup Microsoft SQL server
    
    Copyright (c) Citrix Systems, Inc. All Rights Reserved.
    
.DESCRIPTION
    Configure Microsoft SQL Server VM

.Parameter DbServerInstanceName
    Database Instance name

.Parameter AdNetBIOSName
    AD Net BIOS name
    
.Parameter AdDomainFQDN
    Domain FQDN of Active Directory

.Parameter AdDomainAdminName
    Domain admin username of Active Directory

.Parameter AdDomainAdminPassword
    AD domain admin password

.Parameter SqlAdminUsername
    SQL Admin Username
.Parameter SqlAdminPassword
    SQL Admin Password


#>  
    param( 
        [Parameter(Mandatory = $true)]
        [string] $CitrixModulesPath,
        [Parameter(Mandatory = $true)]
        [string] $DbServerInstanceName,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainControllerPrivateIp,
        [Parameter(Mandatory = $true)]
        [string] $AdNetBIOSName,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainFQDN,
        [Parameter(Mandatory = $true)]
        [string] $AdDomainAdminName,
        [Parameter(Mandatory = $true)]
        [String] $AdDomainAdminPassword,
        [Parameter(Mandatory = $true)]
        [string] $SqlAdminUsername,
        [Parameter(Mandatory = $true)]
        [string] $SqlAdminPassword
    ) 
    
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    $logFilePath = "$($CitrixModulesPath)\CVAD_Installation.log"

    Node localhost
    {
 

        LocalConfigurationManager {    
            RefreshMode        = "PUSH";    
            RebootNodeIfNeeded = $true # This is false by default
            ActionAfterReboot  = "ContinueConfiguration"
            ConfigurationMode  = "ApplyOnly"
        }
    
        Script SetupCitrixModules {
            GetScript  = {
            }

            SetScript  = {
                New-Item -ItemType "Directory" -Path $using:CitrixModulesPath -Force
                New-Item -ItemType "File" -Path $using:logFilePath -Force
            }

            TestScript = {
                try {
                    Test-Path -Path $using:logFilePath
                }
                catch {
                    return $false
                }
            }
        }

        #region Make the AD Domain Controller discoverable on VNet and Domain
        Script EnableNetworkDiscovery {
            DependsOn            = "[Script]SetupCitrixModules"
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
        
        #Domain Join SQL DB Server
        Script EnsureDomainControllerReachability {
            DependsOn  = '[Script]EnableNetworkDiscovery'

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
                # Domain Join Credential Setup
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Try setup AD Join credential"
                $adCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
                        UserName = "$using:AdDomainFQDN\$using:AdDomainAdminName"
                        Password = (ConvertTo-SecureString "$($using:AdDomainAdminPassword)" -AsPlainText -Force)[0]
                    })
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Try AD Join "
                Add-Computer -DomainName $using:AdDomainFQDN -Credential $adCred
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Finished AD Join "
                Restart-Computer -Force
            }

            TestScript = {
                # Check if computer is AD Joined
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Test AD Join $using:AdDomainFQDN"
                try {
                    Test-ComputerSecureChannel -Server $using:AdDomainFQDN
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Failed AD Join Test"
                    return $false
                }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Finished AD Join Test"
            }	
            
        }

        # Create Active Directory Admin DataBase Windows login
        Script EnableRemoteAccessDB {
            DependsOn  = '[Script]DomainJoin'
            GetScript  = {

            }
            SetScript  = {
                # For SQL EXPRESS, display name is "SQL SERVER (SQLEXPRESS)".  For SQL 2012 is "SQL SERVER (MSSQLSERVER)"
                $sqlservice = Get-Service -DisplayName "SQL Server (MSSQLSERVER)"

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Stopping the SQL Service: $sqlservice"
                net stop $sqlservice /y

                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Starting the SQL Service: $sqlservice"
                net start $sqlservice /y
            }
            TestScript = {
                try {
                    #Looking for the correct path to sqlps command
                    $sqlpsFullPath = Join-Path ${ENV:ProgramFiles(x86)} "Microsoft SQL Server\100\Tools\binn"
                    $SqlpsCommand = "$sqlpsFullPath\sqlps.exe"
                    if (-not (Test-Path $SqlpsCommand)) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Searching for sqlpscmd in folder `'$(join-path ${ENV:ProgramFiles(x86)} 'Microsoft SQL Server')`'..."
                        $SqlpsCommand = @(ls (join-path ${ENV:ProgramFiles(x86)} "Microsoft SQL Server") -include 'sqlps.exe' -recurse)[0].FullName
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Sql Database command: $SqlpsCommand"
                        if (-not (Test-Path $SqlpsCommand)) {
                            Throw "SQLPS tool is not found"
                        }
                    }

                    [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo")
                    [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")

                    $wmi = new-object ('Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer')
                    $wmi
            
                    # calculate computer name - this script will only run on this machine
                    $machine = $env:Computername
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Computer name: $($machine)"

                    #Enable tcp
                    $uri = "ManagedComputer[@Name='$machine']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='Tcp']"
                
                    $tcp = $wmi.GetSmoObject($uri)
                    if ($tcp.IsEnabled) {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') TCP is enabled"
                        return $true
                    }
                    else {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Remote Access to DataBase Required, Enabling TCP..."
                        $tcp.IsEnabled = $true
                        $tcp.Alter()
                        return $false
                    }
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') EnableRemoteAccessDB fail"
                    return $false
                }
            }
        }


        # Create Active Directory Admin DataBase Windows login
        Script AddADAdminForDB {
            DependsOn  = '[Script]EnableRemoteAccessDB'
            GetScript  = {
            }

            SetScript  = {
                try {
                    # Create AD Admin DB Windows login
                    $query = "CREATE LOGIN [$using:AdNetBIOSName\$using:AdDomainAdminName] FROM WINDOWS;"
                    Invoke-SqlCmd -ServerInstance $using:DbServerInstanceName -Query $query -Username $using:SqlAdminUsername -Password $using:SqlAdminPassword
                }
                catch {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') AD Admin creation failure"
                }
            }

            TestScript = {
                #Import SQL Server module which comes with the MS SQL Server installation
                $searchPath = @()
                $searchPath += Join-Path ${env:ProgramFiles(x86)} "Microsoft SQL Server"
                $searchPath += Join-Path ${env:ProgramFiles} "Microsoft SQL Server"
                $res = @(Get-Childitem -Recurse -Path $searchPath -Include @('microsoft.sqlserver.management.pssnapins.dll', 'Microsoft.SqlServer.Management.PSProvider.dll'))
                if ($null -ne $res) {
                    $res | ForEach-Object {
                        Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Importing $_"
                        Import-Module -Name $_.FullName
                    }
                }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') Loading SQL Server Module"
                
                #Test if AD Admin is already exist
                $smo = New-Object Microsoft.SqlServer.Management.Smo.Server $env:ComputerName
                if (($smo.logins).Name -contains "$using:AdNetBIOSName\$using:AdDomainAdminName") {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') AD Admin already exist"
                    $true
                }
                else {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') AD Admin does not exist, start creating"
                    $false
                }
            }
            
        }

        Script AddServerRole {
            DependsOn  = '[Script]AddADAdminForDB'
            GetScript  = {
            }

            SetScript  = {
                # Alter AD Admin DB Windows login with proper roles
                # List of server roles can be checked with this article: https://support.citrix.com/article/CTX127998/database-access-and-permission-model-for-xendesktop
                $ServerRolesToAlter = @(
                    "dbcreator",
                    "securityadmin"
                )
                $ServerRolesToAlter | ForEach-Object {
                    $query = "ALTER SERVER ROLE $_ ADD MEMBER [$using:AdNetBIOSName\$using:AdDomainAdminName];"
                    Invoke-SqlCmd -ServerInstance $using:DbServerInstanceName -Query $query -Username $using:SqlAdminUsername -Password $using:SqlAdminPassword
                }
                Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K') AD Admin created"
            }
            TestScript = {
                $query = "SELECT IS_SRVROLEMEMBER ('dbcreator', '$using:AdNetBIOSName\$using:AdDomainAdminName') + IS_SRVROLEMEMBER ('dbcreator', '$using:AdNetBIOSName\$using:AdDomainAdminName')"
                $roleNum = Invoke-SqlCmd -ServerInstance $using:DbServerInstanceName -Query $query -Username $using:SqlAdminUsername -Password $using:SqlAdminPassword
                if ($roleNum -eq 2) {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K')Server Roles dbcreator and securityadmin added compeletely"
                    return $true
                }
                else {
                    Add-content $using:logFilePath -value "$(get-date -Format 'yyyy-MM-dd HH:mm:ss.ffff K')Server Roles not added compeletely"
                    return $false
                }
            }

        }

        File MsSqlInstallCleanup {
            DependsOn       = '[Script]AddADAdminForDB'
            DestinationPath = $CitrixModulesPath
            Type            = "Directory"
            Ensure          = "Absent"
            Force           = $true
        }
            
    }
}

