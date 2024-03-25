# Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [int]$ShowSessionLaunchPassword,
    [Parameter(Mandatory=$true)]
    [string]$CoreResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string]$AdDomainName,
    [Parameter(Mandatory=$true)]
    [string]$AdPublicIP,
    [Parameter(Mandatory=$true)]
    [string]$AdComputerName,
    [Parameter(Mandatory=$true)]
    [string]$AdAdminUsername,
    [Parameter(Mandatory=$true)]
    [string]$AdAdminPassword,
    [Parameter(Mandatory=$true)]
    [string]$DdcComputerName,
    [Parameter(Mandatory=$true)]
    [string]$DdcPublicIp,
    [Parameter(Mandatory=$true)]
    [string]$DdcPrivateIp,
    [Parameter(Mandatory=$true)]
    [string]$StoreVirtualPath,
    [Parameter(Mandatory=$true)]
    [string]$StoreUserPassword,
    [Parameter(Mandatory=$true)]
    [string]$MachineCatalogName,
    [Parameter(Mandatory=$true)]
    [string]$SessionSupport,
    [Parameter(Mandatory=$true)]
    [string]$VdaCount,
    [Parameter(Mandatory=$true)]
    [string]$WebStudioMachine,

    [Parameter(Mandatory=$false)]
    [string]$VdaResourceGroupName = ""
)

try {
    $directorPasswordSummary = ""
    $rdpPasswordSummary = ""
    $sfPasswordSummary = ""
    $webStudioPasswordSummary = ""
    if ($ShowSessionLaunchPassword) {
        $rdpPasswordSummary = "Remote Desktop User Password:      ``````$($AdAdminPassword)`````` `n`n"
        $sfPasswordSummary = "The corresponding password is:                                        ``````$($StoreUserPassword)`````` `n`n"
        $webStudioPasswordSummary = "The corresponding password is:                                                                               ``````$($AdAdminPassword)`````` `n`n"
        $directorPasswordSummary  = "The corresponding password is:                                                                               ``````$($AdAdminPassword)`````` `n`n"
    }

    $vdaResourceGroupSummary = ""
    if ($VdaResourceGroupName) {
        $vdaResourceGroupSummary = "VDA resource group containing the VDAs:                                                                ``````$($VdaResourceGroupName)`````` `n`n"
    }

    Set-Content -Path "../DeploymentSummary.md" -Value $("`n" + `
        "# Resource Groups Created`n`n" + `
        "The following resource groups are created:`n`n" + `
        "Main resource group containing the core components:                                                    ``````$($CoreResourceGroupName)`````` `n`n" + `
        $vdaResourceGroupSummary + `
        "`n" + `
        "# Virtual Machine Summary `n`n" + `
        "Active Directory Domain Controller virtual Machine:           ``````$($AdComputerName).$($AdDomainName) (Public IP: $($AdPublicIP))`````` `n`n" + `
        "Active Directory Domain name:                                 ``````$($AdDomainName)`````` `n`n" + `
        "Desktop Delivery Controller (DDC) virtual Machine:            ``````$($DdcComputerName).$($AdDomainName) (Public IP: $($DdcPublicIp))`````` `n`n" + `
        "`n" + `
        "# Machine Catalog Summary`n`n" + `
        "Citrix Machine Catalog Name:                       ``````$($MachineCatalogName) ($($SessionSupport)) $($VdaCount) VM(s)`````` `n`n" + `
        "Citrix Workspace Store Front URL:                  ``````https://$($DdcComputerName).$($AdDomainName)$($StoreVirtualPath)Web/`````` `n`n" + `
        "`n`n" + `
        "# Session Launch and Management Interface`n`n" + `
        "## 1. Remote Desktop Information`n`n" + `
        "You may use remote desktop with the following information to launch a session from the Active Directory Domain Controller:`n`n" + `
        "Remote Desktop Target Computer:    ``````$($AdPublicIP):3389`````` `n`n" + `
        "Remote Desktop Username:           ``````$($AdDomainName)\$($AdAdminUsername)`````` `n`n" + `
        $rdpPasswordSummary + `
        "`n" + `
        "## 2. Session Launch Information`n`n" + `
        "After log into the remote desktop, you may access Store Front with:   ``````https://$($DdcComputerName).$($AdDomainName)$($StoreVirtualPath)Web/`````` `n`n" + `
        "In the Store Front, you can login with username:                      ``````$($AdDomainName)\user0001`````` `n`n" + `
        $sfPasswordSummary + `
        "`n" + `
        "## 3. Web Studio Access`n`n" + `
        "If you are using CVAD version 2308 or earlier, you may navigate to the following address within the remote desktop session to access WebStudio:    ``````https://$($WebStudioMachine).$($AdDomainName)/Citrix/WebStudio/`````` `n`n" + `
        "For CVAD version 2311 or later, please access with:                                                          ``````https://$($WebStudioMachine).$($AdDomainName)/Citrix/Studio/`````` `n`n" + `
        "If prompted, you may enter the DDC FQDN:                                                                     ``````$($DdcComputerName).$($AdDomainName)`````` `n`n" + `
        "In the Web Studio, you can login with username:                                                              ``````$($AdDomainName)\$($AdAdminUsername)`````` `n`n" + `
        $webStudioPasswordSummary + `
        "`n" + `
        "## 4. Citrix Director Access`n`n" + `
        "To access Citrix Director, you may navigate to the following address within the remote desktop session:      ``````https://$($DdcComputerName).$($AdDomainName)/Director/`````` `n`n" + `
        "In the Director, you can login with username:                                                                ``````$($AdDomainName)\$($AdAdminUsername)`````` `n`n" + `
        $directorPasswordSummary + `
        "`n`n") -Force
}
catch {
    Write-Output "$_"
    continue
}
