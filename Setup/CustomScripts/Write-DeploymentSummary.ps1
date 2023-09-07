[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [bool]$HideSessionLaunchPassword,
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
    if (-not $HideSessionLaunchPassword) {
        $rdpPasswordSummary = "Remote Desktop User Password:      $($AdAdminPassword)`n"
        $sfPasswordSummary = "The corresponding password is:                                        $($StoreUserPassword)`n"
        $webStudioPasswordSummary = "The corresponding password is:                                                                               $($AdAdminPassword)`n"
        $directorPasswordSummary  = "The corresponding password is:                                                                               $($AdAdminPassword)`n"
    }

    $vdaResourceGroupSummary = ""
    if ($VdaResourceGroupName) {
        $vdaResourceGroupSummary = "VDA resource group containing the VDAs:                                                                $($VdaResourceGroupName)`n"
    }

    Set-Content -Path "../DeploymentSummary.log" -Value $("`n" + `
        "#################################################################### Resource Groups Created #####################################################################`n" + `
        "`n" + `
        "The following resource groups are created:`n" + `
        "Main resource group containing the core components:                                                    $($CoreResourceGroupName)`n" + `
        $vdaResourceGroupSummary + `
        "`n" + `
        "##################################################################################################################################################################`n" + `
        "`n`n" + `
        "#################################################################### Virtual Machine Summary #####################################################################`n" + `
        "`n" + `
        "Active Directory Domain Controller virtual Machine:           $($AdComputerName).$($AdDomainName) (Public IP: $($AdPublicIP))`n" + `
        "Active Directory Domain name:                                 $($AdDomainName)`n" + `
        "Desktop Delivery Controller (DDC) virtual Machine:            $($DdcComputerName).$($AdDomainName) (Public IP: $($DdcPublicIp))`n" + `
        "`n" + `
        "##################################################################################################################################################################`n" + `
        "`n`n" + `
        "#################################################################### Machine Catalog Summary #####################################################################`n" + `
        "`n" + `
        "Citrix Machine Catalog Name:                       $($MachineCatalogName) ($($SessionSupport)) $($VdaCount) VM(s)`n" + `
        "Citrix Workspace Store Front URL:                  https://$($DdcComputerName).$($AdDomainName)$($StoreVirtualPath)Web/`n" + `
        "`n" + `
        "##################################################################################################################################################################`n" + `
        "`n`n" + `
        "############################################################## Session Launch and Web Studio Access ##############################################################`n" + `
        "`n" + `
        "You may use remote desktop with the following information to launch a session from the Active Directory Domain Controller:`n" + `
        "Remote Desktop Target Computer:    $($AdPublicIP):3389`n" + `
        "Remote Desktop Username:           $($AdDomainName)\$($AdAdminUsername)`n" + `
        $rdpPasswordSummary + `
        "`n" + `
        "To access Citrix Web Studio, you may navigate to the following address within the remote desktop session:    https://$($WebStudioMachine).$($AdDomainName)/Citrix/WebStudio/`n" + `
        "If prompted, you may enter the DDC FQDN:                                                                     $($DdcComputerName).$($AdDomainName)`n" + `
        "In the Web Studio, you can login with username:                                                              $($AdDomainName)\$($AdAdminUsername)`n" + `
        $webStudioPasswordSummary + `
        "`n" + `
        "To access Citrix Director, you may navigate to the following address within the remote desktop session:      https://$($DdcComputerName).$($AdDomainName)/Director/`n" + `
        "In the Director, you can login with username:                                                                $($AdDomainName)\$($AdAdminUsername)`n" + `
        $directorPasswordSummary + `
        "`n" + `
        "After log into the remote desktop, you may access Store Front with:   https://$($DdcComputerName).$($AdDomainName)$($StoreVirtualPath)Web/`n" + `
        "In the Store Front, you can login with username:                      $($AdDomainName)\user0001`n" + `
        $sfPasswordSummary + `
        "`n" + `
        "##################################################################################################################################################################`n" + `
        "`n")
}
catch {
    Write-Host "$_"
    continue
}
