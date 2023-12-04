<#

    .SYNOPSIS
    Remove CVAD setup with Terraform.

    .DESCRIPTION
    Remove CVAD setup with Terraform.

    .PARAMETER IncludeTerraform
    Optional switch parameter to specify whether the user want to install required dependency using this script.

    .PARAMETER AutoApprove
    Optional switch parameter to let user skip confirmation before deploying the terraform action plan.

    .PARAMETER Parallelism
    Optional parameter specifying the maximum paralellism for terraform. The default value is 2. If the value is too high, Azure could report too many request error.

    .PARAMETER PreserveAzureCredential
    Optional switch parameter specifying whether azure credentials will be preserved after deployment.

    .PARAMETER PreserveAzureCredential
    Optional boolean parameter specifying whether state files will be preserved after deployment.

    .EXAMPLE
    PS> Remove-CvadDeployment.ps1 [-IncludeTerraform] [-AutoApprove] [-Parallelism 2] [-PreserveAzureCredential]

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTerraform,
    [Parameter(Mandatory = $false)]
    [switch]$AutoApprove,
    [Parameter(Mandatory = $false)]
    [int]$Parallelism = 2,
    [Parameter(Mandatory = $false)]
    [switch]$PreserveAzureCredential = $false
)

$ErrorActionPreference = "Stop"

$startingLocation = Get-Location | Convert-Path
$workingDir = Split-Path -Path $($MyInvocation.MyCommand.Source) -Parent

Unblock-File -Path "$($workingDir)\*.ps1"
$siteProvisionTerraformLocation = "$($workingDir)\1-site-provisioning-terraform"
$siteManagementTerraformLocation = "$($workingDir)\2-site-management-terraform"
$vdaSslTerraformLocation = "$($workingDir)\3-vda-ssl-terraform"

$tmpDirectoryPath = "$($workingDir)\tmp\"
$genTfVarsFilePath = "$($tmpDirectoryPath)generated.tfvars.json"

$getCvadCommonModuleResult = Get-Module CVADDeploymentCommon
if (-not $getCvadCommonModuleResult) {
    Import-Module "$($workingDir)\CVADDeploymentCommon.psm1" -Force
}

try {
    Test-PowerShellEnvironment

    # Unblock write summary script
    Unblock-File -Path "$($workingDir)\Setup\CustomScripts\*.ps1"

    # Verify Azure provider configuration
    Test-AzureConfig -WorkingDirectory $workingDir

    # Navigate to vnet, advm, and ddc setup section
    Write-Host "Navigate directory to VNet, AD VM, and DDC terraform workspace"

    if ($IncludeTerraform) {
        Install-Terraform
    }
    
    Test-TerraformEnvironment
    
    # Run terraform script
    # Make sure terraform app reg is assigned with Contributor role
    Write-Host "Initializing Terraform environment"

    $tfAutoApproveArg = $null
    if ($AutoApprove) {
        $tfAutoApproveArg = "-auto-approve"
    }

    New-GeneratedTfVarFile -WorkingDirectory $workingDir -TempDirectoryPath $tmpDirectoryPath -GeneratedTfVarsFilePath $genTfVarsFilePath -ShowSessionLaunchPassword $false -Destroy $true
    Add-DDCManagementInfoToGeneratedTfVarsFile -GeneratedTfVarsFilePath $genTfVarsFilePath -SiteProvisionTerraformLocation $siteProvisionTerraformLocation

    Remove-TerraformResourcesForDestroyAction -TerraformConfigLocation $vdaSslTerraformLocation -GeneratedTfVarsFilePath $genTfVarsFilePath
    Remove-TerraformResourcesForDestroyAction -TerraformConfigLocation $siteManagementTerraformLocation -GeneratedTfVarsFilePath $genTfVarsFilePath
    Remove-TerraformResourcesForDestroyAction -TerraformConfigLocation $siteProvisionTerraformLocation -GeneratedTfVarsFilePath $genTfVarsFilePath

    # Perform Terraform Actions on VDA SSL Module
    Invoke-TerraformAction -Action destroy -TerraformConfigLocation $vdaSslTerraformLocation -WorkingDirectory $workingDir -GeneratedTfVarsFilePath $genTfVarsFilePath -OutputJsonDeploymentSummary $false -TerraformAutoApproveArg $tfAutoApproveArg -Parallelism $Parallelism

    # Perform Terraform Actions on Site Management Module
    Invoke-TerraformAction -Action destroy -TerraformConfigLocation $siteManagementTerraformLocation -WorkingDirectory $workingDir -GeneratedTfVarsFilePath $genTfVarsFilePath -OutputJsonDeploymentSummary $false -TerraformAutoApproveArg $tfAutoApproveArg -Parallelism $Parallelism

    # Perform Terraform Actions on Site Provisioning Module
    Invoke-TerraformAction -Action destroy -TerraformConfigLocation $siteProvisionTerraformLocation -WorkingDirectory $workingDir -GeneratedTfVarsFilePath $genTfVarsFilePath -OutputJsonDeploymentSummary $false -TerraformAutoApproveArg $tfAutoApproveArg -Parallelism $Parallelism

    # Clean up Terraform Temporary Files
    Remove-TerraformTempFiles -TerraformConfigLocations @($siteProvisionTerraformLocation, $siteManagementTerraformLocation, $vdaSslTerraformLocation)

    Remove-DeploymentSummary -TerraformConfigLocations @($siteProvisionTerraformLocation, $siteManagementTerraformLocation, $vdaSslTerraformLocation)
}
catch {
    Write-Host "Execution of New-CvadDeployment.ps1 failed: $($_)"
    throw
}
finally {
    # Cleanup temp files
    Remove-Item -Path "$tmpDirectoryPath" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$($workingDir)\DeploymentSummary.md" -Force -ErrorAction SilentlyContinue

    if (-not $PreserveAzureCredential) {
        $azureConfigJson = @{
            "azure_subscription_id" = ""
            "azure_tenant_id"       = ""
            "azure_client_id"       = ""
            "azure_client_secret"   = ""
        } | ConvertTo-Json 
        Set-Content -path "$($workingDir)\azure.tfvars.json" -value $azureConfigJson -Force
    }

    # Navigate back to user's starting location
    Write-Host "Navigate back to starting location"
    Set-Location $startingLocation

    if (Get-Module CVADDeploymentCommon) {
        Remove-Module CVADDeploymentCommon -Force -ErrorAction SilentlyContinue
    }
}

