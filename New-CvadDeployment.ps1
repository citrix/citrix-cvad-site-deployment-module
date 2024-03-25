# Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.
<#

    .SYNOPSIS
    Deploy CVAD setup with Terraform.

    .DESCRIPTION
    Deploy CVAD setup with Terraform.

    .PARAMETER IncludeTerraform
    Optional switch parameter to specify whether the user want to install required dependency using this script.

    .PARAMETER AutoApprove
    Optional switch parameter to let user skip confirmation before deploying the terraform action plan.

    .PARAMETER ShowSessionLaunchPassword
    Optional switch parameter for apply action to let the script show session launch passwords in deployment summary.

    .PARAMETER OutputJsonDeploymentSummary
    Optional switch parameter specifying whether a terraform json output will be generated.

    .PARAMETER Parallelism
    Optional parameter specifying the maximum paralellism for terraform. The default value is 2. If the value is too high, Azure could report too many request error.

    .PARAMETER PreserveAzureCredential
    Optional switch parameter specifying whether azure credentials will be preserved after deployment.

    .EXAMPLE
    PS> New-CvadDeployment.ps1 [-IncludeTerraform] [-AutoApprove] [-ShowSessionLaunchPassword] [-Parallelism 2] [-PreserveAzureCredential]

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("plan", "apply")]
    [string]$TerraformAction = "apply",
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTerraform,
    [Parameter(Mandatory = $false)]
    [switch]$AutoApprove,
    [Parameter(Mandatory = $false)]
    [switch]$ShowSessionLaunchPassword,
    [Parameter(Mandatory = $false)]
    [switch]$OutputJsonDeploymentSummary,
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
$stageMarkerFilePath = "$($tmpDirectoryPath)stage_marker.json"

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
    Write-Output "Navigate directory to VNet, AD VM, and DDC terraform workspace"

    if ($IncludeTerraform) {
        Install-Terraform
    }
    
    Test-TerraformEnvironment

    # Run terraform script
    # Make sure terraform app reg is assigned with Contributor role
    Write-Output "Initializing Terraform environment"

    $tfAutoApproveArg = $null
    if ($AutoApprove) {
        $tfAutoApproveArg = "-auto-approve"
    }

    New-GeneratedTfVarFile -WorkingDirectory $workingDir -TempDirectoryPath $tmpDirectoryPath -GeneratedTfVarsFilePath $genTfVarsFilePath -ShowSessionLaunchPassword $ShowSessionLaunchPassword -Destroy $false

    $stageMarkerJson = @{
        "provisioning" = $false
        "management" = $false
        "vda_ssl" = $false
    } | ConvertTo-Json
    
    Set-Content -Path $stageMarkerFilePath -Value $stageMarkerJson -Force
    
    # Perform Terraform Actions on Site Provisioning Module
    Invoke-TerraformAction -Action $TerraformAction -TerraformConfigLocation $siteProvisionTerraformLocation -WorkingDirectory $workingDir -GeneratedTfVarsFilePath $genTfVarsFilePath -OutputJsonDeploymentSummary $OutputJsonDeploymentSummary -TerraformAutoApproveArg $tfAutoApproveArg -Parallelism $Parallelism

    $stageMarkerJson = Get-Content $stageMarkerFilePath -Raw | ConvertFrom-Json

    if (-not $stageMarkerJson.provisioning) {
        Write-Output "Failed to deploy CVAD Site, aborting ..." -ForegroundColor Red
        return
    }
    # Perform Terraform Actions on Site Management Module
    Add-DDCManagementInfoToGeneratedTfVarsFile -GeneratedTfVarsFilePath $genTfVarsFilePath -SiteProvisionTerraformLocation $siteProvisionTerraformLocation
    Invoke-TerraformAction -Action $TerraformAction -TerraformConfigLocation $siteManagementTerraformLocation -WorkingDirectory $workingDir -GeneratedTfVarsFilePath $genTfVarsFilePath -OutputJsonDeploymentSummary $OutputJsonDeploymentSummary -TerraformAutoApproveArg $tfAutoApproveArg -Parallelism $Parallelism

    $stageMarkerJson = Get-Content $stageMarkerFilePath -Raw | ConvertFrom-Json
    if (-not $stageMarkerJson.management) {
        Write-Output "Failed to create machine catalog and delivery group, aborting ..." -ForegroundColor Red
        return
    }

    # Perform Terraform Actions on VDA SSL Module
    Invoke-TerraformAction -Action $TerraformAction -TerraformConfigLocation $vdaSslTerraformLocation -WorkingDirectory $workingDir -GeneratedTfVarsFilePath $genTfVarsFilePath -OutputJsonDeploymentSummary $false -TerraformAutoApproveArg $tfAutoApproveArg -Parallelism $Parallelism

    $stageMarkerJson = Get-Content $stageMarkerFilePath -Raw | ConvertFrom-Json
    if (-not $stageMarkerJson.vda_ssl) {
        Write-Output "Failed to enable SSL for VDAs, aborting ..." -ForegroundColor Red
        return
    }

    $showSessionLaunchPasswordParsed = 0
    if ($ShowSessionLaunchPassword) {
        $showSessionLaunchPasswordParsed = 1
    }
    New-DeploymentSummary -WorkingDirectory $workingDir -GeneratedTfVarsFilePath $genTfVarsFilePath -SiteProvisionTerraformLocation $siteProvisionTerraformLocation -SiteManagementTerraformLocation $siteManagementTerraformLocation -ShowSessionLaunchPassword $showSessionLaunchPasswordParsed
   
    # Clean up Terraform Temporary Files
    Remove-TerraformTempFiles -TerraformConfigLocations @($siteProvisionTerraformLocation, $siteManagementTerraformLocation, $vdaSslTerraformLocation)

    Show-DeploymentSummary -WorkingDirectory $workingDir
}
catch {
    Write-Output "Execution of New-CvadDeployment.ps1 failed: $($_)"
    throw
}
finally {
    # Cleanup temp files
    Remove-Item -Path "$tmpDirectoryPath" -Recurse -Force -ErrorAction SilentlyContinue

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
    Write-Output "Navigate back to starting location"
    Set-Location $startingLocation

    if (Get-Module CVADDeploymentCommon) {
        Remove-Module CVADDeploymentCommon -Force -ErrorAction SilentlyContinue
    }
}

