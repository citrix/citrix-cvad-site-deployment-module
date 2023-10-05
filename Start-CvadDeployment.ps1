<#

    .SYNOPSIS
    Deploy CVAD setup with Terraform.

    .DESCRIPTION
    Deploy CVAD setup with Terraform.

    .PARAMETER IncludeTerraform
    Optional switch parameter to specify whether the user want to install required dependency using this script.

    .PARAMETER Destroy
    Optional switch parameter to indicate action of deletion on all resources managed by terraform.
    
    .PARAMETER AutoApprove
    Optional switch parameter to let user skip confirmation before deploying the terraform action plan.

    .PARAMETER HideSessionLaunchPassword
    Optional switch parameter for apply action to let the script hide session launch passwords in deployment summary 

    .EXAMPLE
    PS> main.ps1 [-IncludeTerraform] [-Destroy] [-AutoApprove] [-HideSessionLaunchPassword]

#>

[CmdletBinding(DefaultParameterSetName = 'apply')]
param (
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTerraform,
    [Parameter(ParameterSetName = "destroy", Mandatory = $false)]
    [switch]$Destroy,
    [Parameter(Mandatory = $false)]
    [switch]$AutoApprove,
    [Parameter(ParameterSetName = "apply", Mandatory = $false)]
    [switch]$HideSessionLaunchPassword
)

function Test-EnvironmentSetup {
    try {
        $psVersion = $psversiontable.psversion
        if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
            throw "Incompatible powershell version. Please install powershell version 5.1 or above. Reference link: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3"
        }

        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Administrator Privilege missing! Please run powershell in Administrator mode before running this script!"
        }
    }
    catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit
    }
}

Test-EnvironmentSetup

$ErrorActionPreference = "Stop"

function Get-TfResourceValue {
    param (
        [Parameter(Mandatory = $true)]
        [Object[]]$TfResources,
        [Parameter(Mandatory = $true)]
        [string]$ResourceAddress,
        [Parameter(Mandatory = $true)]
        [string]$ResourceProperty
    )
    $tfResource = $TfResources | Where-Object -Property "address" -eq -Value $ResourceAddress
    if ((-not $tfResource) -or (-not $tfResource.values) -or (-not $tfResource.values.$ResourceProperty)) {
        throw "Unable to find property value for property $($ResourceProperty) of resource address $($ResourceAddress)."
    }
    return $tfResource.values.$ResourceProperty
}

function Install-Terraform {
    # Chocolatey Setup
    $isTerraformInstalled = Get-Command -Name terraform -ErrorAction SilentlyContinue
    $isChocoInstalled = Get-Command -Name choco -ErrorAction SilentlyContinue
    if ((-not $isTerraformInstalled) -and (-not $isChocoInstalled)) {
        Write-Host "Installing Chocolatey"
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "Chocolatey installed"
    }
    else {
        Write-Host "Chocolatey already installed"
    }

    # Install Terraform with Chocolatey
    if (-not $isTerraformInstalled) {
        Write-Host "Installing Terraform"
        choco install terraform -y
        Write-Host "Terraform installed"
    }
    else {
        Write-Host "Terraform already installed"
    }

    Write-Host "Upgrading Chocolatey to latest version"
    choco upgrade chocolatey -fy
    Write-Host "Upgraded Chocolatey to latest version"
    Write-Host "Upgrading Terraform to latest version"
    choco upgrade terraform -fy
    Write-Host "Upgraded Terraform to latest version"
}

function Remove-TerraformResourcesWithPattern {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        [Parameter(Mandatory = $false)]
        [switch]$Destroy
    )
    $targetResources = terraform state list | Select-String -Pattern $Pattern
    foreach ($targetResource in $targetResources) {
        if ($Destroy) {
            terraform destroy -refresh=false -var-file="$genTfVarsFilePath" -target="$($targetResource)" -auto-approve
        }
        else {
            terraform state rm $targetResource
        }
    }
}

function Test-AzureConfigStringValue {
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ConfigStringValue,
        [Parameter(Mandatory = $true)]
        [string]$ConfigStringPropertyName
    )

    $ConfigStringValue = $ConfigStringValue.Replace("`"", "").Replace("'", "").Trim()
    if ((-not $ConfigStringValue) `
            -or ($ConfigStringValue.ToLower() -eq "null") `
            -or ($ConfigStringValue -eq '""') `
            -or ($ConfigStringValue -eq "''")) {
        Write-Host "Variable $($ConfigStringPropertyName) in azure.tfvars cannot be null or empty" -ForegroundColor Red
        return $false
    }
    return $true
}

function Validate-LicenseFile {
    $inputConfig = Get-Content -raw "$($workingDir)\inputs.tfvars" | ConvertFrom-StringData
    if ($inputConfig.ContainsKey("license_file_path")) {
        $license_file_path = $inputConfig.license_file_path.Replace("`"", "").Replace("'", "").Trim()
        if(-not [string]::IsNullOrEmpty($license_file_path)) {
            if(-not (Test-Path $license_file_path -PathType Leaf) -or ([IO.Path]::GetExtension($license_file_path) -ne '.lic')) {
                Write-Error "License file path is either incorrect or contains an incorrect extension. Please check and try again."
                exit 1
            }
            $hostName = ((Get-Content $license_file_path | Select-String 'SERVER this_host (.+)') -split " ")[-1].Trim()
            if($hostname.Contains('HOSTNAME')) {
                $hostname = ($hostname -split '=')[-1]
            }
            $ddc_machine_name = $inputConfig.ddc_machine_name.Replace("`"", "").Replace("'", "").Trim()
            if(($hostName -ne $ddc_machine_name) -and ($hostname -ne "ANY")) {
                Write-Error "Hostname specified in the CVAD license file does not match with the value provided for variable ddc_machine_name in the input.tfvars file"
                exit 1
            }
        }
    }
}

$startingLocation = Get-Location | Convert-Path
$workingDir = Split-Path -Path $($MyInvocation.MyCommand.Source) -Parent

# Unblock write summary script
Unblock-File -Path  "$($workingDir)\Setup\CustomScripts\*.ps1"

# Verify Azure provider configuration
$azureConfig = Get-Content "$($workingDir)\azure.tfvars" | ForEach-Object { if ($_.Contains('#')) { $_.SubString(0, $_.IndexOf('#')) } else { $_ } } | ConvertFrom-StringData
$azureSubscriptionId = $azureConfig.azure_subscription_id
$azureTenantId = $azureConfig.azure_tenant_id
$azureClientId = $azureConfig.azure_client_id
$azureClientSecret = $azureConfig.azure_client_secret

$isSubscriptionIdValid = Test-AzureConfigStringValue -ConfigStringValue $azureSubscriptionId -ConfigStringPropertyName "azure_subscription_id"
$isTenantIdValid = Test-AzureConfigStringValue -ConfigStringValue $azureTenantId -ConfigStringPropertyName "azure_tenant_id"
$isClientIdValid = Test-AzureConfigStringValue -ConfigStringValue $azureClientId -ConfigStringPropertyName "azure_client_id"
$isClientSecretValid = Test-AzureConfigStringValue -ConfigStringValue $azureClientSecret -ConfigStringPropertyName "azure_client_secret"

if (-not ($isSubscriptionIdValid -and $isTenantIdValid -and $isClientIdValid -and $isClientSecretValid)) {
    Write-Host "Please ensure the Azure credentials are up to date in .\azure.tfvars file" -ForegroundColor Yellow
    exit 1
}


if (-not $Destroy) {
    Validate-LicenseFile
}

# Navigate to vnet, advm, and ddc setup section
Write-Host "Navigate directory to VNet, AD VM, and DDC terraform workspace"
Set-Location "$($workingDir)\terraform"

$tmpDirectoryPath = "..\tmp\"
Remove-Item -Path $tmpDirectoryPath -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $tmpDirectoryPath -Force | Out-Null
$tmpDirectoryPath = Convert-Path -Path $tmpDirectoryPath

$tfVarPaths = Get-ChildItem -Path $workingDir -Filter "**.tfvars" -Recurse | Convert-Path

$genTfVarsFilePath = "$($tmpDirectoryPath)generated.tfvars"
New-Item -ItemType File -Path $genTfVarsFilePath | Out-Null

$Original_TF_LOG = $env:TF_LOG
$Original_TF_LOG_PATH = $env:TF_LOG_PATH
$Original_TF_DATA_DIR = $env:TF_DATA_DIR

try {
    if ($IncludeTerraform) {
        Install-Terraform
    }
    
    $terraformCmd = Get-Command -Name terraform -ErrorAction SilentlyContinue
    if (-not $terraformCmd) {
        Write-Host "Terraform cannot be found, please install terraform with version 1.1.0 or higher." -ForegroundColor Red
        exit 1
    }
    else {
        $tfVersionJson = ConvertFrom-Json ([string](terraform -version -json))
        $tfVersion = [version]$tfVersionJson.terraform_version
        if (($tfVersion.Major -lt 1) -or ($tfVersion.Minor -lt 1)) {
            Write-Host "The local Terraform has version $($tfVersionJson.terraform_version), please install terraform with version 1.1.0 or higher." -ForegroundColor Red
            exit 1
        }
    }
    
    # Run terraform script
    # Make sure terraform app reg is assigned with Contributor role
    Write-Host "Initializing Terraform environment"

    $tfAction = "apply"
    $hideSessionLaunchPasswordParsed = 0

    if ($Destroy) {
        $tfAction = "destroy"
        $hideSessionLaunchPasswordParsed = 1
    }

    if ($HideSessionLaunchPassword) {
        $hideSessionLaunchPasswordParsed = 1
    }

    $tfAutoApproveArg = $null
    if ($AutoApprove) {
        $tfAutoApproveArg = "-auto-approve"
    }
    
    $env:TF_LOG = "TRACE"
    $env:TF_LOG_PATH = "..\terraform.log"
    $env:TF_DATA_DIR = "..\.terraform\"

    foreach ($tfvarPath in $tfVarPaths) {
        Add-Content -Path $genTfVarsFilePath -Value $(Get-Content $tfvarPath)
    }

    Add-Content -Path $genTfVarsFilePath -Value  "hide_session_launch_password = $($hideSessionLaunchPasswordParsed)`n"
    Add-Content -Path $genTfVarsFilePath -Value  "local_temp_file_dir = `"$($tmpDirectoryPath.Replace("\", "/"))`"`n"

    terraform init -upgrade -var-file="$genTfVarsFilePath"

    if ($Destroy) {
        Remove-TerraformResourcesWithPattern -Pattern "azurerm_virtual_machine_extension.*"
        Remove-TerraformResourcesWithPattern -Pattern "azurerm_network_interface_security_group_association.*" -Destroy
        Remove-TerraformResourcesWithPattern -Pattern "azurerm_subnet_network_security_group_association.*" -Destroy
    }
    else {
        Write-Warning "Please don't login to VM when the setup is still running"
    }

    terraform $tfAction -var-file="$genTfVarsFilePath" $tfAutoApproveArg -parallelism=2
    
    if (-not $Destroy) {
        Write-Warning "You may check DeploymentSummary.log for the detailed deployment summary information"
        Start-Process PowerShell { "..\Setup\CustomScripts\Display-DeploymentSummary.ps1" } -WindowStyle Normal
    }
    else {
        Remove-Item ".\*.lock.hcl" -Force -ErrorAction SilentlyContinue
        Remove-Item ".\terraform.tfstate.*.backup" -Force -ErrorAction SilentlyContinue
        Remove-Item "..\DeploymentSummary.log" -Force -ErrorAction SilentlyContinue
        Remove-Item "..\.terraform\providers\" -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Host "Execution of Start-CvadDeployment.ps1 failed: $($_)"
    throw
}
finally {
    # Cleanup temp files
    Remove-Item -Path "$tmpDirectoryPath" -Recurse -Force -ErrorAction SilentlyContinue

    # Restore environment variables
    $env:TF_LOG = $Original_TF_LOG
    $env:TF_LOG_PATH = $Original_TF_LOG_PATH
    $env:TF_DATA_DIR = $Original_TF_DATA_DIR

    # Navigate back to user's starting location
    Write-Host "Navigate back to starting location"
    Set-Location $startingLocation
}

