# Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.
function Add-DDCManagementInfoToGeneratedTfVarsFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $GeneratedTfVarsFilePath,
        [Parameter(Mandatory = $true)]
        [string] $SiteProvisionTerraformLocation
    )

    Set-Location $SiteProvisionTerraformLocation
    terraform init -upgrade -var-file="$GeneratedTfVarsFilePath"
    $siteProvisioningOutput = terraform output -json | ConvertFrom-Json

    $tfvarContentJson = Get-Content $GeneratedTfVarsFilePath -Raw | ConvertFrom-Json
    $tfvarContentJson | Add-Member -Name "setup_storage_account_name" -Value $siteProvisioningOutput.resource_group_information.value.cvad_setup_storage_account_name -MemberType NoteProperty -Force
    $tfvarContentJson | Add-Member -Name "active_directory_domain_name" -Value $siteProvisioningOutput.active_directory_information.value.domain_name -MemberType NoteProperty -Force
    $tfvarContentJson | Add-Member -Name "advm_machine_name" -Value $siteProvisioningOutput.domain_controller_details.value.vm_machine_name -MemberType NoteProperty -Force
    $tfvarContentJson | Add-Member -Name "advm_admin_username" -Value $siteProvisioningOutput.active_directory_information.value.domain_admin_username -MemberType NoteProperty -Force
    $tfvarContentJson | Add-Member -Name "advm_admin_password" -Value $siteProvisioningOutput.active_directory_information.value.domain_admin_password -MemberType NoteProperty -Force
    $tfvarContentJson | Add-Member -Name "cvad_component_resource_group_name" -Value $siteProvisioningOutput.resource_group_information.value.cvad_components_resource_group_name -MemberType NoteProperty -Force
    $tfvarContentJson | Add-Member -Name "cvad_vnet_name" -Value $siteProvisioningOutput.resource_group_information.value.cvad_vnet_name -MemberType NoteProperty -Force
    $tfvarContentJson | Add-Member -Name "local_temp_file_dir" -Value $siteProvisioningOutput.local_temp_file_information.value.local_temp_file_dir -MemberType NoteProperty -Force

    $genTfVarsJson = $tfvarContentJson | ConvertTo-Json
    Set-Content -Path $GeneratedTfVarsFilePath -Value $genTfVarsJson -Force
}

function Clear-TerraformResourcesWithPattern {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GeneratedTfVarsFilePath,
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        [Parameter(Mandatory = $false)]
        [switch]$Destroy
    )
    $targetResources = terraform state list | Select-String -Pattern $Pattern
    foreach ($targetResource in $targetResources) {
        if ($Destroy) {
            terraform destroy -refresh=false -var-file="$GeneratedTfVarsFilePath" -target="$($targetResource)" -auto-approve
        }
        else {
            $parsedTarget = $targetResource.ToString() -replace '(.*)\["(.*)"\]', '$1[\"$2\"]'
            terraform state rm $parsedTarget
        }
    }
}

function Clear-TerraformTempFiles {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string] $TerraformConfigurationLocation
    )

    Remove-Item "$($TerraformConfigurationLocation)\*.lock.hcl" -Force -ErrorAction SilentlyContinue
    Remove-Item "$($TerraformConfigurationLocation)\*.lock.info" -Force -ErrorAction SilentlyContinue
    Remove-Item "$($TerraformConfigurationLocation)\*.tfstate*backup" -Force -ErrorAction SilentlyContinue
    Remove-Item "$($TerraformConfigurationLocation)\.terraform\providers\" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$($TerraformConfigurationLocation)\terraform.log" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$($TerraformConfigurationLocation)\.terraform" -Recurse -Force -ErrorAction SilentlyContinue
}

function New-DeploymentSummary {
    param (
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string] $GeneratedTfVarsFilePath,
        [Parameter(Mandatory = $true)]
        [string] $SiteProvisionTerraformLocation,
        [Parameter(Mandatory = $true)]
        [string] $SiteManagementTerraformLocation,
        [Parameter(Mandatory = $true)]
        [int] $ShowSessionLaunchPassword
    )
    $scriptFilePath = "$($WorkingDirectory)\Setup\CustomScripts\Write-DeploymentSummary.ps1"
    $provisionOutput = Invoke-TerraformOutputJson -TerraformConfigLocation $SiteProvisionTerraformLocation
    $managementOutput = Invoke-TerraformOutputJson -TerraformConfigLocation $SiteManagementTerraformLocation

    . $scriptFilePath -ShowSessionLaunchPassword $ShowSessionLaunchPassword `
        -CoreResourceGroupName $provisionOutput.resource_group_information.value.cvad_components_resource_group_name `
        -AdDomainName $provisionOutput.active_directory_information.value.domain_name `
        -AdPublicIP $provisionOutput.domain_controller_details.value.public_ip `
        -AdComputerName $provisionOutput.domain_controller_details.value.vm_machine_name `
        -AdAdminUsername $provisionOutput.active_directory_information.value.domain_admin_username `
        -AdAdminPassword $provisionOutput.active_directory_information.value.domain_admin_password `
        -DdcComputerName $provisionOutput.ddc_details.value.vm_machine_name `
        -DdcPublicIp $provisionOutput.ddc_details.value.public_ip `
        -DdcPrivateIp $provisionOutput.ddc_details.value.private_ip `
        -StoreVirtualPath $provisionOutput.site_information.value.storefront_virtual_path `
        -StoreUserPassword $provisionOutput.active_directory_information.value.domain_user_default_password `
        -MachineCatalogName $managementOutput.machine_catalog_information.value.machine_catalog_name`
        -SessionSupport $managementOutput.machine_catalog_information.value.machine_catalog_session_support `
        -VdaCount $managementOutput.machine_catalog_information.value.vda_count_in_catalog `
        -WebStudioMachine $provisionOutput.site_information.value.default_webstudio_machine_name `
        -VdaResourceGroupName $managementOutput.machine_catalog_information.value.vda_resource_group_name
}

function New-GeneratedTfVarFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string]$TempDirectoryPath,
        [Parameter(Mandatory = $true)]
        [string]$GeneratedTfVarsFilePath,
        [Parameter(Mandatory = $true)]
        [bool]$ShowSessionLaunchPassword,
        [Parameter(Mandatory = $true)]
        [bool]$Destroy
    )

    Remove-Item -Path $TempDirectoryPath -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $TempDirectoryPath -Force | Out-Null
    $TempDirectoryPath = Convert-Path -Path $TempDirectoryPath
    $jsonTfVarPaths = Get-ChildItem -Path $WorkingDirectory -Filter "**.tfvars.json" -Recurse | Convert-Path
    
    New-Item -ItemType File -Path $GeneratedTfVarsFilePath | Out-Null

    $ShowSessionLaunchPassword = $ShowSessionLaunchPassword -and (-not $Destroy)
    
    $genTfVarsJson = "{
        'hide_session_launch_password': $("$(-not $ShowSessionLaunchPassword)".ToLower()),
        'local_temp_file_dir':'$($TempDirectoryPath.Replace("\", "/"))'
    }" | ConvertFrom-Json

    foreach ($jsonTfvarPath in $jsonTfVarPaths) {
        $tfvarContentJson = Get-Content $jsonTfvarPath -Raw | ConvertFrom-Json
        $tfvarContentJson.PSObject.Properties | ForEach-Object {
            $genTfVarsJson | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value -Force
        }
    }

    $genTfVarsJson = $genTfVarsJson | ConvertTo-Json
    Set-Content -Path $GeneratedTfVarsFilePath -Value $genTfVarsJson -Force
}

function Invoke-TerraformAction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("plan", "apply", "destroy")]
        [string] $Action,
        [Parameter(Mandatory = $true)]
        [string] $TerraformConfigLocation,
        [Parameter(Mandatory = $true)]
        [string] $WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string] $GeneratedTfVarsFilePath,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $TerraformAutoApproveArg,
        [Parameter(Mandatory = $true)]
        [bool] $OutputJsonDeploymentSummary,
        [Parameter(Mandatory = $true)]
        [int] $Parallelism
    )

    Set-Location $TerraformConfigLocation
    
    # Backup Original Terraform Environment Variables
    $Original_TF_LOG = $env:TF_LOG
    $Original_TF_LOG_PATH = $env:TF_LOG_PATH
    $Original_TF_DATA_DIR = $env:TF_DATA_DIR

    try {
        # Setup Terraform Environment Variables for Deployment
        $env:TF_LOG = "TRACE"
        $env:TF_LOG_PATH = "$($TerraformConfigLocation)\terraform.log"
        $env:TF_DATA_DIR = "$($TerraformConfigLocation)\.terraform\"

        # Initiate Terraform Environment
        terraform init -upgrade -var-file="$GeneratedTfVarsFilePath"

        Write-Warning "Please don't login to VM when the setup is still running"

        # Perform Terraform Action
        terraform $Action -var-file="$GeneratedTfVarsFilePath" -var-file="$($WorkingDirectory)\inputs.tfvars.json" $TerraformAutoApproveArg -parallelism="$($Parallelism)" -compact-warnings
        
        if ($OutputJsonDeploymentSummary) {
            $tfJsonOutput = terraform output -json
            Set-Content -Path "$($TerraformConfigLocation)\DeploymentSummary.json" -Value $tfJsonOutput -Force
        }
    }
    finally {
        # Restore Terraform Environment Variables
        $env:TF_LOG = $Original_TF_LOG
        $env:TF_LOG_PATH = $Original_TF_LOG_PATH
        $env:TF_DATA_DIR = $Original_TF_DATA_DIR
    }
}

function Invoke-TerraformOutputJson {
    param(
        [Parameter(Mandatory = $true)]
        [string] $TerraformConfigLocation
    )

    Set-Location $TerraformConfigLocation
    
    # Backup Original Terraform Environment Variables
    $Original_TF_LOG = $env:TF_LOG
    $Original_TF_LOG_PATH = $env:TF_LOG_PATH
    $Original_TF_DATA_DIR = $env:TF_DATA_DIR

    $tfJsonOutput = $null
    try {
        # Setup Terraform Environment Variables for Deployment
        $env:TF_LOG = "TRACE"
        $env:TF_LOG_PATH = "$($TerraformConfigLocation)\terraform.log"
        $env:TF_DATA_DIR = "$($TerraformConfigLocation)\.terraform\"

        # Initiate Terraform Environment
        terraform init -upgrade

        $tfJsonOutput = terraform output -json
    }
    finally {
        # Restore Terraform Environment Variables
        $env:TF_LOG = $Original_TF_LOG
        $env:TF_LOG_PATH = $Original_TF_LOG_PATH
        $env:TF_DATA_DIR = $Original_TF_DATA_DIR
    }
    return $tfJsonOutput | ConvertFrom-Json
}

function Install-AzModule {
    $isAzModuleInstalled = Get-InstalledModule -Name Az -ErrorAction SilentlyContinue
    if (-not $isAzModuleInstalled) {
        $retryCount = 0
        while ($retryCount -lt 3) {
            try {
                Write-Output "Attempting to install Az PowerShell module, retry count: $retryCount"
                Remove-Module Az*
                Install-Module -Name Az -Repository PSGallery -Force -ErrorAction Stop
                Uninstall-AzureRM -ErrorAction Stop
            }
            catch {
                Write-Output "Failed to install Az module, increasing retry count" -ForegroundColor Yellow
                $retryCount++
            }
            if ($retryCount -eq 3) {
                Write-Output "Failed to install Az PowerShell module after 3 retries" -ForegroundColor Red
                exit 1
            }
        }
    }
}

function Install-Terraform {
    # Chocolatey Setup
    $isTerraformInstalled = Get-Command -Name terraform -ErrorAction SilentlyContinue
    $isChocoInstalled = Get-Command -Name choco -ErrorAction SilentlyContinue
    if ((-not $isTerraformInstalled) -and (-not $isChocoInstalled)) {
        Write-Output "Installing Chocolatey"
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Output "Chocolatey installed"
    }
    else {
        Write-Output "Chocolatey already installed"
    }

    # Install Terraform with Chocolatey
    if (-not $isTerraformInstalled) {
        Write-Output "Installing Terraform"
        choco install terraform -y
        Write-Output "Terraform installed"
    }
    else {
        Write-Output "Terraform already installed"
    }

    Write-Output "Upgrading Chocolatey to latest version"
    choco upgrade chocolatey -fy
    Write-Output "Upgraded Chocolatey to latest version"
    Write-Output "Upgrading Terraform to latest version"
    choco upgrade terraform -fy
    Write-Output "Upgraded Terraform to latest version"
}

function Read-AzureConfigStringValue {
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ConfigStringValue,
        [Parameter(Mandatory = $true)]
        [string]$ConfigStringPropertyName
    )

    if ([string]::IsNullOrEmpty($ConfigStringValue)) {
        Write-Output "Variable $($ConfigStringPropertyName) in azure.tfvars.json cannot be null or empty" -ForegroundColor Red
        return $false
    }
    return $true
}

function Remove-DeploymentSummary {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string[]]$TerraformConfigLocations
    )

    foreach ($TerraformLocation in $TerraformConfigLocations) {
        Remove-Item "$($TerraformLocation)\DeploymentSummary.md" -Force -ErrorAction SilentlyContinue
        Remove-Item "$($TerraformLocation)\DeploymentSummary.json" -Force -ErrorAction SilentlyContinue
    }
}

function Remove-TerraformResourcesForDestroyAction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $TerraformConfigLocation,
        [parameter(Mandatory = $true)]
        [string] $GeneratedTfVarsFilePath
    )

    Set-Location $TerraformConfigLocation
    
    # Backup Original Terraform Environment Variables
    $Original_TF_LOG = $env:TF_LOG
    $Original_TF_LOG_PATH = $env:TF_LOG_PATH
    $Original_TF_DATA_DIR = $env:TF_DATA_DIR

    try {
        # Setup Terraform Environment Variables for Deployment
        $env:TF_LOG = "TRACE"
        $env:TF_LOG_PATH = "$($TerraformConfigLocation)\terraform.log"
        $env:TF_DATA_DIR = "$($TerraformConfigLocation)\.terraform\"

        # Initiate Terraform Environment
        terraform init -upgrade -var-file="$GeneratedTfVarsFilePath"

        # Perform Terraform Action
        Clear-TerraformResourcesWithPattern -GeneratedTfVarsFilePath $GeneratedTfVarsFilePath -Pattern "azurerm_virtual_machine_extension.*"
        Clear-TerraformResourcesWithPattern -GeneratedTfVarsFilePath $GeneratedTfVarsFilePath -Pattern "azurerm_network_interface_security_group_association.*" -Destroy
        Clear-TerraformResourcesWithPattern -GeneratedTfVarsFilePath $GeneratedTfVarsFilePath -Pattern "azurerm_subnet_network_security_group_association.*" -Destroy
    }
    finally {
        # Restore Terraform Environment Variables
        $env:TF_LOG = $Original_TF_LOG
        $env:TF_LOG_PATH = $Original_TF_LOG_PATH
        $env:TF_DATA_DIR = $Original_TF_DATA_DIR
    }
}

function Remove-TerraformTempFiles {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string[]] $TerraformConfigLocations
    )

    foreach ($TerraformConfigLocation in $TerraformConfigLocations) {
        Clear-TerraformTempFiles -TerraformConfigurationLocation $TerraformConfigLocation
    }
}

function Show-DeploymentSummary {
    param (
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $deploymentSummary = Get-Content "$($WorkingDirectory)\DeploymentSummary.md" -Raw -ErrorAction SilentlyContinue

    Write-Warning "Please record all the information below before exiting this window`n"
    Write-Output $($deploymentSummary.Replace("``````", ""))
    Write-Output
}

function Test-AzModuleEnvironment {
    $installedAzModule = Get-InstalledModule -Name Az -ErrorAction SilentlyContinue
    if (-not $installedAzModule) {
        Write-Output "Az module not found, please install Az Powershell Module v9.0.0 or higher." -ForegroundColor Red
        exit 1
    }
    elseif (([Version]$installedAzModule.Version).Major -lt 9) {
        Write-Output "Local Az PowerShell module has version $($installedAzModule.Version), please upgrade it to v9.0.0 or higher." -ForegroundColor Red
        exit 1
    }
}

function Test-AzureAppRegistrationCreation {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String] $azure_client_id,
        [Parameter(Mandatory = $true)]
        [String] $azure_client_secret,
        [Parameter(Mandatory = $true)]
        [String] $azure_tenant_id,
        [Parameter(Mandatory = $true)]
        [String] $azure_subscription_id
    )

    Write-Output "Waiting for App Registration creation to be finalized on Azure..."

    $retryCount = 0
    $maxRetryCount = 5
    $verificationInterval = 15

    $secret = ConvertTo-SecureString "$azure_client_secret" -AsPlainText -Force
    $credential = New-Object -TypeName pscredential -ArgumentList $azure_client_id, $secret

    while ($retryCount -lt $maxRetryCount) {
        try {
            Start-Sleep -Seconds $verificationInterval
            Connect-AzAccount -Credential $credential -TenantId $azure_tenant_id -ServicePrincipal -SubscriptionId $azure_subscription_id -force -ErrorAction Stop  | Out-Null
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
            break
        }
        catch {
            Write-Output "App Registration creation is not finalized yet on Azure..."
            $retryCount++
            if ($retryCount -eq $maxRetryCount) {
                Write-Output "Failed to create App Registration in Azure subscription $($azure_subscription_id) with tenant $($azure_tenant_id): $($_)`n" -ForegroundColor Red
                exit 1
            }
        }
    }
    Write-Output "`nApp Registration creation is finalized on Azure...`n" -ForegroundColor Green
}

function Test-AzureConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $azureConfig = Get-Content "$($WorkingDirectory)\azure.tfvars.json" -raw | ConvertFrom-Json

    $azureSubscriptionId = $azureConfig.azure_subscription_id
    $isSubscriptionIdValid = Read-AzureConfigStringValue -ConfigStringValue $azureSubscriptionId -ConfigStringPropertyName "azure_subscription_id"
    
    $azureTenantId = $azureConfig.azure_tenant_id
    $isTenantIdValid = Read-AzureConfigStringValue -ConfigStringValue $azureTenantId -ConfigStringPropertyName "azure_tenant_id"
    
    $azureClientId = $azureConfig.azure_client_id
    $isClientIdValid = Read-AzureConfigStringValue -ConfigStringValue $azureClientId -ConfigStringPropertyName "azure_client_id"
    
    $azureClientSecret = $azureConfig.azure_client_secret
    $isClientSecretValid = Read-AzureConfigStringValue -ConfigStringValue $azureClientSecret -ConfigStringPropertyName "azure_client_secret"
    
    if (-not ($isSubscriptionIdValid -and $isTenantIdValid -and $isClientIdValid -and $isClientSecretValid)) {
        Write-Output "Please ensure the Azure credentials are up to date in .\azure.tfvars.json file" -ForegroundColor Yellow
        exit 1
    }
}

function Test-PowerShellEnvironment {
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
        Write-Output $_.Exception.Message -ForegroundColor Red
        exit
    }
}

function Test-TerraformEnvironment {
    $terraformCmd = Get-Command -Name terraform -ErrorAction SilentlyContinue
    if (-not $terraformCmd) {
        Write-Output "Terraform cannot be found, please install terraform with version 1.1.0 or higher." -ForegroundColor Red
        exit 1
    }
    else {
        $tfVersionJson = ConvertFrom-Json ([string](terraform -version -json))
        $tfVersion = [version]$tfVersionJson.terraform_version
        if (($tfVersion.Major -lt 1) -or ($tfVersion.Minor -lt 1)) {
            Write-Output "The local Terraform has version $($tfVersionJson.terraform_version), please install terraform with version 1.1.0 or higher." -ForegroundColor Red
            exit 1
        }
    }
}

Export-ModuleMember -Function Add-*
Export-ModuleMember -Function Install-*
Export-ModuleMember -Function Invoke-*
Export-ModuleMember -Function New-*
Export-ModuleMember -Function Remove-*
Export-ModuleMember -Function Show-*
Export-ModuleMember -Function Test-*
