<#

    .SYNOPSIS
    Create a new Azure Active Directory Application Registration.

    .DESCRIPTION
    Create a new Azure Active Directory Application Registration and output required values to run terraform on Azure.

    .PARAMETER AzureSubscriptionId
    Id of the Azure Subscription to create application registration.

    .PARAMETER AzureApplicationName
    Optional parameter to specify the name of new application. If not specified, default name Ctx-Azure-AD-App will be applied.

    .PARAMETER IncludeAzModule
    Optional switch parameter to specify whether the user want to install required dependency using this script.
    
    .EXAMPLE
    PS> New-AdAppRegistration.ps1 -AzureSubscriptionId "YourSubscriptionId" [-IncludeAzModule]

    .EXAMPLE
    PS> New-AdAppRegistration.ps1 -AzureSubscriptionId "YourSubscriptionId" -AzureApplicationName "ExampleDisplayName" [-IncludeAzModule]

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$AzureSubscriptionId,
    [Parameter(Mandatory = $false)]
    [string]$AzureApplicationName = "Ctx-Azure-AD-App",
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAzModule,
    [Parameter(Mandatory = $false)]
    [string]$AzureTenantId,
    [Parameter(Mandatory = $false)]
    [string]$ApplicationId,
    [Parameter(Mandatory = $false)]
    [string]$ApplicationPassword

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

function Wait-AppRegistrationCreation {
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

    Write-Host "Waiting for App Registration creation to be finalized on Azure..."

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
            Write-Host "App Registration creation is not finalized yet on Azure..."
            $retryCount++
            if ($retryCount -eq $maxRetryCount) {
                Write-Host "Failed to create App Registration in Azure subscription $($azure_subscription_id) with tenant $($azure_tenant_id): $($_)`n" -ForegroundColor Red
                exit 1
            }
        }
    }
    Write-Host "`nApp Registration creation is finalized on Azure...`n" -ForegroundColor Green
}

Test-EnvironmentSetup

$isAzModuleInstalled = Get-InstalledModule -Name Az -ErrorAction SilentlyContinue
if ((-not $isAzModuleInstalled) -and $IncludeAzModule) {
    $retryCount = 0
    while ($retryCount -lt 3) {
        try {
            Write-Host "Attempting to install Az PowerShell module, retry count: $retryCount"
            Remove-Module Az*
            Install-Module -Name Az -Repository PSGallery -Force -ErrorAction Stop
            Uninstall-AzureRM -ErrorAction Stop
        }
        catch {
            Write-Host "Failed to install Az module, increasing retry count" -ForegroundColor Yellow
            $retryCount++
        }
        if ($retryCount -eq 3) {
            Write-Host "Failed to install Az PowerShell module after 3 retries" -ForegroundColor Red
            exit 1
        }
    }
}

$installedAzModule = Get-InstalledModule -Name Az -ErrorAction SilentlyContinue
if (-not $installedAzModule) {
    Write-Host "Az module not found, please install Az Powershell Module v9.0.0 or higher." -ForegroundColor Red
    exit 1
}
elseif (([Version]$installedAzModule.Version).Major -lt 9) {
    Write-Host "Local Az PowerShell module has version $($installedAzModule.Version), please upgrade it to v9.0.0 or higher." -ForegroundColor Red
    exit 1
}

Write-Host "Connecting to user Azure account..."
if ($AzureTenantId -and $ApplicationId -and $ApplicationPassword) {
    $SecurePassword = ConvertTo-SecureString -String $ApplicationPassword -AsPlainText -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecurePassword
    Connect-AzAccount -Subscription $AzureSubscriptionId -ServicePrincipal -TenantId $AzureTenantId -Credential $Credential | Out-Null
}
else {
    if ($AzureTenantId){
        Connect-AzAccount -Subscription $AzureSubscriptionId -Tenant $AzureTenantId -ErrorAction Stop | Out-Null
    }
    else {
        Connect-AzAccount -Subscription $AzureSubscriptionId -ErrorAction Stop | Out-Null
    }
}
$tenantId = (Get-AzSubscription -SubscriptionId $AzureSubscriptionId).TenantId

Write-Host "Creating Azure Active Directory Application in subscription $($AzureSubscriptionId)"
$AzureADApplication = New-AzADApplication -DisplayName $AzureApplicationName -ErrorAction Stop
New-AzADServicePrincipal -ApplicationId $AzureADApplication.AppId -ErrorAction Stop | Out-Null
New-AzRoleAssignment -RoleDefinitionName Contributor -ApplicationId $AzureADApplication.AppId -ErrorAction Stop | Out-Null
$cred = New-AzADAppCredential -ApplicationId $AzureADApplication.AppId -ErrorAction Stop
Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null

Wait-AppRegistrationCreation -azure_client_id $AzureADApplication.AppId -azure_client_secret $cred.SecretText -azure_subscription_id $AzureSubscriptionId -azure_tenant_id $tenantId

$workingDir = Split-Path -Path $($MyInvocation.MyCommand.Source) -Parent
Set-Content -path "$($workingDir)\azure.tfvars" -value $("azure_subscription_id = `"$($AzureSubscriptionId)`"`n" + `
        "azure_tenant_id       = `"$($tenantId)`"`n" + `
        "azure_client_id       = `"$($AzureADApplication.AppId)`"`n" + `
        "azure_client_secret   = `"$($cred.SecretText)`"`n")

Write-Host "azure_subscription_id = $($AzureSubscriptionId)"
Write-Host "azure_client_id = $($AzureADApplication.AppId)"
Write-Host "azure_tenant_id = $($tenantId)"
Write-Host "azure_client_secret = $($cred.SecretText)`n"

Write-Host "Azure configurations are added to azure.tfvars file`n" -ForegroundColor Green
Write-Host "If you have any license file, please make sure its path and the corresponding DDC host name is referenced in inputs.tfvars file, after which you can deploy with the Start-CvadDeployment.ps1 script`n" -ForegroundColor Yellow
