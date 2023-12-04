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

$ErrorActionPreference = "Stop"

$workingDir = Split-Path -Path $($MyInvocation.MyCommand.Source) -Parent

Unblock-File -Path "$($workingDir)\*.ps1"
$getCvadCommonModuleResult = Get-Module CVADDeploymentCommon
if (-not $getCvadCommonModuleResult) {
    Import-Module "$($workingDir)\CVADDeploymentCommon.psm1" -Force
}

try {
    Test-PowerShellEnvironment

    if ($IncludeAzModule) {
        Install-AzModule
    }

    Test-AzModuleEnvironment

    Write-Host "Connecting to user Azure account..."
    if ($AzureTenantId -and $ApplicationId -and $ApplicationPassword) {
        $SecurePassword = ConvertTo-SecureString -String "$($ApplicationPassword)" -AsPlainText -Force
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
    
    Test-AzureAppRegistrationCreation -azure_client_id $AzureADApplication.AppId -azure_client_secret $cred.SecretText -azure_subscription_id $AzureSubscriptionId -azure_tenant_id $tenantId
    
    $workingDir = Split-Path -Path $($MyInvocation.MyCommand.Source) -Parent
    $azureConfigJson = @{
        "azure_subscription_id" = "$($AzureSubscriptionId)"
        "azure_tenant_id"       = "$($tenantId)"
        "azure_client_id"       = "$($AzureADApplication.AppId)"
        "azure_client_secret"   = "$($cred.SecretText)"
    } | ConvertTo-Json
    
    Set-Content -path "$($workingDir)\azure.tfvars.json" -value $azureConfigJson -Force
    
    Write-Host "Please save the following Azure credentials in a safe location" -ForegroundColor Yellow
    Write-Host "azure_subscription_id = $($AzureSubscriptionId)"
    Write-Host "azure_client_id = $($AzureADApplication.AppId)"
    Write-Host "azure_tenant_id = $($tenantId)"
    Write-Host "azure_client_secret = $($cred.SecretText)`n"
    
    Write-Host "Azure configurations are added to azure.tfvars.json file`n" -ForegroundColor Green
    Write-Host "If you have any license file, please make sure its path and the corresponding DDC host name is referenced in inputs.tfvars.json file, after which you can deploy with the New-CvadDeployment.ps1 script`n" -ForegroundColor Yellow
}
finally {
    if (Get-Module CVADDeploymentCommon) {
        Remove-Module CVADDeploymentCommon -Force -ErrorAction SilentlyContinue
    }
}
