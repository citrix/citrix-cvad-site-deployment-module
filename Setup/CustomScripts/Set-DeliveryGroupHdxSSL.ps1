<#
.SYNOPSIS
    Enable HDX SSL on DeliveryGroups

.DESCRIPTION
    Enable the TLS/DTLS listeners on the VDA. 
    Optionally, the TLS/DTLS certificate, port, version and cipher suite to use can be specified.

.PARAMETER DeliveryGroup
    Specifies the DeliveryGroup to enable SSL
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $True)]
    [string]$DeliveryGroup,
    [Parameter(Mandatory = $True)]
    [string] $DomainAdminUsername,
    [Parameter(Mandatory = $True)]
    [string] $DomainAdminPassword
)

$DomainAdminPasswordSecuredString = (ConvertTo-SecureString "$($DomainAdminPassword)" -AsPlainText -Force)
$DomainAdminCredential = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $DomainAdminUsername, $DomainAdminPasswordSecuredString

#starting the session as domain user 
$session = New-PSSession -Credential $DomainAdminCredential
Invoke-Command -Session $session -ScriptBlock {
    Get-BrokerAccessPolicyRule -DesktopGroupName $using:DeliveryGroup | Set-BrokerAccessPolicyRule -HdxSslEnabled $true
    
    $machines = Get-BrokerMachine -DesktopGroupName $using:DeliveryGroup | Where-Object -Property "PowerState" -Value "On" -NE

    foreach ($machine in $machines) {
        New-BrokerHostingPowerAction -MachineName $machine.MachineName -Action TurnOn
    }

    $retryCount = 0
    $maxRetryCount = 10
    while (($machines.Count -ne 0) -and ($retryCount -le $maxRetryCount)) {
        Start-Sleep -Seconds 30
        $machines = Get-BrokerMachine -DesktopGroupName $using:DeliveryGroup | Where-Object -Property "PowerState" -Value "On" -NE
        $retryCount++
    }
}

exit 0
