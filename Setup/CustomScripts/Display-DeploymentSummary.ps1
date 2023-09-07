function Wait-KeyPress {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PauseKey,
        [Parameter(Mandatory = $true)]
        [ConsoleModifiers] $modifier,
        [Parameter(Mandatory = $true)]
        [string] $Prompt
    )
             
    Write-Host -NoNewLine "Press $Prompt to exit . . . "
    do {
        $key = [Console]::ReadKey($true)
    } 
    while (($key.Key -ne $pauseKey) -or ($key.Modifiers -ne $modifer))   
     
    Write-Host
}

$deploymentSummaryPath = "..\DeploymentSummary.log"
$deploymentSummary = Get-Content $deploymentSummaryPath -ErrorAction SilentlyContinue

try {
    if (-not $deploymentSummary) {
        exit 0
    }
    Write-Host
    Write-Warning "Please record all the information below before exiting this window"
    Write-Host
    Write-Host ($deploymentSummary | Out-String)
    Write-Host
    $psHost = Get-Host
    $psWindow = $psHost.UI.RawUI
    $windowSize = $psWindow.BufferSize
    $windowSize.Height = 80
    $windowSize.Width = 170
    $psWindow.BufferSize = $windowSize
    $windowSize = $psWindow.WindowSize
    $windowSize.Height = 80
    $windowSize.Width = 170
    $psWindow.WindowSize = $windowSize
}
catch { }


$modifer = [ConsoleModifiers]::Control
Wait-KeyPress -PauseKey "Z" -Modifier $modifer -Prompt "Ctrl + Z"