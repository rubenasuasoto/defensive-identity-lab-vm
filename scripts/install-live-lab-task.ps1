$ErrorActionPreference = "Stop"

$TaskName = "IdentityLabLiveLab"
$Runner = Join-Path $PSScriptRoot "run-live-lab-task.ps1"

if (-not (Test-Path $Runner)) {
    throw "Task runner not found: $Runner"
}

$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Runner`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Description "Starts the local synthetic Identity Detection Live Lab." `
    -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed and started $TaskName."
Write-Host "Open http://127.0.0.1:8090/"
