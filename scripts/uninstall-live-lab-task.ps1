$ErrorActionPreference = "Stop"

$TaskName = "IdentityLabLiveLab"
$StartupPath = Join-Path ([Environment]::GetFolderPath("Startup")) "$TaskName.cmd"
$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($null -ne $Task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-Host "Uninstalled Scheduled Task: $TaskName."
}
else {
    Write-Host "Scheduled Task not found: $TaskName"
}

if (Test-Path $StartupPath) {
    Remove-Item -LiteralPath $StartupPath -Force
    Write-Host "Removed Startup fallback: $StartupPath."
}

$StopScript = Join-Path $PSScriptRoot "stop-live-lab.ps1"
if (Test-Path $StopScript) {
    & $StopScript
}
