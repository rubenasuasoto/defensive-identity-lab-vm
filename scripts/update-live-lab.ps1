$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$StopScript = Join-Path $PSScriptRoot "stop-live-lab.ps1"
$UninstallScript = Join-Path $PSScriptRoot "uninstall-live-lab-task.ps1"
$InstallScript = Join-Path $PSScriptRoot "install-live-lab-task.ps1"

Set-Location $Root

Write-Host "Stopping Live Lab before updating the virtual environment..."
& $StopScript

Write-Host "Removing startup persistence during update..."
& $UninstallScript

Write-Host "Pulling latest repository changes..."
git pull

Write-Host "Synchronizing Python environment..."
uv sync --extra dev --locked

Write-Host "Reinstalling Live Lab startup persistence..."
& $InstallScript

Write-Host "Update complete. Open http://127.0.0.1:8090/"
