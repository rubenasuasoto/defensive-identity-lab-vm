$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$TaskName = "IdentityLabLiveLab"
$Patterns = @(
    "*identitylab live*",
    "*identitylab.exe*",
    "*run-live-lab-task.ps1*"
)

$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $Task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Write-Host "Stopped Scheduled Task if it was running: $TaskName"
}

$currentPid = $PID
$processes = Get-CimInstance Win32_Process |
    Where-Object {
        $commandLine = [string]$_.CommandLine
        $inRepo = $commandLine -like "*$Root*"
        $matchesLiveLab = $false
        foreach ($pattern in $Patterns) {
            if ($commandLine -like $pattern) {
                $matchesLiveLab = $true
            }
        }
        $inRepo -and $matchesLiveLab -and $_.ProcessId -ne $currentPid
    }

foreach ($process in $processes) {
    Write-Host "Stopping process $($process.ProcessId): $($process.Name)"
    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "Live Lab processes stopped."
