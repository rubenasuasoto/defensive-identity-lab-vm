$ErrorActionPreference = "Stop"

$TaskName = "IdentityLabLiveLab"
$Runner = Join-Path $PSScriptRoot "run-live-lab-task.ps1"
$StartupPath = Join-Path ([Environment]::GetFolderPath("Startup")) "$TaskName.cmd"

if (-not (Test-Path $Runner)) {
    throw "Task runner not found: $Runner"
}

function Start-LiveLabRunner {
    Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-File",
            $Runner
        ) `
        -WindowStyle Hidden
}

try {
    $Action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Runner`""
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
    $Principal = New-ScheduledTaskPrincipal `
        -UserId "$env:USERDOMAIN\$env:USERNAME" `
        -LogonType Interactive `
        -RunLevel LeastPrivilege

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Settings $Settings `
        -Principal $Principal `
        -Description "Starts the local synthetic Identity Detection Live Lab." `
        -Force `
        -ErrorAction Stop | Out-Null

    if (Test-Path $StartupPath) {
        Remove-Item -LiteralPath $StartupPath -Force
    }

    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    Write-Host "Installed and started Scheduled Task: $TaskName."
}
catch {
    Write-Warning "Scheduled Task install failed for this local user: $($_.Exception.Message)"
    Write-Warning "Installing Startup folder fallback instead."

    $cmd = @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$Runner"
"@
    [System.IO.File]::WriteAllText(
        $StartupPath,
        $cmd,
        [System.Text.UTF8Encoding]::new($false)
    )
    Start-LiveLabRunner
    Write-Host "Installed and started Startup fallback: $StartupPath."
}

Write-Host "Open http://127.0.0.1:8090/"
