$ErrorActionPreference = "Stop"

$HubRoot = Split-Path -Parent $PSScriptRoot
$BaseDir = Split-Path -Parent $HubRoot

$Runs = @(
    @{
        Name = "Windows Auth Lab"
        Path = Join-Path $BaseDir "windows-authentication-detection-lab"
        Command = "uv run authlab all"
    },
    @{
        Name = "Microsoft Entra Lab"
        Path = Join-Path $BaseDir "microsoft-entra-detection-lab"
        Command = "uv run entralab all"
    },
    @{
        Name = "Microsoft Sentinel KQL Lab"
        Path = Join-Path $BaseDir "microsoft-sentinel-kql-detection-lab"
        Command = "uv run sentinellab all"
    }
)

foreach ($Run in $Runs) {
    if (-not (Test-Path $Run.Path)) {
        Write-Host "WARN $($Run.Name): missing $($Run.Path)"
        continue
    }

    Write-Host "RUN $($Run.Name): $($Run.Command)"
    Push-Location $Run.Path
    try {
        Invoke-Expression $Run.Command
    }
    finally {
        Pop-Location
    }
}
