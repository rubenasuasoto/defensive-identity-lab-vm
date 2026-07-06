$ErrorActionPreference = "Stop"

$HubRoot = Split-Path -Parent $PSScriptRoot
$BaseDir = Split-Path -Parent $HubRoot

$Labs = @(
    @{
        Name = "windows-authentication-detection-lab"
        Url = "https://github.com/rubenasuasoto/windows-authentication-detection-lab.git"
    },
    @{
        Name = "microsoft-entra-detection-lab"
        Url = "https://github.com/rubenasuasoto/microsoft-entra-detection-lab.git"
    },
    @{
        Name = "microsoft-sentinel-kql-detection-lab"
        Url = "https://github.com/rubenasuasoto/microsoft-sentinel-kql-detection-lab.git"
    }
)

foreach ($Lab in $Labs) {
    $Target = Join-Path $BaseDir $Lab.Name
    if (Test-Path $Target) {
        Write-Host "SKIP $($Lab.Name): already exists at $Target"
        continue
    }

    Write-Host "CLONE $($Lab.Name) -> $Target"
    git clone $Lab.Url $Target
}

Write-Host "Done. Run .\scripts\vm-readiness.ps1 next."
