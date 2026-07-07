$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $Root "runtime\logs"
$LogFile = Join-Path $LogDir "live-lab.log"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Set-Location $Root

"[$(Get-Date -Format o)] Starting Identity Detection Live Lab" | Out-File -FilePath $LogFile -Append -Encoding utf8
uv run identitylab live --host 127.0.0.1 --port 8090 *>> $LogFile
