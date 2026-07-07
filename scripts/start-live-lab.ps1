$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $Root "runtime\logs"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Set-Location $Root
uv run identitylab live --host 127.0.0.1 --port 8090
