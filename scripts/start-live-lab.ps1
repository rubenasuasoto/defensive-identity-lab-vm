$ErrorActionPreference = "Stop"

Set-Location (Split-Path -Parent $PSScriptRoot)
uv run identitylab live --host 127.0.0.1 --port 8090
