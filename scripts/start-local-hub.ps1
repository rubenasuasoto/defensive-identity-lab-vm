$ErrorActionPreference = "Stop"

Set-Location (Split-Path -Parent $PSScriptRoot)
uv run identitylab serve --host 127.0.0.1 --port 8088
