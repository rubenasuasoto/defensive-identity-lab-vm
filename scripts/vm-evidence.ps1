$ErrorActionPreference = "Stop"

Set-Location (Split-Path -Parent $PSScriptRoot)
uv run identitylab vm-evidence --output-dir evidence/latest
