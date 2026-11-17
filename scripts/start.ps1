<#
.SYNOPSIS
    Starts the Local Security Scanner dashboard on 127.0.0.1 (loopback only).
#>
[CmdletBinding()]
param([int]$Port = 0, [string]$Config = '')

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$venvPy = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) { throw 'Virtual environment missing. Run scripts\install.ps1 first.' }

& $venvPy -c "import streamlit, pandas, pydantic, yaml" 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Dependencies missing or blocked. Run scripts\install.ps1 (see docs/INSTALLATION.md).' }

if ($Config) {
    if (-not (Test-Path $Config)) { throw "Config file not found: $Config" }
    $env:LSS_CONFIG = (Resolve-Path $Config).Path
    Write-Host "Using config: $env:LSS_CONFIG" -ForegroundColor DarkGray
}
if ($Port -eq 0) {
    $Port = [int](& $venvPy -c "from utils.config import load_config; print(load_config().dashboard.port)")
}
$url = "http://127.0.0.1:$Port"
Write-Host "Local Security Scanner dashboard: $url" -ForegroundColor Green
Write-Host 'Bound to 127.0.0.1 only. Press Ctrl+C to stop.' -ForegroundColor DarkGray
& $venvPy -m streamlit run (Join-Path $Root 'app.py') `
    --server.address 127.0.0.1 --server.port $Port --server.headless true `
    --browser.gatherUsageStats false --browser.serverAddress 127.0.0.1
