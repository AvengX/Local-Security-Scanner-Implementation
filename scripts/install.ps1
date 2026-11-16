<#
.SYNOPSIS
    Installs Local Security Scanner into a project-local virtual environment. Safe to re-run.
.DESCRIPTION
    Checks Python (3.12+), Git, Trivy and Gitleaks; creates .venv; installs pinned requirements;
    creates config.yaml from config.example.yaml ONLY if it does not exist; initialises SQLite;
    runs the health check. Never overwrites user configuration and never installs scanners silently.
.PARAMETER InstallScanners
    Offer to install missing Trivy/Gitleaks with winget (asks before each install).
#>
[CmdletBinding()]
param([switch]$InstallScanners)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

# Refresh PATH for tools installed in this session (winget updates the user PATH).
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')

# --- Python ---------------------------------------------------------------------------------
$py = $null
foreach ($cand in @('py -3', 'python')) {
    try {
        $ver = & cmd /c "$cand -c ""import sys;print('%d.%d' % sys.version_info[:2])""" 2>$null
        if ($LASTEXITCODE -eq 0 -and $ver) { $py = $cand; break }
    } catch { }
}
if (-not $py) { throw 'Python 3.12+ not found. Install from https://www.python.org/downloads/windows/' }
$major, $minor = $ver.Split('.') | ForEach-Object { [int]$_ }
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 12)) { throw "Python $ver found; 3.12+ is required." }
Ok "Python $ver ($py)"

# --- Git / scanners ---------------------------------------------------------------------------
if (Get-Command git -ErrorAction SilentlyContinue) { Ok (git --version) } else { Warn 'Git not found (winget install Git.Git). Discovery metadata and Gitleaks history scans need it.' }

$scanners = @{ trivy = 'AquaSecurity.Trivy'; gitleaks = 'Gitleaks.Gitleaks' }
foreach ($name in $scanners.Keys) {
    if (Get-Command $name -ErrorAction SilentlyContinue) {
        Ok "$name found: $((Get-Command $name).Source)"
    } elseif ($InstallScanners -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        $answer = Read-Host "$name is missing. Install it now with 'winget install $($scanners[$name])'? [y/N]"
        if ($answer -match '^(y|yes)$') {
            winget install --id $scanners[$name] -e --accept-source-agreements --accept-package-agreements
            $env:Path = [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')
        }
    } else {
        Warn "$name not found. Install with: winget install $($scanners[$name])  (or re-run with -InstallScanners)"
    }
}

# --- Virtual environment ------------------------------------------------------------------------
$venvPy = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    Info 'Creating virtual environment (.venv)'
    & cmd /c "$py -m venv .venv"
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create virtual environment' }
} else { Ok 'Virtual environment exists' }

Info 'Installing pinned dependencies'
& $venvPy -m pip install --disable-pip-version-check -q --upgrade pip
& $venvPy -m pip install --disable-pip-version-check -q -r (Join-Path $Root 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }
& $venvPy -c "import streamlit, pandas, plotly, pydantic, yaml; print('dependencies OK')"
if ($LASTEXITCODE -ne 0) {
    Warn 'A dependency failed to import. If the error mentions an Application Control policy, Windows Smart App Control blocked a package DLL - see docs/INSTALLATION.md.'
}

# --- Configuration + database (never overwrites config.yaml) -------------------------------------
& $venvPy (Join-Path $Root 'run_scan.py') init
Info 'Health check'
& $venvPy (Join-Path $Root 'run_scan.py') health
Ok 'Installation finished. Next: set repository_roots in config.yaml (or the dashboard Settings page), then run scripts\start.ps1'
