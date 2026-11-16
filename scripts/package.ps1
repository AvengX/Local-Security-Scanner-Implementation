<#
.SYNOPSIS
    Builds a clean, shareable zip of Local Security Scanner (source only).
.DESCRIPTION
    Includes code, tests, scripts, docs and config.example.yaml.
    EXCLUDES everything machine- or user-specific: .venv, config.yaml, data (SQLite DB), reports, logs,
    vapt_lab, external_targets (cloned repos + their scan results), caches.
    Output: dist\LocalSecurityScanner-<yyyyMMdd>.zip
#>
[CmdletBinding()]
param([string]$OutDir = '')

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $Root 'dist' }
$name = "LocalSecurityScanner-$(Get-Date -Format yyyyMMdd)"
$stage = Join-Path ([IO.Path]::GetTempPath()) "lss-package-$PID\LocalSecurityScanner"
if (Test-Path (Split-Path $stage)) { Remove-Item -Recurse -Force (Split-Path $stage) }
New-Item -ItemType Directory -Force $stage | Out-Null

$files = 'app.py', 'run_scan.py', 'config.example.yaml', 'requirements.txt', 'README.md', '.gitignore', 'pyproject.toml'
$dirs = '.streamlit', 'engine', 'database', 'dashboard', 'services', 'utils', 'tests', 'scripts', 'docs', 'vapt'

foreach ($f in $files) { Copy-Item (Join-Path $Root $f) $stage }
foreach ($d in $dirs) {
    Copy-Item (Join-Path $Root $d) (Join-Path $stage $d) -Recurse
}
foreach ($d in 'data', 'reports', 'logs') {
    New-Item -ItemType Directory -Force (Join-Path $stage $d) | Out-Null
    New-Item -ItemType File -Force (Join-Path $stage "$d\.gitkeep") | Out-Null
}
# Strip caches and anything that must never be shared.
Get-ChildItem $stage -Recurse -Force -Directory -Include '__pycache__', '.pytest_cache' | Remove-Item -Recurse -Force
Get-ChildItem $stage -Recurse -Force -File -Include '*.pyc', '*.db', '*.db-wal', '*.db-shm', '*.lock', 'config.yaml' |
    Remove-Item -Force

New-Item -ItemType Directory -Force $OutDir | Out-Null
$zip = Join-Path $OutDir "$name.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $stage -DestinationPath $zip
Remove-Item -Recurse -Force (Split-Path $stage)

Write-Host "Package created: $zip ($([math]::Round((Get-Item $zip).Length / 1KB)) KB)" -ForegroundColor Green
Write-Host 'Share this zip. The recipient follows docs\SHARING.md (extract, run scripts\install.ps1, run scripts\start.ps1).'
