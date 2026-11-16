<#
.SYNOPSIS
    Discovers and scans all configured repositories (manual or scheduled use).
.PARAMETER Offline
    Use cached vulnerability databases only (no downloads).
#>
[CmdletBinding()]
param([switch]$Offline, [switch]$Json)

$Root = Split-Path -Parent $PSScriptRoot
$venvPy = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) { Write-Error 'Virtual environment missing. Run scripts\install.ps1 first.'; exit 2 }
$argsList = @((Join-Path $Root 'run_scan.py'), 'scan-all')
if ($Offline) { $argsList += '--offline' }
if ($Json) { $argsList += '--json' }
& $venvPy @argsList
$code = $LASTEXITCODE
switch ($code) {
    0 { Write-Host 'Scan completed.' -ForegroundColor Green }
    1 { Write-Host 'Scan finished with failed/timed-out scanner runs (see output and logs\scanner.log).' -ForegroundColor Yellow }
    3 { Write-Host 'Another scan job is already running; skipped.' -ForegroundColor Yellow }
    default { Write-Host "Scan exited with code $code." -ForegroundColor Red }
}
exit $code
