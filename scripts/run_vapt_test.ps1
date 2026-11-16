<#
.SYNOPSIS
    Runs the end-to-end VAPT acceptance test against an intentionally vulnerable local lab.
.DESCRIPTION
    1. Builds vapt_lab\targets (4 disposable Git repos: vulnerable Python, vulnerable Node, insecure IaC, clean).
    2. Drives the real application CLI: health, discover, scan-all, scan-repo, offline scan-all, report, status.
    3. Verifies 45 PASS/FAIL checks and writes vapt_lab\VAPT_TEST_RESULTS.md (+ .json).
    Everything stays on this machine. The lab and its results are recreated on every run.
.PARAMETER UpdateDb
    Refresh the Trivy vulnerability DB first (needs internet).
.PARAMETER Dashboard
    After the test, open the dashboard on the lab results (http://127.0.0.1:8502).
#>
[CmdletBinding()]
param([switch]$UpdateDb, [switch]$Dashboard)

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$venvPy = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) { Write-Error 'Run scripts\install.ps1 first.'; exit 2 }

if ($UpdateDb) { & $venvPy run_scan.py update-databases --force }

& $venvPy (Join-Path $Root 'vapt\run_vapt_test.py')
$code = $LASTEXITCODE
$results = Join-Path $Root 'vapt_lab\VAPT_TEST_RESULTS.md'
if ($code -eq 0) { Write-Host "`nVAPT test PASSED. Results: $results" -ForegroundColor Green }
else { Write-Host "`nVAPT test FAILED (see FAIL rows). Results: $results" -ForegroundColor Red }

if ($Dashboard) {
    & (Join-Path $PSScriptRoot 'start.ps1') -Config (Join-Path $Root 'vapt_lab\config.vapt.yaml') -Port 8502
}
exit $code
