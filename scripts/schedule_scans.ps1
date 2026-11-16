<#
.SYNOPSIS
    Registers, lists or removes Windows scheduled scans. Always asks for confirmation before changes.
.EXAMPLE
    .\scripts\schedule_scans.ps1 -Frequency daily -Time 02:00
    .\scripts\schedule_scans.ps1 -Frequency weekly -Day SUN -Time 03:00
    .\scripts\schedule_scans.ps1 -List
    .\scripts\schedule_scans.ps1 -Remove
#>
[CmdletBinding(DefaultParameterSetName = 'Create')]
param(
    [Parameter(ParameterSetName = 'Create', Mandatory = $true)][ValidateSet('daily', 'weekly')][string]$Frequency,
    [Parameter(ParameterSetName = 'Create')][ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')][string]$Time = '02:00',
    [Parameter(ParameterSetName = 'Create')][ValidateSet('MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN')][string]$Day = 'SUN',
    [Parameter(ParameterSetName = 'List')][switch]$List,
    [Parameter(ParameterSetName = 'Remove')][switch]$Remove
)

$Root = Split-Path -Parent $PSScriptRoot
$venvPy = Join-Path $Root '.venv\Scripts\python.exe'
$cli = Join-Path $Root 'run_scan.py'
if (-not (Test-Path $venvPy)) { Write-Error 'Run scripts\install.ps1 first.'; exit 2 }

switch ($PSCmdlet.ParameterSetName) {
    'List' {
        foreach ($t in '\LocalSecurityScanner\DailyScan', '\LocalSecurityScanner\WeeklyScan') {
            schtasks /Query /TN $t /FO LIST 2>$null
            if ($LASTEXITCODE -ne 0) { Write-Host "$t : not registered" }
        }
    }
    'Remove' { & $venvPy $cli unschedule --frequency all }
    default {
        $a = @($cli, 'schedule', '--frequency', $Frequency, '--time', $Time)
        if ($Frequency -eq 'weekly') { $a += @('--day', $Day) }
        & $venvPy @a   # prints the exact schtasks command and asks [y/N]
    }
}
exit $LASTEXITCODE
