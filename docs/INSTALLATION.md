# Installation (Windows 10/11, PowerShell)

## Prerequisites
| Tool | Version tested | Install |
|---|---|---|
| Python | 3.14.7 (3.12+ supported) | https://www.python.org/downloads/windows/ |
| Git | 2.55 | `winget install Git.Git` |
| Trivy | 0.76.2 | `winget install AquaSecurity.Trivy` |
| Gitleaks | 8.30.1 | `winget install Gitleaks.Gitleaks` |

winget installs both scanners from their official GitHub releases (hash-verified) under
`%LOCALAPPDATA%\Microsoft\WinGet\Packages\…`. The scanner auto-detects that location even before the
PATH change takes effect; you can also set `trivy.executable` / `gitleaks.executable` in `config.yaml`.

## Steps
```powershell
cd D:\LocalSecurityScanner
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1            # or add -InstallScanners
```
`install.ps1` is idempotent: it creates `.venv` only if missing, installs `requirements.txt`, creates
`config.yaml` from `config.example.yaml` **only if it does not exist**, initialises the SQLite database and
runs `run_scan.py health`.

(`-ExecutionPolicy Bypass` applies to that single PowerShell process only; it does not change the machine
policy. If your policy already allows local scripts, run `.\scripts\install.ps1` directly.)

Manual equivalent:
```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_scan.py init
.\.venv\Scripts\python.exe run_scan.py health
```

## Configure
Edit `config.yaml` (or the dashboard **Settings** page):
```yaml
repository_roots: ['D:\Projects']
```
Then `python run_scan.py discover`.

## Windows Smart App Control / Application Control
On machines with **Smart App Control** (Windows 11) or WDAC enforced, unsigned or low-reputation binaries
can be blocked. On the reference machine:

* `trivy.exe` 0.76.2 was **blocked** (`Code Integrity event 3077`). `run_scan.py health` reports
  `BLOCKED/ERROR`, and every Trivy run is recorded as **FAILED** with the reason; nothing is marked clean.
* Some Python wheels' DLLs were blocked (numpy 2.5.5 `bit_generator`, pandas 3.1.1 `aggregations`,
  several pyarrow 26 modules). `requirements.txt` therefore pins numpy 2.4.6, pandas 2.3.3 and
  pyarrow 22.0.0, which loaded correctly (only pyarrow's unused parquet-encryption modules stay blocked).

Options for Trivy if it is blocked (your decision; the application never bypasses the policy):
1. Ask your administrator to allow-list the Trivy binary (WDAC), or
2. Turn off Smart App Control in *Windows Security → App & browser control* (note: on many builds it
   cannot be turned back on without resetting Windows), or
3. Run Trivy in another environment you control and point `trivy.executable` at a permitted build.

Check the block with:
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 5 | Format-List TimeCreated,Message
```

## Uninstall
```powershell
.\.venv\Scripts\python.exe run_scan.py unschedule --frequency all   # remove scheduled tasks (asks first)
Remove-Item -Recurse .venv, data, reports, logs                       # deletes local results permanently
```
Optionally `winget uninstall AquaSecurity.Trivy` / `winget uninstall Gitleaks.Gitleaks`, and delete the
Trivy cache `%LOCALAPPDATA%\trivy`.
