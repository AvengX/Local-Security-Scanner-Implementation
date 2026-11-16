# Sharing the project and setting it up on another PC

## For the person sharing
Create a clean zip, then send it (or push the folder to a private Git repository):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package.ps1      # -> dist\LocalSecurityScanner-<date>.zip
```
The zip contains **source only**. It deliberately leaves out:

| Left out | Why |
|---|---|
| `.venv\` | Virtual environments are tied to one machine; the recipient creates their own |
| `config.yaml` | Your personal folder paths; the recipient gets `config.example.yaml` |
| `data\`, `reports\`, `logs\` | Your scan results, which may describe your vulnerabilities |
| `vapt_lab\`, `external_targets\` | Test lab and cloned repositories with their results |

Never share `data\security_scanner.db` or `reports\` unless you intend to share your scan results.

If you use Git instead: `.gitignore` already excludes all of the above.

## For the person receiving it (Windows 10/11)

### 1. Install the prerequisites (once)
```powershell
winget install Python.Python.3.14      # or 3.12+ from python.org (tick "Add python.exe to PATH")
winget install Git.Git
winget install AquaSecurity.Trivy
winget install Gitleaks.Gitleaks
```
Close and reopen PowerShell afterwards so the new PATH is picked up.

### 2. Extract and install
Extract the zip anywhere, e.g. `C:\Tools\LocalSecurityScanner`, then:
```powershell
cd C:\Tools\LocalSecurityScanner
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```
This creates `.venv`, installs the pinned Python packages, creates `config.yaml` from the example,
creates the database and runs a health check. It is safe to run again.

### 3. Download the vulnerability database (needs internet, about 80 MB)
```powershell
.\.venv\Scripts\python.exe run_scan.py update-databases
.\.venv\Scripts\python.exe run_scan.py health          # trivy, gitleaks and git should all say OK
```

### 4. Point it at your own projects
Edit `config.yaml`:
```yaml
repository_roots: ['C:\Users\you\source\repos']
```
(or set it on the dashboard's **Settings** page).

### 5. Run it
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1     # dashboard: http://127.0.0.1:8501
```
In the dashboard: **Repositories → Discover repositories → Scan all repositories**.
Or from the command line:
```powershell
.\.venv\Scripts\python.exe run_scan.py discover
.\.venv\Scripts\python.exe run_scan.py scan-all
.\.venv\Scripts\python.exe run_scan.py status
```

### 6. Confirm everything works on the new PC (optional, recommended)
```powershell
.\.venv\Scripts\python.exe -m pytest                              # automated tests
powershell -ExecutionPolicy Bypass -File .\scripts\run_vapt_test.ps1   # 45-check end-to-end test
```

## Troubleshooting on a new PC
| Problem | Fix |
|---|---|
| `health` shows Trivy `BLOCKED/ERROR` | Windows Smart App Control blocked trivy.exe. The owner of that PC must allow it (see docs/INSTALLATION.md). The scanner reports this as FAILED and never pretends the scan passed. |
| `DLL load failed ... Application Control policy` during install | Same cause, for a Python package. Keep the versions pinned in `requirements.txt`. |
| `py` / `python` not found | Reinstall Python with "Add to PATH" ticked, then reopen PowerShell. |
| Scripts refuse to run | Use `powershell -ExecutionPolicy Bypass -File <script>` (affects only that one run). |
| Port 8501 already in use | `.\scripts\start.ps1 -Port 8510` |
| Trivy scans FAILED "vulnerability DB is missing" | Run step 3 while online. |
| Gitleaks FAILED "dubious ownership" | If you trust the repo: `git config --global --add safe.directory "<path>"` |

## Things that stay on each PC
Each person has their own database, reports, logs and settings. Nothing is shared between installations
and nothing is uploaded anywhere. Scheduled scans (`run_scan.py schedule`) must be set up separately on
each PC and always ask for confirmation first.
