# Local Security Scanner

A local-first, privacy-focused security monitoring platform for Windows that discovers every Git repository
under folders you choose, scans them with **Trivy** and **Gitleaks**, stores results and history in
**SQLite**, and presents them in a **Streamlit** dashboard bound to `127.0.0.1`. Source code, reports, the
database and logs never leave your machine.

## 1. Overview
* Engine (`engine/`) and CLI (`run_scan.py`) run independently of the dashboard — scheduled scans work with
  the dashboard closed.
* Every scanner execution is recorded with status, exit code, tool version, Trivy DB timestamp and errors.
  A failed scan is **never** treated as clean.
* Findings are normalised, fingerprinted and compared across scans (NEW / EXISTING / RESOLVED / UNVERIFIED)
  with coverage-aware rules.

## 2. Features
| Area | Highlights |
|---|---|
| Discovery | Recursive, multiple roots, `.git` dirs and `.git` files (worktrees/submodules), nested repos, exclusions, no symlink/junction following, permission errors reported, moved/deleted detection, branch + commit |
| Trivy | `fs` (vuln, misconfig, secret, license), `config`, `image`, CycloneDX SBOM, severity filter, offline flags, DB update, version-aware flags |
| Gitleaks | `git` (history, `--log-opts`) and `dir` (working tree) modes, custom config/allowlists, `--redact` |
| Orchestration | scan-all / scan-repo, bounded concurrency, per-repo + job locks, timeouts, Ctrl+C cancellation, per-scan isolation, batch summaries |
| Storage | SQLite with FKs, WAL, transactions, indexes, migrations, duplicate prevention, retention |
| Dashboard | Overview, Repositories, Findings, Scan History, Reports, Settings — Plotly charts, filters, detail views, empty/error states |
| Reports | Raw JSON per scan, CSV, consolidated JSON, Markdown/HTML summary, per-repository reports |
| Automation | Windows Task Scheduler (daily/weekly) with explicit confirmation |
| Offline | Cached DB only, visible freshness/staleness, DB-missing detection |

## 3. Architecture
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
```
Discovery → Orchestrator → (Trivy | Gitleaks) → JSON parser/normaliser → Comparison → SQLite → Analytics → Dashboard → Exports
```

## 4. Prerequisites
Windows 10/11, PowerShell 5.1+, Python 3.12+ (tested 3.14.7), Git, Trivy (tested 0.76.2), Gitleaks (tested 8.30.1).

## 5. Windows installation
```powershell
cd D:\LocalSecurityScanner
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1      # add -InstallScanners to offer winget installs
```
Details, Smart App Control notes and manual steps: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## 6. Trivy installation
`winget install AquaSecurity.Trivy` (or download from https://github.com/aquasecurity/trivy/releases).
Then, while online: `python run_scan.py update-databases`.

## 7. Gitleaks installation
`winget install Gitleaks.Gitleaks` (or https://github.com/gitleaks/gitleaks/releases).

## 8. Python environment setup
```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 9. Configuration
`config.yaml` (created from `config.example.yaml`, never overwritten by scripts). Key settings:
`repository_roots`, `excluded_dirs`, `scan.timeout_seconds`, `scan.concurrency`, `scan.severities`,
`scan.offline`, `scan.db_freshness_hours`, `scan.retention_days`, `trivy.*`, `gitleaks.*`, `paths.*`.
All values are validated (Pydantic); invalid configs are rejected with a clear message. The dashboard
Settings page edits the same file. Use `--config` or `LSS_CONFIG` for alternative configs.
For production, point `paths.*` outside any scanned root (e.g. `%LOCALAPPDATA%\LocalSecurityScanner\data`);
the app's own data/report/log directories are always excluded from discovery and from Trivy.

## 10. Repository discovery
```powershell
.\.venv\Scripts\python.exe run_scan.py discover
```
or **Repositories → Discover repositories** in the dashboard.

## 11. Manual scanning
```powershell
.\.venv\Scripts\python.exe run_scan.py scan-all
.\.venv\Scripts\python.exe run_scan.py scan-repo --name Phoenix
.\scripts\scan_all.ps1 [-Offline]
```
See [docs/SCANNING.md](docs/SCANNING.md) for every command, status and rule.

## 12. Automated scanning
```powershell
.\.venv\Scripts\python.exe run_scan.py schedule --frequency daily --time 02:00     # asks y/N
.\.venv\Scripts\python.exe run_scan.py schedule --frequency weekly --day SUN --time 03:00
```

## 13. Dashboard startup
```powershell
.\scripts\start.ps1          # http://127.0.0.1:8501
```

## 14. Offline mode
`scan.offline: true` or `scan-all --offline`. Details: [docs/OFFLINE_MODE.md](docs/OFFLINE_MODE.md).

## 15. Database structure
[docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) — `repositories`, `scan_runs`, `findings`,
`finding_changes`, `repo_locks`, `settings`.

## 16. Reports
Raw: `reports/<Repo>_<id>/*.json`. Exports: `reports/exports/` via `run_scan.py report` or the Reports page.
Downloads are restricted to files registered in the DB **and** located inside `reports_dir`.

## 17. Troubleshooting
| Symptom | Fix |
|---|---|
| `trivy … BLOCKED/ERROR` in `health` | Windows Smart App Control/WDAC blocked trivy.exe — see docs/INSTALLATION.md |
| `DLL load failed … Application Control policy` | Keep the pinned numpy/pandas/pyarrow versions from requirements.txt |
| Trivy runs FAILED "vulnerability DB is missing" | `run_scan.py update-databases` while online, or disable offline mode |
| Gitleaks FAILED "dubious ownership" | If you trust the repo: `git config --global --add safe.directory "<path>"` |
| Scan SKIPPED "in progress" | Another process is scanning it; stale locks from dead processes are reclaimed automatically |
| scan-all exits 3 | Another scan-all job is running (e.g. the scheduled task) |
| Nothing discovered | Check `repository_roots`, `excluded_dirs`, `max_depth`; see `discover` output warnings |
| Logs | `logs/scanner.log` (JSON lines), `logs/scheduled_runs.log`, `logs/dashboard_jobs.log` |

## 18. Security limitations
See [docs/SECURITY.md](docs/SECURITY.md). In short: detection is limited to Trivy/Gitleaks rules and DB
freshness; raw Trivy reports may contain masked code context — keep `reports/` private; no app-level auth
(loopback-only); OS application-control policies may block scanners and are reported, not bypassed.

## 19. Testing
```powershell
.\.venv\Scripts\python.exe -m pytest              # all tests
.\.venv\Scripts\python.exe -m pytest -m realtools # only tests that execute real Gitleaks/Trivy
```
Scanner execution is mocked for deterministic tests; real-binary tests use disposable Git repositories with
randomly generated fake tokens (never real credentials) and are skipped if a tool is unavailable.

### VAPT acceptance test
```powershell
.\scripts\run_vapt_test.ps1 -Dashboard
```
Builds a lab of intentionally vulnerable repositories, scans it with the real application and verifies
43 PASS/FAIL checks (CVEs, IaC misconfigurations, secrets incl. Git history, false positives, remediation,
offline mode, reports, secret-leak audit). Scope and details: [docs/VAPT_TEST.md](docs/VAPT_TEST.md).

### Sharing with someone else
Run `scripts\package.ps1` to build a clean source-only zip in `dist\`; the recipient follows
[docs/SHARING.md](docs/SHARING.md).

## 20. Uninstallation and scheduled-task removal
```powershell
.\.venv\Scripts\python.exe run_scan.py unschedule --frequency all    # or: schtasks /Delete /TN \LocalSecurityScanner\DailyScan /F
Remove-Item -Recurse .venv, data, reports, logs                      # permanently deletes local results
winget uninstall AquaSecurity.Trivy; winget uninstall Gitleaks.Gitleaks   # optional
```
