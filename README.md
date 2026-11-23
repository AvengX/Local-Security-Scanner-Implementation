# Local Security Scanner

**Version 1.3.0** — see [CHANGELOG.md](CHANGELOG.md) for what is new.

A local, privacy-focused security assessment tool for Windows. **Paste the path of a project folder, click
Scan, and get a VAPT report as a PDF** — viewable in the page or downloadable. The report follows the layout of a
professional security assessment: executive summary, scope & methodology, findings table (severity, CVSS 3.1,
OWASP), finding details (location, confidence, effort, description, evidence, impact, fix), what's done well,
remediation roadmap and what was not tested.

## How it works
```
Folder you paste ──► Trivy + Gitleaks + Bandit + code scan (+ web scan) ──► SQLite ──► VAPT report (HTML → PDF)
```
1. You paste a folder path (or click **Browse…**). Every Git repository inside it is a project; a folder with no
   Git repository is scanned as one project.
2. **Trivy** checks dependencies for known vulnerabilities (with CVSS scores), the exact versions installed in
   `.venv` / `node_modules`, and Docker / cloud files for unsafe settings.
   **Gitleaks** finds passwords and keys in current files *and* in the Git history (values are never stored).
   **Bandit** (Python) and a built-in **code scan** (JavaScript/TypeScript, HTML/Jinja templates, PHP, Java, Go, C#)
   find risky code such as SQL built from strings, `eval`, `innerHTML` or TLS checks turned off.
   If a local web address is configured for the project, the built-in **web scan (DAST)** probes the running app
   (headers, cookies, exposed files, debug pages, XSS, SQL errors, open redirect, path traversal) — GET-only and
   only on this computer.
3. Results are grouped into readable issues (VAPT-01, VAPT-02, …) and written as one PDF per project, printed with
   the Microsoft Edge / Chrome already on the computer.

The same flow from the command line: `python run_scan.py vapt "D:\Projects\my-app"`.

Nothing is uploaded. Only Trivy downloads its vulnerability list from the internet, and offline mode turns that off.
The web scan only talks to apps on this computer (localhost / 127.0.0.1 / ::1), plus outside websites whose exact
host name you add to `dast.allowed_hosts` in `config.yaml` — only for sites you are authorised to test. Paste such a
site's address (`https://…`) in the folder box to get a black-box VAPT report for it.
The scanner never changes your projects — the only exception is the optional secret guard, which you switch on per project and which adds one file, `.git/hooks/pre-commit` (outside your code and history).

## Tech stack
| Layer | Technology | Used for |
|---|---|---|
| Language | **Python 3.14** (3.12+ supported) | All application code: discovery, scanning, parsing, reports, dashboard |
| Vulnerability scanner | **Trivy** 0.76 (Aqua Security) | Vulnerable libraries, unsafe Docker/Kubernetes/Terraform settings, secrets in files |
| Secret scanner | **Gitleaks** 8.30 | Passwords and keys in current files and in Git history |
| Code scanner (SAST) | **Bandit** 1.9 (Python package, offline) | Security bugs in your own Python code |
| Code scanner, other languages | Built in (pattern rules, Python standard library) | Risky patterns in JavaScript/TypeScript, HTML templates, PHP, Java, Go, C# |
| Web scanner (DAST) | Built in (Python standard library `urllib`, `html.parser`, `http.cookiejar`) | Testing your running local web apps through their address, optionally signed in with a test account |
| Version control | **Git** | Finding repositories, branch/commit details, history scans |
| Database | **SQLite** (Python `sqlite3`) | Repositories, scan runs, findings and history, stored locally in `data\` |
| Dashboard | **Streamlit** 1.67 | Web UI on `127.0.0.1:8501` (tables, filters, buttons that start background scans) |
| Data handling | **pandas** 2.3, **NumPy** 2.4, **PyArrow** 22 | Tables and filtering in the dashboard |
| Validation and config | **Pydantic** 2.14, **PyYAML** 6.0 | Checking `config\config.yaml` and settings |
| Reports | HTML + CSS (print-ready), PDF (via Edge/Chrome already installed), SARIF 2.1.0, CSV, JSON, Markdown | Management summary, audit report, GitHub / VS Code export |
| Testing | **pytest** 9.2, Streamlit AppTest | Unit and dashboard tests; VAPT acceptance test (`vapt\run_vapt_test.py`) |
| Automation | **PowerShell** scripts, Windows Task Scheduler | Install, start, scheduled scans (`scripts\`) |
| Platform | Windows 10/11 (Win32 API via `ctypes`) | Process checks for running scans and tests |

Exact package versions are pinned in [requirements.txt](requirements.txt). No cloud services, external database
or JavaScript build tools are used.

## Install on any Windows 10/11 laptop
Each laptop has its own independent copy with its own settings, database and results. Nothing is shared between PCs.

**1. Install the tools (once).** Open PowerShell:
```powershell
winget install Python.Python.3.14      # or Python 3.12+ from python.org (tick "Add python.exe to PATH")
winget install Git.Git
winget install AquaSecurity.Trivy
winget install Gitleaks.Gitleaks
```
Close and reopen PowerShell so the new tools are found.

**2. Get the code.** Clone it, or extract a zip made with `scripts\package.ps1` on another PC:
```powershell
git clone https://github.com/AvengX/Local-Security-Scanner-Implementation.git C:\Tools\LocalSecurityScanner
cd C:\Tools\LocalSecurityScanner
```

**3. Install the app.** This step:
* creates a private Python environment (`.venv`),
* installs the pinned packages,
* creates `config.yaml` and the database,
* runs a health check.

It is safe to run again.
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

**4. Download the vulnerability database** (needs internet, about 80 MB):
```powershell
.\.venv\Scripts\python.exe run_scan.py update-databases
.\.venv\Scripts\python.exe run_scan.py health          # git, trivy, gitleaks, bandit and dast should all say OK
```

**5. Start the dashboard:**
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1     # opens http://127.0.0.1:8501
```

**6. Point it at your projects.** In the dashboard, open **Settings → Configuration → 1 · Repository roots**,
press **Browse for a folder…** to pick a folder in the normal Windows dialog (or type/paste paths, one per line),
then press **Validate and save**.
Alternatively, edit `config.yaml`:
```yaml
repository_roots: ['C:\Users\you\source\repos', 'D:\Projects']
```

**7. Scan.** Go to **Repositories → Discover repositories → Scan all repositories**. The page updates on its own when the scan finishes.

**8. Optional: prove it works on this laptop.** Open **VAPT Lab → Run VAPT test**, or run:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_vapt_test.ps1   # should report 106/106 PASS
```

**Every day after that:** run `.\scripts\start.ps1` and use the dashboard.
**Get updates:** `git pull`, then `.\scripts\install.ps1` again if `requirements.txt` changed, then restart the dashboard.
Database changes are applied automatically when it starts.

| Problem on a new laptop | Fix |
|---|---|
| Sidebar or `health` shows Trivy **Blocked by Windows** | Windows Smart App Control stopped `trivy.exe` (it is not code-signed). The laptop's owner must allow it ([docs/SECURITY.md](docs/SECURITY.md)). Until then, Trivy scans show as FAILED, never as clean. |
| `DLL load failed ... Application Control` during install | Same cause; keep the versions pinned in `requirements.txt`. |
| Vuln DB shows **Missing** | Step 4 while online, or **Settings → Scanners & vulnerability DB → Update**. |
| No repositories appear | Check the folders in step 6, then press **Discover repositories**. The page explains what is wrong. |
| `python` not found | Reinstall Python with "Add to PATH" ticked, then reopen PowerShell. |
| Port 8501 already in use | `.\scripts\start.ps1 -Port 8510` |
| Gitleaks FAILED "dubious ownership" | `git config --global --add safe.directory "<repo path>"` |

Your `config.yaml`, database, reports and logs are git-ignored and left out of the zip, so sharing the code never shares
your results. Scheduled scans must be set up separately on each laptop. More detail: [docs/SHARING.md](docs/SHARING.md).

## Using the dashboard
One page. Full guide: [docs/UI_GUIDE.md](docs/UI_GUIDE.md).

1. Start it: `scripts\start.ps1`, then open http://127.0.0.1:8501.
2. Paste the project folder path (or **Browse…**) and click **Scan**. Progress is shown live; the scan keeps
   running if you click around or refresh the page.
3. When it finishes, the PDF report opens in the page. Use **Download PDF** to save it or **Open in new tab** to
   view it full-screen. A folder with several projects gives one report per project (pick one from the list).
4. Earlier reports stay available under **Earlier reports** (files in `reports\vapt`).

Advanced settings (web addresses for the live web scan, test-account login, skipped folders, tool paths) live in
`config.yaml` — see `config.example.yaml`.

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
| DAST (built in) | Safe dynamic testing of running local web apps: loopback-only (checked in config and on every request), GET-only, destructive links skipped, request/page/time limits, earlier findings re-tested first, app-down = skipped + unverified, response bodies never stored |
| Code scan, other languages (built in) | Text pattern rules only (nothing is run or imported); skip folders, minified files, node_modules/vendor; files over 1.5 MB skipped and listed; matched source text never stored |
| DAST login (optional) | One POST to the app's own sign-in form, same origin only; password read from an environment variable at scan time, never stored; config errors never echo input values; wrong password = FAILED run |
| SAST (Bandit) | Static analysis of Python code, offline; own `--ini` (repository `.bandit` ignored), skip folders, `sast.skip_tests`, code snippets and password values removed from stored results and saved reports |
| Orchestration | scan-all / scan-repo, bounded concurrency, per-repo + job locks, timeouts, Ctrl+C cancellation, per-scan isolation, batch summaries |
| Storage | SQLite with FKs, WAL, transactions, indexes, migrations, duplicate prevention, retention |
| Dashboard | Dark security-operations UI: Overview (posture, metrics, problems-by-project table, recommended actions, health), Security Findings, Vulnerabilities, Secrets, Code issues, Web app issues, Misconfigurations, Repositories, Scan History, Reports, VAPT Lab, Settings — sidebar health panel, global search, finding history, guided empty/error states. See [docs/UI_GUIDE.md](docs/UI_GUIDE.md) |
| Reports | Raw JSON per scan, CSV, consolidated JSON, Markdown/HTML summary, per-repository reports, detailed VAPT-style audit report (HTML → PDF) |
| Automation | Windows Task Scheduler (daily/weekly) with explicit confirmation |
| Offline | Cached DB only, visible freshness/staleness, DB-missing detection |

## 3. Architecture
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
```
Discovery → Orchestrator → (Trivy | Gitleaks | Bandit | code scan | DAST) → JSON parser/normaliser → Comparison → SQLite → Analytics → Dashboard → Exports
```

## 4. Prerequisites
Windows 10/11, PowerShell 5.1+, Python 3.12+ (tested 3.14.7), Git, Trivy (tested 0.76.2), Gitleaks (tested 8.30.1). Bandit 1.9.4 is installed from requirements.txt. The code scan for other languages and the web scan (DAST) are built in.

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
`scan.offline`, `scan.db_freshness_hours`, `scan.retention_days`, `trivy.*`, `gitleaks.*`, `sast.*`, `dast.*`, `paths.*`.
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
Pages and states are described in [docs/UI_GUIDE.md](docs/UI_GUIDE.md). The latest audit is in
[docs/AUDIT.md](docs/AUDIT.md).

## 14. Offline mode
`scan.offline: true` or `scan-all --offline`. Details: [docs/OFFLINE_MODE.md](docs/OFFLINE_MODE.md).

## 15. Database structure
[docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) — `repositories`, `scan_runs`, `findings`,
`finding_changes`, `repo_locks`, `settings`.

## 16. Reports
Raw: `reports/<Repo>_<id>/*.json`. Exports: `reports/exports/` via `run_scan.py report` or the Reports page.
Detailed audit report, management summary (add `--pdf` for a PDF) and SARIF for GitHub / VS Code:
```powershell
.\.venv\Scripts\python.exe run_scan.py audit --name my-project --pdf
.\.venv\Scripts\python.exe run_scan.py summary --pdf
.\.venv\Scripts\python.exe run_scan.py sarif --name my-project
```
It is built from the database, the raw JSON of the latest successful `trivy fs` run and read-only git metadata.
Dependency paths need a scan made with this version (Trivy runs with `--list-all-pkgs`); older scans say so.
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
See [docs/SECURITY.md](docs/SECURITY.md). In short: detection is limited to Trivy/Gitleaks/Bandit rules and DB
freshness; SAST covers Python in depth and the most common risky patterns in JavaScript/TypeScript, templates, PHP, Java, Go
and C#, not logic flaws such as missing access checks;
the web scan (DAST) tests local apps with GET requests only (plus one sign-in POST when a test account is set), so it does not
replace a manual penetration test; raw Trivy reports may contain masked code context — keep `reports/` private; no app-level auth
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
106 PASS/FAIL checks (PDF and SARIF export, API testing, alerts, secret guard, triage decisions, installed versions, auto-start, CVEs, IaC misconfigurations, secrets incl. Git history, SAST code issues in Python and other languages, DAST web issues incl. behind a login, plain-language explanations, false positives, remediation,
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
