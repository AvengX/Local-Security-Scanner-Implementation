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

## Installation (step by step, from a fresh Windows laptop)
Follow these steps in order on each Windows 10/11 laptop that should run the scanner. Each laptop gets its own
independent copy with its own settings, database and reports — nothing is shared between PCs and nothing is uploaded.
It takes about 10–15 minutes, most of it downloads.

### What you need
| Item | Why | Notes |
|---|---|---|
| Windows 10 or 11 (64-bit) | The app and its scripts are Windows-only | PowerShell 5.1 is built in |
| Internet connection (during setup) | Download the tools and the vulnerability database (~80 MB) | Scans can run offline afterwards |
| **Python 3.12 or newer** | Runs the app | Tested with 3.14 |
| **Git** | Clones the code; reads branch / commit and Git history | |
| **Trivy** | Finds vulnerable libraries and unsafe Docker / cloud settings | |
| **Gitleaks** | Finds passwords and keys in files and in Git history | |
| Microsoft Edge (or Chrome) | Prints the report to PDF | Edge is already on every Windows 10/11 PC |
| winget | Installs the tools above with one command each | Built into Windows 10/11 ("App Installer" in the Microsoft Store) |

Administrator rights are only needed if your company's policy requires them for `winget`.

### Step 1 — Open PowerShell
Press **Start**, type **PowerShell**, and open **Windows PowerShell**. All commands below are typed there.
Check that winget works:
```powershell
winget --version
```
If it says *not recognised*, install **App Installer** from the Microsoft Store, then reopen PowerShell.

### Step 2 — Install the tools (once per laptop)
```powershell
winget install --id Python.Python.3.14 -e
winget install --id Git.Git -e
winget install --id AquaSecurity.Trivy -e
winget install --id Gitleaks.Gitleaks -e
```
If you install Python from https://www.python.org/downloads/windows/ instead, tick **"Add python.exe to PATH"** on the
first screen of the installer.

**Close PowerShell and open a new window** so Windows finds the new programs, then check them:
```powershell
python --version
git --version
trivy --version
gitleaks version
```
Each command should print a version number. If one says *not recognised*, see
[If something goes wrong](#if-something-goes-wrong) below.

### Step 3 — Clone the code
Pick a folder for the app — `C:\Tools\LocalSecurityScanner` is used here. Any folder works, but keep it **outside**
the project folders you plan to scan.
```powershell
git clone https://github.com/AvengX/Local-Security-Scanner-Implementation.git C:\Tools\LocalSecurityScanner
cd C:\Tools\LocalSecurityScanner
```
No Git? Download the zip from the GitHub page (**Code → Download ZIP**), or use a zip made with
`scripts\package.ps1` on another PC, and extract it to `C:\Tools\LocalSecurityScanner`.

### Step 4 — Install the app
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```
This script is safe to run again at any time. It:
1. checks Python (3.12+), Git, Trivy and Gitleaks and tells you what is missing,
2. creates a private Python environment in `.venv` (nothing is installed into your system Python),
3. installs the exact package versions from `requirements.txt`,
4. creates `config.yaml` from `config.example.yaml` — **only if it does not exist yet**, so your settings are never
   overwritten,
5. creates the local database in `data\`,
6. runs a health check.

Missed Trivy or Gitleaks in step 2? Run it with `-InstallScanners` and it offers to install them (it asks first):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -InstallScanners
```
`-ExecutionPolicy Bypass` only applies to this one command; it does not change your PC's settings.

### Step 5 — Download the vulnerability database
Trivy needs its list of known vulnerabilities (about 80 MB, needs internet):
```powershell
.\.venv\Scripts\python.exe run_scan.py update-databases
```
Then check that everything is ready:
```powershell
.\.venv\Scripts\python.exe run_scan.py health
```
`git`, `trivy`, `gitleaks`, `bandit` and `dast` should all say **OK**. Refresh the database now and then (for example
weekly) with the same `update-databases` command.

### Step 6 — Start the dashboard
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
```
Open **http://127.0.0.1:8501** in your browser. The dashboard only listens on this computer (127.0.0.1); other PCs
on the network cannot open it. Keep the PowerShell window open while you use it, and press **Ctrl+C** there to stop
it. Port 8501 busy? Use another one: `.\scripts\start.ps1 -Port 8510`.

### Step 7 — Run your first scan
1. Paste the path of a project folder into **Project folder or website address** (for example `D:\Projects\my-app`),
   or click **Browse…** to pick it.
2. Click **Scan**. Progress is shown live; it takes a few minutes depending on the project size. You can refresh or
   click around — the scan keeps running.
3. When it finishes, the PDF report is shown in the page. Use **Download PDF** or **Open in new tab**.
   A folder containing several Git repositories gives one report per repository.

Reports are saved in `reports\vapt\` and listed under **Earlier reports** in the dashboard.
The same scan from the command line:
```powershell
.\.venv\Scripts\python.exe run_scan.py vapt "D:\Projects\my-app"
```

### Step 8 (optional) — Settings in `config.yaml`
The folder scan works without changing anything. Open `config.yaml` in any text editor for extras (every option is
explained in `config.example.yaml`):

* **Logo on every PDF page:**
  ```yaml
  report:
    logo_path: data/branding/logo.svg     # .svg, .png or .jpg
    organisation: ''                      # optional name next to the logo
  ```
  Put the logo file in `data\branding\` (git-ignored, so it never goes to GitHub).
* **Test a project's running web app** (optionally signed in with a test account): `dast.targets`.
* **Test a live website you are authorised to test:** add its exact host name, then paste its `https://…` address in
  the dashboard — or link it to a project under `dast.targets` so the code and the site are in one report:
  ```yaml
  dast:
    allowed_hosts:
    - staging.example.com
  ```
* **Offline mode** (no internet during scans): `scan.offline: true`.

Restart the dashboard after editing `config.yaml`.

### Every day after that
```powershell
cd C:\Tools\LocalSecurityScanner
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
```

### Updating to a newer version
```powershell
cd C:\Tools\LocalSecurityScanner
git pull
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```
Then restart the dashboard. Your `config.yaml`, database and reports are kept; database changes are applied
automatically.

### If something goes wrong
| Problem | Fix |
|---|---|
| `python`, `git`, `trivy` or `gitleaks` is *not recognised* | Close and reopen PowerShell (new programs are only found in new windows). Still missing: install it again (step 2); for Python, tick "Add python.exe to PATH". |
| `install.ps1` says Python 3.12+ is required | Install a newer Python (step 2), reopen PowerShell and run step 4 again. |
| *running scripts is disabled on this system* | Type the commands exactly as shown, starting with `powershell -ExecutionPolicy Bypass -File …`. |
| `health` shows Trivy **Blocked by Windows**, or `DLL load failed … Application Control` | Windows Smart App Control or a company policy blocked a program. The PC's owner or IT must allow it ([docs/SECURITY.md](docs/SECURITY.md), [docs/INSTALLATION.md](docs/INSTALLATION.md)). Blocked scans are reported as *did not finish*, never as clean. |
| Vulnerability database **Missing** | Run step 5 while online, or turn off `scan.offline`. |
| Gitleaks *dubious ownership* | If you trust the repository: `git config --global --add safe.directory "<repo path>"`. |
| *Another scan is running* | Wait for it to finish (one scan at a time). |
| PDF not created | Make sure Microsoft Edge (or Chrome) is installed. The HTML report is still saved in `reports\vapt\`. |
| Port 8501 already in use | `.\scripts\start.ps1 -Port 8510` |

Logs are in `logs\` (`scanner.log`). Your `config.yaml`, database, reports and logs are git-ignored and left out of
the zip, so sharing the code never shares your results. More: [docs/SHARING.md](docs/SHARING.md).

### Uninstall
```powershell
cd C:\Tools\LocalSecurityScanner
.\.venv\Scripts\python.exe run_scan.py unschedule --frequency all   # only if you set up scheduled scans
cd ..
Remove-Item -Recurse -Force C:\Tools\LocalSecurityScanner           # deletes the app, its settings and all reports
winget uninstall --id AquaSecurity.Trivy -e                         # optional
winget uninstall --id Gitleaks.Gitleaks -e                          # optional
```

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
| Dashboard | One page: paste a folder (or Browse…) or an allowed website address, Scan with live progress, PDF report shown in the page with Download / Open in new tab, earlier reports. See [docs/UI_GUIDE.md](docs/UI_GUIDE.md) |
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
Step by step: [Installation](#installation-step-by-step-from-a-fresh-windows-laptop) above. Smart App Control notes and
manual steps: [docs/INSTALLATION.md](docs/INSTALLATION.md).

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
All values are validated (Pydantic); invalid configs are rejected with a clear message. Use `--config` or `LSS_CONFIG` for alternative configs.
For production, point `paths.*` outside any scanned root (e.g. `%LOCALAPPDATA%\LocalSecurityScanner\data`);
the app's own data/report/log directories are always excluded from discovery and from Trivy.

## 10. Repository discovery
```powershell
.\.venv\Scripts\python.exe run_scan.py discover
```

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
Raw: `reports/<Repo>_<id>/*.json`. VAPT reports: `reports/vapt/`. Exports: `reports/exports/` via `run_scan.py report`.
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
