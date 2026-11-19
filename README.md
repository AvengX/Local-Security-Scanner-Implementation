# Local Security Scanner

A local-first, privacy-focused security monitoring platform for Windows that discovers every Git repository
under folders you choose, scans them with **Trivy**, **Gitleaks**, **Bandit** (SAST) and a built-in **web scan** (DAST), stores results and history in
**SQLite**, and presents them in a **Streamlit** dashboard bound to `127.0.0.1`. Source code, reports, the
database and logs never leave your machine.

## How it works
```
Your project folders ──► Trivy + Gitleaks + Bandit ──► SQLite database ──► Dashboard (http://127.0.0.1:8501)
Your running local apps ──► Web scan (DAST) ──┘
        ▲                  (run_scan.py)        (data\ folder)              │
        └────────────────── buttons start scans in the background ──────────┘
```
1. You choose the folders that hold your projects (`repository_roots`).
2. **Discovery** finds every Git repository inside them.
3. **Trivy** checks dependencies for known vulnerabilities, Docker/IaC files for unsafe settings, and files for secrets.
   **Gitleaks** finds passwords and keys in current files *and* in old commits.
   **Bandit** (SAST) reads your own Python code and finds risky patterns such as SQL built from strings,
   `shell=True`, `pickle.loads` or Flask `debug=True`. It never runs the code.
   A built-in **code scan for other languages** does the same for JavaScript/TypeScript, HTML/Jinja templates, PHP,
   Java, Go and C# (`eval`, `innerHTML`, SQL built from strings, TLS checks turned off, `|safe`, …).
   **Web scan (DAST)** tests your apps *while they run*, through their local address (for example
   `http://127.0.0.1:5000/`): missing security headers, unsafe cookies, exposed `.env`/`.git` files, debug consoles,
   stack traces, directory listing, open CORS, reflected XSS, SQL injection, open redirects and path traversal.
   With a **test-account login** it also tests the pages behind sign-in.
4. Results go into a local SQLite database, compared with the previous scan: new, still open, fixed, or unverified.
5. The **dashboard** reads that database and shows it. It can also start scans in the background.

Nothing is uploaded. Only Trivy downloads its vulnerability list from the internet, and offline mode turns that off.
The web scan only talks to apps on this computer (localhost / 127.0.0.1 / ::1).
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
| Reports | HTML + CSS (print-ready), CSV, JSON, Markdown | Audit report (Print → Save as PDF), exports |
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
powershell -ExecutionPolicy Bypass -File .\scripts\run_vapt_test.ps1   # should report 98/98 PASS
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
Every page answers one question. Full guide: [docs/UI_GUIDE.md](docs/UI_GUIDE.md).

| Page | Question it answers |
|---|---|
| Overview | How safe am I right now? |
| Security Findings | What exactly is wrong, everywhere? |
| Vulnerabilities | Which libraries I use have known security holes? |
| Secrets | Where did passwords or API keys end up in my code? |
| Code issues | Which lines of our own code are written in a risky way? (SAST) |
| Web app issues | What is wrong with our apps when they run? (DAST) |
| Misconfigurations | Which Docker or cloud settings are unsafe? (shown only when a project has such files) |
| Repositories | Which projects are watched, and how do I scan them? |
| Scan History | What happened every time a scan ran? |
| Reports | How do I download or share the results? |
| VAPT Lab | Does the scanner itself work? |
| Settings | How do I change what is scanned, and how? |
| Help & glossary | What do these words and statuses mean, and where do I start? |

**Made to be understood**
* **First-run tour:** the first time the dashboard opens, a five-step welcome explains what the app does and where to
  start (Help → *Show the welcome tour* shows it again).
* **In plain words:** every issue's details open with a box that says *what was found*, *why it matters*, *how an
  attacker could use it*, *how to fix it* (numbered steps) and *how soon* (critical = today, high = this week, …),
  without jargon. The scanner's technical text is still there under *Technical details*.
* **Help & glossary page:** five steps to get started, what each page and status means, severity → how soon to
  fix, what is and is not checked, and a searchable glossary of about 50 security words (CVE, XSS, CORS, …).
* **Management summary** (Reports): a one-page, plain-language report for managers — see Reports below.

**Alerts: hear about new problems without opening the dashboard**
* After every scan — also the scheduled weekly one — findings seen for the **first time**, at or above the chosen
  severity (default *High*) and not marked as false positive / accepted, become **one alert per scan**.
* It appears at the top of the **Overview** until you press *Mark as read*, can pop up as a **Windows
  notification** (built in, nothing to install), and can be sent to an **https webhook** (Teams, Slack, ntfy …).
  Alerts only contain counts, project names, check IDs, packages and file paths — never secret values or code.
* Settings → *Alerts*. Try it: `python run_scan.py test-alert`.

**Secret guard: stop secrets before they are committed**
* Repositories → click a project → *Secret guard* → **Install** (or `python run_scan.py guard install --name X`).
  It adds `.git/hooks/pre-commit`, which runs Gitleaks on the **staged changes** at every commit (about a
  second). A commit that contains a password, key or token is **blocked** with a plain explanation; the value is
  never printed.
* An existing pre-commit hook is kept and still runs first; *Remove* restores it. Projects with a custom hooks
  folder (`core.hooksPath`, e.g. Husky) are not touched — the panel shows the line to add there. If Gitleaks is
  missing or fails, the commit is allowed with a warning. `git commit --no-verify` skips it once; a test value can
  be marked with a `gitleaks:allow` comment.
* `python run_scan.py guard status` lists every project.

**On every page**
* **Sidebar → System health:** Trivy, Gitleaks, Bandit (code scan), web scan (number of app addresses),
  vulnerability DB and results database.
  Green = working, amber = needs attention (for example an old vulnerability list), red = not working (missing or blocked by Windows).
  Running scans are listed underneath.
* **Top bar:** page name, when the last scan finished, scanner status, vulnerability-list age, and **Refresh**.

**Overview**: your security summary and the place to start.
* **Search box:** type a CVE, package or file name to jump to matching findings.
* **Security posture:** one headline based on the worst open problem.
  *Critical exposure* (red) → *Elevated risk* (orange) → *Guarded* → *No open findings* (green).
* **Cards:** repositories, scanned, critical, high, exposed secrets, code issues, web app issues, misconfigurations,
  failed scans.
* **Problems by project:** a plain table — vulnerable libraries, leaked secrets and unsafe settings per project,
  with the most serious level. (No charts: every number is shown as text.)
* The misconfigurations card and the unsafe-settings column are hidden while no project has anything for them
  to check (see below).
* **Recommended actions:** a to-do list built from your results, for example "Upgrade happy-dom 20.14.6 → 21.0.4" or
  "Rotate credentials found in these files".
* **Latest scan activity** and **Scanner health** panels.

**Security Findings**: every problem in every project, in one table.
* **Filters:** project, severity, type, status, date, CVE, package or file. **Export CSV** saves the filtered list.
* **Click a row** to see what the problem is, where (file and line), how to fix it, a reference link, and its
  **history** (first found, every scan that saw it, when it was fixed).
* **Status:** *Open* = still there, *Resolved* = a later scan confirmed it is gone,
  *Unverified* = could not be re-checked, so it is kept rather than assumed fixed.
* **Your decision (triage):** in a finding's details, mark it as a **false positive** (the scanner is wrong here),
  an **accepted risk** (real, but accepted until a review date — at most a year; it comes back by itself then) or
  **archived** (no longer relevant). A reason is always required and every decision, reopen and expiry is kept in
  the finding's decision history. Decided findings leave the counts, the recommended actions and the reports'
  to-do lists, but stay visible under **Status → Decided**, in the audit report's *Decisions recorded* table and in
  the management summary's *Risks we accepted* section. A later scan never removes a decision; **Reopen** does.
* **Old findings in skipped folders:** findings inside folders that scans now skip (for example `.venv`) can never
  be re-checked. The findings pages offer **Archive N** for them in one click.

**Vulnerabilities**: only security holes in packages your projects use (from `package-lock.json`, `requirements.txt`
and similar), with the **installed** version and the **version that fixes it**.
* **Installed versions:** libraries listed without an exact version (`numpy>=1.24`, or just `streamlit`) cannot be
  matched to known flaws from the requirements file alone. When a project has its own environment (`.venv`, `venv`,
  or `node_modules` without a lockfile), the scanner reads the exact installed versions from package metadata —
  nothing is run or installed — and Trivy checks those. Packages already pinned in `requirements.txt` are skipped,
  so nothing is counted twice. These findings show *installed packages (.venv)* as their location, and the fix says
  to upgrade and then pin the version. *What was checked* lists each environment. Turn it off in Settings →
  *Also check installed library versions*.

**Secrets**: only leaked passwords, API keys and tokens.
* **Found in** shows *Working tree* (in a file now) or *Git history* (committed in the past and still readable by anyone with the repository).
* The **secret value is never stored or shown**.
* Fix: rotate the key at the provider (new key, cancel the old one), then remove it from the code.

**Code issues (SAST)**: security bugs in your own code, found without running it: Python by Bandit, and
JavaScript/TypeScript, HTML/Jinja templates, PHP, Java, Go and C# by the built-in check (check IDs such as
**JS-EVAL**, **JS-INNERHTML**, **TPL-SAFE-FILTER**, **PHP-SQL-CONCAT**). Minified files and `node_modules`/`vendor`
are skipped, and source code is never copied into the results.
* Each row gives the check ID (for example **B608** = SQL built from strings), severity, **confidence** (how sure
  Bandit is), file and line. Click a row for the plain-language fix and the CWE weakness type.
* Installed libraries (`.venv`, `node_modules`, …) are skipped, and a project's own `.bandit` file is ignored so it
  cannot hide problems. `assert` in test files is not reported (that is how tests work).
* A real false positive can be marked in the code with `# nosec B608` plus a short reason.
* *What was checked* lists Python files and files per other language for each project. The check for other
  languages can be turned off in Settings.

**Web app issues (DAST)**: problems found by testing your apps while they run.
* **Setup:** Settings → *Web scan (DAST)* → add a row: the project and the address where its app runs (for example
  `http://127.0.0.1:5000/`). Start the app, then scan the project. If the app is not running, the web scan is
  *skipped* and earlier web issues are kept as *Unverified* (never marked fixed).
* The scan visits the start page, follows same-site links (up to 30 pages / 400 requests by default), and checks:
  security headers (CSP, clickjacking, nosniff, HSTS), cookie flags, version disclosure, exposed files (`.env`,
  `.git`, database files, SQL dumps), Flask/Werkzeug debugger and Django debug pages, stack traces, directory
  listing, CORS, TRACE, and — on every URL parameter and GET form — reflected XSS, SQL errors, open redirects and
  path traversal.
* **Safe by design:** only addresses on this computer are accepted; only GET requests are sent (POST forms are never
  submitted, so no data is changed); links such as *log out* or *delete* are never followed; redirects never leave
  the app; no proxy is used; page contents are never stored (an exposed `.env` is recorded by name and size only).
* Each row shows the check ID (for example **DAST-XSS**), severity, page and parameter, and the app address. Click it
  for the evidence, the fix and the CWE weakness type.
* **Pages behind a login:** add the login page, a **test** account's user name and the *name* of an environment
  variable that holds its password (for example `LSS_MYAPP_PASSWORD`; set it with `setx LSS_MYAPP_PASSWORD "…"` and
  restart the dashboard). The scan signs in with exactly one POST to the app's own login form (CSRF tokens are
  copied automatically), then also crawls the page shown after signing in. The password is never written to the
  config, the database, the reports or the logs. A wrong password makes the web scan *fail* (nothing is marked
  fixed). *What was tested* shows whether each address was scanned signed in.
* **Start the app automatically:** add a *Start command* (and optionally a *Start folder*) to the address, for
  example `python app.py`, `venv\Scripts\python.exe app.py` with start folder `landing-page`, or
  `.venv\Scripts\streamlit.exe run app.py --server.port 8502 --server.address 127.0.0.1 --server.headless true`.
  When nothing answers at scan time the scanner starts the app (no shell, no window, in the project folder), waits
  until it answers (`start_wait`, default 60 s), scans it and stops the whole process tree again. An app that is
  already running is used as it is and never stopped. The app's output goes to `logs\apps\`. If it cannot start,
  the web scan *fails* with the reason and earlier web issues stay *Unverified*.
* Limits: JavaScript-only apps (for example Streamlit) get the header, cookie and file checks but have few links to
  follow, and it does not replace a manual penetration test.

**Misconfigurations**: unsafe settings in Dockerfiles, Kubernetes or Terraform, for example "container runs as root".
Click a row for the fix. The page only appears in the sidebar when a monitored project contains a Dockerfile,
docker-compose, Kubernetes, Helm or Terraform file, or has an open misconfiguration. Scans keep checking for
misconfigurations either way, so the page comes back by itself as soon as such a file is added.

**Repositories**: your projects, and where scans start.
* **Discover repositories:** finds Git projects in your folders.
* **Scan all repositories:** scans everything in the background. The **Offline scan** switch uses the saved vulnerability list only.
* **Table:** status (Clean, Findings, Running, Queued, Failed, Not scanned), branch, last scan, duration, problem counts.
* **Click a project** to get **Scan this repository**, shortcuts to its findings and history, and its last 10 scans with any errors.
* Scan buttons are disabled while a scan is running, and the page updates itself when it ends.

**Scan History**: a log of every scanner run.
* **Cards:** runs, success rate, failures, average time.
* **Table:** duration, findings, new and fixed counts, error message.
* **Compare two scans:** pick two scans of the same project to see what is new and what was fixed.

**Vulnerabilities / Misconfigurations when empty**: the page says *why*. It lists each dependency file and how
many libraries Trivy could actually check — libraries without an exact version (e.g. `numpy` instead of
`numpy==1.26.4`) or files Trivy doesn't read (e.g. `requirements-train.txt`) are not checked, and the page says so
instead of claiming a clean result. Misconfigurations lists the configuration files it checked.

**Reports**: downloads.
* **Management summary** (all projects or one): click **Generate summary** for a plain-language report a manager can
  read: overall risk level, a table per project, the ten things to fix first written as actions ("Update the
  library jinja2 from 2.10 to 3.1.5", "Turn debug off"), what was and was not tested, progress over the last 30 days
  and next steps. Print → Save as PDF for a PDF. CLI: `python run_scan.py summary`.
* Choose *all projects* or *one project*, then download **CSV**, **JSON**, **Markdown** or **HTML**.
* **Save all formats to disk** writes them to `reports\exports`.
* **Detailed audit report** (one project): click **Generate audit report** for a full VAPT-style report, then
  download it or open the saved file and choose **Print → Save as PDF**. It has 14 numbered sections: repository and
  scan metadata (commit, tool versions and binary SHA-256, exact commands, exit codes), an executive summary written
  from the data, deduplicated counts, severity distribution, every vulnerability with CVSS / CWE / fixed versions /
  dependency path, direct vs transitive, remediation commands, secrets (never their values), misconfigurations,
  code issues, web app issues, references, and methodology with limitations and raw-report checksums.
* The original Trivy, Gitleaks, Bandit, code-scan and web-scan output of each scan is also downloadable.

**VAPT Lab**: a self-test for the scanner.
* **Run VAPT test** builds 4 practice projects with planted problems (old libraries, fake keys, unsafe settings, insecure Python, JavaScript and template code, plus one clean project) and starts 2 practice web apps on 127.0.0.1 (one unsafe with a members area behind a login, one done right), scans them, and checks 98 expectations — including that every finding has a plain-language explanation and that triage decisions survive rescans.
* Shows the result (for example 98/98), expected versus actual for every check, and past runs.
* It never touches your real projects.

**Settings**
* **Configuration:** project folders (**Browse for a folder…** opens the Windows folder picker), folders to skip (`node_modules`, `.venv`…), scan timeout, parallel scans, offline mode, scanners on or off, storage paths.
  **Validate and save** backs up the old settings first. **Reset to defaults** asks for confirmation.
* **Scanners & vulnerability DB:** tool status and versions; **Update vulnerability database** (needs internet).
* **Database & backups:** size and health of the results database; **Back up database now**.
* **Scheduling:** set up automatic scans right here. Pick *weekly* or *daily*, the time and the day, tick *I understand
  this creates a Windows scheduled task for my user account* and press **Create scheduled scan** (the exact
  PowerShell is shown first). Registered scans are listed with their next run, last run and last result, each with
  **Run now** (to test it) and **Remove** (tick *Confirm* first). Tasks run as your user with limited rights, never
  overlap, and start as soon as the computer is on again if a run was missed. The sidebar and the Overview show a
  **Scheduled scan** health row: *Not set up*, *Weekly – next …*, *Last run failed* or *Missed runs*.

**A typical routine:** **Repositories → Scan all** → read **Overview → Recommended actions** → rotate keys
(**Secrets**) and upgrade packages (**Vulnerabilities**) → scan again. Fixed items turn *Resolved* →
download a summary from **Reports** if someone else needs it.

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
Detailed audit report for one repository (print-ready HTML; Print → Save as PDF):
```powershell
.\.venv\Scripts\python.exe run_scan.py audit --name LOAN_SYSTEM
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
98 PASS/FAIL checks (alerts, secret guard, triage decisions, installed versions, auto-start, CVEs, IaC misconfigurations, secrets incl. Git history, SAST code issues in Python and other languages, DAST web issues incl. behind a login, plain-language explanations, false positives, remediation,
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
