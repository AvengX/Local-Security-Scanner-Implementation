# Dashboard guide (v1.1)

Start the dashboard with `.\scripts\start.ps1` and open http://127.0.0.1:8501. It runs only on this PC.
Every number on every page is read from the local SQLite database. There is no sample or placeholder data.

## Layout
* **Sidebar:** logo, navigation grouped as *Monitor* / *Operate* / *System*, and a **System health** panel
  (Trivy, Gitleaks, Bandit, web scan addresses, vulnerability DB, SQLite database, app version, online/offline mode). Health checks run at
  most once a minute.
  * Green = operational.
  * Amber = warning (for example, a stale DB).
  * Red = missing, error or **Blocked by Windows**.
  * A scanner that cannot run is never shown green.
  * Active scans are listed under the panel.
* **Top bar (every page):** page title and description, last successful scan, scanner status, vulnerability DB
  status, active-job count and **Refresh**, which re-reads the database and re-checks tools.
  * The Overview also has a global search box that opens Security Findings filtered by your text.

## Pages
| Page | What it shows | Actions |
|---|---|---|
| Overview | **Posture:** a level based on the highest open severity, with an explanation. Metrics: repositories, scanned, critical, high, secrets, code issues, web app issues, misconfigurations, failed scans. **Problems by project:** plain table (vulnerable libraries, leaked secrets, code issues, web app issues, unsafe settings, most serious, total) — charts were removed so every number reads as text. The misconfigurations metric and the unsafe-settings column are hidden while the Misconfigurations page is hidden. Also latest scan activity, scanner and DB health, and recommended actions derived from open findings. | Global search, update vulnerability DB (when missing or stale), open scan history |
| Security Findings | **Every finding.** Filters: text, CVE/rule, package, repository, severity, status, category, scanner, first-seen date range. Severity counters. Table and CSV export. **Selecting a row** shows details: description as plain text, package and versions, fix version, reference link (http/https only), remediation, and finding history (every scan that saw, resolved or could not verify it). | Export CSV |
| Vulnerabilities | Same view limited to dependency CVEs: package, installed version, fixed-in version. **What was checked:** each dependency file with how many libraries could be checked (exact versions only) and why others were skipped; an empty page says “No libraries could be checked” / “Only some libraries could be checked” instead of claiming clean. | Export CSV |
| Secrets | Rule, file:line, *found in* (working tree vs Git history), commit, first/last detected, status. **Values are never stored, so they can never be shown.** | Export CSV |
| Code issues | **SAST.** Risky patterns in the projects' own code (never run): Python by Bandit; JavaScript/TypeScript, HTML templates, PHP, Java, Go and C# by the built-in check. Check ID, severity, confidence, title, file:line, repository, first seen, status. Details: **In plain words** box, check name, language and CWE. **What was checked:** Python files and files per other language per project; an empty page says “Nothing to check”, “Code not scanned yet” or “No code issues found”. | Export CSV |
| Web app issues | **DAST.** Problems found by testing running local apps through their address: check ID, severity, title, page / parameter, app address, repository, first seen, status. Details: **In plain words** box, evidence and CWE. **What was tested:** per address — signed in (yes / no / no login set), last tested, result (issues / app was not running), pages and requests. With no address configured the page explains how to add one (Settings → Web scan). | Export CSV |
| Misconfigurations | Check ID, title, file, resource, repository. Description and remediation appear in the details. **Configuration files checked** per project; **Hidden from the sidebar** while no monitored project has a Dockerfile / compose / Kubernetes / Helm / Terraform file and there is no open misconfiguration; it reappears automatically (scans keep checking). | Export CSV |
| Repositories | **Status counters.** A searchable table with state (Running / Queued / Clean / Findings / Failed / Timed out / Not scanned), branch, last commit, last scan, duration and counts. **Details:** recent scans with errors. | Discover; scan all (offline toggle); scan one repository; jump to its findings or history. Scan buttons are disabled while a scan is running or was just queued, which prevents repeated requests. |
| Scan History | **Run metrics:** success rate, failures, average duration. **All runs:** table with exit code and error. **Comparison:** coverage-aware comparison of two scans of the *same* repository. | Filters, comparison |
| Reports | Scope (combined or one repository). **Management summary**: plain-language HTML for managers (risk level, per-project table, top-10 actions, what was tested, 30-day progress). Exports generated now: CSV, JSON, Markdown, HTML. Detailed audit report for one repository (14 sections incl. code and web app issues, print-ready HTML; Print → Save as PDF). Saved export files. Raw Trivy/Gitleaks/Bandit/code-scan/DAST reports with date, status and size. Only files registered in the database *and* inside `reports/` can be downloaded. | Download, save all formats, generate audit report |
| VAPT Lab | **Lab status.** Scenario table (planted weaknesses per lab repository). Checks by phase. Expected vs actual for all 104 checks, and run history. Only the generated lab is scanned, never `external_targets` or your repositories. | Run VAPT test (background, about 1–2 min) |
| Help & glossary | Five steps to get started, severity → how soon to fix, statuses, what each page shows, what is and is not checked, searchable glossary (~50 terms). | Show the welcome tour again |
| Settings | **Browse for a folder…** opens the Windows folder picker and adds the chosen folder to the repository roots. **Configuration**, in sections: roots, exclusions, scanning, scanners, storage, preferences. **Scanners & vulnerability DB:** health, DB location and freshness, update. **Database & backups:** integrity, size, row counts, backup now. **Scheduling:** health of the scheduled scan; registered scans with schedule, next/last run, last result, *Run now* and *Remove* (confirm checkbox); create or replace a daily/weekly scan (time, day, exact PowerShell preview, confirmation checkbox). The chosen time/day are saved as defaults. | Validate and save (backs up `config.yaml` first), reset to defaults (confirmation checkbox, backup first), re-check tools, update DB, back up database |

## States
Every empty, warning and error state uses the same notice design, and each one offers a real next step:
* **No repository folders configured:** an explanation, an example `repository_roots`, and a button to Settings.
* **Configured folders not found:** lists the missing paths.
* **Discovery found no repositories:** suggests checking depth and exclusions. *Not discovered yet* offers **Discover repositories**.
* **Vulnerability database missing or stale:** the expected location, internet requirement, offline limitations, and an update button (disabled if Trivy cannot run).
* **Scanner blocked by Windows:** names the Smart App Control / Application Control restriction and the binary path, and lists only safe verification steps.
* **Failed scans:** the scanner, error and exit code in Repositories and Scan History. Other scanners' results and existing findings are kept, and affected findings become UNVERIFIED.
* **Clean vs no data:** "No findings found" (green) appears only when successful scans exist. Otherwise the page says there is no scan data yet and that this does not mean the code is clean.

## Design system
Defined in `dashboard/theme.py` and `.streamlit/config.toml`.

| Token | Value |
|---|---|
| Background / secondary / card / elevated | `#080D18` / `#101827` / `#141F30` / `#19263A` |
| Accent / secondary accent | `#38BDF8` / `#8B5CF6` |
| Success / warning / critical | `#22C55E` / `#F59E0B` / `#EF4444` |
| Text / muted | `#F8FAFC` / `#94A3B8` |
| Severity | Critical ◆ `#EF4444`, High ▲ `#F97316`, Medium ● `#EAB308`, Low ▼ `#60A5FA`, Unknown ○ |

* **Fonts:** local system fonts (Segoe UI Variable, Cascadia Code). Nothing is downloaded.
* **Accessibility:**
  * Severity always pairs a shape and a word with its colour.
  * Visible focus rings.
  * Notices use `role="alert"` or `role="status"`.
  * Metric cards carry an `aria-label`.
  * Text contrast on cards is ≥ 7:1 for primary text.
* **Motion:** short hover and press transitions and a pulse on running states, all disabled under `prefers-reduced-motion`.
* **Responsive:**
  * Metric cards use an auto-fit grid.
  * Filter rows and the top bar wrap on narrow windows.
  * Verified without horizontal scrolling at 1920×1080, 1600×900, 1366×768, 1024×768 and 800×600.

## Troubleshooting
| Symptom | Fix |
|---|---|
| Sidebar shows Trivy **Blocked by Windows** | See docs/SECURITY.md → "Scanner binaries and Smart App Control". Scans are reported as FAILED until the owner allows the binary. |
| Vulnerability DB **Missing** | Settings → Scanners & vulnerability DB → Update (needs internet), or `python run_scan.py update-databases`. |
| A scan seems stuck | The Repositories page lists running jobs with elapsed time. Rows of crashed processes are recovered automatically and marked CANCELLED. Large dependency folders are skipped by default (`scan.skip_dirs`). |
| Opening `/overview` shows "Page not found" | The Overview is the root page: use http://127.0.0.1:8501/. |
| Port 8501 busy | `.\scripts\start.ps1 -Port 8510` |

## Explanations for non-specialists
* **First-run tour:** a five-step dialog the first time the dashboard opens (skip or finish stores `tour_done`).
* **In plain words** (every finding's details): what was found (with page/parameter or file/line), why it matters,
  how an attacker could use it, numbered fix steps, how soon (by severity), a note when the scanner is unsure, and
  glossary words to look up. Technical scanner text sits in a collapsed *Technical details* section.
* **Settings → Web scan (DAST):** optional columns *Login page*, *Test user*, *Password variable* (environment
  variable name; the password itself is never entered or stored). **Also check JavaScript/TypeScript, HTML
  templates, PHP, Java, Go and C#** toggles the built-in code scan for other languages.

## Triage (your decision)
* Every open finding's details have **Your decision**: *False positive*, *Accepted risk* or *Archived*, a required
  reason, and a review date (required for an accepted risk, at most one year; optional for the others). Decided
  findings show a **Reopen** button with an optional note, and a decision-history table (set, reopened, expired).
* Tables gain a **Decision** column. The **Status** filter gains **Decided**: *Open* / *Unverified* show only
  undecided findings; *Decided* shows the decided ones.
* Findings pages show **Archive N** when old findings sit inside folders that scans now skip (e.g. `.venv`).
* Expired accepted risks come back automatically (checked when the dashboard opens and after every scan batch).

## Installed versions and auto-start
* **Vulnerabilities → What was checked** has an *Installed versions checked* table: project, environment (`.venv`,
  `landing-page/venv`, `web/node_modules`), result and how many packages were read (and how many were skipped
  because `requirements.txt` already pins them).
* **Settings → Scanners:** *Also check installed library versions*. **Settings → Web scan (DAST):** *Start command*
  and *Start folder* columns. **Web app issues → What was tested:** *Starts automatically* column; *App was not
  running* suggests adding a start command.

## Alerts and secret guard
* **Overview:** unread alerts at the top (time, what was new per project, most serious item) with *Mark as read*.
* **Settings → Alerts:** enable, minimum severity, Windows notification, optional https webhook.
* **Repositories → project details → Secret guard:** state (On / Off / another hook exists / custom hooks folder /
  not Git) with *Install* or *Remove*.

## API testing
* **Settings → Web scan (DAST):** *OpenAPI file* (file or app path) and *POST allowed* (comma-separated API paths).
* **Web app issues → What was tested:** *API endpoints* column (tested / POST not allowed / no OpenAPI file). API
  findings show the method and the parameter (`name` for a query parameter, `body.field` for a JSON field).

## Trends
* Project and period filters; *Trends need a little history* while scans cover less than a week.
* Charts are static Altair charts (no wheel-zoom, so the page scrolls over them) with hover tooltips; each has a
  table underneath. Sections: open issues over time (by severity), new vs fixed per week, time to fix, open issues
  by type, projects now vs 30 days ago.
