# Dashboard guide (v1.1)

Start the dashboard with `.\scripts\start.ps1` and open http://127.0.0.1:8501. It runs only on this PC.
Every number on every page is read from the local SQLite database. There is no sample or placeholder data.

## Layout
* **Sidebar:** logo, navigation grouped as *Monitor* / *Operate* / *System*, and a **System health** panel
  (Trivy, Gitleaks, vulnerability DB, SQLite database, app version, online/offline mode). Health checks run at
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
| Overview | **Posture:** a level based on the highest open severity, with an explanation. Seven metrics: repositories, scanned, critical, high, secrets, misconfigurations, failed scans. **Problems by project:** plain table (vulnerable libraries, leaked secrets, unsafe settings, most serious, total) — charts were removed so every number reads as text. Also latest scan activity, scanner and DB health, and recommended actions derived from open findings. | Global search, update vulnerability DB (when missing or stale), open scan history |
| Security Findings | **Every finding.** Filters: text, CVE/rule, package, repository, severity, status, category, scanner, first-seen date range. Severity counters. Table and CSV export. **Selecting a row** shows details: description as plain text, package and versions, fix version, reference link (http/https only), remediation, and finding history (every scan that saw, resolved or could not verify it). | Export CSV |
| Vulnerabilities | Same view limited to dependency CVEs: package, installed version, fixed-in version. **What was checked:** each dependency file with how many libraries could be checked (exact versions only) and why others were skipped; an empty page says “No libraries could be checked” / “Only some libraries could be checked” instead of claiming clean. | Export CSV |
| Secrets | Rule, file:line, *found in* (working tree vs Git history), commit, first/last detected, status. **Values are never stored, so they can never be shown.** | Export CSV |
| Misconfigurations | Check ID, title, file, resource, repository. Description and remediation appear in the details. **Configuration files checked** per project; “Nothing to check” when no Dockerfile / compose / Kubernetes / Helm / Terraform files exist. | Export CSV |
| Repositories | **Status counters.** A searchable table with state (Running / Queued / Clean / Findings / Failed / Timed out / Not scanned), branch, last commit, last scan, duration and counts. **Details:** recent scans with errors. | Discover; scan all (offline toggle); scan one repository; jump to its findings or history. Scan buttons are disabled while a scan is running or was just queued, which prevents repeated requests. |
| Scan History | **Run metrics:** success rate, failures, average duration. **All runs:** table with exit code and error. **Comparison:** coverage-aware comparison of two scans of the *same* repository. | Filters, comparison |
| Reports | Scope (combined or one repository). Exports generated now: CSV, JSON, Markdown, HTML. Detailed audit report for one repository (12 sections, print-ready HTML; Print → Save as PDF). Saved export files. Raw Trivy/Gitleaks reports with date, status and size. Only files registered in the database *and* inside `reports/` can be downloaded. | Download, save all formats, generate audit report |
| VAPT Lab | **Lab status.** Scenario table (planted weaknesses per lab repository). Checks by phase. Expected vs actual for all 45 checks, and run history. Only the generated lab is scanned, never `external_targets` or your repositories. | Run VAPT test (background, about 1–2 min) |
| Settings | **Browse for a folder…** opens the Windows folder picker and adds the chosen folder to the repository roots. **Configuration**, in sections: roots, exclusions, scanning, scanners, storage, preferences. **Scanners & vulnerability DB:** health, DB location and freshness, update. **Database & backups:** integrity, size, row counts, backup now. **Scheduling:** instructions, dry-run preview of the exact PowerShell command, registered tasks. | Validate and save (backs up `config.yaml` first), reset to defaults (confirmation checkbox, backup first), re-check tools, update DB, back up database |

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
