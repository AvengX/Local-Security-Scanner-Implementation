# Architecture

```
Repository Discovery Engine  (engine/repository_discovery.py)
            │  DiscoveredRepo[] → database.repositories.sync_discovered()
            ▼
     Scan Orchestrator        (engine/scan_orchestrator.py)
     ├─ job lock (engine/locks.py) – one scan-all job at a time
     ├─ per-repository DB lock (repo_locks table) – no duplicate concurrent scans
     ├─ bounded ThreadPoolExecutor (scan.concurrency, default 1)
     │
     ├──────────────┬─────────────────┬──────────────────┐
     ▼              ▼                 ▼                  ▼
  TrivyScanner   GitleaksScanner   BanditScanner (SAST)  (SBOM / image jobs via Trivy)
  engine/trivy_scanner.py   engine/gitleaks_scanner.py   engine/sast_scanner.py
     │  subprocess argument lists via engine/runner.py (no shell, timeouts, cancellation)
     ▼
  JSON Report Parser          (engine/report_parser.py)
     │  → NormalizedFinding (engine/finding_normalizer.py): severity, category, stable fingerprint,
     │    cross-scanner dedup_key, redacted metadata – secret values are dropped here
     ▼
  Comparison Engine           (engine/comparison_engine.py)
     │  NEW / EXISTING / RESOLVED / UNVERIFIED, coverage-aware
     ▼
  SQLite                      (database/schema.sql, database/db.py, database/repositories.py)
     ▼
  Analytics / Export services (services/analytics_service.py, export_service.py, report_service.py,
                               audit_report.py)
     ▼
  Streamlit dashboard         (app.py, dashboard/*.py) – 127.0.0.1 only
     ▼
  Local report export         (reports/exports/*.md|html|json|csv, *_security_audit.html)
```

## Key design decisions

| Concern | Decision |
|---|---|
| Engine independent of UI | All scanning lives in `engine/` + `run_scan.py`. The dashboard starts scans as detached CLI subprocesses, so closing the browser/Streamlit never kills a scan and scheduled runs need no UI. |
| Tool-version compatibility | `scanner_health.supported_flags()` parses `trivy <sub> --help` / `gitleaks <mode> --help` once per process and only passes optional flags that the installed version documents. |
| Exit codes | Trivy is run with `--exit-code 0` → any non-zero exit is an execution error. Gitleaks is run with `--exit-code 2` → 0 = clean, 2 = leaks, anything else = error. Bandit: 0 = clean, 1 = issues, anything else = error (the partial report is deleted). Findings always come from the parsed JSON report, never from the exit code alone. |
| "Never mark failed scans clean" | Statuses `FAILED`, `TIMED_OUT`, `CANCELLED`, `SKIPPED` are persisted with the error. A failed scan resolves nothing; open findings in its scope become `UNVERIFIED`. Orphaned `RUNNING` rows (killed process) become `CANCELLED` on next start. |
| Coverage | Each successful run stores a coverage key `scanner|scan_type|target|categories|severities`. A finding can only be resolved by a run whose coverage includes its scanner, scan type, target, category **and** severity. |
| Duplicates | `findings` is unique on `(repository_id, fingerprint)`. Identical entries inside one report are collapsed before insert. Trivy-secret and Gitleaks findings for the same file/line share a `dedup_key`, so overview counts use `COUNT(DISTINCT dedup_key)`. |
| Concurrency safety | Each worker thread opens its own SQLite connection (WAL mode, 30 s busy timeout); writes use `BEGIN IMMEDIATE` transactions. |
| Read-only scanning | Scanners only read repositories. Reports go to `reports_dir`. Git metadata is read with `git -c core.fsmonitor=false rev-parse`. Nothing in the code writes into a scanned repository. |

## Modules

| Module | Responsibility |
|---|---|
| `app.py` | Streamlit shell: logo, grouped navigation (Monitor / Operate / System), sidebar health panel. |
| `dashboard/theme.py` | Design system: palette, CSS, inline SVG icons, HTML components (all text escaped). See docs/UI_GUIDE.md. |
| `dashboard/common.py` | Config/DB access, cached tool health (60 s), top bar, background job launcher, queued-state tracking. |
| `dashboard/states.py` | Guided empty/warning/error states (no roots, missing roots, nothing discovered, blocked/missing scanners, missing/stale vulnerability DB). |
| `dashboard/findings_view.py` | Shared vulnerability-management view behind Findings, Vulnerabilities, Secrets and Misconfigurations. |
| `dashboard/<page>.py` | Overview, Repositories, Scan History, Reports, VAPT Lab, Settings. |
| `utils/config.py` | Pydantic models for `config.yaml`; atomic save; loopback-only dashboard host. |
| `utils/security.py` | Secret redaction for logs, safe report path resolution, image-ref validation, PID liveness (no signals). |
| `utils/logger.py` | JSON-lines rotating log (`logs/scanner.log`) with a redaction filter. |
| `engine/scanner_health.py` | Tool discovery (PATH, winget, scoop, choco), versions, Smart App Control detection, Trivy DB freshness from on-disk metadata. |
| `engine/runner.py` | `Popen` execution, timeouts, Ctrl+C cancellation, stderr excerpts. |
| `services/audit_report.py` | Detailed per-repository audit report (12 sections, print-ready HTML). Combines the findings database, the raw JSON of the latest successful `trivy fs` run (CVSS, CWE, dates, references, package graph from `--list-all-pkgs`) and read-only git metadata (`-c core.fsmonitor=false`; no `git status`). All text is HTML-escaped, links are http/https only with credentials stripped, and secret values are never available to it. |
| `services/scheduling_service.py` | `schtasks` command construction, create/delete/query. |

## SAST (Bandit)
* `engine/sast_scanner.py` runs `python -m bandit -r . -f json` inside the repository with the scanner's own
  interpreter (Bandit is pinned in requirements.txt and works offline). Bandit parses files into an AST and never
  imports or runs them.
* A generated `--ini` file is always passed, so a `.bandit` file in the repository (or in one of its dependencies)
  cannot change targets, exclusions or skipped checks. `scan.skip_dirs` become `-x` path fragments.
* Findings use category `CODE` (schema v2 migration rebuilds `findings` to allow it; rows and history are kept).
  Identity is check ID + file + a hash of the flagged line's text + an occurrence counter, so a finding keeps its
  history when code above it moves.
* Code snippets are never stored, and the saved raw report is rewritten without them. B105/B106/B107 messages
  (which contain the suspected password) are replaced by a fixed text.
* `assert` (B101) in test files is not reported. `sast.skip_tests` skips checks everywhere.
