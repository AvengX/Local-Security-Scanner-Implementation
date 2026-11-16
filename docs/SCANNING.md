# Scanning

## Commands
| Command | Purpose |
|---|---|
| `python run_scan.py discover` | Walk `repository_roots`, upsert repositories, detect moved/deleted ones |
| `python run_scan.py scan-all [--offline\|--online] [--json] [--no-discover]` | Discover, then scan every active repository |
| `python run_scan.py scan-repo --name Phoenix` / `--path D:\Projects\Phoenix` | Scan one repository (must be under a configured root) |
| `python run_scan.py status` | Posture summary + per-repository table |
| `python run_scan.py report [--repository X] [--format md,html,json,csv]` | Write exports to `reports/exports` |
| `python run_scan.py update-databases [--force]` | Download/refresh Trivy vulnerability + Java DBs |
| `python run_scan.py health` | Tool availability, versions, DB freshness |
| `python run_scan.py schedule --frequency daily\|weekly [--time HH:MM] [--day SUN] [--dry-run] [--yes]` | Register a Task Scheduler job (asks first) |
| `python run_scan.py unschedule [--frequency daily\|weekly\|all] [--yes]` | Remove scheduled jobs |
| `python run_scan.py prune [--days N]` | Apply history retention |
| `python run_scan.py init` | Create config (if missing) and database |

Global option: `--config PATH` (or env `LSS_CONFIG`).
Exit codes: `0` OK · `1` at least one scanner run FAILED/TIMED_OUT/CANCELLED · `2` usage/config error · `3` another scan-all job is running.

## What runs per repository
Planned from `config.yaml`:

| Scanner | scan_type | Command (simplified) | Categories |
|---|---|---|---|
| Trivy | `fs` | `trivy fs --scanners vuln,misconfig,secret --format json --output R --severity … --timeout Ns --exit-code 0 PATH` | VULNERABILITY, MISCONFIGURATION, SECRET (+LICENSE if `license` scanner enabled) |
| Trivy | `config` | `trivy config --format json --output R PATH` | MISCONFIGURATION |
| Trivy | `image` | `trivy image --scanners … --format json --output R IMAGE` (per `trivy.images`) | as configured |
| Trivy | `sbom` | `trivy fs --format cyclonedx --output R.cdx.json PATH` (if `generate_sbom`) | – (no findings) |
| Gitleaks | `git` | `gitleaks git PATH --report-format json --report-path R --exit-code 2 --redact --no-banner` | SECRET (commit history) |
| Gitleaks | `dir` | `gitleaks dir PATH …same flags…` | SECRET (working tree incl. untracked) |

Optional flags (`--quiet`, `--no-progress`, `--skip-version-check`, offline flags, …) are only added when the
installed tool's `--help` lists them. Gitleaks syntax above was verified against 8.30.1.

## Folders skipped inside repositories
`scan.skip_dirs` (default `.venv, venv, node_modules, __pycache__, .tox, .mypy_cache, .pytest_cache,
.ruff_cache`) lists folder names that Trivy and Gitleaks do not look inside, at any depth. Installed
dependencies can hold tens of thousands of third-party files: one test repository with a 1.4 GB `.venv`
took 14 minutes to scan without the skip and 9 seconds with it. Dependencies are still assessed from
manifests and lockfiles. Set `skip_dirs: []` (or clear it on the Settings page) to scan everything.

How it is applied:
* Trivy: `--skip-dirs name --skip-dirs **/name`, with Trivy started from inside the repository
  (Trivy 0.76 on Windows resolves skip patterns against its working directory).
* Gitleaks: a temporary config that extends your `gitleaks.config_path`, else the repository's own
  `.gitleaks.toml`, else the Gitleaks defaults, and adds a path allowlist. It is deleted after the scan.
* Comparison: the skip list is recorded in each run's coverage. Findings inside a skipped folder are
  never marked RESOLVED; open ones become UNVERIFIED.

## Status values
`PENDING`, `RUNNING`, `COMPLETED` (no findings), `COMPLETED_WITH_FINDINGS`, `FAILED` (tool missing/blocked,
non-zero exit, invalid/missing report), `TIMED_OUT`, `CANCELLED` (Ctrl+C or killed process), `SKIPPED`
(repository locked by another scan, outside configured roots, or path gone).

## Comparison rules
* **NEW** – first time seen (or seen again after being RESOLVED).
* **EXISTING** – seen again by a comparable successful scan.
* **RESOLVED** – absent from a *successful* scan whose coverage includes the finding's scanner, scan type,
  target, category and severity.
* **UNVERIFIED** – a later scan failed, or a successful scan did not cover it (e.g. severity filter or
  scanner list changed). Never silently cleared.

## Concurrency, locking, timeouts
* `scan.concurrency` (default 1) repositories run in parallel; scanners within a repository run sequentially.
* A per-repository lock prevents two processes scanning the same repository; a job lock prevents two
  overlapping `scan-all` runs (e.g. scheduled + manual).
* Each scanner gets `scan.timeout_seconds` (Trivy also receives `--timeout`). Timed-out processes are killed.

## Scheduling
```powershell
python run_scan.py schedule --frequency daily --time 02:00          # shows what will be registered, asks y/N
python run_scan.py schedule --frequency weekly --day SUN --time 03:00
schtasks /Query /TN \LocalSecurityScanner\DailyScan /V /FO LIST       # inspect
python run_scan.py unschedule                                        # remove (asks)
```
Tasks are registered with PowerShell's `Register-ScheduledTask` (no 261-character command limit, so long
install paths work) and run `"<project>\.venv\Scripts\python.exe" "<project>\run_scan.py" scan-all --scheduled`
as the current user with limited privileges. `-MultipleInstances IgnoreNew` plus the app's job lock prevent
overlapping runs, and `-StartWhenAvailable` catches up after the PC was off. Results go to
`logs/scanner.log` and one line per run to `logs/scheduled_runs.log`. The dashboard does not need to be open.
`scripts/schedule_scans.ps1` wraps the same commands (`-Frequency`, `-List`, `-Remove`).

## Reports on disk
`reports/<Repo>_<id>/<UTC timestamp>_<scanner>_<type>_run<id>.json` (raw) and `reports/exports/*` (exports).
