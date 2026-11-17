# Audit report — Local Security Scanner (2026-11-17)

Baseline before changes: **115 tests passed, 0 failed, 0 skipped** (`pytest`, 4 m 53 s), VAPT acceptance
test **45/45**, `health` shows git 2.55, Trivy 0.76.2 and Gitleaks 8.30.1 all OK, Trivy DB 21 h old.
`repository_roots` holds two real repositories; both were scanned successfully today (6 runs, 0 failures).

The full flow was traced: dashboard button → `launch_background` → `run_scan.py` → `ScanOrchestrator` →
`trivy_scanner` / `gitleaks_scanner` → `runner.run_process` (argument lists, no shell) → `report_parser` →
`finding_normalizer` → `comparison_engine` → SQLite → `analytics_service` → dashboard pages.

## Environment
| Item | Result |
|---|---|
| Trivy binary | winget package `AquaSecurity.Trivy` 0.76.2. **Authenticode: NotSigned** (SHA-256 `DD07ADF8…B24E617`). Aqua publishes cosign signatures and checksums for release archives, not Authenticode signatures, which is why Smart App Control blocked it until the owner allowed it. It now runs. Smart App Control was not changed. |
| Gitleaks binary | winget package, NotSigned, runs. |
| Trivy DB | present, 21 h old, freshness threshold 72 h. |

## Findings and status

Severity is for this local, loopback-only application.

### Security
| # | Issue | Severity | Status |
|---|---|---|---|
| S1 | Findings detail injected scanner-provided `remediation` text into HTML with `unsafe_allow_html` without escaping (HTML injection from a crafted Trivy check in a scanned repo). | Medium | Fixed: all scanner text is escaped. |
| S2 | Finding descriptions were rendered as Markdown, so an image link in scanner text would make the browser fetch a remote URL (breaks local-first). | Medium | Fixed: descriptions shown as plain text. |
| S3 | `reference_url` rendered as a link without a scheme check (`javascript:` possible). | Low | Fixed: only `http(s)` links are shown. |
| S4 | Settings page rewrote `config.yaml` without a backup. | Low | Fixed: timestamped backup in `data/config_backups/` before every save and reset. |
| — | `shell=True`: not used anywhere. Subprocesses use argument lists and validated arguments. Report downloads are limited to DB-registered files inside `reports_dir`. CSV formula injection is neutralised. The dashboard is bound to 127.0.0.1 with XSRF protection. Gitleaks runs with `--redact`, and no secret value is stored. | — | Verified (existing tests and review) |

### Functional
| # | Issue | Status |
|---|---|---|
| F1 | No reset-to-defaults or configuration backup in Settings. | Fixed (reset needs a confirmation checkbox, and a backup is taken first). |
| F2 | "Scan this repository" stayed clickable while that repository was already scanning; the orchestrator lock SKIPPED the duplicate, but the UI allowed repeated requests. | Fixed: disabled while a scan is running or was just queued. |
| F3 | The repository table counted raw finding rows, while the overview counted distinct findings, so the numbers disagreed. | Fixed: both count distinct findings. |
| F4 | The overview's "unverified" count included deactivated repositories. | Fixed. |
| F5 | No application version, and no tool or database health outside the Settings page. | Fixed: version in `utils/version.py`; sidebar health panel. |
| F6 | Tool health spawned three subprocesses on every Settings rerun. | Fixed: cached for 60 s, with a "re-check" button. |
| F7 | The VAPT result was overwritten on each run, with no history and no dashboard view. | Fixed: `vapt_lab/history.jsonl` and a VAPT Lab page. |
| F8 | No index on `finding_changes(finding_id)`, so cascading deletes and per-finding history scanned the whole table. | Fixed (`IF NOT EXISTS`, applied on start). |
| F9 | No per-finding history view and no date-range filter. | Fixed. |
| F10 | No dedicated Vulnerabilities, Secrets or Misconfigurations views. | Added. |
| F11 | Empty states did not separate "no roots configured", "roots configured but nothing discovered" and "missing roots"; the missing-DB banner offered no action. | Fixed: guided empty states with actions. |
| F12 | Default Streamlit look. | Redesigned (see docs/UI_GUIDE.md). |

### Checked and found correct
* **Discovery:** multiple roots, nested repositories, worktrees and submodules (`.git` files), excluded dirs (node_modules, .venv, venv, dist, build, reports, logs and more), the app's own data dirs, junctions not followed, inaccessible folders, missing roots, duplicate roots, and moves and deletions. Covered by 12 discovery tests.
* **Scanners:** exit codes are enforced (Trivy `--exit-code 0`; Gitleaks 0 = clean, 2 = leaks, anything else = FAILED). A missing or blocked binary gives FAILED, never clean. Timeouts kill the process tree.
* **Comparison:** only successful, covering scans can mark findings RESOLVED. Failed or uncovered scans give UNVERIFIED. Comparisons across repositories are rejected.
* **Orchestrator:** per-repository and job locks; one failing repository does not stop the others; orphaned RUNNING rows are recovered.
* **Scheduling:** dry-run only in tests. No task was created during this audit.

## Not changed (by design)
* Smart App Control and Windows security settings.
* `config.yaml` (it is only written when you press Save, after a backup).
* Existing reports and database rows. The database was backed up before the index was added.

## Results after changes (2026-11-17)
| Check | Before | After |
|---|---|---|
| `pytest` | 115 passed, 0 failed, 0 skipped | **130 passed, 0 failed, 0 skipped** (8 more page renders, 7 new regression tests) |
| VAPT acceptance test (real Trivy and Gitleaks) | 45/45 | **45/45**, recorded in `vapt_lab/history.jsonl` |
| Real scan of the two configured repositories | 6 runs, 0 failed | unchanged (no engine changes) |
| Browser check: 10 pages × 1920×1080, 1600×900, 1366×768, 1024×768, 800×600 | — | Rendered in the built-in browser: no exceptions, no horizontal overflow. Fixed during testing: top-bar overlap, truncated metric labels, cramped filter rows, legends covering charts. |
| Interactions exercised in the browser | — | Global search → filtered Findings; repository row → detail with recent scans; secret row → detail and history (no value shown); Settings save with no changes → "No changes to save" (config untouched) |

### Implemented and verified
Everything in the S1–S4 and F1–F12 tables above. Verification was by automated tests, browser rendering or both.

### Implemented but not verified end to end
* The dashboard buttons **Run VAPT test**, **Update vulnerability database** and **Scan this repository / Scan all** were not clicked during the browser check, to avoid starting jobs.
  * They use the same detached launcher as before (`launch_process`), which existing tests cover.
  * The VAPT script itself was run from the CLI.
* **Reset to defaults** and **Back up database now** are covered by unit tests of their helpers. They were not clicked in the browser, which would have changed your `config.yaml` or created a backup.

### Not implemented
* Screenshot files are not stored in `docs/`. Pages were inspected in the in-app browser only.
* Pagination is left to Streamlit's virtualised data grid. It is adequate for the current data size (62 findings, 23 runs).

### Blocked by environment
* None at present. Trivy runs because the PC owner allowed it earlier. If Smart App Control blocks it again, the sidebar and Overview show **Blocked by Windows**, and its scans are recorded as FAILED.

### Known limitations
* Detection is limited to Trivy and Gitleaks rules and the freshness of the vulnerability DB.
* The dashboard has no authentication; it is loopback-only by design.
* Raw Trivy reports include masked code context, so keep `reports/` private.
* On the author's PC, 20 UNVERIFIED secrets inside one repository's `.venv` come from the scan made before `.venv` was skipped. They stay visible, marked Unverified, by design. They are excluded from "Recommended actions".
