# Security model

## Local-first guarantees
* No code path uploads repositories, reports, findings, logs or the database. There are no HTTP clients in
  the application code.
* The only network activity comes from the scanners themselves: Trivy downloading its vulnerability/Java DB
  and check bundle (disabled in offline mode). Gitleaks makes no network calls.
* Streamlit is bound to `127.0.0.1` (`.streamlit/config.toml`, `start.ps1` flags) and its usage statistics
  are disabled. `dashboard.host` only accepts loopback addresses — `0.0.0.0` or LAN IPs fail validation.

## Safeguards implemented
| # | Safeguard | Where |
|---|---|---|
| 1 | No `shell=True`; argument lists only | `engine/runner.py`, `scanner_health.run_tool`, scheduling |
| 2 | Path validation / configured roots only | `ScanOrchestrator.is_path_allowed`, `validators.validate_root` |
| 3 | Reports kept in `reports_dir`; downloads must resolve inside it | `utils/security.safe_report_path`, `services/report_service` |
| 4 | Secrets redacted in logs and stderr excerpts | `utils/security.redact`, `utils/logger.RedactingFilter` |
| 5 | Raw secrets never in SQLite | parser drops secret fields; Gitleaks runs with `--redact` |
| 6 | Dashboard localhost only | config validation + Streamlit flags |
| 7 | Path traversal blocked | `safe_report_path` (tests: `test_report_path_traversal_blocked`) |
| 8 | Transactions | `database/db.transaction` (`BEGIN IMMEDIATE`) |
| 9 | Timeouts and cancellation | `engine/runner.py` |
| 10 | Missing/blocked tools reported, never treated as clean | `scanner_health`, scanners' preflight |
| 11 | CSV formula injection neutralised | `export_service.findings_csv_bytes` |
| 12 | Image references validated before use | `utils/security.is_safe_image_ref` |
| 13 | Git `core.fsmonitor` disabled for metadata reads | `repository_discovery.git_metadata` |
| 14 | All scanner-derived text HTML-escaped before rendering; descriptions shown as plain text (no Markdown, so no remote images); only `http(s)` reference links | `dashboard/theme.py` (`esc`, `safe_url`), `findings_view._detail` (test: `test_scanner_text_is_escaped_and_unsafe_links_dropped`) |
| 15 | No remote fonts, icons or scripts; logo and icons are local SVG | `dashboard/assets`, `.streamlit/config.toml` |
| 16 | `config.yaml` backed up to `data/config_backups/` before every dashboard save or reset | `dashboard/settings.backup_config` |

## Scanner binaries and Smart App Control
The winget builds of Trivy 0.76.2 and Gitleaks 8.30.1 are **not Authenticode-signed** (`Get-AuthenticodeSignature`
reports `NotSigned`); Aqua Security signs release archives with cosign and publishes SHA-256 checksums instead.
Smart App Control may therefore block them. The dashboard shows such a tool as **Blocked by Windows** (red) and
its scans as FAILED. Safe verification: compare the downloaded archive's SHA-256 with the release's
`checksums.txt`, or reinstall through winget (which verifies the manifest hash). Only the PC owner should decide to
allow the binary; the application never changes Windows security settings.

## Read-only with respect to repositories
The application never deletes or edits files in scanned repositories, never upgrades packages, never rewrites
Git history, never rotates keys and never changes repository configuration. Remediation text is advisory.
`safe.directory` errors are reported with the command the user may choose to run — the scanner does not
weaken Git's ownership checks itself.

## Raw report sensitivity
* Gitleaks reports are written with `--redact` (secret values replaced by `REDACTED`).
* The web scan (DAST) contacts loopback addresses only (validated in config and before every request, no proxy,
  no off-site redirects), sends GET requests only (plus one TRACE probe), never submits POST forms, skips links
  such as logout/delete, and never stores response bodies — an exposed `.env` is recorded by path and size only.
* Bandit reports are rewritten after parsing without code snippets, and hardcoded-password messages are
  replaced by a fixed text; a failed, timed-out or cancelled Bandit run leaves no report behind.
* Trivy masks secret matches with asterisks in its JSON, but surrounding code lines are included. Treat
  `reports/` as sensitive: keep it on an encrypted disk or restrict its ACL if the machine is shared, e.g.
  `icacls reports /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"` (manual step; the app does not change ACLs).

## Known limitations
* Detection quality is bounded by Trivy/Gitleaks/Bandit rules and the freshness of Trivy's DB.
* SAST covers Python only and finds known risky patterns; it cannot find logic flaws (for example missing
  authorisation checks). Lines marked `# nosec` are not reported. There is no penetration testing of
  running applications beyond the built-in web scan, which does not log in, sends GET requests only and is not
  a substitute for a manual penetration test.
* Windows Smart App Control / WDAC can block unsigned scanner binaries or Python extension DLLs; the app
  detects and reports this but does not bypass it.
* A user with access to the Windows account can read the database and reports; there is no app-level
  authentication because the dashboard is loopback-only.
