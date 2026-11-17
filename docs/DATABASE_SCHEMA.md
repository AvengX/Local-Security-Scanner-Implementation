# Database schema

SQLite file: `<data_dir>/security_scanner.db` (default `data/security_scanner.db`). Foreign keys are enabled
on every connection; journal mode is WAL. The authoritative DDL is `database/schema.sql`; the schema version
is stored in `settings.schema_version` and migrations are applied by `database/db.py:init_db()`.

## repositories
| Column | Notes |
|---|---|
| id | PK |
| name | folder name |
| path | absolute path |
| path_key | case/separator-normalised path, UNIQUE (prevents duplicates on Windows) |
| root | configured root it was found under |
| repo_kind | `repository` (.git dir) or `worktree_or_submodule` (.git file) |
| current_branch, current_commit | from `git rev-parse` (optional) |
| discovered_at, last_seen_at | UTC ISO-8601 |
| active | 0 when deleted/moved away from a scanned root |

## scan_runs
One row per scanner invocation.
`repository_id, batch_id, scanner (trivy|gitleaks), scan_type (fs|config|image|sbom|git|dir), scan_target,
coverage, started_at, finished_at, duration, status, exit_code, tool_version, database_updated_at, offline,
report_path, error_message, findings_count, new_count, resolved_count, pid`.

`status ∈ PENDING, RUNNING, COMPLETED, COMPLETED_WITH_FINDINGS, FAILED, CANCELLED, TIMED_OUT, SKIPPED` (CHECK constraint).

## findings
One row per unique finding per repository — `UNIQUE(repository_id, fingerprint)`.
`scan_run_id` (last run that saw it, `ON DELETE SET NULL`), `fingerprint`, `dedup_key`, `scanner`, `scan_type`,
`scan_target`, `category`, `severity`, `vulnerability_id`, `rule_id`, `package_name`, `installed_version`,
`fixed_version`, `file_path`, `line`, `title`, `description`, `remediation`, `reference_url`, `metadata_json`,
`first_seen`, `last_seen`, `resolved_at`, `status ∈ OPEN, RESOLVED, UNVERIFIED`.

**No secret values are stored.** Secret findings keep rule id, file, line, commit hash/date/author name and a
SHA-256 fingerprint of those fields only. Gitleaks `Secret`/`Match`/`Email`/`Message` and Trivy
`Match`/`Code` are never read into the model.

## finding_changes
Per-run comparison outcome: `(scan_run_id, finding_id) UNIQUE`, `change_type ∈ NEW, EXISTING, RESOLVED, UNVERIFIED`,
`severity`, `changed_at`. Powers trend charts, run-to-run comparisons and the per-finding history view.
Indexes: `(scan_run_id)`, `(change_type, changed_at)` and `(finding_id, scan_run_id)` (added in 1.1 with
`CREATE INDEX IF NOT EXISTS`, applied automatically on start).

## repo_locks
`repository_id PK, pid, acquired_at` — cross-process lock preventing concurrent scans of the same repository.
Stale locks (dead PID or older than 4×timeout+10 min) are reclaimed.

## settings
`key UNIQUE, value` — `schema_version`, `created_at`, `last_discovery_at`, `last_batch_at`.

## Indexes
See `schema.sql`: repository name/active, scan run (repo, scanner, type, started), status, findings by
repo/status, severity, category, vulnerability id, package, and scope.

## Retention
`scan.retention_days` (0 = keep forever). After each batch, or via `python run_scan.py prune [--days N]`,
runs older than N days are deleted **except the latest run per repository/scanner/type/target**; their raw
reports inside `reports_dir` are deleted too. Findings rows are kept (first/last seen preserve history).
