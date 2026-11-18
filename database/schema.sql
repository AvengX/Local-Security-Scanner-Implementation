-- Local Security Scanner schema (version 2). Applied idempotently.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS repositories (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    path_key        TEXT    NOT NULL UNIQUE,          -- normalised (case-folded) path for de-duplication
    root            TEXT,
    repo_kind       TEXT    NOT NULL DEFAULT 'repository',  -- repository | worktree_or_submodule
    current_branch  TEXT,
    current_commit  TEXT,
    discovered_at   TEXT    NOT NULL,
    last_seen_at    TEXT    NOT NULL,
    active          INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_repositories_name ON repositories(name);
CREATE INDEX IF NOT EXISTS ix_repositories_active ON repositories(active);

CREATE TABLE IF NOT EXISTS scan_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id       INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    batch_id            TEXT,
    scanner             TEXT    NOT NULL,                -- trivy | gitleaks | bandit
    scan_type           TEXT    NOT NULL,                -- fs | config | image | sbom | git | dir
    scan_target         TEXT    NOT NULL DEFAULT '.',
    coverage            TEXT,                            -- comparable coverage key
    started_at          TEXT,
    finished_at         TEXT,
    duration            REAL,
    status              TEXT    NOT NULL CHECK (status IN ('PENDING','RUNNING','COMPLETED',
                            'COMPLETED_WITH_FINDINGS','FAILED','CANCELLED','TIMED_OUT','SKIPPED')),
    exit_code           INTEGER,
    tool_version        TEXT,
    database_updated_at TEXT,
    offline             INTEGER NOT NULL DEFAULT 0,
    report_path         TEXT,
    error_message       TEXT,
    findings_count      INTEGER NOT NULL DEFAULT 0,
    new_count           INTEGER NOT NULL DEFAULT 0,
    resolved_count      INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER
);
CREATE INDEX IF NOT EXISTS ix_scan_runs_repo ON scan_runs(repository_id, scanner, scan_type, started_at);
CREATE INDEX IF NOT EXISTS ix_scan_runs_status ON scan_runs(status);
CREATE INDEX IF NOT EXISTS ix_scan_runs_started ON scan_runs(started_at);

-- One row per unique finding per repository (fingerprint is stable across scans).
CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id       INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,   -- last scan that saw it
    repository_id     INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint       TEXT    NOT NULL,
    dedup_key         TEXT    NOT NULL,          -- cross-scanner duplicate grouping
    scanner           TEXT    NOT NULL,
    scan_type         TEXT    NOT NULL,
    scan_target       TEXT    NOT NULL DEFAULT '.',
    category          TEXT    NOT NULL CHECK (category IN ('VULNERABILITY','SECRET','MISCONFIGURATION','CODE','LICENSE','OTHER')),
    severity          TEXT    NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')),
    vulnerability_id  TEXT,
    rule_id           TEXT,
    package_name      TEXT,
    installed_version TEXT,
    fixed_version     TEXT,
    file_path         TEXT,
    line              INTEGER,
    title             TEXT,
    description       TEXT,
    remediation       TEXT,
    reference_url     TEXT,
    metadata_json     TEXT,                      -- safe, redacted metadata only (never secret values)
    first_seen        TEXT    NOT NULL,
    last_seen         TEXT    NOT NULL,
    resolved_at       TEXT,
    status            TEXT    NOT NULL CHECK (status IN ('OPEN','RESOLVED','UNVERIFIED')),
    UNIQUE (repository_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS ix_findings_repo_status ON findings(repository_id, status);
CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS ix_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS ix_findings_vuln ON findings(vulnerability_id);
CREATE INDEX IF NOT EXISTS ix_findings_pkg ON findings(package_name);
CREATE INDEX IF NOT EXISTS ix_findings_scope ON findings(repository_id, scanner, scan_type, scan_target, status);

-- Per-scan comparison outcome for every affected finding (history / trends).
CREATE TABLE IF NOT EXISTS finding_changes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id  INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    finding_id   INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    change_type  TEXT    NOT NULL CHECK (change_type IN ('NEW','EXISTING','RESOLVED','UNVERIFIED')),
    severity     TEXT    NOT NULL,
    changed_at   TEXT    NOT NULL,
    UNIQUE (scan_run_id, finding_id)
);
CREATE INDEX IF NOT EXISTS ix_changes_run ON finding_changes(scan_run_id);
CREATE INDEX IF NOT EXISTS ix_changes_type_time ON finding_changes(change_type, changed_at);
CREATE INDEX IF NOT EXISTS ix_changes_finding ON finding_changes(finding_id, scan_run_id);

-- Lock rows prevent concurrent scans of the same repository across processes.
CREATE TABLE IF NOT EXISTS repo_locks (
    repository_id INTEGER PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    pid           INTEGER NOT NULL,
    acquired_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    key   TEXT NOT NULL UNIQUE,
    value TEXT
);
