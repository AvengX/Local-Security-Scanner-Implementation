"""Read-only analytics over the SQLite database, returned as pandas DataFrames / dicts."""

from __future__ import annotations

import sqlite3
from typing import Any

import pandas as pd

from database.db import get_setting
from services.triage_service import NOT_TRIAGED
from utils.validators import CATEGORIES, SEVERITIES

ACTIVE = ("OPEN", "UNVERIFIED")
SUCCESS = ("COMPLETED", "COMPLETED_WITH_FINDINGS")
FAILED = ("FAILED", "TIMED_OUT", "CANCELLED")


def _df(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> pd.DataFrame:
    cur = conn.execute(sql, params)
    cols = [c[0] for c in cur.description] if cur.description else []
    return pd.DataFrame([tuple(r) for r in cur.fetchall()], columns=cols)


# Joins that limit a query to monitored repositories (active = inside a configured root).
_ACTIVE_F = "JOIN repositories r ON r.id=f.repository_id AND r.active=1"
_ACTIVE_S = "JOIN repositories r ON r.id=s.repository_id AND r.active=1"


def _in(values: tuple[str, ...]) -> str:
    return ",".join(f"'{v}'" for v in values)  # constants only, never user input


# "Open" for every count and to-do list: reported by the latest scans AND not decided by a person (false positive,
# accepted risk, archived). Decided findings are listed separately, never silently dropped.
_OPEN = f"f.status IN ({_in(ACTIVE)}) AND {NOT_TRIAGED}"


def active_mask(df: pd.DataFrame) -> pd.Series:
    """Rows of a findings_frame that count as open (reported and undecided)."""
    if df.empty:
        return pd.Series([], dtype=bool)
    return df["status"].isin(ACTIVE) & df["decision"].isna()


def overview_metrics(conn: sqlite3.Connection) -> dict[str, Any]:
    q = lambda sql, p=(): conn.execute(sql, p).fetchone()[0]  # noqa: E731
    sev = {s: 0 for s in SEVERITIES}
    for r in conn.execute(
        f"SELECT f.severity, COUNT(DISTINCT f.repository_id || ':' || f.dedup_key) FROM findings f {_ACTIVE_F} "
        f"WHERE {_OPEN} GROUP BY f.severity"
    ):
        sev[r[0]] = r[1]
    cats = {c: 0 for c in CATEGORIES}
    for r in conn.execute(
        f"SELECT f.category, COUNT(DISTINCT f.repository_id || ':' || f.dedup_key) FROM findings f {_ACTIVE_F} "
        f"WHERE {_OPEN} GROUP BY f.category"
    ):
        cats[r[0]] = r[1]
    # "Failed scans" = latest run per repo/scanner/type/target that did not succeed.
    latest_failed = q(
        f"SELECT COUNT(*) FROM scan_runs s JOIN (SELECT MAX(id) id FROM scan_runs "
        f"WHERE status NOT IN ('PENDING','RUNNING') GROUP BY repository_id, scanner, scan_type, scan_target) l "
        f"ON l.id = s.id JOIN repositories r ON r.id = s.repository_id AND r.active = 1 "
        f"WHERE s.status IN ({_in(FAILED)})"
    )
    return {
        "repositories": q("SELECT COUNT(*) FROM repositories WHERE active=1"),
        "repositories_scanned": q(
            f"SELECT COUNT(DISTINCT s.repository_id) FROM scan_runs s JOIN repositories r "
            f"ON r.id=s.repository_id AND r.active=1 WHERE s.status IN ({_in(SUCCESS)})"),
        "severity": sev,
        "category": cats,
        "unverified": q("SELECT COUNT(*) FROM findings f JOIN repositories r ON r.id=f.repository_id "
                        f"AND r.active=1 WHERE f.status='UNVERIFIED' AND {NOT_TRIAGED}"),
        "triaged": q(f"SELECT COUNT(*) FROM finding_triage t JOIN findings f ON f.id=t.finding_id {_ACTIVE_F} "
                     f"WHERE f.status IN ({_in(ACTIVE)})"),
        "failed_scans_latest": latest_failed,
        "failed_scans_total": q(f"SELECT COUNT(*) FROM scan_runs s {_ACTIVE_S} WHERE s.status IN ({_in(FAILED)})"),
        "running": q("SELECT COUNT(*) FROM scan_runs WHERE status='RUNNING'"),
        "last_successful_scan": q(f"SELECT MAX(s.finished_at) FROM scan_runs s {_ACTIVE_S} WHERE s.status IN ({_in(SUCCESS)})"),
        "last_discovery": get_setting(conn, "last_discovery_at"),
        "total_scans": q(f"SELECT COUNT(*) FROM scan_runs s {_ACTIVE_S}"),
    }


def findings_by_repository(conn: sqlite3.Connection) -> pd.DataFrame:
    return _df(conn, f"""
        SELECT r.name AS repository, f.severity, COUNT(DISTINCT f.dedup_key) AS findings
        FROM findings f JOIN repositories r ON r.id=f.repository_id
        WHERE {_OPEN} AND r.active=1
        GROUP BY r.name, f.severity""")


def change_trend(conn: sqlite3.Connection) -> pd.DataFrame:
    """Daily counts of NEW and RESOLVED findings."""
    return _df(conn, f"""
        SELECT substr(c.changed_at, 1, 10) AS day, c.change_type, COUNT(*) AS count
        FROM finding_changes c JOIN scan_runs s ON s.id=c.scan_run_id {_ACTIVE_S}
        WHERE c.change_type IN ('NEW','RESOLVED')
        GROUP BY day, change_type ORDER BY day""")


def open_findings_trend(conn: sqlite3.Connection) -> pd.DataFrame:
    """Findings observed per successful scan day and severity (snapshot of what scans actually saw)."""
    return _df(conn, f"""
        SELECT substr(s.finished_at, 1, 10) AS day, c.severity, COUNT(DISTINCT c.finding_id) AS findings
        FROM finding_changes c JOIN scan_runs s ON s.id=c.scan_run_id {_ACTIVE_S}
        WHERE c.change_type IN ('NEW','EXISTING') AND s.status IN ({_in(SUCCESS)})
        GROUP BY day, c.severity ORDER BY day""")


def repository_table(conn: sqlite3.Connection) -> pd.DataFrame:
    """One row per active repository. Counts are distinct findings (same rule as the overview)."""
    df = _df(conn, f"""
        SELECT r.id, r.name, r.path, r.current_branch AS branch, substr(r.current_commit,1,12) AS last_commit,
               r.repo_kind AS kind, r.last_seen_at,
               (SELECT MAX(started_at) FROM scan_runs s WHERE s.repository_id=r.id) AS last_scan,
               (SELECT GROUP_CONCAT(scanner || ':' || scan_type || '=' || status, ', ') FROM scan_runs s
                 WHERE s.id IN (SELECT MAX(id) FROM scan_runs WHERE repository_id=r.id
                                GROUP BY scanner, scan_type, scan_target)) AS scan_status,
               (SELECT GROUP_CONCAT(status, ',') FROM scan_runs s
                 WHERE s.id IN (SELECT MAX(id) FROM scan_runs WHERE repository_id=r.id
                                GROUP BY scanner, scan_type, scan_target)) AS latest_statuses,
               (SELECT SUM(duration) FROM scan_runs s WHERE s.repository_id=r.id AND s.batch_id=(
                    SELECT batch_id FROM scan_runs WHERE repository_id=r.id ORDER BY id DESC LIMIT 1)) AS last_duration,
               (SELECT COUNT(DISTINCT dedup_key) FROM findings f WHERE f.repository_id=r.id
                  AND {_OPEN} AND f.severity='CRITICAL') AS critical,
               (SELECT COUNT(DISTINCT dedup_key) FROM findings f WHERE f.repository_id=r.id
                  AND {_OPEN} AND f.severity='HIGH') AS high,
               (SELECT COUNT(DISTINCT dedup_key) FROM findings f WHERE f.repository_id=r.id
                  AND {_OPEN}) AS open_findings
        FROM repositories r WHERE r.active=1 ORDER BY r.name COLLATE NOCASE""")
    if not df.empty:
        df["state"] = df["latest_statuses"].map(repository_state)
    return df


_STATE_ORDER = ("RUNNING", "PENDING", "TIMED_OUT", "FAILED", "CANCELLED", "COMPLETED_WITH_FINDINGS", "COMPLETED",
                "SKIPPED")


def repository_state(latest_statuses: Any) -> str:
    """Summarise the latest run of every scanner into one state (the most urgent one wins)."""
    if not isinstance(latest_statuses, str) or not latest_statuses:
        return "NEVER"
    present = set(latest_statuses.split(","))
    return next((s for s in _STATE_ORDER if s in present), "NEVER")


def recent_runs(conn: sqlite3.Connection, limit: int = 8) -> pd.DataFrame:
    return _df(conn, """SELECT s.id, r.name AS repository, s.scanner, s.scan_type, s.status, s.started_at,
                               s.finished_at, s.duration, s.findings_count, s.new_count, s.resolved_count,
                               s.error_message
                        FROM scan_runs s JOIN repositories r ON r.id=s.repository_id AND r.active=1
                        ORDER BY s.id DESC LIMIT ?""", (limit,))


def finding_history(conn: sqlite3.Connection, finding_id: int) -> pd.DataFrame:
    """Every scan that observed, resolved or could not verify this finding."""
    return _df(conn, """SELECT c.changed_at, c.change_type, c.severity, s.id AS run_id, s.scanner, s.scan_type,
                               s.status AS run_status
                        FROM finding_changes c JOIN scan_runs s ON s.id=c.scan_run_id
                        WHERE c.finding_id=? ORDER BY c.id DESC""", (finding_id,))


def upgrade_candidates(conn: sqlite3.Connection, limit: int = 5) -> pd.DataFrame:
    """Open vulnerable packages with a published fix, ranked by severity and number of advisories."""
    return _df(conn, f"""
        SELECT r.name AS repository, f.package_name, f.installed_version, MAX(f.fixed_version) AS fixed_version,
               COUNT(DISTINCT f.vulnerability_id) AS advisories,
               MIN(CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
                                   WHEN 'LOW' THEN 3 ELSE 4 END) AS worst
        FROM findings f JOIN repositories r ON r.id=f.repository_id AND r.active=1
        WHERE f.category='VULNERABILITY' AND {_OPEN}
              AND f.fixed_version IS NOT NULL AND f.fixed_version != ''
        GROUP BY r.name, f.package_name, f.installed_version
        ORDER BY worst, advisories DESC LIMIT ?""", (limit,))


def secret_hotspots(conn: sqlite3.Connection) -> pd.DataFrame:
    """OPEN secret findings (confirmed by the latest covering scan) grouped by repository and file.

    UNVERIFIED rows are excluded: they were not re-confirmed (e.g. inside a folder that is now skipped)."""
    return _df(conn, f"""
        SELECT r.name AS repository, f.file_path, COUNT(DISTINCT f.dedup_key) AS findings,
               MAX(CASE WHEN f.scan_type IN ('dir','fs') THEN 1 ELSE 0 END) AS in_working_tree
        FROM findings f JOIN repositories r ON r.id=f.repository_id AND r.active=1
        WHERE f.category='SECRET' AND f.status='OPEN' AND {NOT_TRIAGED}
        GROUP BY r.name, f.file_path ORDER BY findings DESC""")


def findings_frame(conn: sqlite3.Connection, repository_id: int | None = None) -> pd.DataFrame:
    sql = """SELECT f.id, r.name AS repository, f.repository_id, f.scanner, f.scan_type, f.scan_target,
                    f.category, f.severity, f.status, f.vulnerability_id, f.rule_id, f.package_name,
                    f.installed_version, f.fixed_version, f.file_path, f.line, f.title, f.description,
                    f.remediation, f.reference_url, f.first_seen, f.last_seen, f.resolved_at, f.dedup_key,
                    f.fingerprint, t.decision, t.reason AS decision_reason, t.review_by
             FROM findings f JOIN repositories r ON r.id=f.repository_id
             LEFT JOIN finding_triage t ON t.finding_id=f.id"""
    params: list[Any] = []
    if repository_id is not None:
        sql += " WHERE f.repository_id=?"
        params.append(repository_id)
    else:
        sql += " WHERE r.active=1"  # only monitored repositories (inside a configured root)
    df = _df(conn, sql, params)
    if not df.empty:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        df["_o"] = df["severity"].map(order)
        df["_s"] = df["status"].map({"OPEN": 0, "UNVERIFIED": 1, "RESOLVED": 2}).fillna(3)
        df = df.sort_values(["_o", "_s", "repository", "id"]).drop(columns=["_o", "_s"]).reset_index(drop=True)
        df["identifier"] = df["vulnerability_id"].fillna(df["rule_id"]).fillna("")
    return df


def filter_findings(df: pd.DataFrame, *, repositories: list[str] | None = None,
                    scanners: list[str] | None = None, categories: list[str] | None = None,
                    severities: list[str] | None = None, statuses: list[str] | None = None,
                    cve: str = "", package: str = "", file: str = "") -> pd.DataFrame:
    if df.empty:
        return df
    m = pd.Series(True, index=df.index)
    for col, vals in (("repository", repositories), ("scanner", scanners), ("category", categories),
                      ("severity", severities), ("status", statuses)):
        if vals:
            m &= df[col].isin(vals)
    if cve:
        m &= df["vulnerability_id"].fillna("").str.contains(cve, case=False, regex=False) | \
             df["rule_id"].fillna("").str.contains(cve, case=False, regex=False)
    if package:
        m &= df["package_name"].fillna("").str.contains(package, case=False, regex=False)
    if file:
        m &= df["file_path"].fillna("").str.contains(file, case=False, regex=False)
    return df[m].reset_index(drop=True)


def scan_history(conn: sqlite3.Connection, repository_id: int | None = None, limit: int = 1000) -> pd.DataFrame:
    sql = """SELECT s.id, r.name AS repository, s.scanner, s.scan_type, s.scan_target, s.status,
                    s.started_at, s.finished_at, s.duration, s.findings_count, s.new_count, s.resolved_count,
                    s.tool_version, s.database_updated_at, s.offline, s.exit_code, s.error_message,
                    s.report_path, s.coverage, s.batch_id
             FROM scan_runs s JOIN repositories r ON r.id=s.repository_id"""
    params: list[Any] = []
    if repository_id is not None:
        sql += " WHERE s.repository_id=?"
        params.append(repository_id)
    else:
        sql += " WHERE r.active=1"  # only monitored repositories (inside a configured root)
    sql += " ORDER BY s.id DESC LIMIT ?"
    params.append(limit)
    return _df(conn, sql, params)
