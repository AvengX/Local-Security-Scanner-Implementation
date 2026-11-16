"""Read-only analytics over the SQLite database, returned as pandas DataFrames / dicts."""

from __future__ import annotations

import sqlite3
from typing import Any

import pandas as pd

from database.db import get_setting
from utils.validators import CATEGORIES, SEVERITIES

ACTIVE = ("OPEN", "UNVERIFIED")
SUCCESS = ("COMPLETED", "COMPLETED_WITH_FINDINGS")
FAILED = ("FAILED", "TIMED_OUT", "CANCELLED")


def _df(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> pd.DataFrame:
    cur = conn.execute(sql, params)
    cols = [c[0] for c in cur.description] if cur.description else []
    return pd.DataFrame([tuple(r) for r in cur.fetchall()], columns=cols)


def _in(values: tuple[str, ...]) -> str:
    return ",".join(f"'{v}'" for v in values)  # constants only, never user input


def overview_metrics(conn: sqlite3.Connection) -> dict[str, Any]:
    q = lambda sql, p=(): conn.execute(sql, p).fetchone()[0]  # noqa: E731
    sev = {s: 0 for s in SEVERITIES}
    for r in conn.execute(
        f"SELECT severity, COUNT(DISTINCT repository_id || ':' || dedup_key) FROM findings "
        f"WHERE status IN ({_in(ACTIVE)}) GROUP BY severity"
    ):
        sev[r[0]] = r[1]
    cats = {c: 0 for c in CATEGORIES}
    for r in conn.execute(
        f"SELECT category, COUNT(DISTINCT repository_id || ':' || dedup_key) FROM findings "
        f"WHERE status IN ({_in(ACTIVE)}) GROUP BY category"
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
        "unverified": q("SELECT COUNT(*) FROM findings WHERE status='UNVERIFIED'"),
        "failed_scans_latest": latest_failed,
        "failed_scans_total": q(f"SELECT COUNT(*) FROM scan_runs WHERE status IN ({_in(FAILED)})"),
        "running": q("SELECT COUNT(*) FROM scan_runs WHERE status='RUNNING'"),
        "last_successful_scan": q(f"SELECT MAX(finished_at) FROM scan_runs WHERE status IN ({_in(SUCCESS)})"),
        "last_discovery": get_setting(conn, "last_discovery_at"),
        "total_scans": q("SELECT COUNT(*) FROM scan_runs"),
    }


def findings_by_repository(conn: sqlite3.Connection) -> pd.DataFrame:
    return _df(conn, f"""
        SELECT r.name AS repository, f.severity, COUNT(DISTINCT f.dedup_key) AS findings
        FROM findings f JOIN repositories r ON r.id=f.repository_id
        WHERE f.status IN ({_in(ACTIVE)}) AND r.active=1
        GROUP BY r.name, f.severity""")


def change_trend(conn: sqlite3.Connection) -> pd.DataFrame:
    """Daily counts of NEW and RESOLVED findings."""
    return _df(conn, """
        SELECT substr(changed_at, 1, 10) AS day, change_type, COUNT(*) AS count
        FROM finding_changes WHERE change_type IN ('NEW','RESOLVED')
        GROUP BY day, change_type ORDER BY day""")


def open_findings_trend(conn: sqlite3.Connection) -> pd.DataFrame:
    """Findings observed per successful scan day and severity (snapshot of what scans actually saw)."""
    return _df(conn, f"""
        SELECT substr(s.finished_at, 1, 10) AS day, c.severity, COUNT(DISTINCT c.finding_id) AS findings
        FROM finding_changes c JOIN scan_runs s ON s.id=c.scan_run_id
        WHERE c.change_type IN ('NEW','EXISTING') AND s.status IN ({_in(SUCCESS)})
        GROUP BY day, c.severity ORDER BY day""")


def repository_table(conn: sqlite3.Connection) -> pd.DataFrame:
    return _df(conn, f"""
        SELECT r.id, r.name, r.path, r.current_branch AS branch, substr(r.current_commit,1,12) AS last_commit,
               r.repo_kind AS kind, r.last_seen_at,
               (SELECT MAX(started_at) FROM scan_runs s WHERE s.repository_id=r.id) AS last_scan,
               (SELECT GROUP_CONCAT(scanner || ':' || scan_type || '=' || status, ', ') FROM scan_runs s
                 WHERE s.id IN (SELECT MAX(id) FROM scan_runs WHERE repository_id=r.id
                                GROUP BY scanner, scan_type, scan_target)) AS scan_status,
               (SELECT COUNT(DISTINCT dedup_key) FROM findings f WHERE f.repository_id=r.id
                  AND f.status IN ({_in(ACTIVE)}) AND f.severity='CRITICAL') AS critical,
               (SELECT COUNT(DISTINCT dedup_key) FROM findings f WHERE f.repository_id=r.id
                  AND f.status IN ({_in(ACTIVE)}) AND f.severity='HIGH') AS high,
               (SELECT COUNT(*) FROM findings f WHERE f.repository_id=r.id
                  AND f.status IN ({_in(ACTIVE)})) AS open_findings
        FROM repositories r WHERE r.active=1 ORDER BY r.name COLLATE NOCASE""")


def findings_frame(conn: sqlite3.Connection, repository_id: int | None = None) -> pd.DataFrame:
    sql = """SELECT f.id, r.name AS repository, f.repository_id, f.scanner, f.scan_type, f.scan_target,
                    f.category, f.severity, f.status, f.vulnerability_id, f.rule_id, f.package_name,
                    f.installed_version, f.fixed_version, f.file_path, f.line, f.title, f.description,
                    f.remediation, f.reference_url, f.first_seen, f.last_seen, f.resolved_at, f.dedup_key,
                    f.fingerprint
             FROM findings f JOIN repositories r ON r.id=f.repository_id"""
    params: list[Any] = []
    if repository_id is not None:
        sql += " WHERE f.repository_id=?"
        params.append(repository_id)
    df = _df(conn, sql, params)
    if not df.empty:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        df["_o"] = df["severity"].map(order)
        df = df.sort_values(["_o", "repository", "id"]).drop(columns="_o").reset_index(drop=True)
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
    sql += " ORDER BY s.id DESC LIMIT ?"
    params.append(limit)
    return _df(conn, sql, params)
