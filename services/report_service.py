"""Safe access to raw scanner reports stored in the reports directory."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from utils.security import safe_report_path


@dataclass
class ReportEntry:
    run_id: int
    repository: str
    scanner: str
    scan_type: str
    status: str
    started_at: str | None
    path: Path
    size: int


def list_reports(conn: sqlite3.Connection, reports_dir: Path, scanner: str | None = None,
                 repository_id: int | None = None, limit: int = 300) -> list[ReportEntry]:
    """Only reports registered in the database AND located inside ``reports_dir`` are listed."""
    sql = ("SELECT s.id, r.name, s.scanner, s.scan_type, s.status, s.started_at, s.report_path FROM scan_runs s "
           "JOIN repositories r ON r.id=s.repository_id WHERE s.report_path IS NOT NULL")
    params: list[object] = []
    if scanner:
        sql += " AND s.scanner=?"
        params.append(scanner)
    if repository_id is not None:
        sql += " AND s.repository_id=?"
        params.append(repository_id)
    sql += " ORDER BY s.id DESC LIMIT ?"
    params.append(limit)
    out: list[ReportEntry] = []
    for row in conn.execute(sql, params).fetchall():
        try:
            p = safe_report_path(row["report_path"], reports_dir)
        except (PermissionError, FileNotFoundError):
            continue
        out.append(ReportEntry(row["id"], row["name"], row["scanner"], row["scan_type"], row["status"],
                               row["started_at"], p, p.stat().st_size))
    return out


def read_report_for_run(conn: sqlite3.Connection, run_id: int, reports_dir: Path) -> tuple[str, bytes]:
    """Return (filename, bytes) for a run's raw report, enforcing the reports-directory boundary."""
    row = conn.execute("SELECT report_path FROM scan_runs WHERE id=?", (run_id,)).fetchone()
    if not row or not row["report_path"]:
        raise FileNotFoundError("This scan run has no stored report")
    p = safe_report_path(row["report_path"], reports_dir)
    return p.name, p.read_bytes()
