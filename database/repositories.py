"""Data-access functions for repositories, scan runs, locks and queries used by services/dashboard."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

from database.db import transaction, utcnow
from engine.repository_discovery import DiscoveredRepo
from utils.paths import is_within, normalize_key
from utils.security import pid_alive

FINAL_STATUSES = ("COMPLETED", "COMPLETED_WITH_FINDINGS", "FAILED", "CANCELLED", "TIMED_OUT", "SKIPPED")


def rows(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


# ----------------------------------------------------------------------------- repositories
def sync_discovered(conn: sqlite3.Connection, discovered: Iterable[DiscoveredRepo],
                    roots: Iterable[str]) -> dict[str, int]:
    """Upsert discovered repositories; deactivate ones under scanned roots that disappeared.

    A repository that vanished from one path and re-appeared elsewhere with the same name and HEAD commit
    is treated as *moved* (path updated, history preserved).
    """
    now = utcnow()
    stats = {"new": 0, "updated": 0, "moved": 0, "deactivated": 0}
    roots = list(roots)
    found_keys: set[str] = set()
    with transaction(conn):
        for repo in discovered:
            key = normalize_key(repo.path)
            found_keys.add(key)
            existing = conn.execute("SELECT id FROM repositories WHERE path_key = ?", (key,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE repositories SET name=?, path=?, root=?, repo_kind=?, current_branch=?, "
                    "current_commit=?, last_seen_at=?, active=1 WHERE id=?",
                    (repo.name, repo.path, repo.root, repo.kind, repo.current_branch, repo.current_commit,
                     now, existing["id"]),
                )
                stats["updated"] += 1
                continue
            moved = None
            if repo.current_commit:
                for cand in conn.execute(
                    "SELECT id, path FROM repositories WHERE name=? AND current_commit=?",
                    (repo.name, repo.current_commit),
                ).fetchall():
                    if not os.path.isdir(cand["path"]):
                        moved = cand
                        break
            if moved:
                conn.execute(
                    "UPDATE repositories SET path=?, path_key=?, root=?, repo_kind=?, current_branch=?, "
                    "last_seen_at=?, active=1 WHERE id=?",
                    (repo.path, key, repo.root, repo.kind, repo.current_branch, now, moved["id"]),
                )
                stats["moved"] += 1
            else:
                conn.execute(
                    "INSERT INTO repositories(name, path, path_key, root, repo_kind, current_branch, "
                    "current_commit, discovered_at, last_seen_at, active) VALUES (?,?,?,?,?,?,?,?,?,1)",
                    (repo.name, repo.path, key, repo.root, repo.kind, repo.current_branch,
                     repo.current_commit, now, now),
                )
                stats["new"] += 1
        for r in conn.execute("SELECT id, path, path_key FROM repositories WHERE active=1").fetchall():
            if r["path_key"] in found_keys:
                continue
            under_root = any(is_within(r["path"], root) for root in roots)
            if under_root or not os.path.isdir(r["path"]):
                conn.execute("UPDATE repositories SET active=0 WHERE id=?", (r["id"],))
                stats["deactivated"] += 1
    return stats


def list_repositories(conn: sqlite3.Connection, active_only: bool = True) -> list[dict[str, Any]]:
    sql = "SELECT * FROM repositories" + (" WHERE active=1" if active_only else "") + " ORDER BY name COLLATE NOCASE"
    return rows(conn.execute(sql))


def find_repositories(conn: sqlite3.Connection, name: str | None = None, path: str | None = None
                      ) -> list[dict[str, Any]]:
    if path:
        return rows(conn.execute("SELECT * FROM repositories WHERE path_key=?", (normalize_key(path),)))
    return rows(conn.execute("SELECT * FROM repositories WHERE name=? COLLATE NOCASE AND active=1", (name,)))


def get_repository(conn: sqlite3.Connection, repo_id: int) -> dict[str, Any] | None:
    r = conn.execute("SELECT * FROM repositories WHERE id=?", (repo_id,)).fetchone()
    return dict(r) if r else None


# ----------------------------------------------------------------------------- locks
def acquire_repo_lock(conn: sqlite3.Connection, repo_id: int, pid: int, stale_after_s: int) -> bool:
    """Atomically acquire the per-repository scan lock (stale locks from dead processes are reclaimed)."""
    with transaction(conn):
        row = conn.execute("SELECT pid, acquired_at FROM repo_locks WHERE repository_id=?", (repo_id,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row["acquired_at"])
            if pid_alive(row["pid"]) and age < timedelta(seconds=stale_after_s) and row["pid"] != pid:
                return False
            conn.execute("DELETE FROM repo_locks WHERE repository_id=?", (repo_id,))
        conn.execute("INSERT INTO repo_locks(repository_id, pid, acquired_at) VALUES (?,?,?)",
                     (repo_id, pid, utcnow()))
    return True


def release_repo_lock(conn: sqlite3.Connection, repo_id: int, pid: int) -> None:
    conn.execute("DELETE FROM repo_locks WHERE repository_id=? AND pid=?", (repo_id, pid))


# ----------------------------------------------------------------------------- scan runs
def create_scan_run(conn: sqlite3.Connection, repo_id: int, scanner: str, scan_type: str, scan_target: str,
                    batch_id: str | None, pid: int, status: str = "RUNNING") -> int:
    cur = conn.execute(
        "INSERT INTO scan_runs(repository_id, batch_id, scanner, scan_type, scan_target, started_at, status, pid) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (repo_id, batch_id, scanner, scan_type, scan_target, utcnow(), status, pid),
    )
    return int(cur.lastrowid)


def finish_scan_run(conn: sqlite3.Connection, run_id: int, **fields: Any) -> None:
    allowed = {"status", "started_at", "finished_at", "duration", "exit_code", "tool_version",
               "database_updated_at", "offline", "report_path", "error_message", "coverage",
               "findings_count", "new_count", "resolved_count"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    cols = ", ".join(f"{k}=?" for k in sets)
    conn.execute(f"UPDATE scan_runs SET {cols} WHERE id=?", (*sets.values(), run_id))  # noqa: S608


def recover_orphaned_runs(conn: sqlite3.Connection) -> int:
    """Mark RUNNING/PENDING runs whose process died as CANCELLED (never as clean)."""
    count = 0
    for r in conn.execute("SELECT id, pid FROM scan_runs WHERE status IN ('RUNNING','PENDING')").fetchall():
        if not r["pid"] or not pid_alive(r["pid"]):
            conn.execute(
                "UPDATE scan_runs SET status='CANCELLED', finished_at=?, "
                "error_message=COALESCE(error_message,'Scan process terminated unexpectedly') WHERE id=?",
                (utcnow(), r["id"]),
            )
            count += 1
    return count


def get_scan_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    r = conn.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
    return dict(r) if r else None


def list_scan_runs(conn: sqlite3.Connection, repository_id: int | None = None, limit: int = 500
                   ) -> list[dict[str, Any]]:
    sql = ("SELECT s.*, r.name AS repository FROM scan_runs s JOIN repositories r ON r.id = s.repository_id")
    params: list[Any] = []
    if repository_id is not None:
        sql += " WHERE s.repository_id=?"
        params.append(repository_id)
    sql += " ORDER BY s.id DESC LIMIT ?"
    params.append(limit)
    return rows(conn.execute(sql, params))


def list_findings(conn: sqlite3.Connection, repository_id: int | None = None,
                  statuses: Iterable[str] | None = None) -> list[dict[str, Any]]:
    sql = "SELECT f.*, r.name AS repository FROM findings f JOIN repositories r ON r.id=f.repository_id WHERE 1=1"
    params: list[Any] = []
    if repository_id is not None:
        sql += " AND f.repository_id=?"
        params.append(repository_id)
    statuses = list(statuses or [])
    if statuses:
        sql += f" AND f.status IN ({','.join('?' * len(statuses))})"
        params += statuses
    sql += (" ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
            "WHEN 'LOW' THEN 3 ELSE 4 END, r.name, f.id")
    return rows(conn.execute(sql, params))


def prune_history(conn: sqlite3.Connection, retention_days: int) -> dict[str, Any]:
    """Delete scan runs older than ``retention_days`` except the latest run per repo/scanner/type/target.

    Findings themselves are kept (first/last seen timestamps preserve history). Returns the number of runs
    deleted and their report paths so the caller can remove them from the reports directory.
    """
    if retention_days <= 0:
        return {"runs_deleted": 0, "report_paths": []}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    where = ("started_at < ? AND id NOT IN (SELECT MAX(id) FROM scan_runs "
             "GROUP BY repository_id, scanner, scan_type, scan_target)")
    with transaction(conn):
        paths = [r["report_path"] for r in conn.execute(
            f"SELECT report_path FROM scan_runs WHERE {where}", (cutoff,)).fetchall() if r["report_path"]]  # noqa: S608
        cur = conn.execute(f"DELETE FROM scan_runs WHERE {where}", (cutoff,))  # noqa: S608
    return {"runs_deleted": cur.rowcount, "report_paths": paths}
