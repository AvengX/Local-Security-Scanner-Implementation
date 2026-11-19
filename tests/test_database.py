"""SQLite schema, inserts, duplicate prevention, locks, history and retention."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from conftest import load_fixture
from database import repositories as dao
from database.db import get_setting, init_db, transaction
from engine.comparison_engine import apply_scan_results, mark_unverified_after_failure
from engine.finding_normalizer import Coverage
from engine.report_parser import parse_trivy_data
from engine.repository_discovery import DiscoveredRepo
from utils.validators import SEVERITIES

COV = Coverage("trivy", "fs", ".", frozenset({"VULNERABILITY", "MISCONFIGURATION", "SECRET"}), frozenset(SEVERITIES))


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = init_db(tmp_path / "t.db")
    repo = DiscoveredRepo("Phoenix", str(tmp_path / "Phoenix"), str(tmp_path))
    (tmp_path / "Phoenix").mkdir()
    dao.sync_discovered(c, [repo], [str(tmp_path)])
    return c


def repo_id(conn) -> int:
    return dao.list_repositories(conn)[0]["id"]


def test_initialisation_idempotent(tmp_path: Path) -> None:
    c = init_db(tmp_path / "x.db")
    assert get_setting(c, "schema_version") == "5"
    assert c.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"repositories", "scan_runs", "findings", "settings", "finding_changes", "repo_locks"} <= tables
    c.close()
    init_db(tmp_path / "x.db").close()  # second run must not fail


def test_insert_repository_scan_and_findings(conn) -> None:
    rid = repo_id(conn)
    run = dao.create_scan_run(conn, rid, "trivy", "fs", ".", "b1", os.getpid())
    findings = parse_trivy_data(load_fixture("trivy_fs.json"))
    res = apply_scan_results(conn, rid, run, COV, findings)
    dao.finish_scan_run(conn, run, status="COMPLETED_WITH_FINDINGS", findings_count=len(findings))
    assert len(res.new) == 4
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 4
    assert dao.get_scan_run(conn, run)["status"] == "COMPLETED_WITH_FINDINGS"


def test_no_secret_values_in_database(conn) -> None:
    rid = repo_id(conn)
    run = dao.create_scan_run(conn, rid, "trivy", "fs", ".", "b1", os.getpid())
    apply_scan_results(conn, rid, run, COV, parse_trivy_data(load_fixture("trivy_fs.json")))
    dump = "\n".join(conn.iterdump())
    assert "SHOULDNEVERBESTORED" not in dump


def test_duplicate_prevention_across_scans(conn) -> None:
    rid = repo_id(conn)
    for _ in range(3):
        run = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, os.getpid())
        apply_scan_results(conn, rid, run, COV, parse_trivy_data(load_fixture("trivy_fs.json")))
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 4
    assert conn.execute("SELECT COUNT(*) FROM finding_changes").fetchone()[0] == 12
    with pytest.raises(sqlite3.IntegrityError):
        row = conn.execute("SELECT * FROM findings LIMIT 1").fetchone()
        conn.execute("INSERT INTO findings(repository_id, fingerprint, dedup_key, scanner, scan_type, category, "
                     "severity, first_seen, last_seen, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (rid, row["fingerprint"], "k", "trivy", "fs", "OTHER", "LOW", "t", "t", "OPEN"))


def test_failed_scan_preserves_findings(conn) -> None:
    rid = repo_id(conn)
    run1 = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, os.getpid())
    apply_scan_results(conn, rid, run1, COV, parse_trivy_data(load_fixture("trivy_fs.json")))
    run2 = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, os.getpid())
    dao.finish_scan_run(conn, run2, status="FAILED", error_message="boom")
    mark_unverified_after_failure(conn, rid, run2, "trivy", "fs", ".")
    statuses = {r[0] for r in conn.execute("SELECT status FROM findings")}
    assert statuses == {"UNVERIFIED"}
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status='RESOLVED'").fetchone()[0] == 0


def test_historical_queries(conn) -> None:
    rid = repo_id(conn)
    for _ in range(2):
        run = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, os.getpid())
        apply_scan_results(conn, rid, run, COV, parse_trivy_data(load_fixture("trivy_fs.json")))
        dao.finish_scan_run(conn, run, status="COMPLETED_WITH_FINDINGS", finished_at="2026-11-16T00:00:00+00:00")
    assert len(dao.list_scan_runs(conn, rid)) == 2
    assert len(dao.list_findings(conn, rid, ["OPEN"])) == 4


def test_transaction_rollback(conn) -> None:
    with pytest.raises(RuntimeError):
        with transaction(conn):
            conn.execute("INSERT INTO settings(key, value) VALUES ('tmp', 'x')")
            raise RuntimeError
    assert get_setting(conn, "tmp") is None


def test_repo_lock(conn) -> None:
    rid = repo_id(conn)
    assert dao.acquire_repo_lock(conn, rid, os.getpid(), 3600)
    # A different *live* process holds it -> refuse. Use parent PID which is alive.
    conn.execute("UPDATE repo_locks SET pid=? WHERE repository_id=?", (os.getppid(), rid))
    assert not dao.acquire_repo_lock(conn, rid, os.getpid(), 3600)
    # Dead PID -> reclaimed.
    conn.execute("UPDATE repo_locks SET pid=? WHERE repository_id=?", (999999, rid))
    assert dao.acquire_repo_lock(conn, rid, os.getpid(), 3600)
    dao.release_repo_lock(conn, rid, os.getpid())
    assert conn.execute("SELECT COUNT(*) FROM repo_locks").fetchone()[0] == 0


def test_orphaned_runs_recovered(conn) -> None:
    rid = repo_id(conn)
    run = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, 999999)
    assert dao.recover_orphaned_runs(conn) == 1
    assert dao.get_scan_run(conn, run)["status"] == "CANCELLED"


def test_retention_keeps_latest(conn) -> None:
    rid = repo_id(conn)
    old = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, os.getpid())
    new = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, os.getpid())
    conn.execute("UPDATE scan_runs SET started_at='2000-01-01T00:00:00+00:00', status='COMPLETED'")
    res = dao.prune_history(conn, 30)
    assert res["runs_deleted"] == 1
    assert dao.get_scan_run(conn, old) is None and dao.get_scan_run(conn, new) is not None
