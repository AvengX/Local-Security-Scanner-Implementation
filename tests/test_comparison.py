"""NEW / EXISTING / RESOLVED / UNVERIFIED classification and coverage rules."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from database import repositories as dao
from database.db import init_db
from engine.comparison_engine import apply_scan_results, compare_runs, mark_unverified_after_failure
from engine.finding_normalizer import Coverage, NormalizedFinding
from engine.repository_discovery import DiscoveredRepo

ALL = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"})
FULL = Coverage("trivy", "fs", ".", frozenset({"VULNERABILITY", "SECRET"}), ALL)


def vuln(cve: str, sev: str = "HIGH", pkg: str = "lib") -> NormalizedFinding:
    return NormalizedFinding("trivy", "fs", "VULNERABILITY", sev, vulnerability_id=cve, package_name=pkg,
                             installed_version="1.0", file_path="requirements.txt", identity=(cve, pkg, "1.0"))


def secret(rule: str = "github-pat") -> NormalizedFinding:
    return NormalizedFinding("trivy", "fs", "SECRET", "CRITICAL", rule_id=rule, file_path="a.py", line=1,
                             identity=(rule, "a.py", 1))


@pytest.fixture
def ctx(tmp_path: Path):
    conn = init_db(tmp_path / "c.db")
    (tmp_path / "R").mkdir()
    dao.sync_discovered(conn, [DiscoveredRepo("R", str(tmp_path / "R"), str(tmp_path))], [str(tmp_path)])
    rid = dao.list_repositories(conn)[0]["id"]

    def run(findings, cov=FULL, status="COMPLETED_WITH_FINDINGS"):
        r = dao.create_scan_run(conn, rid, cov.scanner, cov.scan_type, cov.scan_target, None, os.getpid())
        res = apply_scan_results(conn, rid, r, cov, findings)
        dao.finish_scan_run(conn, r, status=status, coverage=cov.key())
        return r, res

    def status_of(cve_or_rule: str) -> str:
        return conn.execute("SELECT status FROM findings WHERE vulnerability_id=? OR rule_id=?",
                            (cve_or_rule, cve_or_rule)).fetchone()[0]

    return conn, rid, run, status_of


def test_new_existing_resolved(ctx) -> None:
    conn, rid, run, status_of = ctx
    r1, res1 = run([vuln("CVE-1"), vuln("CVE-2")])
    assert len(res1.new) == 2
    r2, res2 = run([vuln("CVE-2"), vuln("CVE-3")])
    assert len(res2.new) == 1 and len(res2.existing) == 1 and len(res2.resolved) == 1
    assert status_of("CVE-1") == "RESOLVED" and status_of("CVE-2") == "OPEN"
    diff = compare_runs(conn, r1, r2)
    assert len(diff["new"]) == 1 and len(diff["existing"]) == 1 and len(diff["resolved"]) == 1


def test_first_seen_preserved_last_seen_updated(ctx) -> None:
    conn, rid, run, _ = ctx
    run([vuln("CVE-1")])
    conn.execute("UPDATE findings SET first_seen='2020-01-01T00:00:00+00:00', last_seen='2020-01-01T00:00:00+00:00'")
    run([vuln("CVE-1")])
    first, last = conn.execute("SELECT first_seen, last_seen FROM findings").fetchone()
    assert first.startswith("2020") and not last.startswith("2020")


def test_reopened_finding_counts_as_new(ctx) -> None:
    conn, rid, run, status_of = ctx
    run([vuln("CVE-1")])
    run([])
    assert status_of("CVE-1") == "RESOLVED"
    _, res = run([vuln("CVE-1")])
    assert len(res.new) == 1 and len(res.reopened) == 1 and status_of("CVE-1") == "OPEN"
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_failed_scan_never_resolves(ctx) -> None:
    conn, rid, run, status_of = ctx
    run([vuln("CVE-1")])
    failed = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, os.getpid())
    dao.finish_scan_run(conn, failed, status="FAILED")
    ids = mark_unverified_after_failure(conn, rid, failed, "trivy", "fs", ".")
    assert len(ids) == 1 and status_of("CVE-1") == "UNVERIFIED"
    # Next successful scan that still sees it -> back to OPEN (EXISTING)
    _, res = run([vuln("CVE-1")])
    assert len(res.existing) == 1 and status_of("CVE-1") == "OPEN"


def test_incomplete_category_coverage_does_not_resolve(ctx) -> None:
    conn, rid, run, status_of = ctx
    run([vuln("CVE-1"), secret()])
    vuln_only = Coverage("trivy", "fs", ".", frozenset({"VULNERABILITY"}), ALL)
    _, res = run([vuln("CVE-1")], cov=vuln_only)
    assert res.resolved == []
    assert status_of("github-pat") == "UNVERIFIED"  # not re-checked, not cleared


def test_severity_filter_coverage(ctx) -> None:
    conn, rid, run, status_of = ctx
    run([vuln("CVE-LOW", "LOW"), vuln("CVE-HIGH", "HIGH")])
    high_only = Coverage("trivy", "fs", ".", frozenset({"VULNERABILITY", "SECRET"}), frozenset({"HIGH", "CRITICAL"}))
    _, res = run([], cov=high_only)
    assert status_of("CVE-HIGH") == "RESOLVED"
    assert status_of("CVE-LOW") == "UNVERIFIED"


def test_different_scanner_or_target_untouched(ctx) -> None:
    conn, rid, run, status_of = ctx
    run([vuln("CVE-1")])
    gl = Coverage("gitleaks", "git", ".", frozenset({"SECRET"}), ALL)
    img = Coverage("trivy", "image", "nginx:1", frozenset({"VULNERABILITY"}), ALL)
    run([], cov=gl)
    run([], cov=img)
    assert status_of("CVE-1") == "OPEN"


def test_compare_runs_rejects_incomparable(ctx) -> None:
    conn, rid, run, _ = ctx
    r1, _ = run([vuln("CVE-1")])
    r2, _ = run([vuln("CVE-1")], cov=Coverage("trivy", "fs", ".", frozenset({"VULNERABILITY"}), ALL))
    with pytest.raises(ValueError, match="coverage"):
        compare_runs(conn, r1, r2)
    r3, _ = run([vuln("CVE-1")], status="FAILED")
    with pytest.raises(ValueError, match="not successful"):
        compare_runs(conn, r1, r3)


def test_compare_runs_rejects_other_repository(ctx, tmp_path: Path) -> None:
    conn, rid, run, _ = ctx
    r1, _ = run([vuln("CVE-1")])
    (tmp_path / "S").mkdir()
    dao.sync_discovered(conn, [DiscoveredRepo("S", str(tmp_path / "S"), str(tmp_path))], [])
    other = dao.find_repositories(conn, name="S")[0]["id"]
    r2 = dao.create_scan_run(conn, other, "trivy", "fs", ".", None, os.getpid())
    dao.finish_scan_run(conn, r2, status="COMPLETED", coverage=FULL.key())
    with pytest.raises(ValueError, match="different repositories"):
        compare_runs(conn, r1, r2)
