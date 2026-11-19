"""Triage: false positive / accepted risk / archived - validation, counts, expiry, reports, history."""

from __future__ import annotations

import os
from datetime import date, timedelta
from pathlib import Path

import pytest

from database.db import init_db
from services import analytics_service as an
from services import triage_service as tri

from test_dashboard import env, populate  # noqa: F401 - shared fixture (isolated config + database)


def _conn(cfg):  # noqa: ANN001, ANN202
    populate(cfg)
    return init_db(cfg.db_path)


def _open_ids(conn) -> list[int]:  # noqa: ANN001
    return [r[0] for r in conn.execute("SELECT id FROM findings WHERE status IN ('OPEN','UNVERIFIED') ORDER BY id")]


def test_validation_rules(env) -> None:  # noqa: ANN001
    conn = _conn(env)
    fid = _open_ids(conn)[0]
    with pytest.raises(tri.TriageError, match="reason"):
        tri.set_decision(conn, fid, "FALSE_POSITIVE", "  ")
    with pytest.raises(tri.TriageError, match="review date"):
        tri.set_decision(conn, fid, "ACCEPTED_RISK", "fix planned next release")
    with pytest.raises(tri.TriageError, match="future"):
        tri.set_decision(conn, fid, "ACCEPTED_RISK", "fix planned", date.today())
    with pytest.raises(tri.TriageError, match="one year"):
        tri.set_decision(conn, fid, "ACCEPTED_RISK", "fix planned", date.today() + timedelta(days=400))
    with pytest.raises(tri.TriageError, match="Unknown"):
        tri.set_decision(conn, fid, "IGNORE", "whatever reason")
    assert tri.get_decision(conn, fid) is None and not tri.history(conn, fid)


def test_decision_removes_finding_from_counts_and_lists_it_separately(env) -> None:  # noqa: ANN001
    conn = _conn(env)
    before = an.overview_metrics(conn)
    total_before = sum(before["severity"].values())
    fid = _open_ids(conn)[0]
    sev = conn.execute("SELECT severity FROM findings WHERE id=?", (fid,)).fetchone()[0]
    tri.set_decision(conn, fid, "FALSE_POSITIVE", "Test fixture value, not a real dependency")
    after = an.overview_metrics(conn)
    assert sum(after["severity"].values()) == total_before - 1
    assert after["severity"][sev] == before["severity"][sev] - 1
    assert after["triaged"] == 1
    df = an.findings_frame(conn)
    row = df[df["id"] == fid].iloc[0]
    assert row["decision"] == "FALSE_POSITIVE" and not an.active_mask(df)[df["id"] == fid].any()
    listed = tri.decisions(conn)
    assert [x["id"] for x in listed] == [fid] and listed[0]["reason"].startswith("Test fixture")
    assert [h["action"] for h in tri.history(conn, fid)] == ["FALSE_POSITIVE"]


def test_reopen_and_expiry(env) -> None:  # noqa: ANN001
    conn = _conn(env)
    a, b = _open_ids(conn)[:2]
    tri.set_decision(conn, a, "ARCHIVED", "Not relevant any more")
    assert tri.reopen(conn, a, "Turned out to matter") and tri.get_decision(conn, a) is None
    assert not tri.reopen(conn, a)
    tri.set_decision(conn, b, "ACCEPTED_RISK", "Fix planned for next release", date.today() + timedelta(days=30))
    assert tri.expire_due(conn) == 0
    assert tri.expire_due(conn, today=date.today() + timedelta(days=30)) == 1
    assert tri.get_decision(conn, b) is None
    assert [h["action"] for h in tri.history(conn, b)] == ["ACCEPTED_RISK", "EXPIRED"]
    assert [h["action"] for h in tri.history(conn, a)] == ["ARCHIVED", "REOPENED"]


def test_decision_survives_rescan_and_reports_show_it(env) -> None:  # noqa: ANN001
    from services.audit_report import generate_audit
    from services.summary_report import generate_summary
    from utils.config import load_config

    conn = _conn(env)
    fid = _open_ids(conn)[0]
    tri.set_decision(conn, fid, "ACCEPTED_RISK", "Vendor fix pending; not reachable from the internet",
                     date.today() + timedelta(days=60))
    populate(env)  # same findings observed again by a new scan
    assert tri.get_decision(conn, fid)["decision"] == "ACCEPTED_RISK"
    cfg = load_config(Path(os.environ["LSS_CONFIG"]))
    rid = conn.execute("SELECT repository_id FROM findings WHERE id=?", (fid,)).fetchone()[0]
    _, doc, data = generate_audit(conn, cfg, rid)
    assert fid not in {r["id"] for r in data["active"]}
    assert "Decisions recorded" in doc and "Vendor fix pending" in doc
    _, sdoc, sdata = generate_summary(conn, cfg)
    assert "Risks we accepted" in sdoc and "Vendor fix pending" in sdoc
    tri.reopen(conn, fid)
    _, _, again = generate_summary(conn, cfg)
    assert sum(again["totals"].values()) == sum(sdata["totals"].values()) + 1  # it was left out of the counts
    assert sum(p["count"] for p in sdata["priorities"]) == sum(sdata["totals"].values())


def test_archive_findings_in_skipped_folders(env) -> None:  # noqa: ANN001
    conn = _conn(env)
    fid = _open_ids(conn)[0]
    conn.execute("UPDATE findings SET file_path='C:/proj/.venv/Lib/site-packages/x/a.py', status='UNVERIFIED' "
                 "WHERE id=?", (fid,))
    assert tri.skipped_folder_findings(conn, [".venv", "node_modules"]) == [fid]
    assert tri.archive_skipped(conn, [".venv"]) == 1
    d = tri.get_decision(conn, fid)
    assert d["decision"] == "ARCHIVED" and ".venv" in d["reason"]
    assert tri.skipped_folder_findings(conn, [".venv"]) == []


def test_schema_v4_tables_exist(tmp_path: Path) -> None:
    conn = init_db(tmp_path / "t.db")
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"finding_triage", "triage_log"} <= names
