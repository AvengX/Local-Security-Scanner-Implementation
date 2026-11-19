"""Trends over time from the recorded history."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from database.db import init_db
from services import trends_service as tr
from services import triage_service as tri

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).replace(microsecond=0).isoformat()


def _db(tmp_path: Path):  # noqa: ANN202
    conn = init_db(tmp_path / "t.db")
    conn.execute("INSERT INTO repositories(name, path, path_key, discovered_at, last_seen_at, active) "
                 "VALUES('app', 'C:/app', 'c:/app', ?, ?, 1)", (_iso(60), _iso(0)))
    conn.execute("INSERT INTO scan_runs(repository_id, scanner, scan_type, status, finished_at) "
                 "VALUES(1, 'trivy', 'fs', 'COMPLETED', ?)", (_iso(45),))
    conn.execute("INSERT INTO scan_runs(repository_id, scanner, scan_type, status, finished_at) "
                 "VALUES(1, 'trivy', 'fs', 'COMPLETED', ?)", (_iso(0),))
    rows = [  # (key, severity, category, first seen days ago, resolved days ago or None)
        ("a", "CRITICAL", "VULNERABILITY", 40, 37),   # fixed in 3 days
        ("b", "HIGH", "SECRET", 40, None),             # still open
        ("c", "HIGH", "CODE", 20, 10),                 # fixed in 10 days
        ("d", "LOW", "WEB", 5, None),                  # new recently
    ]
    for i, (key, sev, cat, first, res) in enumerate(rows, 1):
        conn.execute("INSERT INTO findings(repository_id, fingerprint, dedup_key, scanner, scan_type, category, "
                     "severity, title, first_seen, last_seen, resolved_at, status) VALUES(1,?,?,?,?,?,?,?,?,?,?,?)",
                     (f"fp{i}", key, "trivy", "fs", cat, sev, key, _iso(first), _iso(0),
                      _iso(res) if res is not None else None, "RESOLVED" if res is not None else "OPEN"))
    return conn


def test_open_over_time_counts_what_was_open_each_day(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    df = tr.open_over_time(conn, days=30, now=NOW)
    assert len(df) == 31 and list(df.columns) == ["Critical", "High", "Medium", "Low"]
    assert df.iloc[-1].to_dict() == {"Critical": 0, "High": 1, "Medium": 0, "Low": 1}   # today: b, d
    day15 = df.loc[(NOW - timedelta(days=15)).date()]
    assert day15["High"] == 2 and day15["Low"] == 0                                     # b and c
    long = tr.open_over_time(conn, days=90, now=NOW)
    assert len(long) == 13  # weekly points
    cat = tr.open_over_time(conn, days=30, by="category", now=NOW)
    assert set(cat.columns) <= {"Vulnerable libraries", "Leaked secrets", "Code issues", "Web app issues"}


def test_new_vs_fixed_and_time_to_fix(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    nf = tr.new_vs_fixed(conn, days=60, now=NOW)
    assert nf["New"].sum() == 4 and nf["Fixed"].sum() == 2
    ttf = tr.time_to_fix(conn, now=NOW).set_index("Severity")
    assert ttf.loc["Critical", "Average days to fix"] == 3.0
    assert ttf.loc["High", "Fixed"] == 1 and ttf.loc["High", "Typical days to fix (median)"] == 10.0
    assert ttf.loc["High", "Still open"] == 1 and ttf.loc["High", "Typical age of open (days)"] == 40.0


def test_project_change_and_overall_change(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    pc = tr.project_change(conn, 30, now=NOW).iloc[0]
    # 30 days ago: a resolved at 37 -> no; b open; c not yet -> 1 open. Now: b, d -> 2.
    assert pc["Open 30 days ago"] == 1 and pc["Open now"] == 2 and pc["Trend"] == "Worse" and pc["Change"] == "+100%"
    oc = tr.overall_change(conn, None, 30, now=NOW)
    assert oc["enough_history"] and oc["change_pct"] == 100
    # A decision removes the finding from the counts from that moment on.
    fid = conn.execute("SELECT id FROM findings WHERE dedup_key='d'").fetchone()[0]
    tri.set_decision(conn, fid, "FALSE_POSITIVE", "test value only")
    assert tr.open_over_time(conn, days=30).iloc[-1]["Low"] == 0


def test_not_enough_history_is_said_plainly(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    conn.execute("DELETE FROM scan_runs WHERE finished_at < ?", (_iso(10),))
    pc = tr.project_change(conn, 30, now=NOW).iloc[0]
    assert pc["Trend"].startswith("Not enough history") and pc["Change"] == "-"
    assert tr.overall_change(conn, None, 30, now=NOW)["change_pct"] is None


def test_empty_database(tmp_path: Path) -> None:
    conn = init_db(tmp_path / "e.db")
    assert tr.open_over_time(conn, days=30).to_numpy().sum() == 0
    assert tr.new_vs_fixed(conn, days=30)["New"].sum() == 0
    assert tr.time_to_fix(conn)["Fixed"].sum() == 0
    assert tr.history_span_days(conn) == 0
    assert date.today()  # sanity
