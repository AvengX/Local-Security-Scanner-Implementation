"""Trends: how the security picture changes over time, built from the history every scan already records.

* open_over_time  - how many issues were open at the end of each day/week, per severity or per type
* new_vs_fixed    - issues found for the first time vs issues confirmed fixed, per week
* time_to_fix     - how many days issues stayed open before a scan confirmed them fixed, per severity
* project_change  - open issues per project now vs N days ago (better / worse / same)

"Open at a moment" = first seen on or before it, and not resolved by then. Findings that a person marked as false
positive / accepted / archived are left out from the moment of that decision (same rule as everywhere else).
The same problem reported by two scanners counts once (repository + dedup key).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
CATS = {"VULNERABILITY": "Vulnerable libraries", "SECRET": "Leaked secrets", "CODE": "Code issues",
        "WEB": "Web app issues", "MISCONFIGURATION": "Unsafe settings", "LICENSE": "Licences"}


def _ts(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, utc=True, errors="coerce", format="ISO8601")


def history_frame(conn: sqlite3.Connection, repository_id: int | None = None) -> pd.DataFrame:
    """One row per distinct problem (repository + dedup key) with first seen, resolved and decision times."""
    sql = ("SELECT f.repository_id, r.name AS repository, f.dedup_key, f.category, f.severity, f.status, "
           "f.first_seen, f.resolved_at, t.decided_at FROM findings f JOIN repositories r ON r.id=f.repository_id "
           "LEFT JOIN finding_triage t ON t.finding_id=f.id")
    params: tuple = ()
    if repository_id is not None:
        sql += " WHERE f.repository_id=?"
        params = (repository_id,)
    else:
        sql += " WHERE r.active=1"
    cur = conn.execute(sql, params)
    df = pd.DataFrame([tuple(r) for r in cur.fetchall()], columns=[c[0] for c in cur.description])
    if df.empty:
        return df
    df["first"] = _ts(df["first_seen"])
    # A problem resolved in one scanner but still open in another is still open: take the latest resolution only
    # when every row of the group is resolved.
    df["resolved"] = _ts(df["resolved_at"]).where(df["status"] == "RESOLVED")
    df["decided"] = _ts(df["decided_at"])
    g = df.groupby(["repository_id", "dedup_key"], as_index=False).agg(
        repository=("repository", "first"), category=("category", "first"),
        severity=("severity", lambda s: min(s, key=lambda x: SEVS.index(x) if x in SEVS else 9)),
        first=("first", "min"), resolved=("resolved", lambda s: s.max() if s.notna().all() else pd.NaT),
        decided=("decided", "min"))
    return g


def _utc(now: datetime | None) -> pd.Timestamp:
    t = pd.Timestamp(now or datetime.now(timezone.utc))
    return t.tz_localize("UTC") if t.tzinfo is None else t.tz_convert("UTC")


def _points(days: int, now: datetime | None) -> list[pd.Timestamp]:
    """End of each day (periods up to a month) or each week (longer periods), oldest first, ending today."""
    step = 1 if days <= 31 else 7
    end = _utc(now).normalize() + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
    return [end - pd.Timedelta(days=step * i) for i in range(days // step, -1, -1)]


def _open_at(h: pd.DataFrame, t: pd.Timestamp) -> pd.DataFrame:
    if h.empty:
        return h
    m = (h["first"] <= t) & (h["resolved"].isna() | (h["resolved"] > t)) & (h["decided"].isna() | (h["decided"] > t))
    return h[m]


def open_over_time(conn: sqlite3.Connection, repository_id: int | None = None, days: int = 90,
                   by: str = "severity", now: datetime | None = None) -> pd.DataFrame:
    """Index = date; one column per severity (or type) with the number of open issues at the end of that day."""
    h = history_frame(conn, repository_id)
    rows = []
    for t in _points(days, now):
        o = _open_at(h, t)
        if by == "category":
            counts = {CATS.get(c, c.title()): int((o["category"] == c).sum()) if not o.empty else 0 for c in CATS}
        else:
            counts = {s.title(): int((o["severity"] == s).sum()) if not o.empty else 0 for s in SEVS[:4]}
        rows.append({"date": t.date(), **counts})
    df = pd.DataFrame(rows).set_index("date") if rows else pd.DataFrame()
    if by == "category" and not df.empty:
        df = df.loc[:, (df != 0).any(axis=0)] if (df != 0).any().any() else df.iloc[:, :0]
    return df


def new_vs_fixed(conn: sqlite3.Connection, repository_id: int | None = None, days: int = 90,
                 now: datetime | None = None) -> pd.DataFrame:
    """Per week (Monday): issues seen for the first time, and issues confirmed fixed by a scan."""
    h = history_frame(conn, repository_id)
    now_ts = _utc(now)
    start = (now_ts - pd.Timedelta(days=days)).normalize()
    w = start - pd.Timedelta(days=start.weekday())
    rows = []
    while w <= now_ts:
        e = w + pd.Timedelta(days=7)
        new = int(((h["first"] >= w) & (h["first"] < e)).sum()) if not h.empty else 0
        fixed = int(((h["resolved"] >= w) & (h["resolved"] < e)).sum()) if not h.empty else 0
        rows.append({"week": w.date(), "New": new, "Fixed": fixed})
        w = e
    return pd.DataFrame(rows).set_index("week") if rows else pd.DataFrame(columns=["New", "Fixed"])


def time_to_fix(conn: sqlite3.Connection, repository_id: int | None = None,
                now: datetime | None = None) -> pd.DataFrame:
    """Per severity: fixed count, average and median days to fix, and the median age of what is still open."""
    h = history_frame(conn, repository_id)
    now_ts = _utc(now)
    rows = []
    for s in SEVS[:4]:
        hs = h[h["severity"] == s] if not h.empty else h
        fixed = hs[hs["resolved"].notna()] if not hs.empty else hs
        days = ((fixed["resolved"] - fixed["first"]).dt.total_seconds() / 86400) if not fixed.empty else pd.Series()
        still = hs[hs["resolved"].isna() & hs["decided"].isna()] if not hs.empty else hs
        age = ((now_ts - still["first"]).dt.total_seconds() / 86400) if not still.empty else pd.Series()
        rows.append({"Severity": s.title(), "Fixed": int(len(fixed)),
                     "Average days to fix": round(float(days.mean()), 1) if len(days) else None,
                     "Typical days to fix (median)": round(float(days.median()), 1) if len(days) else None,
                     "Still open": int(len(still)),
                     "Typical age of open (days)": round(float(age.median()), 1) if len(age) else None})
    return pd.DataFrame(rows)


def project_change(conn: sqlite3.Connection, days: int = 30, now: datetime | None = None) -> pd.DataFrame:
    """Per active project: open issues now vs `days` ago, and whether that is better, worse or the same."""
    h = history_frame(conn)
    t_now = _points(days, now)[-1]
    t_then = t_now - pd.Timedelta(days=days)
    first_scan = {r[0]: r[1] for r in conn.execute(
        "SELECT r.name, MIN(s.finished_at) FROM repositories r JOIN scan_runs s ON s.repository_id=r.id "
        "WHERE r.active=1 AND s.status IN ('COMPLETED','COMPLETED_WITH_FINDINGS') GROUP BY r.name")}
    names = [r[0] for r in conn.execute("SELECT name FROM repositories WHERE active=1 ORDER BY name COLLATE NOCASE")]
    rows = []
    for name in names:
        hp = h[h["repository"] == name] if not h.empty else h
        a, b = len(_open_at(hp, t_then)), len(_open_at(hp, t_now))
        crit_now = int((_open_at(hp, t_now)["severity"].isin(["CRITICAL", "HIGH"])).sum()) if not hp.empty else 0
        scanned = first_scan.get(name)
        if not scanned or _utc(pd.Timestamp(scanned).to_pydatetime()) > t_then:
            trend, pct = f"Not enough history yet (first scanned {str(scanned or 'never')[:10]})", "-"
        else:
            trend = "Better" if b < a else ("Worse" if b > a else "Same")
            pct = f"{(b - a) / a * 100:+.0f}%" if a else ("new" if b else "-")
        rows.append({"Project": name, f"Open {days} days ago": a, "Open now": b, "Change": pct, "Trend": trend,
                     "Critical + high now": crit_now})
    return pd.DataFrame(rows)


def overall_change(conn: sqlite3.Connection, repository_id: int | None = None, days: int = 30,
                   now: datetime | None = None) -> dict[str, Any]:
    """Open now vs `days` ago for a one-line summary."""
    h = history_frame(conn, repository_id)
    t_now = _points(days, now)[-1]
    a, b = len(_open_at(h, t_now - pd.Timedelta(days=days))), len(_open_at(h, t_now))
    first = h["first"].min() if not h.empty else None
    span = (t_now - first).days if first is not None and pd.notna(first) else 0
    enough = history_span_days(conn) >= days
    return {"then": a, "now": b, "days": days, "history_days": span, "enough_history": enough,
            "change_pct": round((b - a) / a * 100) if a and enough else None}


def history_span_days(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MIN(finished_at), MAX(finished_at) FROM scan_runs WHERE status IN "
                       "('COMPLETED','COMPLETED_WITH_FINDINGS')").fetchone()
    if not row or not row[0]:
        return 0
    a, b = pd.Timestamp(row[0]), pd.Timestamp(row[1])
    return int((b - a) / timedelta(days=1))
