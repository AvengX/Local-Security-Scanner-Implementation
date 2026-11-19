"""Triage: human decisions about findings - false positive, accepted risk, archived.

A decision never changes the scan status (OPEN / UNVERIFIED / RESOLVED is still decided by scans). It only takes
the finding out of the open counts, the recommended actions and the reports' to-do lists, and every report lists
the decisions separately with their reasons, so nothing is hidden silently.

* FALSE_POSITIVE - the scanner is wrong here (test value, unreachable code, ...). Optional review date.
* ACCEPTED_RISK  - real, but accepted for now. A review date is required (at most one year ahead); on that date
                   the decision expires and the finding counts again.
* ARCHIVED       - no longer relevant (for example old findings inside installed-library folders that scans now
                   skip). Optional review date.
Every action is written to triage_log and shown in the finding's history.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import date, timedelta
from typing import Any

from database.db import transaction, utcnow

DECISIONS: dict[str, str] = {
    "FALSE_POSITIVE": "False positive",
    "ACCEPTED_RISK": "Accepted risk",
    "ARCHIVED": "Archived",
}
HELP: dict[str, str] = {
    "FALSE_POSITIVE": "The scanner is wrong here, for example a test value or code no user input can reach.",
    "ACCEPTED_RISK": "It is real, but you decide to live with it for now. Needs a review date - it comes back then.",
    "ARCHIVED": "No longer relevant, for example old findings in installed-library folders that are no longer "
                "scanned.",
}
MAX_REVIEW_DAYS = 366
# SQL fragment for "has no current decision"; use with the findings table aliased as f.
NOT_TRIAGED = "f.id NOT IN (SELECT finding_id FROM finding_triage)"


class TriageError(ValueError):
    pass


def _clean_reason(reason: str) -> str:
    reason = re.sub(r"\s+", " ", (reason or "")).strip()
    if len(reason) < 5:
        raise TriageError("Write a short reason (at least 5 characters) so others know why.")
    if len(reason) > 500:
        raise TriageError("Keep the reason under 500 characters.")
    return reason


def _clean_review(decision: str, review_by: date | str | None, today: date | None = None) -> str | None:
    today = today or date.today()
    if isinstance(review_by, str):
        try:
            review_by = date.fromisoformat(review_by[:10]) if review_by.strip() else None
        except ValueError as exc:
            raise TriageError("Review date must look like 2027-02-01.") from exc
    if review_by is None:
        if decision == "ACCEPTED_RISK":
            raise TriageError("An accepted risk needs a review date - the finding comes back on that date.")
        return None
    if review_by <= today:
        raise TriageError("The review date must be in the future.")
    if review_by > today + timedelta(days=MAX_REVIEW_DAYS):
        raise TriageError("Choose a review date within one year.")
    return review_by.isoformat()


def set_decision(conn: sqlite3.Connection, finding_id: int, decision: str, reason: str,
                 review_by: date | str | None = None) -> None:
    decision = (decision or "").upper()
    if decision not in DECISIONS:
        raise TriageError(f"Unknown decision {decision!r}")
    reason = _clean_reason(reason)
    review = _clean_review(decision, review_by)
    if not conn.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone():
        raise TriageError(f"Finding {finding_id} does not exist")
    now = utcnow()
    with transaction(conn):
        conn.execute("INSERT INTO finding_triage(finding_id, decision, reason, review_by, decided_at) "
                     "VALUES(?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET decision=excluded.decision, "
                     "reason=excluded.reason, review_by=excluded.review_by, decided_at=excluded.decided_at",
                     (finding_id, decision, reason, review, now))
        conn.execute("INSERT INTO triage_log(finding_id, action, reason, review_by, at) VALUES(?,?,?,?,?)",
                     (finding_id, decision, reason, review, now))


def reopen(conn: sqlite3.Connection, finding_id: int, note: str = "") -> bool:
    """Remove the decision so the finding counts again. Returns False when there was none."""
    with transaction(conn):
        cur = conn.execute("DELETE FROM finding_triage WHERE finding_id=?", (finding_id,))
        if not cur.rowcount:
            return False
        conn.execute("INSERT INTO triage_log(finding_id, action, reason, at) VALUES(?,?,?,?)",
                     (finding_id, "REOPENED", re.sub(r"\s+", " ", note).strip()[:500] or None, utcnow()))
    return True


def expire_due(conn: sqlite3.Connection, today: date | None = None) -> int:
    """Expire decisions whose review date has passed (the finding counts again). Returns how many expired."""
    day = (today or date.today()).isoformat()
    due = [r[0] for r in conn.execute("SELECT finding_id FROM finding_triage WHERE review_by IS NOT NULL AND "
                                      "review_by <= ?", (day,))]
    if not due:
        return 0
    now = utcnow()
    with transaction(conn):
        for fid in due:
            conn.execute("DELETE FROM finding_triage WHERE finding_id=?", (fid,))
            conn.execute("INSERT INTO triage_log(finding_id, action, reason, at) VALUES(?,?,?,?)",
                         (fid, "EXPIRED", "Review date reached - the finding counts again until decided anew.",
                          now))
    return len(due)


def get_decision(conn: sqlite3.Connection, finding_id: int) -> dict[str, Any] | None:
    r = conn.execute("SELECT decision, reason, review_by, decided_at FROM finding_triage WHERE finding_id=?",
                     (finding_id,)).fetchone()
    return dict(r) if r else None


def history(conn: sqlite3.Connection, finding_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT action, reason, review_by, at FROM triage_log WHERE finding_id=? "
                                          "ORDER BY id", (finding_id,))]


def decisions(conn: sqlite3.Connection, repository_id: int | None = None) -> list[dict[str, Any]]:
    """Current decisions on findings that are still reported (OPEN / UNVERIFIED), for reports."""
    sql = ("SELECT t.decision, t.reason, t.review_by, t.decided_at, f.id, f.category, f.severity, f.rule_id, "
           "f.vulnerability_id, f.package_name, f.file_path, f.line, f.title, f.scan_target, r.name AS repository "
           "FROM finding_triage t JOIN findings f ON f.id=t.finding_id JOIN repositories r ON r.id=f.repository_id "
           "WHERE f.status IN ('OPEN','UNVERIFIED')")
    params: tuple = ()
    if repository_id is not None:
        sql += " AND f.repository_id=?"
        params = (repository_id,)
    else:
        sql += " AND r.active=1"
    return [dict(r) for r in conn.execute(sql + " ORDER BY t.decision, r.name, f.severity", params)]


def _in_skipped(path: str | None, skip: set[str]) -> bool:
    return bool(skip & {p.lower() for p in re.split(r"[\\/]", path or "")})


def skipped_folder_findings(conn: sqlite3.Connection, skip_dirs: list[str]) -> list[int]:
    """Open/unverified, undecided findings inside folders that scans now skip (e.g. .venv): they can never be
    re-checked, so they can only be decided by a person."""
    skip = {d.lower() for d in skip_dirs}
    if not skip:
        return []
    rows = conn.execute(f"SELECT f.id, f.file_path FROM findings f JOIN repositories r ON r.id=f.repository_id "
                        f"WHERE r.active=1 AND f.status IN ('OPEN','UNVERIFIED') AND {NOT_TRIAGED}").fetchall()
    return [r["id"] for r in rows if _in_skipped(r["file_path"], skip)]


def archive_skipped(conn: sqlite3.Connection, skip_dirs: list[str]) -> int:
    ids = skipped_folder_findings(conn, skip_dirs)
    reason = ("Inside a folder that scans now skip (" + ", ".join(sorted(skip_dirs)[:6]) +
              "): installed third-party code that can no longer be re-checked.")
    for fid in ids:
        set_decision(conn, fid, "ARCHIVED", reason)
    return len(ids)
