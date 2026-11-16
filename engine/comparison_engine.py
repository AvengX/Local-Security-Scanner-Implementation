"""Historical comparison of findings between comparable scans.

Rules enforced here:
* Only a *successful* scan may change findings to RESOLVED, and only findings its coverage includes
  (same scanner, scan type, target, category and severity filter).
* Findings outside the new scan's coverage are never resolved; open ones become UNVERIFIED.
* A failed / timed-out / cancelled scan resolves nothing: open findings in its scope become UNVERIFIED.
* Findings are unique per (repository, fingerprint); first_seen is preserved, last_seen updated.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from database.db import transaction, utcnow
from engine.finding_normalizer import Coverage, NormalizedFinding

ACTIVE_STATUSES = ("OPEN", "UNVERIFIED")


@dataclass
class ComparisonResult:
    new: list[int] = field(default_factory=list)
    existing: list[int] = field(default_factory=list)
    resolved: list[int] = field(default_factory=list)
    unverified: list[int] = field(default_factory=list)
    reopened: list[int] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {"new": len(self.new), "existing": len(self.existing), "resolved": len(self.resolved),
                "unverified": len(self.unverified), "reopened": len(self.reopened)}


_UPDATE_COLS = ("dedup_key", "category", "severity", "vulnerability_id", "rule_id", "package_name",
                "installed_version", "fixed_version", "file_path", "line", "title", "description",
                "remediation", "reference_url")


def _values(f: NormalizedFinding) -> tuple:
    return (f.dedup_key, f.category, f.severity, f.vulnerability_id, f.rule_id, f.package_name,
            f.installed_version, f.fixed_version, f.file_path, f.line, f.title, f.description,
            f.remediation, f.reference_url)


def _record(conn: sqlite3.Connection, run_id: int, finding_id: int, change: str, severity: str, now: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO finding_changes(scan_run_id, finding_id, change_type, severity, changed_at) "
        "VALUES (?,?,?,?,?)", (run_id, finding_id, change, severity, now),
    )


def _scope_rows(conn: sqlite3.Connection, repo_id: int, cov: Coverage) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM findings WHERE repository_id=? AND scanner=? AND scan_type=? AND scan_target=?",
        (repo_id, cov.scanner, cov.scan_type, cov.scan_target),
    ).fetchall()


def apply_scan_results(conn: sqlite3.Connection, repo_id: int, run_id: int, coverage: Coverage,
                       findings: list[NormalizedFinding]) -> ComparisonResult:
    """Persist findings of a successful scan and classify NEW / EXISTING / RESOLVED / UNVERIFIED."""
    now = utcnow()
    result = ComparisonResult()
    current = {f.fingerprint: f for f in findings}
    with transaction(conn):
        known = {r["fingerprint"]: r for r in _scope_rows(conn, repo_id, coverage)}
        for fp, f in current.items():
            row = known.get(fp)
            if row is None:
                # The fingerprint could exist under another scope only if hashing collided; guard anyway.
                cur = conn.execute(
                    "INSERT INTO findings(scan_run_id, repository_id, fingerprint, scanner, scan_type, scan_target, "
                    f"{', '.join(_UPDATE_COLS)}, metadata_json, first_seen, last_seen, status) "
                    f"VALUES (?,?,?,?,?,?,{','.join('?' * len(_UPDATE_COLS))},?,?,?,'OPEN') "
                    "ON CONFLICT(repository_id, fingerprint) DO UPDATE SET last_seen=excluded.last_seen, "
                    "status='OPEN', scan_run_id=excluded.scan_run_id RETURNING id",
                    (run_id, repo_id, fp, f.scanner, f.scan_type, f.scan_target, *_values(f),
                     f.metadata_json(), now, now),
                )
                fid = int(cur.fetchone()[0])
                result.new.append(fid)
                _record(conn, run_id, fid, "NEW", f.severity, now)
                continue
            fid = int(row["id"])
            change = "EXISTING"
            if row["status"] == "RESOLVED":
                change = "NEW"
                result.new.append(fid)
                result.reopened.append(fid)
            else:
                result.existing.append(fid)
            conn.execute(
                f"UPDATE findings SET {', '.join(c + '=?' for c in _UPDATE_COLS)}, metadata_json=?, "
                "scan_run_id=?, last_seen=?, status='OPEN', resolved_at=NULL WHERE id=?",
                (*_values(f), f.metadata_json(), run_id, now, fid),
            )
            _record(conn, run_id, fid, change, f.severity, now)

        for fp, row in known.items():
            if fp in current or row["status"] not in ACTIVE_STATUSES:
                continue
            fid = int(row["id"])
            if coverage.covers(row["scanner"], row["scan_type"], row["scan_target"], row["category"],
                               row["severity"]):
                conn.execute("UPDATE findings SET status='RESOLVED', resolved_at=? WHERE id=?", (now, fid))
                result.resolved.append(fid)
                _record(conn, run_id, fid, "RESOLVED", row["severity"], now)
            elif row["status"] == "OPEN":
                conn.execute("UPDATE findings SET status='UNVERIFIED' WHERE id=?", (fid,))
                result.unverified.append(fid)
                _record(conn, run_id, fid, "UNVERIFIED", row["severity"], now)
    return result


def mark_unverified_after_failure(conn: sqlite3.Connection, repo_id: int, run_id: int, scanner: str,
                                  scan_type: str, scan_target: str) -> list[int]:
    """A failed scan cannot confirm anything: open findings in its scope become UNVERIFIED (never RESOLVED)."""
    now = utcnow()
    ids: list[int] = []
    with transaction(conn):
        for row in conn.execute(
            "SELECT id, severity FROM findings WHERE repository_id=? AND scanner=? AND scan_type=? "
            "AND scan_target=? AND status='OPEN'", (repo_id, scanner, scan_type, scan_target),
        ).fetchall():
            conn.execute("UPDATE findings SET status='UNVERIFIED' WHERE id=?", (row["id"],))
            _record(conn, run_id, int(row["id"]), "UNVERIFIED", row["severity"], now)
            ids.append(int(row["id"]))
    return ids


def compare_runs(conn: sqlite3.Connection, older_run_id: int, newer_run_id: int) -> dict[str, list[int]]:
    """Compare the finding sets observed by two runs (NEW/EXISTING observations) — for history views.

    Refuses to compare runs whose coverage differs or which were not successful.
    """
    runs = {r["id"]: r for r in conn.execute(
        "SELECT id, repository_id, status, coverage FROM scan_runs WHERE id IN (?,?)",
        (older_run_id, newer_run_id))}
    for rid in (older_run_id, newer_run_id):
        r = runs.get(rid)
        if r is None:
            raise ValueError(f"Scan run {rid} not found")
        if r["status"] not in ("COMPLETED", "COMPLETED_WITH_FINDINGS"):
            raise ValueError(f"Scan run {rid} was not successful ({r['status']}); not comparable")
    if runs[older_run_id]["repository_id"] != runs[newer_run_id]["repository_id"]:
        raise ValueError("Scan runs belong to different repositories and cannot be compared")
    if runs[older_run_id]["coverage"] != runs[newer_run_id]["coverage"]:
        raise ValueError("Scan runs have different coverage and cannot be compared")

    def seen(rid: int) -> set[int]:
        return {r[0] for r in conn.execute(
            "SELECT finding_id FROM finding_changes WHERE scan_run_id=? AND change_type IN ('NEW','EXISTING')",
            (rid,))}

    a, b = seen(older_run_id), seen(newer_run_id)
    return {"new": sorted(b - a), "existing": sorted(a & b), "resolved": sorted(a - b)}
