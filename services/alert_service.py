"""Alerts: tell someone when a scan batch finds NEW serious problems.

After every scan batch (manual, dashboard or scheduled) the findings that were seen for the first time in that
batch, at or above ``alerts.min_severity`` and not already decided (triage), become one alert:
* stored in the ``alerts`` table and shown in the dashboard until marked as read;
* optionally shown as a Windows notification (built-in Windows toast API via PowerShell - nothing to install);
* optionally posted to an https webhook (Teams, Slack, ntfy ...) as a short text.

Only counts, project names, check / advisory IDs, package names and file paths are used - never secret values
(they are never stored) and never source code.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import urllib.request
from typing import Any

from database.db import utcnow
from utils.config import AppConfig
from utils.logger import get_logger

log = get_logger(__name__)
SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
RANK = {s: i for i, s in enumerate(SEVS)}
CAT = {"VULNERABILITY": "vulnerable libraries", "SECRET": "leaked secrets", "CODE": "code issues",
       "WEB": "web app issues", "MISCONFIGURATION": "unsafe settings", "LICENSE": "licence issues"}
CREATE_NO_WINDOW = 0x08000000

_TOAST_PS = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$t = [Security.SecurityElement]::Escape($env:LSS_TOAST_TITLE)
$b = [Security.SecurityElement]::Escape($env:LSS_TOAST_BODY)
$xml = "<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>"
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toast)
"""


def _label(r: sqlite3.Row) -> str:
    if r["category"] == "VULNERABILITY":
        return f"{r['package_name']} {r['installed_version']} ({r['vulnerability_id']})"
    where = r["file_path"] or ""
    if r["category"] == "WEB":
        where = f"{r['scan_target']} {where}".strip()
    return f"{r['rule_id'] or r['title']} in {where}".strip()


def build_alert(conn: sqlite3.Connection, batch_id: str, min_severity: str = "HIGH") -> dict[str, Any] | None:
    """New, undecided findings of this batch at or above min_severity, summarised. None when there are none."""
    limit = RANK.get(min_severity, 1)
    rows = conn.execute(
        "SELECT DISTINCT f.id, f.category, f.severity, f.rule_id, f.title, f.vulnerability_id, f.package_name, "
        "f.installed_version, f.file_path, f.scan_target, f.dedup_key, r.name AS repository "
        "FROM finding_changes c JOIN scan_runs s ON s.id=c.scan_run_id JOIN findings f ON f.id=c.finding_id "
        "JOIN repositories r ON r.id=f.repository_id "
        "WHERE s.batch_id=? AND c.change_type='NEW' AND f.status IN ('OPEN','UNVERIFIED') "
        "AND f.id NOT IN (SELECT finding_id FROM finding_triage)", (batch_id,)).fetchall()
    rows = [r for r in rows if RANK.get(r["severity"], 9) <= limit]
    seen: set[tuple[str, str]] = set()
    uniq = []
    for r in rows:  # the same problem reported by two scanners counts once
        key = (r["repository"], r["dedup_key"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    if not uniq:
        return None
    uniq.sort(key=lambda r: (RANK.get(r["severity"], 9), r["repository"]))
    projects: dict[str, dict[str, Any]] = {}
    for r in uniq:
        p = projects.setdefault(r["repository"], {"severity": {}, "category": {}})
        p["severity"][r["severity"]] = p["severity"].get(r["severity"], 0) + 1
        p["category"][r["category"]] = p["category"].get(r["category"], 0) + 1
    worst = uniq[0]["severity"]
    return {"batch_id": batch_id, "severity": worst, "new_count": len(uniq), "projects": projects,
            "top": [{"repository": r["repository"], "severity": r["severity"], "category": r["category"],
                     "item": _label(r)[:160]} for r in uniq[:8]]}


def alert_text(alert: dict[str, Any]) -> tuple[str, str]:
    """(title, body) in plain words."""
    n, worst = alert["new_count"], alert["severity"].title()
    title = f"Security scan: {n} new {'problem' if n == 1 else 'problems'} (worst: {worst})"
    parts = []
    for name, p in alert["projects"].items():
        cats = ", ".join(f"{c} {CAT.get(k, k.lower())}" for k, c in sorted(p["category"].items(), key=lambda kv: -kv[1]))
        parts.append(f"{name}: {cats}")
    body = "; ".join(parts)
    if alert["top"]:
        t = alert["top"][0]
        body += f". Most serious: {t['severity'].title()} - {t['item']}"
    return title, body[:600]


def notify_windows(title: str, body: str) -> str:
    """Show a Windows notification. Returns '' on success or a short error."""
    if sys.platform != "win32":
        return "not Windows"
    env = {**os.environ, "LSS_TOAST_TITLE": title[:120], "LSS_TOAST_BODY": body[:400]}
    try:
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                               "-Command", _TOAST_PS], env=env, capture_output=True, text=True, timeout=30,
                              creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"notification failed: {exc}"[:200]
    return "" if proc.returncode == 0 else f"notification failed: {(proc.stderr or proc.stdout).strip()[:160]}"


def post_webhook(url: str, title: str, body: str, alert: dict[str, Any]) -> str:
    """POST a short JSON summary (works with Teams/Slack 'text' webhooks). Returns '' or a short error."""
    payload = {"text": f"{title}\n{body}", "title": title, "severity": alert["severity"],
               "new_count": alert["new_count"],
               "projects": {k: v["severity"] for k, v in alert["projects"].items()}}
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "LocalSecurityScanner-alerts"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - https only (validated in config)
            return "" if 200 <= resp.status < 300 else f"webhook answered HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001 - delivery problems must never break a scan
        return f"webhook failed: {type(exc).__name__}"


def process_batch(conn: sqlite3.Connection, cfg: AppConfig, batch_id: str) -> int | None:
    """Create (and deliver) the alert for one finished batch. Returns the alert id, or None."""
    a = cfg.alerts
    if not a.enabled:
        return None
    alert = build_alert(conn, batch_id, a.min_severity)
    if alert is None:
        return None
    title, body = alert_text(alert)
    delivered: list[str] = []
    if a.windows_notification:
        err = notify_windows(title, body)
        delivered.append(err or "windows")
    if a.webhook_url:
        err = post_webhook(a.webhook_url, title, body, alert)
        delivered.append(err or "webhook")
    cur = conn.execute("INSERT INTO alerts(created_at, batch_id, severity, new_count, summary_json, delivered) "
                       "VALUES(?,?,?,?,?,?)", (utcnow(), batch_id, alert["severity"], alert["new_count"],
                                               json.dumps(alert), ", ".join(delivered) or "dashboard only"))
    log.info("Alert created", extra={"alert_id": cur.lastrowid, "new": alert["new_count"],
                                     "severity": alert["severity"], "delivered": delivered})
    return cur.lastrowid


def unread(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    out = []
    for r in conn.execute("SELECT * FROM alerts WHERE read_at IS NULL ORDER BY id DESC LIMIT ?", (limit,)):
        d = dict(r)
        d["summary"] = json.loads(d.pop("summary_json") or "{}")
        out.append(d)
    return out


def recent(conn: sqlite3.Connection, limit: int = 30) -> list[dict[str, Any]]:
    out = []
    for r in conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)):
        d = dict(r)
        d["summary"] = json.loads(d.pop("summary_json") or "{}")
        out.append(d)
    return out


def mark_read(conn: sqlite3.Connection, alert_id: int | None = None) -> int:
    if alert_id is None:
        return conn.execute("UPDATE alerts SET read_at=? WHERE read_at IS NULL", (utcnow(),)).rowcount
    return conn.execute("UPDATE alerts SET read_at=? WHERE id=? AND read_at IS NULL", (utcnow(), alert_id)).rowcount
