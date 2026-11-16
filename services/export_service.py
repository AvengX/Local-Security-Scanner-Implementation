"""Local report exports: findings CSV, consolidated JSON, Markdown/HTML summaries, per-repository reports."""

from __future__ import annotations

import html
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from engine.scanner_health import DbFreshness
from services import analytics_service as an
from utils.validators import SEVERITIES

EXPORT_COLUMNS = ["id", "repository", "scanner", "scan_type", "category", "severity", "status", "identifier",
                  "package_name", "installed_version", "fixed_version", "file_path", "line", "title",
                  "remediation", "reference_url", "first_seen", "last_seen", "resolved_at"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:60] or "all"


def findings_csv_bytes(df: pd.DataFrame) -> bytes:
    cols = [c for c in EXPORT_COLUMNS if c in df.columns]
    frame = df[cols] if not df.empty else pd.DataFrame(columns=EXPORT_COLUMNS)
    # Neutralise spreadsheet formula injection in text cells.
    frame = frame.map(lambda v: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v)
    return frame.to_csv(index=False).encode("utf-8-sig")


def consolidated_data(conn: sqlite3.Connection, repository_id: int | None = None,
                      freshness: DbFreshness | None = None) -> dict[str, Any]:
    findings = an.findings_frame(conn, repository_id)
    history = an.scan_history(conn, repository_id, limit=5000)
    repos = an.repository_table(conn)
    if repository_id is not None and not repos.empty:
        repos = repos[repos["id"] == repository_id]
    to_records = lambda d: json.loads(d.to_json(orient="records")) if not d.empty else []  # noqa: E731
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "Local Security Scanner",
        "scope": "repository" if repository_id is not None else "all",
        "vulnerability_db": vars(freshness) if freshness else None,
        "metrics": an.overview_metrics(conn) if repository_id is None else None,
        "repositories": to_records(repos),
        "scan_runs": to_records(history.drop(columns=["report_path"], errors="ignore")),
        "findings": to_records(findings.drop(columns=["fingerprint"], errors="ignore")),
    }


def consolidated_json_bytes(conn: sqlite3.Connection, repository_id: int | None = None,
                            freshness: DbFreshness | None = None) -> bytes:
    return json.dumps(consolidated_data(conn, repository_id, freshness), indent=2, default=str).encode("utf-8")


def summary_markdown(conn: sqlite3.Connection, repository_id: int | None = None,
                     freshness: DbFreshness | None = None) -> str:
    data = consolidated_data(conn, repository_id, freshness)
    findings = pd.DataFrame(data["findings"])
    active = findings[findings["status"].isin(an.ACTIVE)] if not findings.empty else findings
    title = "Security Summary Report"
    if repository_id is not None and data["repositories"]:
        title += f" — {data['repositories'][0]['name']}"
    lines = [f"# {title}", "", f"Generated: {data['generated_at']} (local, offline-capable)", ""]
    if freshness:
        lines += [f"**Vulnerability DB:** {freshness.message}", ""]
    lines += ["## Open findings by severity", "", "| Severity | Count |", "|---|---|"]
    for s in SEVERITIES:
        n = int((active["severity"] == s).sum()) if not active.empty else 0
        lines.append(f"| {s} | {n} |")
    lines += ["", "## Repositories", "", "| Repository | Branch | Last scan | Critical | High | Open |",
              "|---|---|---|---|---|---|"]
    for r in data["repositories"]:
        lines.append(f"| {r['name']} | {r.get('branch') or ''} | {r.get('last_scan') or 'never'} | "
                     f"{r.get('critical', 0)} | {r.get('high', 0)} | {r.get('open_findings', 0)} |")
    failed = [s for s in data["scan_runs"] if s["status"] in an.FAILED][:20]
    if failed:
        lines += ["", "## Failed / incomplete scans (findings from these were NOT resolved)", "",
                  "| Run | Repository | Scanner | Status | Error |", "|---|---|---|---|---|"]
        for s in failed:
            err = (s.get("error_message") or "").replace("|", "/").replace("\n", " ")[:160]
            lines.append(f"| {s['id']} | {s['repository']} | {s['scanner']}:{s['scan_type']} | {s['status']} | {err} |")
    if not active.empty:
        lines += ["", "## Top open findings", "", "| Severity | Repository | Identifier | Package / File | Fix |",
                  "|---|---|---|---|---|"]
        for _, f in active.head(50).iterrows():
            where = f.get("package_name") or f.get("file_path") or ""
            lines.append(f"| {f['severity']} | {f['repository']} | {f.get('identifier') or ''} | {where} | "
                         f"{f.get('fixed_version') or ''} |")
        if (active["category"] == "SECRET").any():
            lines += ["", "> **Secrets detected.** Values are never stored or displayed. If a credential is real, "
                      "revoke and rotate it with the issuing provider before cleaning it from history."]
    return "\n".join(lines) + "\n"


def summary_html(markdown_text: str) -> str:
    """Minimal, dependency-free Markdown table/heading rendering to standalone HTML."""
    body: list[str] = []
    in_table = False
    for line in markdown_text.splitlines():
        if line.startswith("|"):
            cells = [html.escape(c.strip()) for c in line.strip("|").split("|")]
            if set("".join(cells)) <= {"-", ""}:
                continue
            if not in_table:
                body.append("<table>")
                in_table = True
                body.append("<tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr>")
            else:
                body.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("> "):
            body.append(f"<blockquote>{html.escape(line[2:]).replace('**', '')}</blockquote>")
        elif line.strip():
            body.append(f"<p>{html.escape(line).replace('**', '')}</p>")
    if in_table:
        body.append("</table>")
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1f2937}table{border-collapse:collapse;"
           "margin:8px 0 20px}th,td{border:1px solid #d1d5db;padding:6px 10px;font-size:13px;text-align:left}"
           "th{background:#f3f4f6}h1{color:#111827}h2{color:#374151;border-bottom:1px solid #e5e7eb}"
           "blockquote{background:#fef3c7;padding:10px;border-left:4px solid #f59e0b}")
    return (f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Security Summary</title>"
            f"<style>{css}</style></head><body>{''.join(body)}</body></html>")


def write_export(reports_dir: Path, name: str, content: bytes | str) -> Path:
    folder = reports_dir / "exports"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    return path


def export_bundle(conn: sqlite3.Connection, reports_dir: Path, repository_id: int | None = None,
                  repository_name: str | None = None, formats: tuple[str, ...] = ("md", "html", "json", "csv"),
                  freshness: DbFreshness | None = None) -> list[Path]:
    """Write the requested report formats to ``reports/exports`` and return their paths."""
    base = f"{_stamp()}_{_safe(repository_name or 'all')}"
    out: list[Path] = []
    md = summary_markdown(conn, repository_id, freshness) if {"md", "html"} & set(formats) else ""
    if "md" in formats:
        out.append(write_export(reports_dir, f"{base}_summary.md", md))
    if "html" in formats:
        out.append(write_export(reports_dir, f"{base}_summary.html", summary_html(md)))
    if "json" in formats:
        out.append(write_export(reports_dir, f"{base}_consolidated.json",
                                consolidated_json_bytes(conn, repository_id, freshness)))
    if "csv" in formats:
        out.append(write_export(reports_dir, f"{base}_findings.csv",
                                findings_csv_bytes(an.findings_frame(conn, repository_id))))
    return out
