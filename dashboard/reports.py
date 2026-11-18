"""Reports — exports generated on demand, saved export bundles and raw scanner reports (all local)."""

from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from dashboard import theme as t
from dashboard.common import (ROW_SELECT, selected_row, fmt_bytes, fmt_ts, get_config, get_conn, get_freshness, html, notice, page_header,
                              section)
from database import repositories as dao
from services import analytics_service as an
from services import audit_report as audit
from services import export_service as ex
from services.report_service import list_reports, read_report_for_run
from utils.security import safe_report_path

MIME = {".csv": "text/csv", ".json": "application/json", ".md": "text/markdown", ".html": "text/html"}


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Reports", "Download consolidated exports and raw scanner output — generated and stored on this PC")
    freshness = get_freshness(cfg)

    repos = dao.list_repositories(conn)
    with st.container(key="panel_scope"):
        s1, s2 = st.columns([2, 3], vertical_alignment="bottom")
        choice = s1.selectbox("Report scope", ["All repositories (combined)", *[r["name"] for r in repos]])
        repo = next((r for r in repos if r["name"] == choice), None)
        repo_id = repo["id"] if repo else None
        label = repo["name"] if repo else "all"
        fdf = an.findings_frame(conn, repo_id)
        active = int(fdf["status"].isin(an.ACTIVE).sum()) if not fdf.empty else 0
        s2.markdown(f"<div class='lss-chips' style='justify-content:flex-start'>"
                    f"{t.chip(f'{active} open / unverified findings', 'warn' if active else 'ok', 'bug')}"
                    f"{t.chip(f'{len(fdf)} findings incl. resolved', 'neutral', 'database')}</div>",
                    unsafe_allow_html=True)

    section("Exports", "generated now from the database · secret values are never included")
    if not repos:
        notice("neutral", "No repositories yet", "Exports will contain data after repositories are discovered and "
               "scanned. Empty exports can still be downloaded.")
    md = ex.summary_markdown(conn, repo_id, freshness)
    with st.container(key="actions_exports"):
        c1, c2, c3, c4 = st.columns(4)
        c1.download_button("Findings CSV", ex.findings_csv_bytes(fdf), f"findings_{label}.csv", "text/csv",
                           width="stretch", icon=":material/table:")
        c2.download_button("Consolidated JSON", ex.consolidated_json_bytes(conn, repo_id, freshness),
                           f"consolidated_{label}.json", "application/json", width="stretch",
                           icon=":material/data_object:")
        c3.download_button("Summary (Markdown)", md.encode("utf-8"), f"summary_{label}.md", "text/markdown",
                           width="stretch", icon=":material/description:")
        c4.download_button("Summary (HTML)", ex.summary_html(md).encode("utf-8"), f"summary_{label}.html",
                           "text/html", width="stretch", icon=":material/html:")
    b1, b2 = st.columns([1, 3], vertical_alignment="center")
    if b1.button("Save all formats to disk", icon=":material/save:", width="stretch"):
        paths = ex.export_bundle(conn, cfg.reports_dir, repo_id, repo["name"] if repo else None, freshness=freshness)
        st.toast("Saved " + ", ".join(p.name for p in paths), icon=":material/save:")
    b2.caption(f"Saved to {cfg.reports_dir / 'exports'}")
    with st.expander("Preview summary"):
        st.markdown(md)

    _audit_report(conn, cfg, repo)
    _saved_exports(cfg)
    _raw_reports(conn, cfg, repo_id)


def _audit_report(conn, cfg, repo) -> None:  # noqa: ANN001
    section("Detailed audit report", "full VAPT-style report for one repository · print to PDF from the browser")
    if repo is None:
        notice("neutral", "Choose one repository", "The detailed audit report covers a single repository. Pick it in "
               "“Report scope” above.")
        return
    st.caption("Repository and scan metadata, executive summary, deduplicated counts, severity distribution, every "
               "vulnerability with CVSS / CWE / fixed versions / dependency path, direct vs transitive, remediation, "
               "secrets (never their values), misconfigurations, code issues (SAST), web app issues (DAST), references and methodology.")
    c1, c2 = st.columns([1, 3], vertical_alignment="center")
    if c1.button("Generate audit report", icon=":material/assignment:", type="primary", width="stretch",
                 key="audit_generate"):
        try:
            with st.spinner("Building the audit report…"):
                name, doc, data = audit.generate_audit(conn, cfg, repo["id"])
                path = ex.write_export(cfg.reports_dir, name, doc)
        except Exception as exc:  # noqa: BLE001 — show the reason instead of a stack trace
            notice("err", "Could not build the audit report", str(exc))
            return
        st.session_state["audit_last"] = {"repo_id": repo["id"], "path": str(path), "name": name,
                                          "status": audit.scan_status(data), "active": len(data["active"]),
                                          "vulns": len(data["vulns"]), "secrets": len(data["secrets"]),
                                          "misconfs": len(data["misconfs"]), "code": len(data.get("code", [])),
                                          "web": len(data.get("web", []))}
    last = st.session_state.get("audit_last")
    if not last or last["repo_id"] != repo["id"]:
        c2.caption("Generates an HTML file in reports/exports. Open it and choose Print → Save as PDF for a PDF copy.")
        return
    try:
        path = safe_report_path(last["path"], cfg.reports_dir)
    except (PermissionError, FileNotFoundError) as exc:
        notice("err", "Report file not available", str(exc))
        return
    status, note = last["status"]
    c2.markdown(f"<div class='lss-chips' style='justify-content:flex-start'>"
                f"{t.chip(f'Scan status: {status}', 'ok' if status == 'COMPLETED' else 'warn', 'shield_check')}"
                f"{t.chip(f'{last['vulns']} vulnerabilities', 'neutral', 'package')}"
                f"{t.chip(f'{last['secrets']} secrets', 'neutral', 'key')}"
                f"{t.chip(f'{last.get('code', 0)} code issues', 'neutral', 'code')}"
                f"{t.chip(f'{last.get('web', 0)} web app issues', 'neutral', 'globe')}"
                f"{t.chip(f'{last['misconfs']} misconfigurations', 'neutral', 'sliders')}</div>",
                unsafe_allow_html=True)
    d1, d2 = st.columns([1, 3], vertical_alignment="center")
    d1.download_button("Download report (HTML)", path.read_bytes(), path.name, "text/html", icon=":material/download:",
                       width="stretch", key="audit_download")
    d2.caption(f"Saved to {path} · open it in a browser and choose Print → Save as PDF. {note}")


def _saved_exports(cfg) -> None:  # noqa: ANN001
    exports = cfg.reports_dir / "exports"
    files = sorted((p for p in exports.glob("*") if p.is_file() and p.suffix in MIME),
                   key=lambda p: p.stat().st_mtime, reverse=True)[:60] if exports.is_dir() else []
    section("Saved export files", f"{len(files)} file(s) in reports/exports")
    if not files:
        st.caption("No saved exports yet. Use “Save all formats to disk” or `python run_scan.py report`.")
        return
    labels = {p.name: f"{p.name} · {fmt_bytes(p.stat().st_size)} · "
                      f"{datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC"
              for p in files}
    c1, c2 = st.columns([3, 1], vertical_alignment="bottom")
    name = c1.selectbox("Saved export", list(labels), format_func=labels.get)
    try:
        path = safe_report_path(str(exports / name), cfg.reports_dir)
        c2.download_button("Download", path.read_bytes(), path.name, MIME.get(path.suffix, "application/octet-stream"),
                           icon=":material/download:", width="stretch", key="dl_saved")
    except (PermissionError, FileNotFoundError) as exc:
        notice("err", "File not available", str(exc))


def _raw_reports(conn, cfg, repo_id) -> None:  # noqa: ANN001
    section("Raw scanner reports", "only reports registered in the database and inside the reports folder")
    tool = st.segmented_control("Scanner", ["trivy", "gitleaks", "bandit", "dast"], default="trivy", key="raw_tool",
                                format_func=str.title) or "trivy"
    entries = list_reports(conn, cfg.reports_dir, scanner=tool, repository_id=repo_id)
    if not entries:
        notice("neutral", f"No {tool.title()} reports for this scope",
               "Raw reports are written for every successful scanner run.")
        return
    total = sum(e.size for e in entries)
    st.caption(f"{len(entries)} report(s) · {fmt_bytes(total)}")
    rows = [{"Run": e.run_id, "Repository": e.repository, "Type": e.scan_type,
             "Status": t.STATUS_LABELS.get(e.status, e.status), "Scan date": fmt_ts(e.started_at),
             "Size": fmt_bytes(e.size)} for e in entries]
    event = st.dataframe(rows, hide_index=True, width="stretch", on_select="rerun", selection_mode=ROW_SELECT,
                         height=min(360, 40 + 35 * len(rows)), key=f"raw_table_{tool}")
    row = selected_row(event)
    entry = entries[row] if row is not None and row < len(entries) else entries[0]
    try:
        name, data = read_report_for_run(conn, entry.run_id, cfg.reports_dir)
    except (PermissionError, FileNotFoundError) as exc:
        notice("err", "Report not available", str(exc))
        return
    c1, c2 = st.columns([1, 2], vertical_alignment="center")
    c1.download_button(f"Download run #{entry.run_id}", data, name, "application/json", icon=":material/download:",
                       width="stretch", key="dl_raw")
    c2.caption(f"{name} · click a row to choose another report. "
               + ("Trivy masks secret matches; treat raw reports as sensitive local files." if tool == "trivy" else
                  "Gitleaks reports are generated with --redact (secret values replaced by REDACTED)."))
