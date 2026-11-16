"""Page 5 — Reports: raw scanner reports (DB-registered, inside reports dir only) and exports."""

from __future__ import annotations

import streamlit as st

from dashboard.common import empty_state, fmt_ts, get_config, get_conn, get_freshness, page_header
from database import repositories as dao
from services import analytics_service as an
from services import export_service as ex
from services.report_service import list_reports, read_report_for_run


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Reports", "Download raw scanner output and consolidated exports — generated and stored locally")
    freshness = get_freshness(cfg)

    repos = dao.list_repositories(conn)
    names = ["All repositories", *[r["name"] for r in repos]]
    choice = st.selectbox("Scope", names)
    repo = next((r for r in repos if r["name"] == choice), None)
    repo_id = repo["id"] if repo else None
    label = repo["name"] if repo else "all"

    st.subheader("Exports")
    c1, c2, c3, c4 = st.columns(4)
    fdf = an.findings_frame(conn, repo_id)
    c1.download_button("Findings CSV", ex.findings_csv_bytes(fdf), f"findings_{label}.csv", "text/csv",
                       width="stretch", icon=":material/table:")
    c2.download_button("Consolidated JSON", ex.consolidated_json_bytes(conn, repo_id, freshness),
                       f"consolidated_{label}.json", "application/json", width="stretch", icon=":material/data_object:")
    md = ex.summary_markdown(conn, repo_id, freshness)
    c3.download_button("Summary (Markdown)", md.encode("utf-8"), f"summary_{label}.md", "text/markdown",
                       width="stretch", icon=":material/description:")
    c4.download_button("Summary (HTML)", ex.summary_html(md).encode("utf-8"), f"summary_{label}.html",
                       "text/html", width="stretch", icon=":material/html:")
    if st.button("Save all formats to reports/exports", icon=":material/save:"):
        paths = ex.export_bundle(conn, cfg.reports_dir, repo_id, repo["name"] if repo else None, freshness=freshness)
        st.success("Saved: " + ", ".join(p.name for p in paths))
    with st.expander("Preview summary"):
        st.markdown(md)

    st.subheader("Raw scanner reports")
    tool = st.radio("Scanner", ["trivy", "gitleaks"], horizontal=True)
    entries = list_reports(conn, cfg.reports_dir, scanner=tool, repository_id=repo_id)
    if not entries:
        empty_state(f"No {tool} reports available for this scope.")
        return
    labels = {e.run_id: f"#{e.run_id} · {e.repository} · {e.scan_type} · {e.status} · {fmt_ts(e.started_at)} · "
                        f"{e.size / 1024:.1f} KB" for e in entries}
    run_id = st.selectbox("Report", list(labels), format_func=labels.get)
    try:
        name, data = read_report_for_run(conn, run_id, cfg.reports_dir)
    except (PermissionError, FileNotFoundError) as exc:
        st.error(str(exc))
        return
    st.download_button(f"Download {name}", data, name, "application/json", icon=":material/download:")
    if tool == "trivy":
        st.caption("Trivy masks secret matches in its raw output; treat raw reports as sensitive local files.")
    else:
        st.caption("Gitleaks reports are generated with --redact, so secret values are replaced with REDACTED.")
