"""Page 2 — Repository Management."""

from __future__ import annotations

import streamlit as st

from dashboard.common import (PAGES, empty_state, fmt_ts, get_config, get_conn, launch_background, page_header)
from database import repositories as dao
from services import analytics_service as an


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Repository Management", "Discover repositories under the configured roots and launch scans")

    if not cfg.repository_roots:
        st.warning("No repository roots configured. Add them on the Settings page.", icon=":material/settings:")

    running = conn.execute("SELECT COUNT(*) FROM scan_runs WHERE status='RUNNING'").fetchone()[0]
    a1, a2, a3, a4 = st.columns([1, 1, 1, 2])
    if a1.button("Discover repositories", icon=":material/travel_explore:", width="stretch",
                 disabled=not cfg.repository_roots):
        with st.spinner("Discovering repositories…"):
            from engine.scan_orchestrator import ScanOrchestrator

            result, stats = ScanOrchestrator(cfg).discover()
        st.toast(f"Found {len(result.repositories)} repositories · new {stats['new']} · "
                 f"moved {stats['moved']} · deactivated {stats['deactivated']}")
        for e in result.errors[:10]:
            st.warning(e)
    offline = a3.toggle("Offline scan", value=cfg.scan.offline, help="Use cached vulnerability DB only")
    if a2.button("Scan all repositories", icon=":material/play_circle:", type="primary", width="stretch",
                 disabled=not cfg.repository_roots or running > 0):
        pid = launch_background(["scan-all", "--offline" if offline else "--online"], cfg)
        st.toast(f"Scan-all started in the background (pid {pid}). Progress appears in Scan History.")
    if running:
        a4.info(f"{running} scan job(s) running — refresh to update.", icon=":material/progress_activity:")
    if a4.button("Refresh", icon=":material/refresh:"):
        st.rerun()

    df = an.repository_table(conn)
    if df.empty:
        empty_state("No repositories in the database yet. Click **Discover repositories**.")
        return

    q = st.text_input("Filter repositories", placeholder="name or path…", label_visibility="collapsed")
    view = df
    if q:
        view = df[df["name"].str.contains(q, case=False, regex=False) | df["path"].str.contains(q, case=False,
                                                                                               regex=False)]
    view = view.assign(last_scan=view["last_scan"].map(fmt_ts))
    event = st.dataframe(
        view[["name", "path", "branch", "last_commit", "last_scan", "scan_status", "critical", "high",
              "open_findings", "kind"]],
        hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
        column_config={
            "name": st.column_config.TextColumn("Repository", width="medium"),
            "path": st.column_config.TextColumn("Path", width="large"),
            "branch": "Branch", "last_commit": "Last commit", "last_scan": "Last scan",
            "scan_status": st.column_config.TextColumn("Latest scan status", width="large"),
            "critical": st.column_config.NumberColumn("Critical", format="%d"),
            "high": st.column_config.NumberColumn("High", format="%d"),
            "open_findings": st.column_config.NumberColumn("Open", format="%d"),
            "kind": "Type",
        },
    )
    rows = event.selection.rows if event and event.selection else []
    if not rows:
        st.caption("Select a repository row to scan it or view its findings and history.")
        return
    repo = view.iloc[rows[0]]
    st.subheader(repo["name"])
    st.caption(repo["path"])
    b1, b2, b3 = st.columns(3)
    if b1.button("Scan this repository", icon=":material/play_arrow:", type="primary", width="stretch"):
        pid = launch_background(["scan-repo", "--path", repo["path"], "--offline" if offline else "--online"], cfg)
        st.toast(f"Scan started for {repo['name']} (pid {pid}).")
    if b2.button("View findings", icon=":material/bug_report:", width="stretch"):
        st.session_state["findings_repo"] = [repo["name"]]
        if "findings" in PAGES:
            st.switch_page(PAGES["findings"])
    if b3.button("View scan history", icon=":material/history:", width="stretch"):
        st.session_state["history_repo"] = repo["name"]
        if "history" in PAGES:
            st.switch_page(PAGES["history"])

    runs = dao.list_scan_runs(conn, int(repo["id"]), limit=10)
    if runs:
        st.markdown("**Recent scans**")
        st.dataframe(
            [{"Run": r["id"], "Scanner": f"{r['scanner']}:{r['scan_type']}", "Status": r["status"],
              "Started": fmt_ts(r["started_at"]), "Duration (s)": r["duration"], "Findings": r["findings_count"],
              "Error": (r["error_message"] or "")[:160]} for r in runs],
            hide_index=True, width="stretch",
        )
