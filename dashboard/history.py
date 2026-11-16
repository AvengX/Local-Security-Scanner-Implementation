"""Page 4 — Scan History with historical comparison and trends."""

from __future__ import annotations

import plotly.express as px
import streamlit as st

from dashboard.common import (PLOTLY_LAYOUT, STATUS_COLORS, empty_state, fmt_ts, get_config, get_conn,
                              page_header)
from engine.comparison_engine import compare_runs
from services import analytics_service as an


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Scan History", "Every scanner execution, its outcome and historical comparisons")
    df = an.scan_history(conn, limit=5000)
    if df.empty:
        empty_state("No scans have been run yet.")
        return

    repos = sorted(df["repository"].unique().tolist())
    pre = st.session_state.pop("history_repo", None)
    c1, c2, c3 = st.columns(3)
    sel_repo = c1.selectbox("Repository", ["All", *repos], index=(repos.index(pre) + 1) if pre in repos else 0)
    sel_tool = c2.multiselect("Tool", sorted(df["scanner"].unique().tolist()))
    sel_status = c3.multiselect("Status", sorted(df["status"].unique().tolist()))
    view = df
    if sel_repo != "All":
        view = view[view["repository"] == sel_repo]
    if sel_tool:
        view = view[view["scanner"].isin(sel_tool)]
    if sel_status:
        view = view[view["status"].isin(sel_status)]

    t1, t2 = st.columns(2)
    with t1:
        sc = view.assign(day=view["started_at"].str[:10]).groupby(["day", "status"]).size().reset_index(name="scans")
        fig = px.bar(sc, x="day", y="scans", color="status", color_discrete_map=STATUS_COLORS, title="Scans per day")
        fig.update_layout(**PLOTLY_LAYOUT)
        fig.update_xaxes(type="category")
        st.plotly_chart(fig, width="stretch")
    with t2:
        ok = view[view["status"].isin(an.SUCCESS)]
        if ok.empty:
            empty_state("No successful scans in this selection.")
        else:
            ok = ok.assign(label=ok["scanner"] + ":" + ok["scan_type"])
            fig = px.line(ok.sort_values("started_at"), x="started_at", y="findings_count", color="label",
                          markers=True, line_group="repository", hover_data=["repository", "new_count",
                                                                             "resolved_count"],
                          title="Findings per successful scan")
            fig.update_layout(**PLOTLY_LAYOUT)
            st.plotly_chart(fig, width="stretch")

    show = view.assign(started_at=view["started_at"].map(fmt_ts), offline=view["offline"].map(bool),
                       tool=view["scanner"] + ":" + view["scan_type"])
    st.dataframe(
        show[["id", "started_at", "repository", "tool", "scan_target", "status", "duration", "findings_count",
              "new_count", "resolved_count", "tool_version", "offline", "exit_code", "error_message"]],
        hide_index=True, width="stretch", height=420,
        column_config={
            "id": "Run", "started_at": "Scan date", "repository": "Repository", "tool": "Tool",
            "scan_target": "Target", "status": "Status", "duration": st.column_config.NumberColumn("Duration (s)",
                                                                                                    format="%.1f"),
            "findings_count": "Findings", "new_count": "New", "resolved_count": "Resolved",
            "tool_version": "Version", "offline": "Offline", "exit_code": "Exit",
            "error_message": st.column_config.TextColumn("Error", width="large"),
        },
    )

    st.subheader("Compare two scans")
    st.caption("Only successful scans with identical coverage (same tool, scan type, target, categories and "
               "severity filter) can be compared.")
    succ = view[view["status"].isin(an.SUCCESS)]
    if len(succ) < 2:
        empty_state("At least two successful scans are needed for a comparison.")
        return
    labels = {int(r.id): f"#{r.id} · {r.repository} · {r.scanner}:{r.scan_type} · {fmt_ts(r.started_at)}"
              for r in succ.itertuples()}
    ids = list(labels)
    k1, k2 = st.columns(2)
    newer = k1.selectbox("Newer scan", ids, format_func=labels.get, index=0)
    idx = succ.set_index("id")
    older_candidates = [i for i in ids if i < newer and idx.loc[i, "coverage"] == idx.loc[newer, "coverage"]
                        and idx.loc[i, "repository"] == idx.loc[newer, "repository"]]
    if not older_candidates:
        k2.info("No earlier comparable scan for the selected run.")
        return
    older = k2.selectbox("Older scan", older_candidates, format_func=labels.get, index=0)
    try:
        diff = compare_runs(conn, older, newer)
    except ValueError as exc:
        st.error(str(exc))
        return
    m1, m2, m3 = st.columns(3)
    m1.metric("New", len(diff["new"]))
    m2.metric("Still present", len(diff["existing"]))
    m3.metric("Resolved", len(diff["resolved"]))
    ids_all = diff["new"] + diff["resolved"]
    if ids_all:
        fdf = an.findings_frame(conn)
        fdf = fdf[fdf["id"].isin(ids_all)].assign(
            change=lambda d: d["id"].map(lambda i: "NEW" if i in diff["new"] else "RESOLVED"))
        st.dataframe(fdf[["change", "severity", "identifier", "package_name", "file_path", "title"]],
                     hide_index=True, width="stretch")
