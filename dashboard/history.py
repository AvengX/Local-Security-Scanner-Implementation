"""Scan History — every scanner execution, trends and repository-specific, coverage-aware comparisons."""

from __future__ import annotations

import streamlit as st

from dashboard import theme as t
from dashboard.common import (fmt_ts, get_config, get_conn, html, notice, page_header, section)
from dashboard.states import no_repositories
from engine.comparison_engine import compare_runs
from services import analytics_service as an


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Scan History", "Every scanner execution, its outcome and historical comparisons")
    df = an.scan_history(conn, limit=5000)
    if df.empty:
        if conn.execute("SELECT COUNT(*) FROM repositories WHERE active=1").fetchone()[0] == 0:
            no_repositories(cfg, conn, "hist")
        else:
            notice("neutral", "No scans have run yet", "Start a scan from the Repositories page; every scanner run "
                   "(including failures) is recorded here.")
        return

    repos = sorted(df["repository"].unique().tolist())
    pre = st.session_state.pop("history_repo", None)
    with st.container(key="panel_hist_filters"):
        c1, c2, c3 = st.columns(3)
        sel_repo = c1.selectbox("Repository", ["All", *repos], index=(repos.index(pre) + 1) if pre in repos else 0)
        sel_tool = c2.multiselect("Scanner", sorted(df["scanner"].unique().tolist()))
        sel_status = c3.multiselect("Status", sorted(df["status"].unique().tolist()))
    view = df
    if sel_repo != "All":
        view = view[view["repository"] == sel_repo]
    if sel_tool:
        view = view[view["scanner"].isin(sel_tool)]
    if sel_status:
        view = view[view["status"].isin(sel_status)]
    if view.empty:
        notice("neutral", "No scans match the filters", "Clear a filter to see more runs.")
        return

    done = view[~view["status"].isin(["PENDING", "RUNNING", "SKIPPED"])]  # skipped runs did not attempt a scan
    ok = view[view["status"].isin(an.SUCCESS)]
    failed = view[view["status"].isin(an.FAILED)]
    rate = f"{100 * len(ok) / len(done):.0f}%" if len(done) else "—"
    avg = f"{ok['duration'].mean():.1f} s" if len(ok) and ok["duration"].notna().any() else "—"
    html(t.metric_grid([
        t.metric_card("Scanner runs", len(view), f"{view['repository'].nunique()} repositories", "info", "scan"),
        t.metric_card("Success rate", rate, f"{len(ok)} successful", "ok" if len(failed) == 0 else "warn", "check_circle"),
        t.metric_card("Failed", len(failed), "failed · timed out · cancelled", "err" if len(failed) else "ok", "x_circle"),
        t.metric_card("Avg duration", avg, "successful runs", "violet", "clock"),
        t.metric_card("New findings", int(view["new_count"].sum()), f"{int(view['resolved_count'].sum())} resolved",
                      "warn", "activity"),
    ], min_width=150))

    section("All scanner runs", "failed runs keep their error message; they never clear existing findings")
    show = view.assign(started=view["started_at"].map(fmt_ts), tool=view["scanner"] + ":" + view["scan_type"],
                       offline_t=view["offline"].map(lambda x: "yes" if x else ""),
                       status_t=view["status"].map(lambda s: f"{t.STATUS_LABELS.get(s, s)}"),
                       error=view["error_message"].fillna(""))
    st.dataframe(
        show[["id", "started", "repository", "tool", "status_t", "duration", "findings_count", "new_count",
              "resolved_count", "tool_version", "offline_t", "exit_code", "error"]],
        hide_index=True, width="stretch", height=min(440, 40 + 35 * len(show)),
        column_config={
            "id": st.column_config.NumberColumn("Run", format="%d", width="small"), "started": "Started",
            "repository": "Repository", "tool": "Scan type", "status_t": "Status",
            "duration": st.column_config.NumberColumn("Duration (s)", format="%.1f"),
            "findings_count": st.column_config.NumberColumn("Findings", format="%d"),
            "new_count": st.column_config.NumberColumn("New", format="%d"),
            "resolved_count": st.column_config.NumberColumn("Resolved", format="%d"),
            "tool_version": "Version", "offline_t": "Offline",
            "exit_code": st.column_config.NumberColumn("Exit", format="%d", width="small"),
            "error": st.column_config.TextColumn("Error", width="large"),
        },
    )

    section("Compare two scans", "same repository, scanner, scan type, target, categories, severities and skip list")
    succ = view[view["status"].isin(an.SUCCESS)]
    if len(succ) < 2:
        notice("neutral", "Not enough successful scans to compare", "At least two successful scans of the same kind "
               "in the same repository are needed.")
        return
    labels = {int(r.id): f"#{r.id} · {r.repository} · {r.scanner}:{r.scan_type} · {fmt_ts(r.started_at)}"
              for r in succ.itertuples()}
    ids = list(labels)
    with st.container(key="panel_compare"):
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
            notice("err", "These scans cannot be compared", str(exc))
            return
        html(t.metric_grid([t.metric_card("New", len(diff["new"]), "appeared in the newer scan", "err", "alert"),
                            t.metric_card("Still present", len(diff["existing"]), "in both scans", "warn", "activity"),
                            t.metric_card("Resolved", len(diff["resolved"]), "gone in the newer scan", "ok",
                                          "check_circle")], min_width=160))
        ids_all = diff["new"] + diff["resolved"]
        if ids_all:
            fdf = an.findings_frame(conn)
            fdf = fdf[fdf["id"].isin(ids_all)].assign(
                change=lambda d: d["id"].map(lambda i: "New" if i in diff["new"] else "Resolved"))
            st.dataframe(fdf[["change", "severity", "identifier", "package_name", "file_path", "title"]],
                         hide_index=True, width="stretch",
                         column_config={"change": "Change", "severity": "Severity", "identifier": "Finding",
                                        "package_name": "Package", "file_path": "File", "title": "Title"})
