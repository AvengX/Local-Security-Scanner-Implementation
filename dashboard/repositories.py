"""Repository management — discovery, per-repository state and scan launching."""

from __future__ import annotations

import streamlit as st

from dashboard import theme as t
from dashboard.common import (ROW_SELECT, selected_row, PAGES, ago, clear_queued, fmt_ts, get_config, get_conn, html, is_queued,
                              launch_background, mark_queued, notice, page_header, queued_at, running_jobs,
                              scans_started_since, section, watch_until_idle)
from dashboard.states import no_repositories, system_alerts
from database import repositories as dao
from services import analytics_service as an

STATE_TEXT = {"RUNNING": "● Running", "PENDING": "◌ Queued", "QUEUED": "◌ Queued", "COMPLETED": "✓ Clean",
              "COMPLETED_WITH_FINDINGS": "▲ Findings", "FAILED": "✕ Failed", "TIMED_OUT": "✕ Timed out",
              "CANCELLED": "– Cancelled", "SKIPPED": "– Skipped", "NEVER": "○ Not scanned"}


def _settle_queued(conn) -> None:  # noqa: ANN001
    """Drop 'queued' markers for jobs that have started and finished, so buttons re-enable straight away."""
    if running_jobs(conn):
        return
    for key in list(st.session_state.get("lss_queued", {})):
        if key == "scan-all" or key.startswith("repo:"):
            ts = queued_at(key) or 0
            if scans_started_since(conn, ts, None if key == "scan-all" else key[5:]):
                clear_queued(key)


def _busy(conn) -> bool:  # noqa: ANN001
    _settle_queued(conn)
    return bool(running_jobs(conn)) or any(
        is_queued(k) for k in st.session_state.get("lss_queued", {}) if k == "scan-all" or k.startswith("repo:"))


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    _settle_queued(conn)
    page_header("Repositories", "Discover Git repositories under your configured folders and launch scans")
    system_alerts(cfg, "repo")

    jobs = running_jobs(conn)
    active_paths = {j["path"] for j in jobs}
    scan_all_busy = bool(jobs) or is_queued("scan-all")

    with st.container(key="actions_repo"):
        a1, a2, a3, a4 = st.columns([1.2, 1.2, 1, 1.6], vertical_alignment="center")
        disc = a1.button("Discover repositories", icon=":material/travel_explore:", width="stretch",
                         disabled=not cfg.repository_roots, help="Walk the configured folders for .git directories")
        offline = a3.toggle("Offline scan", value=cfg.scan.offline, help="Use the cached vulnerability DB only")
        if a2.button("Scan all repositories", icon=":material/play_circle:", type="primary", width="stretch",
                     disabled=not cfg.repository_roots or scan_all_busy,
                     help="Already running" if scan_all_busy else "Scan every active repository in the background"):
            pid = launch_background(["scan-all", "--offline" if offline else "--online"], cfg)
            mark_queued("scan-all")
            st.toast(f"Scan of all repositories queued (pid {pid}). Press Refresh to follow progress.",
                     icon=":material/play_circle:")
            st.rerun()
        a4.caption(f"Roots: {', '.join(cfg.repository_roots) or 'none configured'}")
    if disc:
        from engine.scan_orchestrator import ScanOrchestrator

        with st.spinner("Discovering repositories…"):
            result, stats = ScanOrchestrator(cfg).discover()
        st.toast(f"Found {len(result.repositories)} repositories · new {stats['new']} · moved {stats['moved']} · "
                 f"deactivated {stats['deactivated']}", icon=":material/check:")
        for e in result.errors[:10]:
            notice("warn", "Discovery warning", e)

    if jobs or is_queued("scan-all"):
        lines = "".join(f"<li><span class='lss-step' style='--c:{t.ACCENT}'>{t.icon('activity', 14, t.ACCENT)}</span>"
                        f"<div class='grow'><div class='t'>{t.esc(j['repository'])}</div><div class='s'>"
                        f"{t.esc(j['scanner'])} · {'queued' if j['status'] == 'PENDING' else 'running ' + j['elapsed']}"
                        f"</div></div></li>" for j in jobs)
        if not jobs:
            lines = "<li><div class='grow'><div class='t'>Starting…</div><div class='s'>The scan job was launched; " \
                    "scanner runs appear here within a few seconds.</div></div></li>"
        notice("info", "Scanning in progress", body_html=f"<ul class='lss-list'>{lines}</ul>", icon_name="activity")
        watch_until_idle(lambda: _busy(conn), "repo_scan")

    df = an.repository_table(conn)
    if df.empty:
        no_repositories(cfg, conn, "repo")
        return

    df["state"] = [("RUNNING" if p in active_paths else "QUEUED" if is_queued(f"repo:{p}") and s not in ("RUNNING",)
                    else s) for p, s in zip(df["path"], df["state"])]
    counts = df["state"].value_counts().to_dict()
    html(t.metric_grid([
        t.metric_card("Repositories", len(df), "active", "info", "folder"),
        t.metric_card("Scanning", counts.get("RUNNING", 0) + counts.get("QUEUED", 0) + counts.get("PENDING", 0),
                      "running or queued", "info", "activity"),
        t.metric_card("With findings", int((df["open_findings"] > 0).sum()), "open or unverified", "warn", "alert"),
        t.metric_card("Failed / timed out", counts.get("FAILED", 0) + counts.get("TIMED_OUT", 0), "latest attempt",
                      "err" if counts.get("FAILED", 0) + counts.get("TIMED_OUT", 0) else "ok", "x_circle"),
        t.metric_card("Never scanned", counts.get("NEVER", 0), "no scanner run yet", "neutral", "clock"),
    ], min_width=150))

    q = st.text_input("Search repositories", placeholder="Search by name, path or branch…", key="repo_q")
    view = df
    if q:
        hay = (df["name"] + " " + df["path"] + " " + df["branch"].fillna("")).str.lower()
        view = df[hay.str.contains(q.lower(), regex=False)]
    if view.empty:
        notice("neutral", "No repositories match the search", "Clear the search box to see all repositories.")
        return
    view = view.assign(state_t=view["state"].map(lambda s: STATE_TEXT.get(s, s)),
                       last_scan_t=view["last_scan"].map(lambda v: ago(v) if v else "never"),
                       duration_t=view["last_duration"].map(lambda v: f"{v:.0f} s" if v == v and v else "—"))
    event = st.dataframe(
        view[["name", "state_t", "branch", "last_commit", "last_scan_t", "duration_t", "critical", "high",
              "open_findings", "path"]],
        hide_index=True, width="stretch", on_select="rerun", selection_mode=ROW_SELECT, key="repo_table",
        height=min(480, 40 + 35 * len(view)),
        column_config={
            "name": st.column_config.TextColumn("Repository", width="medium"),
            "state_t": st.column_config.TextColumn("Status", width="small"),
            "branch": "Branch", "last_commit": "Last commit", "last_scan_t": "Last scan", "duration_t": "Duration",
            "critical": st.column_config.NumberColumn("Critical", format="%d", width="small"),
            "high": st.column_config.NumberColumn("High", format="%d", width="small"),
            "open_findings": st.column_config.NumberColumn("Open", format="%d", width="small"),
            "path": st.column_config.TextColumn("Path", width="large"),
        },
    )
    row = selected_row(event)
    if row is None or row >= len(view):
        st.caption("Click a repository to scan it on its own or see its details and recent scans.")
        return
    repo = view.iloc[row]
    busy = repo["state"] in ("RUNNING", "QUEUED", "PENDING") or scan_all_busy
    with st.container(key="panel_repo_detail"):
        html(f"<div style='display:flex;gap:.6rem;align-items:center;flex-wrap:wrap'>"
             f"<span style='font-size:1.1rem;font-weight:700'>{t.esc(repo['name'])}</span>"
             f"{t.status_badge(repo['state'] if repo['state'] != 'NEVER' else 'SKIPPED', STATE_TEXT.get(repo['state'], '')[2:])}</div>")
        c1, c2 = st.columns(2)
        c1.markdown(t.kv_table([("Path", f"<code>{t.esc(repo['path'])}</code>"), ("Type", t.esc(repo["kind"])),
                                ("Branch", t.esc(repo["branch"] or "—")),
                                ("Last commit", f"<code>{t.esc(repo['last_commit'] or '—')}</code>")]),
                    unsafe_allow_html=True)
        c2.markdown(t.kv_table([("Last scan", t.esc(fmt_ts(repo["last_scan"]))),
                                ("Duration", t.esc(repo["duration_t"])),
                                ("Open + unverified", f"{int(repo['open_findings'])} ({int(repo['critical'])} critical, "
                                                  f"{int(repo['high'])} high)"),
                                ("Latest per scanner", t.esc(repo["scan_status"] or "—"))]), unsafe_allow_html=True)
        with st.container(key="actions_detail"):
            b1, b2, b3 = st.columns(3)
            if b1.button("Scanning…" if busy else "Scan this repository", icon=":material/play_arrow:", type="primary",
                         width="stretch", disabled=busy, key="repo_scan_one",
                         help="A scan is already running or queued" if busy else None):
                pid = launch_background(["scan-repo", "--path", repo["path"], "--offline" if offline else "--online"], cfg)
                mark_queued(f"repo:{repo['path']}")
                st.toast(f"Scan queued for {repo['name']} (pid {pid}).", icon=":material/play_arrow:")
                st.rerun()
            if b2.button("View findings", icon=":material/bug_report:", width="stretch", key="repo_view_findings"):
                st.session_state["findings_repo"] = [repo["name"]]
                if "findings" in PAGES:
                    st.switch_page(PAGES["findings"])
            if b3.button("View scan history", icon=":material/history:", width="stretch", key="repo_view_history"):
                st.session_state["history_repo"] = repo["name"]
                if "history" in PAGES:
                    st.switch_page(PAGES["history"])
        runs = dao.list_scan_runs(conn, int(repo["id"]), limit=10)
        section("Recent scans", f"{len(runs)} most recent scanner runs")
        if not runs:
            st.caption("This repository has not been scanned yet.")
        else:
            rows_html = "".join(
                f"<tr><td>#{r['id']}</td><td>{t.esc(r['scanner'])}:{t.esc(r['scan_type'])}</td>"
                f"<td>{t.status_badge(r['status'])}</td><td>{t.esc(fmt_ts(r['started_at'], short=True))}</td>"
                f"<td style='text-align:right'>{(r['duration'] or 0):.1f} s</td><td style='text-align:right'>"
                f"{r['findings_count']}</td><td style='color:#FCA5A5'>{t.esc((r['error_message'] or '')[:200])}</td></tr>"
                for r in runs)
            html("<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Run</th><th>Scanner</th>"
                 "<th>Status</th><th>Started</th><th style='text-align:right'>Duration</th>"
                 f"<th style='text-align:right'>Findings</th><th>Error</th></tr></thead><tbody>{rows_html}</tbody></table></div>")
