"""Page — Trends: is security getting better or worse over time? Charts (Streamlit built-in, nothing extra
installed), each with a table of the same numbers, and plain-language captions."""

from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from dashboard import theme as t
from dashboard.common import get_config, get_conn, notice, page_header, section
from dashboard.states import no_repositories
from services import trends_service as tr

SEV_COLORS = [t.SEVERITY_COLORS[s] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]


def _chart(df: pd.DataFrame, kind: str, colors: list[str] | None = None, y: str = "Open issues",
           height: int = 260) -> None:
    """Static Altair chart (no wheel-zoom, so scrolling the page works over it) with hover tooltips."""
    idx = df.index.name or "index"
    long = df.reset_index().melt(id_vars=idx, var_name="Series", value_name="Value")
    long[idx] = pd.to_datetime(long[idx])
    order = list(df.columns)
    color = alt.Color("Series:N", sort=order, legend=alt.Legend(orient="bottom", title=None),
                      scale=alt.Scale(domain=order, range=colors) if colors else alt.Undefined)
    base = alt.Chart(long).encode(
        x=alt.X(f"{idx}:T", title=None, axis=alt.Axis(format="%d %b", labelAngle=0)),
        y=alt.Y("Value:Q", title=y, scale=alt.Scale(domainMin=0)),
        color=color, tooltip=[alt.Tooltip(f"{idx}:T", title="Date", format="%d %b %Y"), "Series:N",
                              alt.Tooltip("Value:Q", title=y)])
    if kind == "bar":  # one column per week, bars side by side
        long["Week"] = long[idx].dt.strftime("%d %b")
        weeks = list(dict.fromkeys(long["Week"]))
        mark = alt.Chart(long).mark_bar(opacity=.9).encode(
            x=alt.X("Week:O", sort=weeks, title="Week starting", axis=alt.Axis(labelAngle=0)),
            xOffset=alt.XOffset("Series:N", sort=order), y=alt.Y("Value:Q", title=y), color=color,
            tooltip=[alt.Tooltip("Week:O", title="Week starting"), "Series:N", alt.Tooltip("Value:Q", title=y)])
    else:
        mark = base.mark_line(point=True, strokeWidth=2)
    st.altair_chart(mark.properties(height=height), width="stretch")


def _table(df: pd.DataFrame, label: str) -> None:
    with st.expander(f"{label} as a table", icon=":material/table:"):
        st.dataframe(df.reset_index(), hide_index=True, width="stretch")


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Trends", "Is security getting better or worse over time? Built from every scan's history")
    repos = [(r[0], r[1]) for r in conn.execute("SELECT id, name FROM repositories WHERE active=1 "
                                                "ORDER BY name COLLATE NOCASE")]
    if not repos:
        no_repositories(cfg, conn, "trends")
        return
    c1, c2 = st.columns([2, 1])
    choice = c1.selectbox("Project", ["All projects", *[n for _, n in repos]], key="trends_repo")
    period = c2.segmented_control("Period", [30, 90, 180, 365], default=90, key="trends_days",
                                  format_func=lambda d: f"{d} days") or 90
    repo_id = next((i for i, n in repos if n == choice), None)

    span = tr.history_span_days(conn)
    if span < 7:
        notice("info", "Trends need a little history",
               f"Scans so far cover {span} day(s). The lines fill in as scans run - the weekly scheduled scan "
               "(Settings → Scheduling) is the easiest way. Everything below is already correct for the days that "
               "exist.")

    change = tr.overall_change(conn, repo_id, 30)
    if change["enough_history"] and change["change_pct"] is not None:
        better = change["now"] < change["then"]
        notice("ok" if better else ("warn" if change["now"] > change["then"] else "neutral"),
               f"Open issues {'down' if better else 'up' if change['now'] > change['then'] else 'unchanged'} "
               f"{abs(change['change_pct'])}% in 30 days",
               f"{change['then']} open 30 days ago, {change['now']} open now.")

    section("Open issues over time", "how many problems were open at the end of each day or week, by severity")
    df = tr.open_over_time(conn, repo_id, period)
    if df.empty or not df.to_numpy().any():
        st.caption("No open issues in this period.")
    else:
        _chart(df, "line", SEV_COLORS[:len(df.columns)], height=280)
        st.caption("Going down = problems are being fixed faster than new ones appear. A sudden jump usually means "
                   "a new check found older problems (for example the installed-versions check), not new mistakes.")
        _table(df, "Open issues over time")

    section("New vs fixed each week", "found for the first time vs confirmed fixed by a later scan")
    nf = tr.new_vs_fixed(conn, repo_id, period)
    if nf.empty or not nf.to_numpy().any():
        st.caption("Nothing new or fixed in this period.")
    else:
        _chart(nf, "bar", [t.DANGER, t.SUCCESS], y="Issues")
        st.caption("Red taller than green week after week means the backlog is growing.")
        _table(nf, "New vs fixed")

    section("Time to fix", "days from first found to confirmed fixed, by severity")
    ttf = tr.time_to_fix(conn, repo_id)
    chart = ttf[["Severity", "Average days to fix"]].dropna()
    if not chart.empty:
        st.altair_chart(alt.Chart(chart).mark_bar(color=t.ACCENT).encode(
            x=alt.X("Average days to fix:Q", title="Average days to fix", axis=alt.Axis(format=".1f")),
            y=alt.Y("Severity:N", sort=["Critical", "High", "Medium", "Low"], title=None),
            tooltip=["Severity", "Average days to fix"]).properties(height=160), width="stretch")
    st.dataframe(ttf, hide_index=True, width="stretch")
    st.caption("Rule of thumb: critical within days, high within a couple of weeks. 'Typical age of open' shows how "
               "long the problems still open have been waiting.")

    section("By type", "open issues over time per kind of problem")
    cat = tr.open_over_time(conn, repo_id, period, by="category")
    if cat.empty or not cat.to_numpy().any():
        st.caption("No open issues in this period.")
    else:
        _chart(cat, "line")
        _table(cat, "Open issues by type")

    if repo_id is None:
        section("Projects: now vs 30 days ago")
        st.dataframe(tr.project_change(conn, 30), hide_index=True, width="stretch")
