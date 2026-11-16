"""Page 1 — Security Overview."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.common import (CATEGORY_COLORS, PLOTLY_LAYOUT, SEVERITY_COLORS, card, card_row, empty_state,
                              fmt_ts, freshness_banner, get_config, get_conn, page_header)
from services import analytics_service as an
from utils.validators import CATEGORIES, SEVERITIES


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Security Overview", "Posture across all locally discovered repositories · data never leaves this machine")
    freshness = freshness_banner(cfg)
    m = an.overview_metrics(conn)

    if m["repositories"] == 0:
        empty_state("No repositories discovered yet. Configure repository roots in Settings, then run discovery "
                    "from Repository Management (or `python run_scan.py discover`).")
        return

    sev = m["severity"]
    card_row([
        card("Repositories", m["repositories"], f"{m['repositories_scanned']} scanned successfully"),
        card("Critical", sev["CRITICAL"], "open + unverified", SEVERITY_COLORS["CRITICAL"]),
        card("High", sev["HIGH"], "open + unverified", SEVERITY_COLORS["HIGH"]),
        card("Medium", sev["MEDIUM"], "open + unverified", SEVERITY_COLORS["MEDIUM"]),
        card("Low", sev["LOW"], f"+{sev['UNKNOWN']} unknown", SEVERITY_COLORS["LOW"]),
    ])
    st.write("")
    db_value = "Missing" if not freshness.present else (f"{freshness.age_hours:.0f}h" if freshness.age_hours
                                                        is not None else "?")
    card_row([
        card("Exposed secrets", m["category"]["SECRET"], "values never stored", CATEGORY_COLORS["SECRET"]),
        card("Misconfigurations", m["category"]["MISCONFIGURATION"], "", CATEGORY_COLORS["MISCONFIGURATION"]),
        card("Failed scans", m["failed_scans_latest"], f"latest per scanner · {m['failed_scans_total']} total",
             "#EF4444" if m["failed_scans_latest"] else "#22C55E"),
        card("Last successful scan", fmt_ts(m["last_successful_scan"], short=True), f"{m['running']} running now"),
        card("Vuln DB age", db_value, "STALE" if freshness.stale else "fresh",
             "#EF4444" if freshness.stale else "#22C55E"),
    ])
    if m["unverified"]:
        st.caption(f":material/help: {m['unverified']} findings are UNVERIFIED — a later scan failed or did not "
                   "cover them, so they are kept (never auto-resolved).")
    st.divider()

    c1, c2 = st.columns(2)
    with c1:
        sdf = pd.DataFrame({"severity": list(SEVERITIES), "count": [sev[s] for s in SEVERITIES]})
        fig = px.bar(sdf, x="severity", y="count", color="severity", color_discrete_map=SEVERITY_COLORS,
                     title="Open findings by severity", text="count")
        fig.update_layout(**PLOTLY_LAYOUT, showlegend=False)
        fig.update_yaxes(rangemode="tozero", tickformat=",d")
        st.plotly_chart(fig, width="stretch")
    with c2:
        cdf = pd.DataFrame({"category": list(CATEGORIES), "count": [m["category"][c] for c in CATEGORIES]})
        cdf = cdf[cdf["count"] > 0]
        if cdf.empty:
            empty_state("No open findings by category.")
        else:
            fig = px.pie(cdf, names="category", values="count", hole=0.55, color="category",
                         color_discrete_map=CATEGORY_COLORS, title="Open findings by category")
            fig.update_layout(**PLOTLY_LAYOUT)
            st.plotly_chart(fig, width="stretch")

    rdf = an.findings_by_repository(conn)
    if not rdf.empty:
        order = rdf.groupby("repository")["findings"].sum().sort_values(ascending=True).index.tolist()
        fig = px.bar(rdf, y="repository", x="findings", color="severity", orientation="h",
                     color_discrete_map=SEVERITY_COLORS, category_orders={"repository": order,
                                                                          "severity": list(SEVERITIES)},
                     title="Open findings by repository")
        layout = {**PLOTLY_LAYOUT, "height": max(260, 34 * len(order) + 120)}
        fig.update_layout(**layout)
        fig.update_xaxes(tickformat=",d")
        st.plotly_chart(fig, width="stretch")

    c3, c4 = st.columns(2)
    with c3:
        tdf = an.change_trend(conn)
        if tdf.empty:
            empty_state("New vs resolved trend appears after the first scans.")
        else:
            piv = tdf.pivot_table(index="day", columns="change_type", values="count", fill_value=0).reset_index()
            fig = go.Figure()
            if "NEW" in piv:
                fig.add_bar(x=piv["day"], y=piv["NEW"], name="New", marker_color="#EF4444")
            if "RESOLVED" in piv:
                fig.add_bar(x=piv["day"], y=piv["RESOLVED"], name="Resolved", marker_color="#22C55E")
            fig.update_layout(**PLOTLY_LAYOUT, barmode="group", title="New vs resolved findings")
            st.plotly_chart(fig, width="stretch")
    with c4:
        odf = an.open_findings_trend(conn)
        if odf.empty:
            empty_state("Historical trend appears after successful scans.")
        else:
            fig = px.area(odf, x="day", y="findings", color="severity", color_discrete_map=SEVERITY_COLORS,
                          category_orders={"severity": list(SEVERITIES)}, title="Findings observed by scans over time")
            fig.update_layout(**PLOTLY_LAYOUT)
            st.plotly_chart(fig, width="stretch")
