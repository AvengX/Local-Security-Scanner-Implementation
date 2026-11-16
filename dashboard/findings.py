"""Page 3 — Security Findings (search, filters, detail view). Secret values are never available."""

from __future__ import annotations

import json

import streamlit as st

from dashboard.common import (SEVERITY_COLORS, empty_state, fmt_ts, get_config, get_conn, page_header,
                              severity_pill)
from services import analytics_service as an
from services.export_service import findings_csv_bytes
from utils.validators import CATEGORIES, SEVERITIES


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Security Findings", "Vulnerabilities, secrets and misconfigurations · secret values are never shown")
    df = an.findings_frame(conn)
    if df.empty:
        empty_state("No findings recorded yet. Run a scan from Repository Management.")
        return

    with st.container(border=True):
        s1, s2, s3 = st.columns(3)
        cve = s1.text_input("Search CVE / rule", placeholder="CVE-2024-…", key="f_cve")
        pkg = s2.text_input("Search package", placeholder="openssl", key="f_pkg")
        file = s3.text_input("Search file", placeholder="requirements.txt", key="f_file")
        f1, f2, f3, f4, f5 = st.columns(5)
        repos = sorted(df["repository"].unique().tolist())
        default_repos = [r for r in st.session_state.pop("findings_repo", []) if r in repos]
        if default_repos:
            st.session_state["f_repo"] = default_repos
        sel_repo = f1.multiselect("Repository", repos, key="f_repo")
        sel_scanner = f2.multiselect("Scanner", sorted(df["scanner"].unique().tolist()), key="f_scanner")
        sel_cat = f3.multiselect("Category", list(CATEGORIES), key="f_cat")
        sel_sev = f4.multiselect("Severity", list(SEVERITIES), key="f_sev")
        sel_status = f5.multiselect("Status", ["OPEN", "UNVERIFIED", "RESOLVED"], default=["OPEN", "UNVERIFIED"],
                                    key="f_status")

    view = an.filter_findings(df, repositories=sel_repo, scanners=sel_scanner, categories=sel_cat,
                              severities=sel_sev, statuses=sel_status, cve=cve, package=pkg, file=file)
    counts = view["severity"].value_counts().to_dict() if not view.empty else {}
    st.markdown(" ".join(f"{severity_pill(s)} <b>{counts.get(s, 0)}</b>&nbsp;&nbsp;" for s in SEVERITIES) +
                f"&nbsp;&nbsp;<span style='color:#94A3B8'>{len(view)} of {len(df)} findings</span>",
                unsafe_allow_html=True)
    if view.empty:
        empty_state("No findings match the current filters.")
        return

    display = view.assign(first_seen=view["first_seen"].map(fmt_ts), last_seen=view["last_seen"].map(fmt_ts),
                          package_or_rule=view["package_name"].fillna(view["rule_id"]).fillna(""),
                          installed_version=view["installed_version"].fillna(""),
                          fixed_version=view["fixed_version"].fillna(""),
                          file_path=view["file_path"].fillna(""))
    event = st.dataframe(
        display[["identifier", "repository", "severity", "category", "status", "package_or_rule", "file_path",
                 "installed_version", "fixed_version", "scanner", "first_seen", "last_seen", "remediation"]],
        hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
        height=min(460, 38 + 35 * len(display)),
        column_config={
            "identifier": st.column_config.TextColumn("Finding", width="medium"),
            "repository": "Repository", "severity": "Severity", "category": "Category", "status": "Status",
            "package_or_rule": "Package / rule", "file_path": st.column_config.TextColumn("File", width="medium"),
            "installed_version": "Installed", "fixed_version": "Fixed", "scanner": "Scanner",
            "first_seen": "First seen", "last_seen": "Last seen",
            "remediation": st.column_config.TextColumn("Remediation", width="large"),
        },
    )
    st.download_button("Export filtered findings (CSV)", findings_csv_bytes(view), "findings_filtered.csv",
                       "text/csv", icon=":material/download:")

    rows = event.selection.rows if event and event.selection else []
    if rows:
        f = view.iloc[rows[0]]
        with st.expander(f"Details — {f['identifier'] or f['title']}", expanded=True):
            color = SEVERITY_COLORS.get(f["severity"], "#6B7280")
            st.markdown(f"{severity_pill(f['severity'])} &nbsp; **{f['title'] or ''}**", unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            c1.markdown(f"**Repository:** {f['repository']}  \n**Scanner:** {f['scanner']} ({f['scan_type']})  \n"
                        f"**Category:** {f['category']}  \n**Status:** {f['status']}")
            loc = f"{f['file_path'] or ''}" + (f":{int(f['line'])}" if f["line"] == f["line"] and f["line"] else "")
            c2.markdown(f"**Location:** `{loc}`  \n**Package:** {f['package_name'] or '—'}  \n"
                        f"**Installed → Fixed:** {f['installed_version'] or '—'} → {f['fixed_version'] or '—'}  \n"
                        f"**First / last seen:** {fmt_ts(f['first_seen'])} / {fmt_ts(f['last_seen'])}")
            if f["description"]:
                st.markdown(f"**Description**  \n{f['description']}")
            st.markdown(f"<div style='border-left:4px solid {color};padding:8px 12px;background:#0F172A'>"
                        f"<b>Remediation</b><br>{(f['remediation'] or 'Review and remediate.')}</div>",
                        unsafe_allow_html=True)
            if f["reference_url"]:
                st.markdown(f"[Reference]({f['reference_url']})")
            if f["category"] == "SECRET":
                st.warning("If this credential is real, revoke and rotate it at the provider first. The scanner "
                           "stores only rule, file, line and commit — never the secret value.", icon=":material/key:")
            meta = conn.execute("SELECT metadata_json FROM findings WHERE id=?", (int(f["id"]),)).fetchone()
            if meta and meta[0]:
                st.json(json.loads(meta[0]), expanded=False)
