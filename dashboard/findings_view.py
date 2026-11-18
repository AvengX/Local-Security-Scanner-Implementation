"""Shared vulnerability-management view used by the Findings, Vulnerabilities, Secrets,
Misconfigurations, Code issues and Web app issues pages. Secret values are never stored, so they can never be displayed."""

from __future__ import annotations

import json
from datetime import date
from typing import Any

import pandas as pd
import streamlit as st

from dashboard import theme as t
from dashboard.common import (ROW_SELECT, fmt_ts, get_config, get_conn, html, notice, page_header, repo_coverage,
                              section, selected_row)
from dashboard.states import no_repositories
from services import analytics_service as an
from services.export_service import findings_csv_bytes
from utils.validators import CATEGORIES, SEVERITIES

KINDS: dict[str, dict[str, Any]] = {
    "all": {"title": "Security Findings", "category": None,
            "subtitle": "Vulnerabilities, secrets, misconfigurations and code issues across every repository · secret values are never shown"},
    "vuln": {"title": "Vulnerabilities", "category": "VULNERABILITY",
             "subtitle": "Known CVEs in dependencies, detected from manifests and lockfiles by Trivy"},
    "secret": {"title": "Secrets", "category": "SECRET",
               "subtitle": "Hard-coded credentials in current files and Git history · only rule, file, line and commit are stored"},
    "misconf": {"title": "Misconfigurations", "category": "MISCONFIGURATION",
                "subtitle": "Infrastructure-as-code and container configuration issues detected by Trivy"},
    "code": {"title": "Code issues", "category": "CODE",
             "subtitle": "Security bugs in your own Python code (SAST) · found by Bandit without running the code"},
    "web": {"title": "Web app issues", "category": "WEB",
            "subtitle": "Problems found by testing your running apps through their web address (DAST) · local apps only"},
}
SCANNER_FOR = {"vuln": "trivy", "misconf": "trivy", "code": "bandit", "web": "dast"}
NO_TARGETS = ("No web addresses added yet. DAST tests an app while it runs, so it needs the address where the app "
              "answers (for example http://127.0.0.1:5000/). Add it under Settings → Web scan (DAST), start the "
              "app, then scan the project.")


def _web_checked(cfg, conn, empty: bool) -> None:  # noqa: ANN001
    """Per web address: when it was last tested, the outcome, and how many pages and requests that covered."""
    from engine.dast_scanner import read_report_summary

    if not cfg.dast.targets:
        notice("neutral", "Nothing to test", NO_TARGETS)
        return
    rows = []
    for tgt in cfg.dast.targets:
        r = conn.execute("SELECT s.status, s.finished_at, s.report_path, s.error_message, s.findings_count "
                         "FROM scan_runs s JOIN repositories r ON r.id=s.repository_id WHERE r.name=? AND "
                         "s.scanner='dast' AND s.scan_target=? ORDER BY s.id DESC LIMIT 1",
                         (tgt.repository, tgt.url)).fetchone()
        summ = read_report_summary(r["report_path"]) if r else None
        if r is None:
            result = "Not tested yet"
        elif r["status"] == "SKIPPED":
            result = "App was not running"
        elif r["status"] in ("COMPLETED", "COMPLETED_WITH_FINDINGS"):
            result = f"{r['findings_count']} issue(s)"
        else:
            result = r["status"].replace("_", " ").title()
        rows.append({"Project": tgt.repository, "Address": tgt.url,
                     "Last tested": fmt_ts(r["finished_at"]) if r else "—", "Result": result,
                     "Pages tested": str(summ["pages"]) if summ else "—",
                     "Requests": str(summ["requests"]) if summ else "—"})
    if empty:
        ran = [x for x in rows if x["Pages tested"] != "—"]
        if ran:
            notice("ok", "No web app issues found",
                   f"{len(ran)} address(es) were tested ({sum(int(x['Pages tested']) for x in ran)} page(s)) and no "
                   "known problem was found. Only what the scan could reach without logging in was tested.")
        else:
            notice("neutral", "Web apps not tested yet",
                   "No address has been tested successfully. Start the app, then scan its project from the "
                   "Repositories page. This does not mean the app is safe.")
    st.markdown("**What was tested**")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    st.caption("Only GET requests are sent (forms that change data are never submitted), links such as log out or "
               "delete are not followed, and only apps on this computer can be tested. Pages behind a login are not "
               "tested.")


def _meta(conn, finding_id: int) -> dict[str, Any]:  # noqa: ANN001
    row = conn.execute("SELECT metadata_json FROM findings WHERE id=?", (finding_id,)).fetchone()
    try:
        return json.loads(row[0]) if row and row[0] else {}
    except (TypeError, ValueError):
        return {}


def _sev_text(s: str) -> str:
    return f"{t.SEVERITY_GLYPH.get(s, '○')} {s.title()}"


def _what_was_checked(cfg, conn, kind: str, empty: bool) -> None:  # noqa: ANN001
    """Explain an empty page: which files Trivy could read in each project, and why nothing was found."""
    covs = repo_coverage(cfg, conn) if kind != "web" else []
    if kind == "vuln":
        files = [(c.repository, d) for c in covs for d in c.dependency_files]
        pinned = sum(d.pinned or 0 for _, d in files if d.checkable)
        locks = sum(1 for _, d in files if d.checkable and d.total is None)
        if empty:
            if not files:
                notice("neutral", "Nothing to check", "None of your projects has a dependency file that Trivy can read "
                       "(requirements.txt, package-lock.json, poetry.lock, go.sum, …), so no libraries were checked. "
                       "This is not a clean result.")
            elif not pinned and not locks:
                notice("warn", "No libraries could be checked",
                       "Your projects list their libraries without exact versions (for example 'numpy' instead of "
                       "'numpy==1.26.4'). Trivy needs the exact version to look up known flaws, so nothing was checked "
                       "and an empty page here does not mean the libraries are safe. Fix: pin versions — run "
                       "'pip freeze > requirements.txt' in the project's environment — then scan again.")
            else:
                what = " and ".join(x for x in (f"{pinned} library version(s) with an exact version" if pinned else "",
                                                f"{locks} lockfile(s)" if locks else "") if x)
                skipped = sum((d.total or 0) - (d.pinned or 0) for _, d in files if d.total is not None)
                skipped += sum(1 for _, d in files if d.total is None and not d.checkable)
                if skipped:
                    notice("warn", "Only some libraries could be checked",
                           f"Trivy checked {what} and found no known flaws, but {skipped} other librar"
                           f"{'y was' if skipped == 1 else 'ies were'} not checked — they have no exact version, or "
                           "sit in a file Trivy does not read. See the table below for each file and how to fix it.")
                else:
                    notice("ok", "No known vulnerabilities",
                           f"Trivy checked {what} and found no known flaws.")
        if not files:
            if not empty:
                st.caption("No dependency files found.")
            return
        rows = []
        for repo, d in files:
            can = (f"{d.pinned} of {d.total}" if d.total is not None else ("all (lockfile)" if d.checkable else "0"))
            rows.append({"Project": repo, "File": d.path, "Type": d.ecosystem, "Libraries checked": can,
                         "Why / what to do": d.note + (f" e.g. {', '.join(d.unpinned_examples[:3])}"
                                                       if d.unpinned_examples and d.checkable else "")})
        st.markdown("**What was checked**")
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    elif kind == "web":
        _web_checked(cfg, conn, empty)
    elif kind == "code":
        total = sum(c.python_files for c in covs)
        if empty:
            if not total:
                notice("neutral", "Nothing to check",
                       "None of your projects contains Python (.py) files, which is what the code check reads. "
                       "The page is empty because there is nothing to check, not because the code is safe.")
            else:
                notice("ok", "No code issues found",
                       f"Bandit checked about {total} Python file(s) in your own code and found no known risky "
                       "patterns (installed libraries such as .venv are skipped).")
        rows = [{"Project": c.repository, "Python files checked": c.python_files,
                 "Note": "" if c.python_files else "No Python files: nothing for the code check to read."}
                for c in covs]
        if rows:
            st.markdown("**What was checked**")
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        st.caption("Only Python is checked today. Code in other languages (JavaScript, Java, …) is not analysed.")
    else:
        files = [(c.repository, kind_, path) for c in covs for kind_, path in c.config_files]
        if empty:
            if not files:
                notice("neutral", "Nothing to check",
                       "None of your projects contains a Dockerfile, docker-compose, Kubernetes, Helm or Terraform "
                       "file — these are the files this check looks at. The page is empty because there is nothing to "
                       "check, not because a problem was fixed.")
            else:
                notice("ok", "No unsafe settings found",
                       f"Trivy checked {len(files)} configuration file(s) and none failed a check.")
        if files:
            st.markdown("**Configuration files checked**")
            st.dataframe(pd.DataFrame(files, columns=["Project", "Kind", "File"]), hide_index=True, width="stretch")
        elif not empty:
            st.caption("No configuration files found.")


def render_findings(kind: str) -> None:
    spec = KINDS[kind]
    cfg = get_config()
    conn = get_conn(cfg)
    page_header(spec["title"], spec["subtitle"])
    df = an.findings_frame(conn)
    if spec["category"] and not df.empty:
        df = df[df["category"] == spec["category"]].reset_index(drop=True)
    if df.empty:
        if conn.execute("SELECT COUNT(*) FROM repositories WHERE active=1").fetchone()[0] == 0:
            no_repositories(cfg, conn, f"fv_{kind}")
            return
        # Only runs of monitored repositories, and only the scanner that can report this kind of finding.
        scanner = SCANNER_FOR.get(kind)
        ok_runs, ok_repos = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT s.repository_id) FROM scan_runs s JOIN repositories r "
            "ON r.id=s.repository_id AND r.active=1 WHERE s.status IN ('COMPLETED','COMPLETED_WITH_FINDINGS')"
            + (" AND s.scanner=?" if scanner else ""), (scanner,) if scanner else ()).fetchone()
        if kind == "web" and not cfg.dast.targets:
            _web_checked(cfg, conn, empty=True)
        elif ok_runs and scanner:
            _what_was_checked(cfg, conn, kind, empty=True)
        elif ok_runs:
            who = "scanner run(s)"
            notice("ok", f"No {spec['title'].lower()} found",
                   f"{ok_runs} successful {who} across {ok_repos} monitored repositor"
                   f"{'y' if ok_repos == 1 else 'ies'} reported none. This is a clean result, not missing data.")
        elif kind == "web":
            _web_checked(cfg, conn, empty=True)
        elif kind == "code":
            notice("neutral", "Code not scanned yet",
                   "The code check (Bandit) has not completed on any project yet, so there is nothing to show. "
                   "This does not mean the code is safe. Run a scan from the Repositories page.")
        else:
            notice("neutral", "No scan data yet",
                   "No scanner has completed successfully, so there is nothing to show. This does not mean the "
                   "repositories are clean. Start a scan from the Repositories page.")
        return

    if kind in ("vuln", "misconf", "code", "web"):
        with st.expander("What was checked in each project", icon=":material/fact_check:"):
            _what_was_checked(cfg, conn, kind, empty=False)

    prefill_q = st.session_state.pop("findings_q", None)
    if prefill_q:
        st.session_state[f"{kind}_q"] = prefill_q
    # Every monitored repository is selectable — also the ones with nothing to show on this page.
    all_repos = sorted({*(r[0] for r in conn.execute("SELECT name FROM repositories WHERE active=1")),
                        *df["repository"].unique().tolist()}, key=str.lower)
    with_findings = set(df["repository"])
    pre_repo = [r for r in st.session_state.pop("findings_repo", []) if r in all_repos]
    if pre_repo:
        st.session_state[f"{kind}_repo"] = pre_repo

    with st.container(key=f"panel_filters_{kind}"):
        s1, s2, s3 = st.columns([2, 1, 1])
        q = s1.text_input("Search", placeholder="CVE, rule, package, file or title…", key=f"{kind}_q")
        id_label = {"vuln": "CVE", "secret": "Rule", "misconf": "Check ID", "code": "Check ID",
                    "web": "Check ID"}.get(kind,
                                                                                                "CVE / rule")
        cve = s2.text_input(id_label, placeholder="CVE-2024-…" if kind in ("all", "vuln") else "", key=f"{kind}_cve")
        by_file = kind in ("secret", "misconf", "code", "web")
        pkg = s3.text_input("Page" if kind == "web" else "File" if by_file else "Package", key=f"{kind}_pkg",
                            placeholder={"secret": ".env", "misconf": "Dockerfile", "code": "app.py",
                                         "web": "/search"}.get(kind,
                                                                                                       "openssl"))
        f1, f2, f3, f4, f5 = st.columns(5)
        sel_repo = f1.multiselect("Repository", all_repos, key=f"{kind}_repo",
                                  format_func=lambda r: r if r in with_findings else f"{r} (none found)")
        sel_sev = f2.multiselect("Severity", list(SEVERITIES), key=f"{kind}_sev")
        # Toggle chips instead of a dropdown: every option stays fully readable however narrow the column is.
        sel_status = f3.pills("Status", ["OPEN", "UNVERIFIED", "RESOLVED"], selection_mode="multi",
                              default=["OPEN", "UNVERIFIED"], format_func=str.title, key=f"{kind}_status",
                              help="Click to turn a status on or off. None selected = show all.") or []
        if kind == "all":
            sel_cat = f4.multiselect("Category", list(CATEGORIES), key=f"{kind}_cat")
        else:
            sel_cat = []
            f4.multiselect("Scan type", sorted(df["scan_type"].unique().tolist()), key=f"{kind}_stype")
        sel_scanner = f5.multiselect("Scanner", sorted(df["scanner"].unique().tolist()), key=f"{kind}_scanner")
        first = pd.to_datetime(df["first_seen"].str[:10], errors="coerce")
        dmin = first.min().date() if first.notna().any() else date.today()
        dmax = max(first.max().date() if first.notna().any() else date.today(), date.today())
        d1, _ = st.columns([2, 3])
        rng = d1.date_input("First seen between", (dmin, dmax), min_value=dmin, max_value=dmax, key=f"{kind}_dates",
                            format="YYYY-MM-DD")

    view = an.filter_findings(df, repositories=sel_repo, scanners=sel_scanner, categories=sel_cat,
                              severities=sel_sev, statuses=sel_status, cve=cve,
                              package="" if by_file else pkg, file=pkg if by_file else "")
    stypes = st.session_state.get(f"{kind}_stype") or []
    if stypes and not view.empty:
        view = view[view["scan_type"].isin(stypes)]
    if q and not view.empty:
        hay = (view["identifier"].fillna("") + " " + view["package_name"].fillna("") + " " +
               view["file_path"].fillna("") + " " + view["title"].fillna("")).str.lower()
        view = view[hay.str.contains(q.lower(), regex=False)]
    if isinstance(rng, (tuple, list)) and len(rng) == 2 and not view.empty:
        day = view["first_seen"].str[:10]
        view = view[(day >= rng[0].isoformat()) & (day <= rng[1].isoformat())]
    view = view.reset_index(drop=True)

    counts = view["severity"].value_counts().to_dict() if not view.empty else {}
    html("<div class='lss-chips' style='justify-content:flex-start;margin:.2rem 0 .5rem'>" +
         "".join(f"<span class='lss-badge' style='--c:{t.SEVERITY_COLORS[s]}'>{t.SEVERITY_GLYPH[s]} {s.title()} "
                 f"<b>{counts.get(s, 0)}</b></span>" for s in SEVERITIES) +
         f"<span class='lss-chip'>{len(view)} of {len(df)} findings</span></div>")
    if view.empty:
        clean = [r for r in sel_repo if r not in with_findings]
        if clean and len(clean) == len(sel_repo):
            what = {"all": "findings", "vuln": "vulnerabilities", "secret": "secrets",
                    "misconf": "misconfigurations", "code": "code issues", "web": "web app issues"}[kind]
            notice("ok", f"No {what} in {', '.join(clean)}",
                   f"The scanners have never reported any {what} for {'this project' if len(clean) == 1 else 'these projects'}."
                   + (" See “What was checked in each project” above for what could be checked."
                      if kind in ("vuln", "misconf", "code", "web") else ""))
        else:
            notice("neutral", "No findings match the current filters", "Clear a filter or widen the date range.")
        return

    display = _display_frame(conn, view, kind)
    cols, config = _columns(kind)
    event = st.dataframe(display[cols], hide_index=True, width="stretch", on_select="rerun",
                         selection_mode=ROW_SELECT, height=min(520, 40 + 35 * len(display)), column_config=config,
                         key=f"{kind}_table")
    a1, a2 = st.columns([1, 3], vertical_alignment="center")
    a1.download_button("Export CSV", findings_csv_bytes(view), f"{kind}_findings.csv", "text/csv",
                       icon=":material/download:", width="stretch", key=f"{kind}_csv")
    a2.caption("Click any row to open its details and history.")
    row = selected_row(event)
    if row is not None and row < len(view):
        _detail(conn, view.iloc[row], kind)


def _display_frame(conn, view: pd.DataFrame, kind: str) -> pd.DataFrame:  # noqa: ANN001
    d = view.assign(
        sev=view["severity"].map(_sev_text), first=view["first_seen"].map(fmt_ts),
        last=view["last_seen"].map(fmt_ts),
        pkg_rule=view["package_name"].fillna(view["rule_id"]).fillna(""),
        installed=view["installed_version"].fillna(""), fixed=view["fixed_version"].fillna("—"),
        file=view["file_path"].fillna(""), status_t=view["status"].str.title(), category_t=view["category"].str.title(),
    )
    if kind == "secret":
        metas = [_meta(conn, int(i)) for i in view["id"]]
        d["commit"] = [str(m.get("commit") or "")[:10] for m in metas]
        d["source"] = view["scan_type"].map({"git": "Git history", "dir": "Working tree", "fs": "Working tree"}).fillna("")
        d["location"] = d["file"] + view["line"].map(lambda x: f":{int(x)}" if x == x and x else "")
    if kind == "misconf":
        metas = [_meta(conn, int(i)) for i in view["id"]]
        d["resource"] = [str(m.get("resource") or "") for m in metas]
    if kind == "code":
        metas = [_meta(conn, int(i)) for i in view["id"]]
        d["confidence"] = [str(m.get("confidence") or "").title() for m in metas]
        d["location"] = d["file"] + view["line"].map(lambda x: f":{int(x)}" if x == x and x else "")
    if kind == "web":
        metas = [_meta(conn, int(i)) for i in view["id"]]
        d["page"] = [f + (f"  ?{m['parameter']}=" if m.get("parameter") else "") for f, m in zip(d["file"], metas)]
        d["address"] = view["scan_target"].fillna("") if "scan_target" in view.columns else ""
    return d


def _columns(kind: str) -> tuple[list[str], dict[str, Any]]:
    tc = st.column_config.TextColumn
    base = {"identifier": tc("Finding ID", width="medium"), "sev": tc("Severity", width="small"),
            "category_t": "Category", "repository": "Repository", "pkg_rule": "Package / rule",
            "file": tc("File path", width="medium"), "first": "First seen", "last": "Last seen", "status_t": "Status",
            "installed": "Installed", "fixed": "Fixed in", "title": tc("Title", width="large"),
            "commit": "Commit", "source": "Found in", "location": tc("File : line", width="medium"),
            "resource": "Resource", "package_name": "Package",
            "confidence": tc("Confidence", width="small", help="How sure Bandit is that this is a real problem"),
            "page": tc("Page / parameter", width="medium"), "address": tc("App address", width="medium")}
    cols = {
        "all": ["identifier", "sev", "category_t", "repository", "pkg_rule", "file", "first", "status_t"],
        "vuln": ["identifier", "sev", "package_name", "installed", "fixed", "repository", "file", "first", "status_t"],
        "secret": ["identifier", "sev", "repository", "location", "source", "commit", "first", "last", "status_t"],
        "misconf": ["identifier", "sev", "title", "file", "resource", "repository", "status_t"],
        "code": ["identifier", "sev", "confidence", "title", "location", "repository", "first", "status_t"],
        "web": ["identifier", "sev", "title", "page", "address", "repository", "first", "status_t"],
    }[kind]
    if kind == "secret":
        base["identifier"] = tc("Secret type / rule", width="medium")
    if kind in ("misconf", "code", "web"):
        base["identifier"] = tc("Check ID", width="small")
    return cols, base


def _detail(conn, f: pd.Series, kind: str) -> None:  # noqa: ANN001
    meta = _meta(conn, int(f["id"]))
    color = t.SEVERITY_COLORS.get(f["severity"], t.FAINT)
    with st.container(key=f"panel_detail_{kind}"):
        html(f"<div style='display:flex;gap:.6rem;align-items:center;flex-wrap:wrap'>{t.sev_badge(f['severity'])}"
             f"{t.status_badge(f['status'])}<span style='font-weight:650;font-size:1.02rem'>"
             f"{t.esc(f['identifier'] or f['title'])}</span></div>"
             f"<div style='color:#CBD5E1;margin:.35rem 0 .6rem'>{t.esc(f['title'])}</div>")
        c1, c2 = st.columns(2)
        line = f":{int(f['line'])}" if f["line"] == f["line"] and f["line"] else ""
        left = [("Repository", t.esc(f["repository"])), ("Scanner", f"{t.esc(f['scanner'])} ({t.esc(f['scan_type'])})"),
                ("Category", t.esc(f["category"].title())), ("Location", f"<code>{t.esc((f['file_path'] or '') + line)}</code>")]
        right = [("First seen", t.esc(fmt_ts(f["first_seen"]))), ("Last seen", t.esc(fmt_ts(f["last_seen"])))]
        if f["category"] == "VULNERABILITY":
            right = [("CVE / advisory", t.esc(f["vulnerability_id"] or "—")), ("Package", t.esc(f["package_name"] or "—")),
                     ("Installed", t.esc(f["installed_version"] or "—")),
                     ("Fixed in", t.esc(f["fixed_version"] or "no fix published yet"))] + right
        elif f["category"] == "SECRET":
            right = [("Rule", t.esc(f["rule_id"] or "—")),
                     ("Commit", t.esc(str(meta.get("commit") or "working tree")[:12])),
                     ("Commit date", t.esc(fmt_ts(meta.get("commit_date"))))] + right
        elif f["category"] == "MISCONFIGURATION":
            right = [("Check", t.esc(f["rule_id"] or f["vulnerability_id"] or "—")),
                     ("Resource", t.esc(meta.get("resource") or "—")), ("Type", t.esc(meta.get("type") or "—"))] + right
        elif f["category"] == "CODE":
            cwe = meta.get("cwe")
            name = str(meta.get("test_name") or "").replace("_", " ")
            right = [("Check", t.esc(f"{f['rule_id'] or '—'} · {name}")),
                     ("Confidence", t.esc(str(meta.get("confidence") or "—").title())),
                     ("Weakness type", t.esc(f"CWE-{cwe}" if cwe else "—"))] + right
        elif f["category"] == "WEB":
            cwe = meta.get("cwe")
            left[-1] = ("Page", f"<code>{t.esc(meta.get('url') or f['file_path'] or '')}</code>")
            right = [("Check", t.esc(f["rule_id"] or "—")),
                     ("Parameter", t.esc(meta.get("parameter") or "—")),
                     ("Evidence", t.esc(meta.get("evidence") or "—")),
                     ("Weakness type", t.esc(f"CWE-{cwe}" if cwe else "—"))] + right
        c1.markdown(t.kv_table(left), unsafe_allow_html=True)
        c2.markdown(t.kv_table(right), unsafe_allow_html=True)
        if f["description"]:
            section("Description")
            html(f"<div class='lss-desc'>{t.esc(f['description'])}</div>")  # plain text: no remote images or links
        section("Remediation")
        html(f"<div class='lss-remed' style='--c:{color}'>{t.esc(f['remediation'] or 'Review and remediate.')}</div>")
        url = t.safe_url(f["reference_url"])
        if url:
            html(f"<p style='margin-top:.6rem'><a href='{t.esc(url)}' target='_blank' rel='noopener noreferrer'>"
                 f"Reference ↗</a> <span style='color:#64748B;font-size:.78rem'>{t.esc(url)}</span></p>")
        if f["category"] == "SECRET":
            notice("warn", "Treat as compromised if real",
                   "Revoke and rotate it at the provider first, then remove it from the code (and history if needed). "
                   "The scanner stores only rule, file, line and commit — never the secret value.", icon_name="key")
        hist = an.finding_history(conn, int(f["id"]))
        section("Finding history", f"{len(hist)} scan observation(s)")
        if hist.empty:
            st.caption("No scan history recorded for this finding.")
        else:
            rows = "".join(f"<tr><td>{t.esc(fmt_ts(r.changed_at))}</td><td>{t.status_badge(r.change_type if r.change_type != 'NEW' else 'OPEN', r.change_type.title())}</td>"
                           f"<td>#{int(r.run_id)} · {t.esc(r.scanner)}:{t.esc(r.scan_type)}</td><td>{t.status_badge(r.run_status)}</td></tr>"
                           for r in hist.head(30).itertuples())
            html("<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>When</th><th>Change</th>"
                 f"<th>Scan run</th><th>Run status</th></tr></thead><tbody>{rows}</tbody></table></div>")
