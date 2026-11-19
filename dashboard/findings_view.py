"""Shared vulnerability-management view used by the Findings, Vulnerabilities, Secrets,
Misconfigurations, Code issues and Web app issues pages. Secret values are never stored, so they can never be displayed."""

from __future__ import annotations

import json
from datetime import date, timedelta
from typing import Any

import pandas as pd
import streamlit as st

from dashboard import theme as t
from dashboard.common import (ROW_SELECT, fmt_ts, get_config, get_conn, html, notice, page_header, repo_coverage,
                              section, selected_row)
from dashboard.states import no_repositories
from services import analytics_service as an
from services import triage_service as tri
from services.explain import explain
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
             "subtitle": "Security bugs in your own code (SAST) · Python by Bandit; JavaScript/TypeScript, HTML "
                         "templates, PHP, Java, Go and C# by the built-in check · the code is never run"},
    "web": {"title": "Web app issues", "category": "WEB",
            "subtitle": "Problems found by testing your running apps through their web address (DAST) · local apps only"},
}
SCANNER_FOR = {"vuln": ("trivy",), "misconf": ("trivy",), "code": ("bandit", "codescan"), "web": ("dast",)}
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
                     "Signed in": ("yes" if summ and summ.get("logged_in") else "no") if tgt.login else "no login set",
                     "Last tested": fmt_ts(r["finished_at"]) if r else "—", "Result": result,
                     "Pages tested": str(summ["pages"]) if summ else "—",
                     "Requests": str(summ["requests"]) if summ else "—"})
    if empty:
        ran = [x for x in rows if x["Pages tested"] != "—"]
        if ran:
            notice("ok", "No web app issues found",
                   f"{len(ran)} address(es) were tested ({sum(int(x['Pages tested']) for x in ran)} page(s)) and no "
                   "known problem was found. Pages behind a login were only tested for addresses with a "
                   "test-account login set in Settings.")
        else:
            notice("neutral", "Web apps not tested yet",
                   "No address has been tested successfully. Start the app, then scan its project from the "
                   "Repositories page. This does not mean the app is safe.")
    st.markdown("**What was tested**")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    st.caption("Only GET requests are sent (forms that change data are never submitted), links such as log out or "
               "delete are not followed, and only apps on this computer can be tested. Pages behind a login are "
               "tested only for addresses with a test-account login set in Settings (one sign-in POST, password "
               "read from an environment variable).")


def _skipped_leftovers(cfg, conn, df: pd.DataFrame) -> None:  # noqa: ANN001
    """Offer to archive old findings inside folders scans now skip: they can never be re-checked by a scan."""
    ids = set(tri.skipped_folder_findings(conn, cfg.scan.skip_dirs))
    here = ids & set(df["id"].astype(int)) if not df.empty else set()
    if not here:
        return
    c1, c2 = st.columns([3, 1], vertical_alignment="center")
    c1.markdown(t.notice("warn", f"{len(here)} old finding(s) can never be re-checked",
                         "They are inside folders that scans now skip (" + ", ".join(cfg.scan.skip_dirs[:4])
                         + " …) - installed third-party code, so they stay Unverified forever. Archive them to take "
                         "them out of the counts; they stay listed under Status → Decided and in the reports."),
                unsafe_allow_html=True)
    if c2.button(f"Archive {len(here)}", icon=":material/inventory_2:", width="stretch",
                 key="archive_skipped"):
        n = tri.archive_skipped(conn, cfg.scan.skip_dirs)
        st.toast(f"Archived {n} finding(s) inside skipped folders", icon=":material/inventory_2:")
        st.rerun()


def _decision_panel(conn, f: pd.Series) -> None:  # noqa: ANN001
    """False positive / accepted risk / archive, with a reason (and review date), or reopen."""
    fid = int(f["id"])
    current = tri.get_decision(conn, fid)
    section("Your decision", "mark it as a false positive, accept the risk, or archive it - always with a reason")
    if current:
        label = tri.DECISIONS[current["decision"]]
        when = f" · review on {current['review_by']}" if current["review_by"] else ""
        notice("neutral", f"{label}{when}", f"Reason: {current['reason']} (decided {fmt_ts(current['decided_at'])}). "
               "This finding is left out of the open counts and to-do lists, and shown under Status → Decided and "
               "in the reports' decisions section.", icon_name="check_circle")
        with st.form(f"reopen_{fid}", border=False):
            r1, r2 = st.columns([3, 1], vertical_alignment="bottom")
            note = r1.text_input("Note (optional)", key=f"reopen_note_{fid}", placeholder="Why it should count again")
            if r2.form_submit_button("Reopen", icon=":material/undo:", width="stretch"):
                tri.reopen(conn, fid, note)
                st.rerun()
    elif f["status"] in an.ACTIVE:
        with st.form(f"triage_{fid}", border=True):
            choice = st.radio("Decision", list(tri.DECISIONS), format_func=tri.DECISIONS.get, horizontal=True,
                              key=f"tri_choice_{fid}", captions=[tri.HELP[k] for k in tri.DECISIONS])
            reason = st.text_area("Reason (required)", key=f"tri_reason_{fid}", max_chars=500, height=80,
                                  placeholder="e.g. Test fixture value, not a real key / Fix planned in the next "
                                              "release / Third-party code we do not ship")
            d1, d2 = st.columns([1, 2], vertical_alignment="bottom")
            review = d1.date_input("Review date", value=date.today() + timedelta(days=90),
                                   min_value=date.today() + timedelta(days=1),
                                   max_value=date.today() + timedelta(days=tri.MAX_REVIEW_DAYS), key=f"tri_rev_{fid}",
                                   format="YYYY-MM-DD")
            use_review = d2.checkbox("Bring it back on the review date", value=True, key=f"tri_use_rev_{fid}",
                                     help="Always on for an accepted risk. For a false positive or archive you can "
                                          "turn it off.")
            if st.form_submit_button("Save decision", type="primary", icon=":material/gavel:"):
                try:
                    tri.set_decision(conn, fid, choice, reason,
                                     review if (use_review or choice == "ACCEPTED_RISK") else None)
                except tri.TriageError as exc:
                    notice("err", "Not saved", str(exc))
                else:
                    st.toast(f"Marked as {tri.DECISIONS[choice].lower()}", icon=":material/gavel:")
                    st.rerun()
    else:
        st.caption("Resolved findings need no decision.")
    log = tri.history(conn, fid)
    if log:
        rows = "".join(f"<tr><td>{t.esc(fmt_ts(x['at']))}</td><td>{t.esc(tri.DECISIONS.get(x['action'], x['action'].title()))}"
                       f"</td><td>{t.esc(x['reason'] or '')}</td><td>{t.esc(x['review_by'] or '')}</td></tr>"
                       for x in reversed(log[-20:]))
        html("<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>When</th><th>Decision</th>"
             f"<th>Reason</th><th>Review on</th></tr></thead><tbody>{rows}</tbody></table></div>")


def explanation_html(f: dict[str, Any], meta: dict[str, Any], color: str) -> str:
    """The plain-language card: what was found, why it matters, how it is abused, fix steps, how soon."""
    e = explain({**f, "metadata": meta})
    steps = "".join(f"<li>{t.esc(s)}</li>" for s in e.fix)
    terms = (f"<div class='lss-note'>New to these words? See Help → Glossary: {t.esc(', '.join(e.terms))}.</div>"
             if e.terms else "")
    note = f"<div class='lss-note'>{t.esc(e.note)}</div>" if e.note else ""
    return (f"<div class='lss-explain' style='--c:{color}'>"
            f"<h4>What was found</h4><p>{t.esc(e.what)}</p>"
            f"<h4>Why it matters</h4><p>{t.esc(e.why)}</p>"
            f"<h4>How an attacker could use it</h4><p>{t.esc(e.attack)}</p>"
            f"<h4>How to fix it</h4><ol>{steps}</ol>"
            f"<h4>How soon</h4><span class='lss-urgent'>{t.esc(e.urgency)}</span>{note}{terms}</div>")


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
        other = sum(sum(c.other_files.values()) for c in covs) if cfg.sast.other_languages else 0
        if empty:
            if not total and not other:
                notice("neutral", "Nothing to check",
                       "None of your projects contains code files the code check reads (Python, JavaScript/"
                       "TypeScript, HTML templates, PHP, Java, Go, C#). The page is empty because there is nothing "
                       "to check, not because the code is safe.")
            else:
                notice("ok", "No code issues found",
                       f"About {total} Python file(s) and {other} file(s) in other languages were checked and no "
                       "known risky pattern was found (installed libraries such as .venv and node_modules are "
                       "skipped).")
        rows = [{"Project": c.repository, "Python files": c.python_files,
                 "Other languages": ", ".join(f"{n} {lang}" for lang, n in sorted(c.other_files.items()))
                 if cfg.sast.other_languages and c.other_files else "—",
                 "Note": "" if c.python_files or c.other_files else "No code files: nothing for the code check to read."}
                for c in covs]
        if rows:
            st.markdown("**What was checked**")
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        st.caption("Python is checked in depth by Bandit. JavaScript/TypeScript, HTML templates, PHP, Java, Go and C# "
                   "are checked by the built-in code scan for the most common risky patterns. Other languages are "
                   "not analysed." if cfg.sast.other_languages else
                   "Only Python is checked (the check for other languages is turned off in Settings).")
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
            + (f" AND s.scanner IN ({','.join('?' * len(scanner))})" if scanner else ""), scanner or ()).fetchone()
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
                   "The code check has not completed on any project yet, so there is nothing to show. "
                   "This does not mean the code is safe. Run a scan from the Repositories page.")
        else:
            notice("neutral", "No scan data yet",
                   "No scanner has completed successfully, so there is nothing to show. This does not mean the "
                   "repositories are clean. Start a scan from the Repositories page.")
        return

    if kind in ("vuln", "misconf", "code", "web"):
        with st.expander("What was checked in each project", icon=":material/fact_check:"):
            _what_was_checked(cfg, conn, kind, empty=False)
    _skipped_leftovers(cfg, conn, df)

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
        sel_status = f3.pills("Status", ["OPEN", "UNVERIFIED", "RESOLVED", "DECIDED"], selection_mode="multi",
                              default=["OPEN", "UNVERIFIED"], format_func=str.title, key=f"{kind}_status",
                              help="Click to turn a status on or off. None selected = show all. Decided = marked "
                                   "as false positive, accepted risk or archived (open ones are hidden from "
                                   "Open/Unverified).") or []
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
                              severities=sel_sev, statuses=None, cve=cve,
                              package="" if by_file else pkg, file=pkg if by_file else "")
    if sel_status and not view.empty:
        plain = [s for s in sel_status if s != "DECIDED"]
        keep = view["status"].isin(plain) & (view["decision"].isna() | view["status"].eq("RESOLVED"))
        if "DECIDED" in sel_status:
            keep |= view["decision"].notna() & view["status"].isin(an.ACTIVE)
        view = view[keep]
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
        decision_t=view["decision"].map(tri.DECISIONS).fillna(""),
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
            "page": tc("Page / parameter", width="medium"), "address": tc("App address", width="medium"),
            "decision_t": tc("Decision", width="small", help="False positive, accepted risk or archived")}
    cols = {
        "all": ["identifier", "sev", "category_t", "repository", "pkg_rule", "file", "first", "status_t"],
        "vuln": ["identifier", "sev", "package_name", "installed", "fixed", "repository", "file", "first", "status_t"],
        "secret": ["identifier", "sev", "repository", "location", "source", "commit", "first", "last", "status_t"],
        "misconf": ["identifier", "sev", "title", "file", "resource", "repository", "status_t"],
        "code": ["identifier", "sev", "confidence", "title", "location", "repository", "first", "status_t"],
        "web": ["identifier", "sev", "title", "page", "address", "repository", "first", "status_t"],
    }[kind] + ["decision_t"]
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
                     ("Language", t.esc(meta.get("language") or "Python")),
                     ("Confidence", t.esc(str(meta.get("confidence") or "—").title())),
                     ("Weakness type", t.esc(f"CWE-{cwe}" if cwe else "—"))] + right
        elif f["category"] == "WEB":
            cwe = meta.get("cwe")
            left[-1] = ("Page", f"<code>{t.esc(meta.get('url') or f['file_path'] or '')}</code>")
            right = [("Check", t.esc(f["rule_id"] or "—")),
                     ("Parameter", t.esc(meta.get("parameter") or "—")),
                     ("Evidence", t.esc(meta.get("evidence") or "—")),
                     ("Weakness type", t.esc(f"CWE-{cwe}" if cwe else "—"))] + right
        section("In plain words", "what it is, why it matters and how to fix it")
        html(explanation_html(dict(f), meta, color))
        c1.markdown(t.kv_table(left), unsafe_allow_html=True)
        c2.markdown(t.kv_table(right), unsafe_allow_html=True)
        with st.expander("Technical details from the scanner", icon=":material/terminal:"):
            if f["description"]:
                st.markdown("**Description**")
                html(f"<div class='lss-desc'>{t.esc(f['description'])}</div>")  # plain text: no remote images/links
            st.markdown("**Scanner's remediation**")
            html(f"<div class='lss-remed' style='--c:{color}'>{t.esc(f['remediation'] or 'Review and remediate.')}"
                 "</div>")
            url = t.safe_url(f["reference_url"])
            if url:
                html(f"<p style='margin-top:.6rem'><a href='{t.esc(url)}' target='_blank' rel='noopener noreferrer'>"
                     f"Reference ↗</a> <span style='color:#64748B;font-size:.78rem'>{t.esc(url)}</span></p>")
        _decision_panel(conn, f)
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
