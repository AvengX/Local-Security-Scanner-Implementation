"""Overview — executive security dashboard. Every number comes from the local SQLite database."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

from dashboard import theme as t
from dashboard.common import (PAGES, ago, db_health, get_config, get_conn, get_freshness, html, misconfig_relevant,
                              page_header, section, tool_health, vuln_db_state)
from dashboard.states import no_repositories, system_alerts
from services import analytics_service as an
from utils.validators import SEVERITIES


def _posture(m: dict, wt_secrets: int) -> tuple[str, str, str, str]:
    sev = m["severity"]
    if m["repositories_scanned"] == 0:
        return "neutral", "Not assessed", "info", "No successful scan yet. Run a scan to assess these repositories."
    if sev["CRITICAL"]:
        return "err", "Critical exposure", "flame", (f"{sev['CRITICAL']} critical finding(s) are open. Treat these "
                                                     "first — they are typically remotely exploitable.")
    if sev["HIGH"] or wt_secrets:
        parts = []
        if sev["HIGH"]:
            parts.append(f"{sev['HIGH']} high-severity finding(s)")
        if m["category"]["SECRET"]:
            parts.append(f"{m['category']['SECRET']} exposed secret(s)")
        return "warn", "Elevated risk", "alert", " and ".join(parts) + " need attention."
    if sev["MEDIUM"] or sev["LOW"] or sev["UNKNOWN"]:
        return "info", "Guarded", "shield", "Only medium/low findings are open. Plan fixes in normal maintenance."
    return "ok", "No open findings", "shield_check", "The latest successful scans found nothing open."


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Security Overview", "Posture across all locally discovered repositories · data never leaves this PC",
                search=True)
    system_alerts(cfg, "ov")
    m = an.overview_metrics(conn)
    if m["repositories"] == 0:
        no_repositories(cfg, conn, "ov")
        return

    sev, cat = m["severity"], m["category"]
    show_misconf = misconfig_relevant(cfg, conn)
    week = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    new7, res7 = (conn.execute("SELECT COUNT(*) FROM finding_changes c JOIN scan_runs s ON s.id=c.scan_run_id "
                               "JOIN repositories r ON r.id=s.repository_id AND r.active=1 "
                               "WHERE c.change_type=? AND c.changed_at>=?",
                               (k, week)).fetchone()[0] for k in ("NEW", "RESOLVED"))
    hot = an.secret_hotspots(conn)
    wt_secrets = int(hot["in_working_tree"].sum()) if not hot.empty else 0
    open_total = sum(sev.values())

    tone, level, ic, text = _posture(m, wt_secrets)
    if m["failed_scans_latest"]:
        text += f" Coverage is incomplete: {m['failed_scans_latest']} scanner run(s) failed on their latest attempt."
    c = t.TONES[tone]
    stats = [(f"{m['repositories_scanned']}/{m['repositories']}", "repositories scanned"),
             (f"{open_total}", "open findings (incl. unverified)"), (f"{new7}", "new in last 7 days"),
             (f"{res7}", "resolved in last 7 days")]
    html(f"<section class='lss-hero' style='--c:{c}' aria-label='Security posture'>"
         f"<div><div class='lss-hero-kicker'>Security posture · based on highest open severity</div>"
         f"<div class='lss-hero-level'>{t.icon(ic, 26, c, 2)}{t.esc(level)}</div>"
         f"<div class='lss-hero-text'>{t.esc(text)}</div></div><div class='lss-hero-stats'>" +
         "".join(f"<div class='lss-hero-stat'><b>{t.esc(v)}</b><span>{t.esc(lbl)}</span></div>" for v, lbl in stats) +
         "</div></section>")

    html(t.metric_grid([
        t.metric_card("Repositories", m["repositories"], f"last discovery {ago(m['last_discovery'])}", "info", "folder"),
        t.metric_card("Scanned", m["repositories_scanned"], f"{m['total_scans']} scanner runs total", "violet", "scan"),
        t.metric_card("Critical", sev["CRITICAL"], "open + unverified", t.SEVERITY_COLORS["CRITICAL"], "flame"),
        t.metric_card("High", sev["HIGH"], "open + unverified", t.SEVERITY_COLORS["HIGH"], "alert"),
        t.metric_card("Exposed secrets", cat["SECRET"], "values never stored", t.CATEGORY_COLORS["SECRET"], "key"),
        t.metric_card("Code issues", cat["CODE"], "risky patterns in your code", t.CATEGORY_COLORS["CODE"], "code",
                      aria=f"Code issues: {cat['CODE']}"),
        t.metric_card("Web app issues", cat["WEB"], "found by testing running apps", t.CATEGORY_COLORS["WEB"],
                      "globe", aria=f"Web app issues: {cat['WEB']}"),
        *([t.metric_card("Misconfigs", cat["MISCONFIGURATION"], "IaC / Dockerfile settings",
                         t.CATEGORY_COLORS["MISCONFIGURATION"], "sliders",
                         aria=f"Misconfigurations: {cat['MISCONFIGURATION']}")] if show_misconf else []),
        t.metric_card("Failed scans", m["failed_scans_latest"], f"latest per scanner · {m['failed_scans_total']} total",
                      "err" if m["failed_scans_latest"] else "ok", "x_circle" if m["failed_scans_latest"] else
                      "check_circle"),
    ], min_width=145))
    if m["unverified"]:
        st.caption(f":material/help: {m['unverified']} findings are UNVERIFIED — a later scan failed or did not cover "
                   "them, so they are kept (never auto-resolved).")

    with st.container(key="panel_by_project"):
        section("Problems by project", "open + unverified · each problem counted once")
        html(_by_project_html(conn, show_misconf))

    with st.container(key="wrap_bottom"):
        b1, b2, b3 = st.columns([1.25, 1.25, 1])
        with b1, st.container(key="panel_actions"):
            section("Recommended actions", "derived from open findings")
            html(_actions_html(conn, m, hot, cfg))
        with b2, st.container(key="panel_activity"):
            section("Latest scan activity")
            runs = an.recent_runs(conn, 7)
            if runs.empty:
                html(t.notice("neutral", "No scans yet", "Run a scan from Repositories."))
            else:
                rows = "".join(
                    f"<tr><td><b>{t.esc(r.repository)}</b><br><span style='color:#64748B'>{t.esc(r.scanner)}:"
                    f"{t.esc(r.scan_type)}</span></td><td>{t.status_badge(r.status)}</td>"
                    f"<td style='text-align:right'>{int(r.findings_count)}</td>"
                    f"<td style='color:#64748B'>{t.esc(ago(r.finished_at or r.started_at))}</td></tr>"
                    for r in runs.itertuples())
                html("<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Repository</th><th>Status</th>"
                     f"<th style='text-align:right'>Found</th><th>When</th></tr></thead><tbody>{rows}</tbody></table></div>")
                if st.button("Open scan history", icon=":material/history:", key="ov_hist_btn") and "history" in PAGES:
                    st.switch_page(PAGES["history"])
        with b3, st.container(key="panel_health"):
            section("Scanner health")
            html(_health_html(cfg, conn))


def _by_project_html(conn, show_misconf: bool = True) -> str:  # noqa: ANN001
    """Plain table instead of charts: what kind of problem, how many, and the most serious one, per project."""
    repos = an.repository_table(conn)
    fdf = an.findings_frame(conn)
    act = fdf[an.active_mask(fdf)].drop_duplicates(["repository", "dedup_key"]) if not fdf.empty else fdf
    rows = []
    for r in repos.itertuples():
        f = act[act["repository"] == r.name] if not act.empty else act
        cnt = f["category"].value_counts().to_dict() if not f.empty else {}
        if r.state == "NEVER":
            worst = "<span style='color:#94A3B8'>Not scanned yet</span>"
        elif f.empty:
            worst = "<span style='color:#22C55E'>No problems found</span>"
        else:
            worst = t.sev_badge(min(f["severity"], key=lambda s: SEVERITIES.index(s)))

        def cell(n: int) -> str:
            shown = str(n) if n else "<span style='color:#64748B'>0</span>"
            return f"<td style='text-align:right'>{shown}</td>"

        rows.append(f"<tr><td><b>{t.esc(r.name)}</b></td>{cell(cnt.get('VULNERABILITY', 0))}{cell(cnt.get('SECRET', 0))}"
                    f"{cell(cnt.get('CODE', 0))}{cell(cnt.get('WEB', 0))}"
                    f"{cell(cnt.get('MISCONFIGURATION', 0)) if show_misconf else ''}<td>{worst}</td>"
                    f"<td style='text-align:right'><b>{len(f)}</b></td></tr>")
    head = ("<th>Project</th><th style='text-align:right'>Vulnerable libraries</th>"
            "<th style='text-align:right'>Leaked secrets</th><th style='text-align:right'>Code issues</th>"
            "<th style='text-align:right'>Web app issues</th>"
            + ("<th style='text-align:right'>Unsafe settings</th>" if show_misconf else "") +
            "<th>Most serious</th><th style='text-align:right'>Total</th>")
    return (f"<div class='lss-table-wrap'><table class='lss-table'><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
            "<div style='color:#94A3B8;font-size:.85rem;margin-top:.45rem'>Vulnerable libraries = third-party packages "
            "with known security flaws · Leaked secrets = passwords, keys or tokens written in files · Code issues = "
            "risky patterns in your own code, such as SQL built from strings · Web app issues = problems found by "
            "testing the running app through its web address"
            + (" · Unsafe settings = risky Docker / cloud configuration" if show_misconf else "") + ".</div>")


def _actions_html(conn, m: dict, hot: pd.DataFrame, cfg) -> str:  # noqa: ANN001
    items: list[tuple[str, str, str]] = []  # (tone, title, detail)
    f = get_freshness(cfg)
    if not f.present or f.stale:
        items.append(("warn", "Update the vulnerability database", f.message))
    if m["failed_scans_latest"]:
        items.append(("err", f"Investigate {m['failed_scans_latest']} failed scanner run(s)",
                      "See Scan History for the error; failed scans never clear existing findings."))
    if not hot.empty:
        wt = hot[hot["in_working_tree"] == 1]
        hist = hot[hot["in_working_tree"] == 0]
        if not wt.empty:
            files = ", ".join(f"{r.repository}/{r.file_path}" for r in wt.head(3).itertuples())
            items.append(("err", f"Rotate credentials found in {len(wt)} current file(s)",
                          f"{files}{' …' if len(wt) > 3 else ''}. Revoke at the provider first; keep the files out of Git."))
        if not hist.empty:
            items.append(("warn", f"Review {len(hist)} file(s) with secrets only in Git history",
                          "Rotate if real; history stays readable to anyone with repository access."))
    for r in an.upgrade_candidates(conn, 4).itertuples():
        items.append(("warn" if r.worst <= 1 else "info", f"Upgrade {r.package_name} {r.installed_version} → "
                      f"{r.fixed_version}", f"{r.repository} · fixes {r.advisories} advisor"
                      f"{'y' if r.advisories == 1 else 'ies'}"))
    if m["category"]["CODE"]:
        items.append(("info", f"Review {m['category']['CODE']} code issue(s)",
                      "See the Code issues page: each one names the file, line and the safer way to write it."))
    if m["category"]["WEB"]:
        items.append(("warn", f"Fix {m['category']['WEB']} web app issue(s)",
                      "See the Web app issues page: each one names the page, what was seen and how to fix it."))
    elif cfg.dast.enabled and not cfg.dast.targets:
        items.append(("info", "Add your web app's address to test it while it runs (DAST)",
                      "Settings → Web scan (DAST), for example http://127.0.0.1:5000/."))
    if m["category"]["MISCONFIGURATION"]:
        items.append(("info", f"Fix {m['category']['MISCONFIGURATION']} misconfiguration(s)",
                      "See the Misconfigurations page for per-file remediation."))
    if not items:
        return t.notice("ok", "Nothing to do right now", "No open findings and all scanners are healthy.")
    li = "".join(f"<li><span class='lss-step' style='--c:{t.TONES[tone]}'>{i}</span><div class='grow'>"
                 f"<div class='t'>{t.esc(title)}</div><div class='s'>{t.esc(detail)}</div></div></li>"
                 for i, (tone, title, detail) in enumerate(items[:7], 1))
    return f"<ul class='lss-list'>{li}</ul>"


def _health_html(cfg, conn) -> str:  # noqa: ANN001
    health = tool_health(cfg.trivy.executable, cfg.gitleaks.executable)
    f = get_freshness(cfg)
    vstate, vlabel = vuln_db_state(f)
    dbh = db_health(cfg, conn)
    rows = []
    for key, label in (("trivy", "Trivy"), ("gitleaks", "Gitleaks"), ("bandit", "Bandit (code)"), ("git", "Git")):
        h = health[key]
        rows.append((label, h["state"], h["label"], h["version"] and f"v{h['version']}"))
    if cfg.sast.enabled and cfg.sast.other_languages:
        rows.append(("Code scan, other languages", "ok", "Built in", "JavaScript/TypeScript, templates, PHP, Java, Go, C#"))
    if cfg.dast.enabled:
        n = len(cfg.dast.targets)
        rows.append(("Web scan (DAST)", "ok" if n else "warn", "Built in" if n else "No addresses added",
                     f"{n} address{'es' if n != 1 else ''}" if n else "add one in Settings"))
    rows.append(("Vulnerability DB", vstate, vlabel, f"updated {ago(f.updated_at)}" if f.present else "not downloaded"))
    rows.append(("SQLite database", dbh["state"], dbh["label"], f"{dbh['size'] / 1024:.0f} KB"))
    li = "".join(f"<li><span class='lss-step' style='--c:{t.TONES[s]}'>{t.icon('check_circle' if s == 'ok' else 'alert', 14, t.TONES[s])}"
                 f"</span><div class='grow'><div class='t'>{t.esc(n)}</div><div class='s'>{t.esc(lbl)}"
                 f"{' · ' + t.esc(extra) if extra else ''}</div></div></li>" for n, s, lbl, extra in rows)
    return f"<ul class='lss-list'>{li}</ul>"
