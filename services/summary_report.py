"""Management summary: a short, plain-language VAPT report for non-technical readers (managers, clients).

One page per scope (all monitored projects, or one): an overall risk level, a table per project, the ten things to
fix first written as actions, what was and was not tested, progress over the last 30 days, and next steps.
Built only from the local database; secret values are never included (they are never stored).
"""

from __future__ import annotations

import html
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from services.explain import LOCAL_SECRET_FILE, URGENCY, explain, risk_level
from utils.config import AppConfig
from utils.version import __version__

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEV_RANK = {s: i for i, s in enumerate(SEVS)}
ACTIVE = ("OPEN", "UNVERIFIED")
OK = ("COMPLETED", "COMPLETED_WITH_FINDINGS")
CAT_LABEL = {"VULNERABILITY": "Outdated library", "SECRET": "Leaked password / key", "CODE": "Risky code",
             "WEB": "Web app problem", "MISCONFIGURATION": "Unsafe setting", "LICENSE": "Licence"}
CHECKS = [  # (label, scanner, scan_type or None for any)
    ("Libraries with known flaws", "trivy", "fs"),
    ("Passwords and keys in files", "gitleaks", "dir"),
    ("Passwords and keys in Git history", "gitleaks", "git"),
    ("Python code", "bandit", None),
    ("Code in other languages", "codescan", None),
    ("Docker / cloud settings", "trivy", "config"),
]


def _e(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def _first_sentence(text: str) -> str:
    m = re.match(r"(.+?[.!?])(\s|$)", text.strip())
    return m.group(1) if m else text.strip()


def _when(ts: str | None) -> str:
    return ts[:16].replace("T", " ") + " UTC" if ts else "never"


def build_summary(conn: sqlite3.Connection, cfg: AppConfig, repository_id: int | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    where = "id=?" if repository_id is not None else "active=1"
    repos = [dict(r) for r in conn.execute(f"SELECT id, name FROM repositories WHERE {where} ORDER BY name COLLATE "
                                           "NOCASE", (repository_id,) if repository_id is not None else ())]
    since = (now - timedelta(days=30)).isoformat()
    projects, priorities, totals = [], [], {s: 0 for s in SEVS}
    resolved_30 = new_30 = 0
    for repo in repos:
        rows = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE repository_id=?", (repo["id"],))]
        for r in rows:
            try:
                r["metadata"] = json.loads(r.get("metadata_json") or "{}")
            except ValueError:
                r["metadata"] = {}
        skip = {d.lower() for d in cfg.scan.skip_dirs}
        # Old findings inside folders that scans now skip (installed libraries such as .venv) can never be
        # re-checked; they are third-party code. Counted separately instead of inflating the risk.
        in_skipped = [r for r in rows if r["status"] in ACTIVE and skip
                      & {p.lower() for p in re.split(r"[\\/]", r["file_path"] or "")}]
        active = [r for r in rows if r["status"] in ACTIVE and r not in in_skipped]
        # The same configuration problem can be reported by two Trivy modes; count it once.
        seen_conf: set[tuple] = set()
        uniq = []
        for r in active:
            if r["category"] == "MISCONFIGURATION":
                key = (r["rule_id"], r["file_path"], r["line"])
                if key in seen_conf:
                    continue
                seen_conf.add(key)
            uniq.append(r)
        active = uniq
        counts = {s: 0 for s in SEVS}
        for r in active:
            counts[r["severity"] if r["severity"] in counts else "UNKNOWN"] += 1
        for s in SEVS:
            totals[s] += counts[s]
        resolved_30 += sum(1 for r in rows if r["status"] == "RESOLVED" and (r["resolved_at"] or "") >= since)
        new_30 += sum(1 for r in rows if (r["first_seen"] or "") >= since)
        unverified = sum(1 for r in active if r["status"] == "UNVERIFIED")

        # What was tested: latest run of each check.
        runs = {}
        for r in conn.execute("SELECT scanner, scan_type, scan_target, status, finished_at, report_path, "
                              "error_message FROM scan_runs WHERE repository_id=? ORDER BY id", (repo["id"],)):
            runs[(r["scanner"], r["scan_type"], r["scan_target"])] = dict(r)
        tested = []
        for label, scanner, stype in CHECKS:
            hits = [v for (sc, ty, _), v in runs.items() if sc == scanner and (stype is None or ty == stype)]
            if not hits:
                tested.append((label, "not run", ""))
                continue
            last = max(hits, key=lambda v: v["finished_at"] or "")
            state = "done" if last["status"] in OK else ("skipped" if last["status"] == "SKIPPED" else "failed")
            tested.append((label, state, _when(last["finished_at"])))
        for t in cfg.dast.targets:
            if t.repository != repo["name"]:
                continue
            last = runs.get(("dast", "web", t.url))
            if not last:
                tested.append((f"Web app at {t.url}", "not run", ""))
                continue
            state = ("done" if last["status"] in OK else "app not running" if last["status"] == "SKIPPED"
                     else "failed")
            signed = ""
            if t.login is not None and last["status"] in OK:
                from engine.dast_scanner import read_report_summary

                summ = read_report_summary(last["report_path"])
                signed = " (signed in with test account)" if summ and summ.get("logged_in") else ""
            tested.append((f"Web app at {t.url}{signed}", state, _when(last["finished_at"])))
        last_scan = max((v["finished_at"] or "" for v in runs.values() if v["status"] in OK), default="") or None

        # Group issues into actions.
        groups: dict[tuple, dict[str, Any]] = {}
        for r in active:
            if r["category"] == "VULNERABILITY":
                key = ("VULN", r["package_name"], r["installed_version"])
            elif r["category"] == "SECRET":
                key = ("SECRET", r["file_path"])  # one action per file, whichever scanners reported it
            else:
                # Same root cause found by different scanners (e.g. Flask debug in code and on the running app)
                # becomes one action.
                topic = explain(r).topic
                key = ("TOPIC", topic) if topic != "generic" else (r["category"], r["rule_id"] or r["title"])
            g = groups.setdefault(key, {"rows": [], "sev": "UNKNOWN"})
            g["rows"].append(r)
            if SEV_RANK.get(r["severity"], 9) < SEV_RANK.get(g["sev"], 9):
                g["sev"] = r["severity"]
        top_problem = ""
        for key, g in groups.items():
            r0 = min(g["rows"], key=lambda r: SEV_RANK.get(r["severity"], 9))
            e = explain(r0)
            n = len(g["rows"])
            if key[0] == "VULN":
                fixes = sorted({x["fixed_version"].split(",")[0].strip() for x in g["rows"] if x["fixed_version"]})
                action = (f"Update the library {r0['package_name']} from version {r0['installed_version']}"
                          + (f" to {fixes[-1]} or newer" if fixes else " (no fixed version published yet)"))
                detail = f"It has {n} publicly known security flaw{'s' if n != 1 else ''}."
            elif key[0] == "SECRET" and LOCAL_SECRET_FILE.search(key[1] or "") and all(
                    x["scan_type"] != "git" for x in g["rows"]):
                action = (f"Make sure {key[1]} stays listed in .gitignore and is never shared; rotate the key only "
                          "if it ever was")
                detail = ("A real password or key is kept in a local secrets file. That is the right place, and it "
                          "was not found in the Git history.")
            else:
                action = _first_sentence(e.fix[0]) if e.fix else "Review and fix"
                where = sorted({(x["file_path"] or "/") for x in g["rows"]})
                detail = (_first_sentence(e.what.split(" Found ")[0]) +
                          f" ({n} place{'s' if n != 1 else ''}: {', '.join(where[:3])}{' …' if len(where) > 3 else ''})")
            priorities.append({"project": repo["name"], "severity": g["sev"], "count": n, "action": action,
                               "detail": detail, "why": _first_sentence(e.attack), "category": r0["category"],
                               "when": URGENCY.get(g["sev"], URGENCY["UNKNOWN"]).split(".")[0] + "."})
            if not top_problem or SEV_RANK.get(g["sev"], 9) < SEV_RANK.get(top_problem[0], 9):
                top_problem = (g["sev"], action)
        projects.append({"name": repo["name"], "counts": counts, "total": len(active), "unverified": unverified,
                         "skipped_old": len(in_skipped),
                         "last_scan": last_scan, "tested": tested,
                         "top": top_problem[1] if top_problem else "Nothing open",
                         "by_cat": {c: sum(1 for r in active if r["category"] == c) for c in CAT_LABEL}})
    priorities.sort(key=lambda p: (SEV_RANK.get(p["severity"], 9), -p["count"], p["project"]))
    label, colour, sentence = risk_level(totals)
    return {"generated_at": now.isoformat(), "projects": projects, "priorities": priorities, "totals": totals,
            "risk": (label, colour, sentence), "resolved_30": resolved_30, "new_30": new_30,
            "scope": repos[0]["name"] if repository_id is not None and repos else "All monitored projects",
            "app_version": __version__}


_CSS = """
@page { size: A4; margin: 15mm 13mm 16mm; }
* { box-sizing: border-box; }
body { font: 10.5pt/1.5 'Segoe UI', Arial, sans-serif; color: #111827; margin: 0 auto; max-width: 900px; padding: 24px; }
h1 { font-size: 20pt; margin: 0; } h2 { font-size: 13pt; margin: 22px 0 8px; padding-bottom: 4px;
  border-bottom: 2px solid #1f2937; break-after: avoid; }
.sub { color: #4b5563; margin: 2px 0 14px; }
.risk { border-radius: 8px; padding: 12px 16px; color: #111827; border: 2px solid var(--c);
  background: color-mix(in srgb, var(--c) 12%, white); }
.risk b { font-size: 15pt; display: block; }
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 12px 0; }
.card { border: 1px solid #e5e7eb; border-top: 4px solid var(--c); border-radius: 6px; padding: 8px 10px; }
.card .n { font-size: 18pt; font-weight: 700; } .card .l { color: #4b5563; font-size: 9pt; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 12px; font-size: 9.5pt; }
th, td { border: 1px solid #d1d5db; padding: 5px 7px; text-align: left; vertical-align: top; }
th { background: #f3f4f6; } .num { text-align: right; white-space: nowrap; } tr { break-inside: avoid; }
.sev { font-weight: 700; white-space: nowrap; } .CRITICAL { color: #b91c1c; } .HIGH { color: #c2410c; }
.MEDIUM { color: #a16207; } .LOW { color: #1d4ed8; } .UNKNOWN { color: #6b7280; }
ol.todo { padding-left: 1.2rem; } ol.todo li { margin: 0 0 9px; break-inside: avoid; }
ol.todo .a { font-weight: 650; } ol.todo .m { color: #4b5563; font-size: 9.5pt; }
.done { color: #047857; font-weight: 600; } .failed, .not { color: #b91c1c; font-weight: 600; }
.skipped, .app { color: #a16207; font-weight: 600; }
.note { background: #f9fafb; border: 1px solid #e5e7eb; padding: 8px 12px; font-size: 9.5pt; border-radius: 6px; }
.muted { color: #6b7280; } ul li { margin: 3px 0; }
@media print { body { padding: 0; max-width: none; } }
"""
SEV_COL = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#ca8a04", "LOW": "#1d4ed8", "UNKNOWN": "#6b7280"}


def render_summary_html(d: dict[str, Any]) -> str:
    label, colour, sentence = d["risk"]
    tot = d["totals"]
    s = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>Security status summary</title>"
         f"<style>{_CSS}</style></head><body>",
         f"<h1>Security status summary</h1><div class='sub'>{_e(d['scope'])} · {len(d['projects'])} project(s) · "
         f"{_e(_when(d['generated_at']))} · Local Security Scanner {_e(d['app_version'])}</div>",
         f"<div class='risk' style='--c:{colour}'><b>{_e(label)}</b>{_e(sentence)}</div>",
         "<div class='cards'>" + "".join(
             f"<div class='card' style='--c:{SEV_COL[k]}'><div class='n'>{tot[k]}</div><div class='l'>{lbl}</div></div>"
             for k, lbl in (("CRITICAL", "Critical - fix today"), ("HIGH", "High - fix this week"),
                            ("MEDIUM", "Medium - plan this month"), ("LOW", "Low - when convenient"))) + "</div>",
         "<p>This report summarises an automated security check (vulnerability assessment) of our own software, run "
         "on our own computer. It looks for outdated libraries with known flaws, passwords or keys left in code, "
         "risky code, unsafe settings, and problems in our web apps while they run. Nothing was uploaded.</p>"]

    s.append("<h2>1. Projects at a glance</h2>")
    rows = "".join(
        f"<tr><td><b>{_e(p['name'])}</b></td>" + "".join(
            f"<td class='num'><span class='sev {k}'>{p['counts'][k]}</span></td>" for k in SEVS[:4])
        + f"<td>{_e(p['top'])}</td><td>{_e(_when(p['last_scan']))}</td></tr>" for p in d["projects"])
    s.append("<table><thead><tr><th>Project</th><th class='num'>Critical</th><th class='num'>High</th>"
             "<th class='num'>Medium</th><th class='num'>Low</th><th>Most important action</th><th>Last checked</th>"
             f"</tr></thead><tbody>{rows or '<tr><td colspan=7>No projects.</td></tr>'}</tbody></table>")
    cats = {c: sum(p["by_cat"][c] for p in d["projects"]) for c in CAT_LABEL}
    s.append("<p class='muted'>Open issues by type: " + " · ".join(
        f"{_e(CAT_LABEL[c])}: {n}" for c, n in cats.items() if n) + (" none" if not any(cats.values()) else "")
             + "</p>")

    s.append("<h2>2. What to fix first</h2>")
    top = d["priorities"][:10]
    if top:
        s.append("<ol class='todo'>" + "".join(
            f"<li><span class='sev {p['severity']}'>{_e(p['severity'].title())}</span> · <b>{_e(p['project'])}</b> · "
            f"<span class='a'>{_e(p['action'])}</span><div class='m'>{_e(p['detail'])} Risk: {_e(p['why'])} "
            f"<b>{_e(p['when'])}</b></div></li>" for p in top) + "</ol>")
        if len(d["priorities"]) > 10:
            s.append(f"<p class='muted'>{len(d['priorities']) - 10} more action(s) are listed in the dashboard and in "
                     "each project's detailed audit report.</p>")
    else:
        s.append("<p>Nothing open. Keep scanning regularly - new flaws in libraries are published every day.</p>")

    s.append("<h2>3. What was tested</h2>")
    for p in d["projects"]:
        rows = "".join(f"<tr><td>{_e(lbl)}</td><td class='{st.split()[0]}'>{_e(st)}</td><td>{_e(when)}</td></tr>"
                       for lbl, st, when in p["tested"])
        s.append(f"<p><b>{_e(p['name'])}</b>" + (f" <span class='muted'>· {p['unverified']} issue(s) could not be "
                                                  "re-checked in the last scan and are kept as unverified</span>"
                                                  if p["unverified"] else "")
                 + (f" <span class='muted'>· {p['skipped_old']} older finding(s) inside installed-library folders "
                    "(such as .venv) are no longer checked and are not counted here - they belong to third-party "
                    "code</span>" if p.get("skipped_old") else "") + "</p>"
                 f"<table><thead><tr><th>Check</th><th>Result</th><th>When</th></tr></thead><tbody>{rows}</tbody>"
                 "</table>")
    s.append("<p class='muted'>'not run' means the check did not apply or was not enabled (for example no Docker "
             "files, or no web address added). 'app not running' means the web app was not started during the scan, "
             "so its earlier issues are kept as unverified - never counted as fixed.</p>")

    s.append("<h2>4. Progress in the last 30 days</h2>"
             f"<p><b>{d['resolved_30']}</b> issue(s) fixed and confirmed by a re-scan · <b>{d['new_30']}</b> issue(s) "
             "found for the first time.</p>")

    s.append("<h2>5. What this check does not cover</h2><ul>"
             "<li>Business-logic flaws, for example whether one user can see another user's data.</li>"
             "<li>Apps running on other computers or on the internet (the web test only touches this computer).</li>"
             "<li>Forms that change data are never submitted, so data-changing features are not attacked.</li>"
             "<li>Libraries listed without an exact version cannot be matched to known flaws.</li>"
             "<li>It is an automated first line of defence and does not replace a manual penetration test.</li></ul>")
    s.append("<h2>6. Recommended next steps</h2><ol>"
             "<li>Work through section 2 from the top: critical today, high this week.</li>"
             "<li>Re-scan after each fix; fixed issues are confirmed automatically.</li>"
             "<li>Keep the weekly scheduled scan running so new flaws are caught early.</li>"
             "<li>Before a major release, consider a manual penetration test for business-logic issues.</li></ol>")
    s.append("<div class='note'>Severity guide - <b>Critical</b>: easy to abuse, serious damage; fix today. "
             "<b>High</b>: real attack possible; fix this week. <b>Medium</b>: needs extra conditions or limited "
             "damage; plan this month. <b>Low</b>: small risk on its own. Secret values are never stored or shown. "
             "Technical details for each issue are in the dashboard and the per-project audit report.</div>"
             "<p class='muted'>To save as PDF: open this file in a browser and choose Print → Save as PDF.</p>"
             "</body></html>")
    return "".join(s)


def summary_filename(scope: str, generated_at: str) -> str:
    stamp = re.sub(r"[^0-9TZ]", "", generated_at[:19]) + "Z"
    return f"{stamp}_{re.sub(r'[^A-Za-z0-9._-]+', '_', scope)[:50]}_management_summary.html"


def generate_summary(conn: sqlite3.Connection, cfg: AppConfig, repository_id: int | None = None
                     ) -> tuple[str, str, dict[str, Any]]:
    d = build_summary(conn, cfg, repository_id)
    return summary_filename(d["scope"], d["generated_at"]), render_summary_html(d), d
