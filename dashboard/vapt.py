"""VAPT Lab — run and review the local acceptance test against the disposable vulnerable lab.

Only the generated lab in vapt_lab/targets is ever scanned from here. external_targets/ and your real
repositories are never touched by this page.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard import theme as t
from dashboard.common import (ago, clear_queued, fmt_ts, get_config, html, is_queued, launch_process,
                              mark_queued, notice, page_header, queued_at, section, watch_until_idle)
from utils.paths import PROJECT_ROOT
from utils.security import same_process_alive

LAB = PROJECT_ROOT / "vapt_lab"
SCRIPT = PROJECT_ROOT / "vapt" / "run_vapt_test.py"
SCENARIO = [
    ("vuln-python-app", "Dependencies + secrets + code (SAST) + running app (DAST)",
     "requests 2.25.0, urllib3 1.26.4, PyYAML 5.3, Jinja2 2.10; fake AWS key + GitHub token in code; a token only in "
     "Git history; SQL injection, shell=True, pickle.loads, yaml.load and a hardcoded password in app/db.py; a fake "
     "token and unsafe code inside an untracked .venv (must be skipped); a local web app with XSS, SQL injection, "
     "open redirect, path traversal, exposed .env, debugger console, stack traces, directory listing, open CORS and "
     "an unsafe cookie (log-out/delete links must never be followed)"),
    ("vuln-node-app", "Dependencies", "lodash 4.17.15 and minimist 1.2.0 in package-lock.json"),
    ("insecure-infra", "Infrastructure as code", "Dockerfile (:latest, root, ADD from URL), privileged Kubernetes "
     "pod with hostNetwork, Terraform S3 without public-access block, SSH open to 0.0.0.0/0"),
    ("clean-app", "False-positive control", "Nothing planted, plus a correctly secured local web app — must "
     "produce zero findings"),
]


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _history() -> list[dict]:
    p = LAB / "history.jsonl"
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


MARKER_MAX_AGE = 3 * 3600  # a real test takes minutes; an older marker is a leftover from a killed run


def marker_running(marker: Path) -> bool:
    """True only if the marker's process is alive, is the same process (start time matches) and is recent.

    A test killed from Task Manager leaves its marker behind; if Windows later reuses the PID for another
    program, the start time no longer matches, so the page does not show "Running" forever."""
    try:
        if not marker.is_file() or time.time() - marker.stat().st_mtime > MARKER_MAX_AGE:
            return False
        text = marker.read_text(encoding="utf-8").strip()
        if text.startswith("{"):
            data = json.loads(text)
            return same_process_alive(int(data["pid"]), data.get("start"))
        return same_process_alive(int(text), None)  # marker from an older version: PID only
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _running() -> bool:
    return marker_running(LAB / "RUNNING.pid")


def _busy() -> bool:
    """Running if the test's marker process is alive, or it was just launched and has not produced results yet."""
    if _running():
        return True
    if not is_queued("vapt"):
        return False
    results = LAB / "VAPT_TEST_RESULTS.json"
    ts = queued_at("vapt") or 0
    if results.is_file() and results.stat().st_mtime >= ts:
        clear_queued("vapt")  # finished after it was launched from here
        return False
    return True


def render() -> None:
    cfg = get_config()
    page_header("VAPT Lab", "End-to-end acceptance test against a disposable, intentionally vulnerable local lab")
    notice("info", "Scope: local lab only",
           body_html="The test creates throwaway Git repositories in <code>vapt_lab\\targets</code> with harmless, "
                     "randomly generated fake credentials, scans them with the real scanners and checks the results. "
                     "It never scans your repositories, <code>external_targets</code> or any network service. "
                     "This covers the <b>vulnerability assessment</b> part of VAPT (static analysis); penetration "
                     "testing of running systems needs separate, authorised tooling.", icon_name="lab")

    result = _load_json(LAB / "VAPT_TEST_RESULTS.json")
    hist = _history()
    running = _busy()
    targets = [p.name for p in (LAB / "targets").iterdir() if p.is_dir()] if (LAB / "targets").is_dir() else []

    if result:
        ok = result["passed"] == result["total"]
        last = t.metric_card("Last result", f"{result['passed']}/{result['total']}", "all checks passed" if ok else
                             f"{result['total'] - result['passed']} check(s) failed", "ok" if ok else "err",
                             "check_circle" if ok else "x_circle")
    else:
        last = t.metric_card("Last result", "—", "never run on this PC", "neutral", "info")
    html(t.metric_grid([
        last,
        t.metric_card("Last run", ago(result.get("finished")) if result else "never",
                      fmt_ts(result.get("finished"), short=True) if result else "", "info", "clock"),
        t.metric_card("Lab repositories", len(targets), "present in vapt_lab/targets", "violet", "folder"),
        t.metric_card("Runs recorded", len(hist), "history on this PC", "neutral", "activity"),
        t.metric_card("Status", "Running" if running else "Idle", "test in progress" if running else "ready",
                      "info" if running else "ok", "activity" if running else "shield_check"),
    ], min_width=150))

    with st.container(key="actions_vapt"):
        c1, c2 = st.columns([1, 2], vertical_alignment="center")
        if c1.button("Running…" if running else "Run VAPT test", icon=":material/science:", type="primary",
                     width="stretch", disabled=running, help="Takes about 1–2 minutes; runs in the background"):
            pid = launch_process(SCRIPT, [], cfg, log_name="vapt_runs.log")
            mark_queued("vapt")
            st.toast(f"VAPT test started (pid {pid}). Press Refresh in about two minutes.", icon=":material/science:")
            st.rerun()
        c2.caption("Recreates the lab, runs discovery, full and offline scans (incl. the SAST code scan and the DAST web scan of two local lab apps), remediation "
                   "rescans, exports and a secret-leak audit. Output: vapt_lab\\VAPT_TEST_RESULTS.md · log: logs\\vapt_runs.log")
    if running:
        notice("info", "VAPT test in progress", "Results appear here automatically when it finishes (about 1–2 "
               "minutes). Progress is written to logs\vapt_runs.log.", icon_name="activity")
        watch_until_idle(_busy, "vapt")

    section("Test scenario", "what the lab plants and the scanner must find")
    rows = "".join(f"<tr><td><b>{t.esc(n)}</b></td><td>{t.esc(k)}</td><td>{t.esc(d)}</td>"
                   f"<td>{t.status_badge('COMPLETED' if n in targets else 'SKIPPED', 'Present' if n in targets else 'Not created')}</td></tr>"
                   for n, k, d in SCENARIO)
    html("<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Repository</th><th>Focus</th>"
         f"<th>Planted weaknesses</th><th>Lab</th></tr></thead><tbody>{rows}</tbody></table></div>")

    if not result:
        notice("neutral", "No results yet", "Run the test to see expected versus actual detection for every check.")
        return

    checks = pd.DataFrame(result["checks"])
    section("Checks by phase", "each phase of the test and how many of its checks passed")
    g = checks.groupby("phase", sort=False)["passed"].agg(ok="sum", total="count").reset_index()
    rows = "".join(
        f"<tr><td><b>{t.esc(r.phase)}</b></td><td style='text-align:right'>{int(r.ok)}</td>"
        f"<td style='text-align:right'>{int(r.total - r.ok)}</td><td>"
        + (t.status_badge("COMPLETED", "All passed") if r.ok == r.total else
           t.status_badge("FAILED", f"{int(r.total - r.ok)} failed")) + "</td></tr>"
        for r in g.itertuples())
    html("<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Phase</th>"
         "<th style='text-align:right'>Passed</th><th style='text-align:right'>Failed</th><th>Result</th></tr>"
         f"</thead><tbody>{rows}</tbody></table></div>")

    section("Expected versus actual", f"{int(checks['passed'].sum())} of {len(checks)} checks passed · run "
            f"{fmt_ts(result.get('started'))} → {fmt_ts(result.get('finished'))}")
    only_failed = st.toggle("Show failed checks only", value=False, key="vapt_failed")
    view = checks[~checks["passed"]] if only_failed else checks
    if view.empty:
        notice("ok", "No failed checks", "Every expectation was met in the last run.")
    else:
        st.dataframe(view.assign(result=view["passed"].map(lambda p: "✓ Pass" if p else "✕ Fail"))[
                         ["phase", "name", "result", "detail"]],
                     hide_index=True, width="stretch", height=min(520, 40 + 35 * len(view)),
                     column_config={"phase": st.column_config.TextColumn("Phase", width="small"),
                                    "name": st.column_config.TextColumn("Expected", width="large"),
                                    "result": st.column_config.TextColumn("Result", width="small"),
                                    "detail": st.column_config.TextColumn("Actual", width="large")})
    if hist:
        section("Run history")
        st.dataframe([{"Started": fmt_ts(h.get("started")), "Finished": fmt_ts(h.get("finished")),
                       "Result": f"{h.get('passed')}/{h.get('total')}",
                       "Failed checks": ", ".join(h.get("failed") or []) or "—"} for h in reversed(hist)],
                     hide_index=True, width="stretch")
