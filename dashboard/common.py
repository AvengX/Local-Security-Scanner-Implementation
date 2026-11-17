"""Shared dashboard plumbing: config/DB access, cached health checks, app shell (sidebar + top bar),
background jobs and small formatting helpers. Visual primitives live in ``dashboard.theme``."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

from dashboard import theme as t
from database.db import init_db
from engine.scanner_health import (CREATE_NO_WINDOW, DbFreshness, check_git, check_gitleaks, check_trivy,
                                   default_trivy_cache_dir, trivy_db_freshness)
from utils.config import AppConfig, load_config
from utils.paths import PROJECT_ROOT
from utils.version import __version__

# Re-exported for pages and backwards compatibility.
SEVERITY_COLORS = t.SEVERITY_COLORS
CATEGORY_COLORS = t.CATEGORY_COLORS
STATUS_COLORS = t.STATUS_COLORS
PAGES: dict[str, Any] = {}
QUEUE_GRACE_SECONDS = 90  # a just-launched job shows as "Queued" until its scan_run row appears


# ------------------------------------------------------------------------------------------ config / DB
@st.cache_resource(show_spinner=False)
def _conn_for(db_path: str) -> sqlite3.Connection:
    return init_db(Path(db_path))


def get_config() -> AppConfig:
    return load_config()


def get_conn(cfg: AppConfig | None = None) -> sqlite3.Connection:
    cfg = cfg or get_config()
    cfg.ensure_dirs()
    conn = _conn_for(str(cfg.db_path))
    # A RUNNING row whose process has died would otherwise show as "running" forever.
    from database.repositories import recover_orphaned_runs

    recover_orphaned_runs(conn)
    return conn


def get_freshness(cfg: AppConfig) -> DbFreshness:
    return trivy_db_freshness(cfg.trivy.cache_dir, cfg.scan.db_freshness_hours)


def trivy_db_location(cfg: AppConfig) -> Path:
    root = Path(os.path.expandvars(cfg.trivy.cache_dir)) if cfg.trivy.cache_dir else default_trivy_cache_dir()
    return root / "db"


# -------------------------------------------------------------------------------------------- health
def _classify(status: Any) -> dict[str, Any]:
    if status.usable:
        state, label = "ok", "Operational"
    elif not status.installed:
        state, label = "err", "Missing"
    elif status.error and "blocked" in status.error.lower():
        state, label = "err", "Blocked by Windows"
    else:
        state, label = "err", "Error"
    return {"name": status.name, "state": state, "label": label, "version": status.version or "",
            "path": status.path or "", "detail": status.error or ""}


@st.cache_data(ttl=60, show_spinner=False)
def tool_health(trivy_exe: str | None, gitleaks_exe: str | None) -> dict[str, dict[str, Any]]:
    """Run the version checks at most once a minute (each check starts a process)."""
    return {s["name"]: s for s in (_classify(check_trivy(trivy_exe)), _classify(check_gitleaks(gitleaks_exe)),
                                   _classify(check_git()))}


def db_health(cfg: AppConfig, conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        ok = conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        size = cfg.db_path.stat().st_size if cfg.db_path.is_file() else 0
    except (sqlite3.Error, OSError) as exc:
        return {"state": "err", "label": "Error", "detail": str(exc), "size": 0}
    return {"state": "ok" if ok else "err", "label": "Healthy" if ok else "Integrity error",
            "detail": str(cfg.db_path), "size": size}


def vuln_db_state(f: DbFreshness) -> tuple[str, str]:
    if not f.present:
        return "err", "Missing"
    if f.stale:
        return "warn", f"Stale · {f.age_hours:.0f}h" if f.age_hours is not None else "Stale"
    return "ok", f"Fresh · {f.age_hours:.0f}h" if f.age_hours is not None else "Fresh"


# ------------------------------------------------------------------------------------------- jobs
def running_jobs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Scanner runs currently queued or in progress, with elapsed time."""
    out = []
    for r in conn.execute("SELECT s.id, r.name, r.path, s.scanner, s.scan_type, s.status, s.started_at, "
                          "NULL AS created_at FROM scan_runs s JOIN repositories r ON r.id=s.repository_id "
                          "WHERE s.status IN ('RUNNING','PENDING') ORDER BY s.id"):
        ts = r["started_at"] or r["created_at"]
        try:
            secs = max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds()))
        except (TypeError, ValueError):
            secs = 0
        out.append({"id": r["id"], "repository": r["name"], "path": r["path"],
                    "scanner": f"{r['scanner']}:{r['scan_type']}", "status": r["status"],
                    "elapsed": f"{secs // 60}m {secs % 60:02d}s"})
    return out


def mark_queued(key: str) -> None:
    st.session_state.setdefault("lss_queued", {})[key] = time.time()


def is_queued(key: str) -> bool:
    ts = st.session_state.get("lss_queued", {}).get(key)
    return bool(ts and time.time() - ts < QUEUE_GRACE_SECONDS)


def queued_at(key: str) -> float | None:
    return st.session_state.get("lss_queued", {}).get(key)


def clear_queued(key: str) -> None:
    st.session_state.get("lss_queued", {}).pop(key, None)


def scans_started_since(conn: sqlite3.Connection, ts: float, repo_path: str | None = None) -> int:
    """Scanner runs created after a launch time (used to tell a just-queued job has actually run)."""
    iso = datetime.fromtimestamp(ts, timezone.utc).replace(microsecond=0).isoformat()
    sql = ("SELECT COUNT(*) FROM scan_runs s JOIN repositories r ON r.id=s.repository_id "
           "WHERE COALESCE(s.started_at, s.finished_at) >= ?")
    params: list[Any] = [iso]
    if repo_path:
        sql += " AND r.path=?"
        params.append(repo_path)
    return conn.execute(sql, params).fetchone()[0]


def watch_until_idle(is_busy: Any, key: str, interval: str = "3s") -> None:
    """While a background job runs, re-check every few seconds and refresh the page once it finishes.

    Implemented as a Streamlit fragment, so only this tiny check reruns until the state changes."""

    @st.fragment(run_every=interval)
    def _watch() -> None:
        if not is_busy():
            tool_health.clear()
            st.rerun(scope="app")
        st.caption(f":material/progress_activity: Checking every {interval[:-1]} s — the page updates "
                   "automatically when the job finishes.")

    _watch()


def _python() -> str:
    py = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    return str(py) if py.is_file() else sys.executable


def launch_process(script: Path, args: list[str], cfg: AppConfig, log_name: str = "dashboard_jobs.log") -> int:
    """Start a project script detached from the Streamlit process; output goes to logs/<log_name>."""
    log_path = cfg.logs_dir / log_name
    cfg.logs_dir.mkdir(parents=True, exist_ok=True)
    flags = CREATE_NO_WINDOW | (0x00000200 if os.name == "nt" else 0)  # CREATE_NEW_PROCESS_GROUP
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(f"\n=== {script.name} {' '.join(args)}\n")
        fh.flush()
        proc = subprocess.Popen(  # noqa: S603 - fixed project script + validated arguments, no shell
            [_python(), str(script), *args], cwd=str(PROJECT_ROOT), stdout=fh, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, shell=False, creationflags=flags,
        )
    return proc.pid


def launch_background(args: list[str], cfg: AppConfig) -> int:
    """Start a run_scan.py CLI job (scan/discover/update-databases) in the background."""
    return launch_process(PROJECT_ROOT / "run_scan.py", args, cfg)


# --------------------------------------------------------------------------------------- table selection
# Let users open a row by ticking its checkbox *or* clicking any cell in it.
ROW_SELECT = ["single-row", "single-cell"]


def selected_row(event: Any) -> int | None:
    """Index of the row chosen in an st.dataframe event (row checkbox or clicked cell)."""
    sel = getattr(event, "selection", None) if event else None
    if not sel:
        return None
    rows = sel.get("rows") if isinstance(sel, dict) else getattr(sel, "rows", None)
    if rows:
        return int(rows[0])
    cells = sel.get("cells") if isinstance(sel, dict) else getattr(sel, "cells", None)
    if cells:
        first = cells[0]
        return int(first[0] if isinstance(first, (list, tuple)) else first["row"])
    return None


# ------------------------------------------------------------------------------------------ formatting
def fmt_ts(value: Any, short: bool = False) -> str:
    if not value or (isinstance(value, float) and value != value):
        return "—"
    return str(value).replace("T", " ")[: 16 if short else 19]


def ago(value: Any) -> str:
    if not value or (isinstance(value, float) and value != value):
        return "never"
    try:
        secs = (datetime.now(timezone.utc) - datetime.fromisoformat(str(value))).total_seconds()
    except ValueError:
        return fmt_ts(value, short=True)
    if secs < 90:
        return "just now"
    if secs < 3600:
        return f"{secs / 60:.0f} min ago"
    if secs < 86400 * 2:
        return f"{secs / 3600:.0f} h ago"
    return f"{secs / 86400:.0f} days ago"


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def notice(kind: str, title: str, body: str = "", **kw: Any) -> None:
    html(t.notice(kind, title, body, **kw))


def empty_state(message: str, title: str = "Nothing to show yet") -> None:
    notice("neutral", title, message, icon_name="info")


def section(title: str, caption: str = "") -> None:
    html(t.section_title(title, caption))


def chart(fig: Any, height: int = 300, title: str | None = None, legend: bool = True, key: str | None = None) -> None:
    st.plotly_chart(t.style_fig(fig, height, title, legend), width="stretch", config=t.PLOTLY_CONFIG, key=key)


# ----------------------------------------------------------------------------------------- app shell
def inject_css() -> None:
    st.markdown(t.CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str, search: bool = False) -> None:
    """Compact top bar: title, description, live status chips, optional global search and Refresh."""
    cfg = get_config()
    conn = get_conn(cfg)
    last = conn.execute("SELECT MAX(finished_at) FROM scan_runs WHERE status IN "
                        "('COMPLETED','COMPLETED_WITH_FINDINGS')").fetchone()[0]
    health = tool_health(cfg.trivy.executable, cfg.gitleaks.executable)
    scanners = [h for n, h in health.items() if n in ("trivy", "gitleaks")]
    bad = [h["name"].title() for h in scanners if h["state"] != "ok"]
    vstate, vlabel = vuln_db_state(get_freshness(cfg))
    jobs = running_jobs(conn)
    chips = [t.chip(f"Last scan {ago(last)}", "neutral", "clock", title=fmt_ts(last))]
    chips.append(t.chip("Scanners operational" if not bad else f"{', '.join(bad)} unavailable",
                        "ok" if not bad else "err", "shield_check" if not bad else "alert"))
    chips.append(t.chip(f"Vuln DB {vlabel.lower()}", vstate, "database"))
    if jobs:
        chips.append(t.chip(f"{len(jobs)} scan job{'s' if len(jobs) != 1 else ''} active", "info", "activity"))
    with st.container(key="topbar"):
        c1, c2, c3 = st.columns([5, 5, 1.1], vertical_alignment="top")
        c1.markdown(f"<div class='lss-head'><div class='lss-title' role='heading' aria-level='1'>{t.esc(title)}</div>"
                    f"<div class='lss-subtitle'>{t.esc(subtitle)}</div></div>",
                    unsafe_allow_html=True)
        c2.markdown(f"<div class='lss-chips'>{''.join(chips)}</div>", unsafe_allow_html=True)
        if c3.button("Refresh", icon=":material/refresh:", key=f"refresh_{title}", help="Reload data from the database",
                     width="stretch"):
            tool_health.clear()
            st.rerun()
    if search:
        with st.form(f"search_{title}", border=False, clear_on_submit=True):
            s1, s2 = st.columns([6, 1], vertical_alignment="bottom")
            q = s1.text_input("Search all findings", placeholder="Search findings by CVE, rule, package, file or title…",
                              label_visibility="collapsed")
            go = s2.form_submit_button("Search", icon=":material/search:", width="stretch")
        if go and q.strip():
            st.session_state["findings_q"] = q.strip()[:200]
            if "findings" in PAGES:
                st.switch_page(PAGES["findings"])


def render_sidebar(cfg: AppConfig, conn: sqlite3.Connection) -> None:
    health = tool_health(cfg.trivy.executable, cfg.gitleaks.executable)
    f = get_freshness(cfg)
    vstate, vlabel = vuln_db_state(f)
    dbh = db_health(cfg, conn)
    rows = [("Trivy", health["trivy"]["state"], health["trivy"]["label"]),
            ("Gitleaks", health["gitleaks"]["state"], health["gitleaks"]["label"]),
            ("Vuln DB", vstate, vlabel),
            ("Database", dbh["state"], dbh["label"])]
    body = "".join(f"<div class='lss-health-row' style='--c:{t.TONES[s]}'><span>{t.esc(n)}</span>"
                   f"<span class='state'><i aria-hidden='true'></i>{t.esc(label)}</span></div>" for n, s, label in rows)
    mode = "Offline mode" if cfg.scan.offline else "Online mode"
    html(f"<div class='lss-health' aria-label='System health'><div class='lss-health-title'>System health</div>{body}"
         f"<div class='lss-health-foot'>v{__version__} · {mode} · 127.0.0.1 only</div></div>")
    jobs = running_jobs(conn)
    if jobs:
        lines = "<br>".join(f"<b>{t.esc(j['repository'])}</b> · {t.esc(j['scanner'])} · "
                            f"{'queued' if j['status'] == 'PENDING' else j['elapsed']}" for j in jobs[:6])
        html(f"<div class='lss-running' role='status'>Scanning now<br>{lines}</div>")
