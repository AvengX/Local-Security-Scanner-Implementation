"""Guided empty/warning/error states shared by several pages (each one offers a real action)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import streamlit as st

from dashboard import theme as t
from dashboard.common import (PAGES, get_freshness, html, is_queued, launch_background, mark_queued, notice,
                              tool_health, trivy_db_location)
from database.db import get_setting
from utils.config import AppConfig

EXAMPLE_CONFIG = "repository_roots:\n  - 'D:\\Projects'\n  - 'C:\\Users\\you\\source\\repos'"


def _go(page: str) -> None:
    if page in PAGES:
        st.switch_page(PAGES[page])


def no_repositories(cfg: AppConfig, conn: sqlite3.Connection, key: str) -> None:
    """Explain *why* no repositories are visible and offer the next step."""
    roots = cfg.repository_roots
    missing = [r for r in roots if not Path(r).is_dir()]
    last_discovery = get_setting(conn, "last_discovery_at")
    if not roots:
        notice("info", "No repository folders configured",
               body_html="The scanner only looks inside folders you choose. Add one or more <b>repository roots</b> "
                         "(folders that contain your Git projects), then run discovery.")
        st.code(EXAMPLE_CONFIG, language="yaml")
        if st.button("Configure repository folders", icon=":material/settings:", type="primary", key=f"{key}_cfg"):
            _go("settings")
        return
    if missing and len(missing) == len(roots):
        notice("err", "Configured folders were not found",
               body_html="None of the configured repository roots exist on this PC: " +
                         ", ".join(f"<code>{t.esc(m)}</code>" for m in missing) +
                         ". Check the paths (or reconnect the drive) in Settings.")
        if st.button("Fix repository folders", icon=":material/settings:", type="primary", key=f"{key}_fix"):
            _go("settings")
        return
    if last_discovery:
        notice("warn", "Discovery found no Git repositories",
               body_html=f"Discovery last ran {t.esc(last_discovery[:16].replace('T', ' '))} and found no "
                         "folders containing <code>.git</code> under: " +
                         ", ".join(f"<code>{t.esc(r)}</code>" for r in roots) +
                         ". Check <b>Max search depth</b> and <b>Excluded directory names</b> in Settings.")
    else:
        notice("info", "Repositories have not been discovered yet",
               body_html="Repository roots are configured: " + ", ".join(f"<code>{t.esc(r)}</code>" for r in roots) +
                         ". Run discovery to find the Git repositories inside them.")
    c1, c2, _ = st.columns([1, 1, 2])
    if c1.button("Discover repositories", icon=":material/travel_explore:", type="primary", key=f"{key}_disc",
                 width="stretch"):
        from engine.scan_orchestrator import ScanOrchestrator

        with st.spinner("Discovering repositories…"):
            result, stats = ScanOrchestrator(cfg).discover()
        st.toast(f"Found {len(result.repositories)} repositories · new {stats['new']}", icon=":material/check:")
        for e in result.errors[:10]:
            notice("warn", "Discovery warning", e)
        if result.repositories:
            st.rerun()
    if c2.button("Open settings", icon=":material/settings:", key=f"{key}_set", width="stretch"):
        _go("settings")


def system_alerts(cfg: AppConfig, key: str) -> None:
    """Honest scanner / vulnerability-DB problems, each with a safe next step."""
    health = tool_health(cfg.trivy.executable, cfg.gitleaks.executable)
    for name, label in (("trivy", "Trivy"), ("gitleaks", "Gitleaks")):
        h = health[name]
        enabled = cfg.trivy.enabled if name == "trivy" else cfg.gitleaks.enabled
        if h["state"] == "ok" or not enabled:
            continue
        if h["label"] == "Blocked by Windows":
            notice("err", f"{label} is blocked by Windows",
                   body_html=f"Windows Smart App Control / Application Control refused to start "
                             f"<code>{t.esc(h['path'])}</code>. {label} scans are reported as <b>FAILED</b>, never as "
                             "clean. Safe steps: confirm the file came from the official winget package or GitHub "
                             "release and compare its SHA-256 with the published checksum; then the PC owner may allow "
                             "it in Windows Security. The scanner never bypasses this policy.")
        elif h["label"] == "Missing":
            cmd = "winget install AquaSecurity.Trivy" if name == "trivy" else "winget install Gitleaks.Gitleaks"
            notice("err", f"{label} is not installed",
                   body_html=f"{t.esc(h['detail'])}. Install it with <code>{cmd}</code>, reopen PowerShell, then "
                             "press Refresh.")
        else:
            notice("err", f"{label} could not run", h["detail"] or "Unknown error")
    f = get_freshness(cfg)
    if not cfg.trivy.enabled:
        return
    loc = trivy_db_location(cfg)
    if not f.present:
        body = (f"Trivy needs its vulnerability database to find vulnerable packages. Expected location: "
                f"<code>{t.esc(loc)}</code>. Downloading it needs internet access (about 80 MB). "
                + ("<b>Offline mode is on</b>, so vulnerability scans will fail until the database is copied here or "
                   "offline mode is turned off." if cfg.scan.offline else
                   "Secrets and misconfiguration checks still work without it."))
        notice("err", "Vulnerability database missing", body_html=body, icon_name="database")
        _update_button(cfg, key, health["trivy"]["state"] == "ok")
    elif f.stale:
        notice("warn", "Vulnerability database is out of date",
               body_html=f"{t.esc(f.message)}. New advisories published since then will not be detected. "
                         f"Location: <code>{t.esc(loc)}</code>." +
                         (" Offline mode is on: update while online, or copy a fresh DB here." if cfg.scan.offline
                          else ""), icon_name="database")
        _update_button(cfg, key, health["trivy"]["state"] == "ok")


def _update_button(cfg: AppConfig, key: str, trivy_ok: bool) -> None:
    queued = is_queued("update-db")
    if st.button("Update vulnerability database (internet)", icon=":material/cloud_download:", key=f"{key}_upd",
                 disabled=not trivy_ok or queued,
                 help="Runs 'run_scan.py update-databases' in the background" if trivy_ok else "Trivy is unavailable"):
        pid = launch_background(["update-databases"], cfg)
        mark_queued("update-db")
        st.toast(f"Database update started (pid {pid}). Press Refresh in a minute.", icon=":material/cloud_download:")
    if queued:
        html(t.notice("info", "Update in progress", "Started from this dashboard; press Refresh to see the result."))
