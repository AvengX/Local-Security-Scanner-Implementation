"""Settings — validated editing of config.yaml (with automatic backups), tool and DB health, database
backups and scheduling (read-only here: tasks are created only from the CLI after confirmation)."""

from __future__ import annotations

import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

import streamlit as st
from pydantic import ValidationError

from dashboard import theme as t
from dashboard.common import (fmt_bytes, fmt_ts, get_config, get_conn, get_freshness, html, notice, page_header,
                              section, tool_health, trivy_db_location, vuln_db_state, db_health)
from dashboard.states import _update_button
from services import scheduling_service as sch
from utils.config import AppConfig, save_config
from utils.paths import config_path
from utils.validators import GITLEAKS_MODES, SEVERITIES, TRIVY_SCAN_TYPES, TRIVY_SCANNERS

MAX_CONFIG_BACKUPS = 30


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.replace(",", "\n").splitlines() if ln.strip()]


def backup_config(cfg: AppConfig) -> Path | None:
    """Copy the current config.yaml to data/config_backups before it is changed. Keeps the newest 30."""
    src = config_path()
    if not src.is_file():
        return None
    dest_dir = cfg.data_dir / "config_backups"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"config_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.yaml"
    shutil.copy2(src, dest)
    for old in sorted(dest_dir.glob("config_*.yaml"))[:-MAX_CONFIG_BACKUPS]:
        old.unlink(missing_ok=True)
    return dest


def backup_database(cfg: AppConfig, conn: sqlite3.Connection) -> Path:
    """Consistent online copy using SQLite's backup API (safe while scans are running)."""
    dest_dir = cfg.data_dir / "backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / cfg.db_path.name
    target = sqlite3.connect(dest)
    try:
        conn.backup(target)
    finally:
        target.close()
    return dest


@st.cache_data(ttl=60, show_spinner=False)
def _scheduled_tasks() -> list[dict[str, str]]:
    return sch.query_tasks()


def render() -> None:
    cfg = get_config()
    conn = get_conn(cfg)
    page_header("Settings", f"Configuration file: {config_path()}")
    tab_cfg, tab_tools, tab_db, tab_sched = st.tabs(["Configuration", "Scanners & vulnerability DB",
                                                     "Database & backups", "Scheduling"])
    with tab_cfg:
        _config_tab(cfg)
    with tab_tools:
        _tools_tab(cfg)
    with tab_db:
        _db_tab(cfg, conn)
    with tab_sched:
        _sched_tab(cfg)


def _browse_roots(cfg: AppConfig) -> None:
    """Browse button: opens the Windows folder dialog and appends the chosen folder to the roots list."""
    current = _lines(st.session_state.get("roots_text", ""))
    b1, b2 = st.columns([1, 3], vertical_alignment="center")
    if b1.button("Browse for a folder…", icon=":material/folder_open:", width="stretch", key="roots_browse",
                 help="Opens the Windows folder picker on this PC"):
        from utils.folder_picker import FolderPickerError, pick_folder

        start = current[-1] if current else str(Path.home())
        try:
            with st.spinner("Waiting for you to choose a folder in the Windows dialog…"):
                chosen = pick_folder("Select a folder that contains your Git projects", start)
        except FolderPickerError as exc:
            notice("err", "Could not open the folder picker", f"{exc} You can still type or paste the path below.")
        else:
            if not chosen:
                st.toast("No folder selected", icon=":material/info:")
            elif chosen.lower() in {c.lower() for c in current}:
                st.toast(f"Already in the list: {chosen}", icon=":material/info:")
            else:
                st.session_state["roots_text"] = "\n".join([*current, chosen])
                st.session_state["roots_added"] = chosen
                st.rerun()
    added = st.session_state.pop("roots_added", None)
    if added:
        b2.markdown(t.chip(f"Added {added} — press Validate and save to keep it", "info", "folder"),
                    unsafe_allow_html=True)
    else:
        b2.caption("Pick a folder with the Windows dialog, or type/paste paths into the box below (one per line).")


def _config_tab(cfg: AppConfig) -> None:
    if "roots_sync" in st.session_state:  # set after save/reset, applied before the widget is created
        st.session_state["roots_text"] = st.session_state.pop("roots_sync")
    st.session_state.setdefault("roots_text", "\n".join(cfg.repository_roots))
    flash = st.session_state.pop("settings_flash", None)
    if flash:
        notice(*flash)
    section("1 · Repository roots", "folders that contain your Git projects (one per line, absolute paths)")
    _browse_roots(cfg)
    with st.form("settings"):
        roots = st.text_area("Repository root directories", key="roots_text",
                             placeholder="D:\\Projects\nC:\\Users\\you\\source\\repos", label_visibility="collapsed")
        section("2 · Discovery and scan exclusions")
        e1, e2 = st.columns(2)
        excl = e1.text_area("Folders never searched for repositories", "\n".join(cfg.excluded_dirs), height=140)
        scan_skip = e2.text_area(
            "Folders skipped inside repositories while scanning", "\n".join(cfg.scan.skip_dirs), height=140,
            help="Installed dependencies and caches (.venv, node_modules…) can hold tens of thousands of files. "
                 "Dependencies are still checked from manifests and lockfiles. Leave empty to scan everything.")
        d1, d2 = st.columns(2)
        max_depth = d1.number_input("Max search depth", 1, 64, cfg.max_depth)
        follow = d2.checkbox("Follow symlinks/junctions (not recommended)", cfg.follow_symlinks)

        section("3 · Scanning")
        s1, s2, s3 = st.columns(3)
        timeout = s1.number_input("Scan timeout per scanner (seconds)", 30, 86400, cfg.scan.timeout_seconds, step=60)
        conc = s2.number_input("Concurrency (repositories in parallel)", 1, 8, cfg.scan.concurrency)
        fresh_h = s3.number_input("Vulnerability DB freshness threshold (hours)", 1, 2160, cfg.scan.db_freshness_hours)
        sev = st.multiselect("Severity filter", list(SEVERITIES), cfg.scan.severities)
        o1, o2 = st.columns(2)
        offline = o1.toggle("Offline mode (cached databases only, no downloads)", cfg.scan.offline)
        retention = o2.number_input("History retention (days, 0 = keep forever)", 0, 3650, cfg.scan.retention_days)

        section("4 · Scanners")
        t1, t2 = st.columns(2)
        with t1:
            trivy_on = st.checkbox("Enable Trivy", cfg.trivy.enabled)
            trivy_types = st.multiselect("Trivy scan types", list(TRIVY_SCAN_TYPES), cfg.trivy.scan_types)
            trivy_scanners = st.multiselect("Trivy scanners", list(TRIVY_SCANNERS), cfg.trivy.scanners)
            sbom = st.checkbox("Generate CycloneDX SBOM", cfg.trivy.generate_sbom)
        with t2:
            gl_on = st.checkbox("Enable Gitleaks", cfg.gitleaks.enabled)
            gl_modes = st.multiselect("Gitleaks modes", list(GITLEAKS_MODES), cfg.gitleaks.modes,
                                      help="git = commit history · dir = current working tree")
            gl_cfg = st.text_input("Gitleaks config file (allowlists)", cfg.gitleaks.config_path or "")
            gl_log = st.text_input("Gitleaks git log options", cfg.gitleaks.log_opts or "", placeholder="--all")

        section("5 · Reports and storage", "relative paths are resolved from the project folder")
        p1, p2, p3 = st.columns(3)
        data_dir = p1.text_input("Data directory (database)", cfg.paths.data_dir)
        reports_dir = p2.text_input("Reports directory", cfg.paths.reports_dir)
        logs_dir = p3.text_input("Logs directory", cfg.paths.logs_dir)

        section("6 · Application preferences")
        a1, a2 = st.columns(2)
        levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        log_level = a1.selectbox("Log level", levels, index=levels.index(cfg.log_level))
        a2.text_input("Dashboard address (fixed to loopback)", f"{cfg.dashboard.host}:{cfg.dashboard.port}",
                      disabled=True, help="The dashboard is never exposed outside this PC.")
        submitted = st.form_submit_button("Validate and save", type="primary", icon=":material/save:")

    if submitted:
        data = cfg.model_dump()
        data.update(repository_roots=_lines(roots), excluded_dirs=_lines(excl), max_depth=int(max_depth),
                    follow_symlinks=follow, log_level=log_level)
        data["scan"].update(timeout_seconds=int(timeout), concurrency=int(conc), severities=sev, offline=offline,
                            db_freshness_hours=int(fresh_h), retention_days=int(retention), skip_dirs=_lines(scan_skip))
        data["trivy"].update(enabled=trivy_on, scan_types=trivy_types, scanners=trivy_scanners, generate_sbom=sbom)
        data["gitleaks"].update(enabled=gl_on, modes=gl_modes, config_path=gl_cfg.strip() or None,
                                log_opts=gl_log.strip() or None)
        data["paths"].update(data_dir=data_dir.strip(), reports_dir=reports_dir.strip(), logs_dir=logs_dir.strip())
        try:
            new_cfg = AppConfig.model_validate(data)
        except ValidationError as exc:
            for err in exc.errors():
                notice("err", f"Not saved — {'.'.join(str(x) for x in err['loc'])}", err["msg"])
        else:
            if new_cfg.model_dump() == cfg.model_dump():
                notice("neutral", "No changes to save", "The configuration is unchanged.")
            else:
                backup = backup_config(cfg)
                save_config(new_cfg)
                st.toast("Settings saved", icon=":material/check:")
                notice("ok", "Settings saved", f"Previous version backed up to {backup}" if backup else "")
                missing = [r for r in new_cfg.repository_roots if not Path(r).is_dir()]
                if missing:
                    notice("warn", "Some roots do not exist (saved anyway)", ", ".join(missing))

    with st.expander("Reset to defaults"):
        st.write("Replaces config.yaml with the built-in defaults, including an **empty** repository list. "
                 "The current file is backed up first.")
        confirm = st.checkbox("I understand — reset all settings", key="reset_confirm")
        if st.button("Reset to defaults", icon=":material/restart_alt:", disabled=not confirm):
            backup = backup_config(cfg)
            save_config(AppConfig())
            st.session_state["roots_sync"] = ""
            st.session_state["settings_flash"] = ("ok", "Settings reset to defaults",
                                                  f"Backup: {backup}" if backup else "")
            st.rerun()
    backups = sorted((cfg.data_dir / "config_backups").glob("config_*.yaml"), reverse=True)
    if backups:
        st.caption(f"{len(backups)} configuration backup(s) in {cfg.data_dir / 'config_backups'} · newest: "
                   f"{backups[0].name}")


def _tools_tab(cfg: AppConfig) -> None:
    health = tool_health(cfg.trivy.executable, cfg.gitleaks.executable)
    section("Scanner health", "checked at most once a minute")
    rows = []
    for key, h in health.items():
        rows.append(f"<tr><td><b>{t.esc(key.title())}</b></td><td>{t.status_badge('COMPLETED' if h['state'] == 'ok' else 'FAILED', h['label'])}"
                    f"</td><td>{t.esc(h['version'] or '—')}</td><td><code>{t.esc(h['path'] or '—')}</code></td>"
                    f"<td>{t.esc(h['detail'])}</td></tr>")
    html("<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Tool</th><th>Status</th><th>Version</th>"
         f"<th>Path</th><th>Details</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>")
    if st.button("Re-check now", icon=":material/refresh:", key="recheck"):
        tool_health.clear()
        st.rerun()
    f = get_freshness(cfg)
    vstate, vlabel = vuln_db_state(f)
    section("Trivy vulnerability database")
    html(t.kv_table([("Status", t.status_badge('COMPLETED' if vstate == 'ok' else 'FAILED' if vstate == 'err' else 'UNVERIFIED', vlabel)),
                     ("Location", f"<code>{t.esc(trivy_db_location(cfg))}</code>"),
                     ("DB updated", t.esc(fmt_ts(f.updated_at))), ("Downloaded", t.esc(fmt_ts(f.downloaded_at))),
                     ("Java DB cached", "yes" if f.java_db_present else "no"),
                     ("Freshness threshold", f"{cfg.scan.db_freshness_hours} h"),
                     ("Mode", "Offline — cached databases only" if cfg.scan.offline else "Online"),
                     ("Details", t.esc(f.message))]))
    st.caption("Updating needs internet access (about 80 MB). Offline scans use only the cached copy; advisories "
               "published after the DB date are not detected.")
    _update_button(cfg, "settings", health["trivy"]["state"] == "ok")


def _db_tab(cfg: AppConfig, conn: sqlite3.Connection) -> None:
    dbh = db_health(cfg, conn)
    counts = {tbl: conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]  # noqa: S608 - fixed table names
              for tbl in ("repositories", "scan_runs", "findings", "finding_changes")}
    section("SQLite database")
    html(t.kv_table([("Status", t.status_badge('COMPLETED' if dbh['state'] == 'ok' else 'FAILED', dbh['label'])),
                     ("File", f"<code>{t.esc(cfg.db_path)}</code>"), ("Size", fmt_bytes(dbh["size"])),
                     ("Rows", " · ".join(f"{k} {v:,}" for k, v in counts.items())),
                     ("Reports folder", f"<code>{t.esc(cfg.reports_dir)}</code>"),
                     ("Logs folder", f"<code>{t.esc(cfg.logs_dir)}</code>"),
                     ("History retention", f"{cfg.scan.retention_days} days" if cfg.scan.retention_days else "forever")]))
    if st.button("Back up database now", icon=":material/backup:", key="db_backup"):
        dest = backup_database(cfg, conn)
        notice("ok", "Database backed up", str(dest))
    backups = sorted((cfg.data_dir / "backups").glob("*/*.db"), reverse=True)
    if backups:
        st.dataframe([{"Backup": b.parent.name, "File": str(b), "Size": fmt_bytes(b.stat().st_size)} for b in backups[:20]],
                     hide_index=True, width="stretch")
    st.caption("Restore: stop the dashboard and scans, then copy a backup over the database file. Retention clean-up "
               "runs with `python run_scan.py prune`.")


def _sched_tab(cfg: AppConfig) -> None:
    notice("info", "Scheduled tasks are created only from the command line",
           "Scheduled scans run `run_scan.py scan-all` through Windows Task Scheduler while the dashboard is closed, "
           "and never overlap. This page shows the commands and what is registered; it does not create tasks.")
    st.code(sch.instructions(), language="powershell")
    section("Preview (dry run)", "exact PowerShell that `schedule` would register — nothing is executed")
    c1, c2, c3 = st.columns(3)
    freq = c1.selectbox("Frequency", ["daily", "weekly"], key="sch_freq")
    tm = c2.text_input("Time (HH:MM)", cfg.schedule.time, key="sch_time")
    day = c3.selectbox("Day (weekly)", ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"],
                       index=["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"].index(cfg.schedule.weekly_day),
                       key="sch_day", disabled=freq == "daily")
    try:
        st.code(sch.build_create_script(freq, tm, day), language="powershell", wrap_lines=True)
    except ValueError as exc:
        notice("err", "Invalid schedule", str(exc))
    section("Registered tasks")
    tasks = _scheduled_tasks()
    if tasks:
        st.dataframe(tasks, hide_index=True, width="stretch")
    else:
        notice("neutral", "No scheduled tasks", "No Local Security Scanner tasks are registered in Task Scheduler.")
