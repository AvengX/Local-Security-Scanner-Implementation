"""Page 6 — Settings: validated editing of config.yaml, tool health and scheduling instructions."""

from __future__ import annotations

from pathlib import Path

import streamlit as st
from pydantic import ValidationError

from dashboard.common import fmt_ts, get_config, get_freshness, page_header
from engine.scanner_health import check_git, check_gitleaks, check_trivy
from services import scheduling_service as sch
from utils.config import AppConfig, save_config
from utils.paths import config_path
from utils.validators import GITLEAKS_MODES, SEVERITIES, TRIVY_SCAN_TYPES, TRIVY_SCANNERS


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.replace(",", "\n").splitlines() if ln.strip()]


def render() -> None:
    cfg = get_config()
    page_header("Settings", f"Configuration file: {config_path()}")

    tab_cfg, tab_health, tab_sched = st.tabs(["Configuration", "Tool health", "Scheduling"])
    with tab_cfg:
        with st.form("settings"):
            st.markdown("**Repository discovery**")
            roots = st.text_area("Repository root directories (one per line)", "\n".join(cfg.repository_roots),
                                 placeholder="D:\\Projects")
            excl = st.text_area("Excluded directory names", "\n".join(cfg.excluded_dirs), height=120)
            d1, d2 = st.columns(2)
            max_depth = d1.number_input("Max search depth", 1, 64, cfg.max_depth)
            follow = d2.checkbox("Follow symlinks/junctions (not recommended)", cfg.follow_symlinks)

            st.markdown("**Scanning**")
            s1, s2, s3 = st.columns(3)
            timeout = s1.number_input("Scan timeout (seconds)", 30, 86400, cfg.scan.timeout_seconds, step=60)
            conc = s2.number_input("Concurrency (repositories)", 1, 8, cfg.scan.concurrency)
            fresh_h = s3.number_input("DB freshness threshold (hours)", 1, 2160, cfg.scan.db_freshness_hours)
            sev = st.multiselect("Severity filter", list(SEVERITIES), cfg.scan.severities)
            o1, o2 = st.columns(2)
            offline = o1.toggle("Offline mode (cached databases only)", cfg.scan.offline)
            retention = o2.number_input("History retention (days, 0 = forever)", 0, 3650, cfg.scan.retention_days)

            st.markdown("**Scanners**")
            t1, t2 = st.columns(2)
            trivy_on = t1.checkbox("Enable Trivy", cfg.trivy.enabled)
            trivy_types = t1.multiselect("Trivy scan types", list(TRIVY_SCAN_TYPES), cfg.trivy.scan_types)
            trivy_scanners = t1.multiselect("Trivy scanners", list(TRIVY_SCANNERS), cfg.trivy.scanners)
            sbom = t1.checkbox("Generate CycloneDX SBOM", cfg.trivy.generate_sbom)
            gl_on = t2.checkbox("Enable Gitleaks", cfg.gitleaks.enabled)
            gl_modes = t2.multiselect("Gitleaks modes", list(GITLEAKS_MODES), cfg.gitleaks.modes,
                                      help="git = commit history · dir = current working tree")
            gl_cfg = t2.text_input("Gitleaks config file (allowlists)", cfg.gitleaks.config_path or "")
            gl_log = t2.text_input("Gitleaks git log options", cfg.gitleaks.log_opts or "", placeholder="--all")

            st.markdown("**Storage**")
            p1, p2, p3 = st.columns(3)
            data_dir = p1.text_input("Data directory", cfg.paths.data_dir)
            reports_dir = p2.text_input("Reports directory", cfg.paths.reports_dir)
            logs_dir = p3.text_input("Logs directory", cfg.paths.logs_dir)
            submitted = st.form_submit_button("Validate and save", type="primary", icon=":material/save:")

        if submitted:
            data = cfg.model_dump()
            data.update(repository_roots=_lines(roots), excluded_dirs=_lines(excl), max_depth=int(max_depth),
                        follow_symlinks=follow)
            data["scan"].update(timeout_seconds=int(timeout), concurrency=int(conc), severities=sev,
                                offline=offline, db_freshness_hours=int(fresh_h), retention_days=int(retention))
            data["trivy"].update(enabled=trivy_on, scan_types=trivy_types, scanners=trivy_scanners,
                                 generate_sbom=sbom)
            data["gitleaks"].update(enabled=gl_on, modes=gl_modes, config_path=gl_cfg.strip() or None,
                                    log_opts=gl_log.strip() or None)
            data["paths"].update(data_dir=data_dir.strip(), reports_dir=reports_dir.strip(), logs_dir=logs_dir.strip())
            try:
                new_cfg = AppConfig.model_validate(data)
                missing = [r for r in new_cfg.repository_roots if not Path(r).is_dir()]
                save_config(new_cfg)
                st.success("Settings saved.")
                if missing:
                    st.warning("These roots do not exist (saved anyway): " + ", ".join(missing))
            except ValidationError as exc:
                for err in exc.errors():
                    st.error(f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}")

    with tab_health:
        f = get_freshness(cfg)
        rows = []
        for t in (check_git(), check_trivy(cfg.trivy.executable), check_gitleaks(cfg.gitleaks.executable)):
            rows.append({"Tool": t.name, "Status": "OK" if t.usable else ("Blocked / error" if t.installed else "Missing"),
                         "Version": t.version or "", "Path": t.path or "", "Details": t.error or ""})
        st.dataframe(rows, hide_index=True, width="stretch")
        st.markdown(f"**Trivy vulnerability DB:** {f.message}")
        st.caption(f"Updated: {fmt_ts(f.updated_at)} · downloaded: {fmt_ts(f.downloaded_at)} · "
                   f"Java DB cached: {f.java_db_present}")
        st.code("python run_scan.py update-databases   # online, refreshes cached DBs\n"
                "python run_scan.py health", language="powershell")
        st.caption(f"Database: {cfg.db_path} · Reports: {cfg.reports_dir} · Logs: {cfg.logs_dir}")

    with tab_sched:
        st.markdown("Scheduled scans run `run_scan.py scan-all` through Windows Task Scheduler using the "
                    "project virtual environment. They work while the dashboard is closed and never overlap "
                    "(a job lock skips a run if another is in progress). Tasks are only created when you run the "
                    "command below and confirm.")
        st.code(sch.instructions(), language="powershell")
        tasks = sch.query_tasks()
        if tasks:
            st.dataframe(tasks, hide_index=True, width="stretch")
        else:
            st.info("No Local Security Scanner scheduled tasks are registered.")
