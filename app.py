"""Local Security Scanner — Streamlit dashboard entry point.

Start with:  scripts\\start.ps1   (or)   streamlit run app.py --server.address 127.0.0.1
The dashboard only reads the local SQLite database and launches local CLI jobs; it never uploads data.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402
from pydantic import ValidationError  # noqa: E402

st.set_page_config(page_title="Local Security Scanner", page_icon=":material/shield_lock:", layout="wide",
                   initial_sidebar_state="expanded")

from dashboard import findings, history, overview, reports, repositories, settings  # noqa: E402
from dashboard.common import PAGES, get_config, get_conn, inject_css, running_jobs  # noqa: E402
from utils.logger import setup_logging  # noqa: E402


def main() -> None:
    inject_css()
    try:
        cfg = get_config()
    except ValidationError as exc:
        st.error(f"config.yaml is invalid:\n\n{exc}")
        st.stop()
    except Exception as exc:  # noqa: BLE001
        st.error(f"Could not load configuration: {exc}")
        st.stop()
    setup_logging(cfg.logs_dir, cfg.log_level, console=False)

    pages = {
        "overview": st.Page(overview.render, title="Security Overview", icon=":material/dashboard:",
                            url_path="overview", default=True),
        "repositories": st.Page(repositories.render, title="Repositories", icon=":material/folder_code:",
                                url_path="repositories"),
        "findings": st.Page(findings.render, title="Security Findings", icon=":material/bug_report:",
                            url_path="findings"),
        "history": st.Page(history.render, title="Scan History", icon=":material/history:", url_path="history"),
        "reports": st.Page(reports.render, title="Reports", icon=":material/summarize:", url_path="reports"),
        "settings": st.Page(settings.render, title="Settings", icon=":material/settings:", url_path="settings"),
    }
    PAGES.update(pages)
    nav = st.navigation({"Monitor": [pages["overview"], pages["findings"], pages["history"]],
                         "Manage": [pages["repositories"], pages["reports"], pages["settings"]]})

    with st.sidebar:
        st.markdown("### :material/shield_lock: Local Security Scanner")
        st.caption("Trivy + Gitleaks · local-first · 127.0.0.1 only")
        conn = get_conn(cfg)
        jobs = running_jobs(conn)
        if jobs:
            st.info("Scanning: " + "; ".join(f"{j['repository']} ({j['scanner']}, {j['elapsed']})" for j in jobs),
                    icon=":material/progress_activity:")
        st.caption(f"Offline mode: **{'ON' if cfg.scan.offline else 'OFF'}**")
    nav.run()


main()
