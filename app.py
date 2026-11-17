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

st.set_page_config(page_title="Local Security Scanner", page_icon=str(ROOT / "dashboard" / "assets" / "emblem.svg"),
                   layout="wide", initial_sidebar_state="auto")

from dashboard import (findings, history, misconfigurations, overview, reports, repositories, secrets,  # noqa: E402
                       settings, vapt, vulnerabilities)
from dashboard.common import PAGES, get_config, get_conn, inject_css, notice, render_sidebar, sync_roots  # noqa: E402
from utils.logger import setup_logging  # noqa: E402

ASSETS = ROOT / "dashboard" / "assets"


def main() -> None:
    inject_css()
    st.logo(str(ASSETS / "logo.svg"), size="large", icon_image=str(ASSETS / "emblem.svg"))
    try:
        cfg = get_config()
    except ValidationError as exc:
        notice("err", "config.yaml is invalid", str(exc))
        st.stop()
    except Exception as exc:  # noqa: BLE001
        notice("err", "Could not load configuration", str(exc))
        st.stop()
    setup_logging(cfg.logs_dir, cfg.log_level, console=False)

    def page(fn, title: str, icon: str, path: str, default: bool = False):  # noqa: ANN001, ANN202
        return st.Page(fn, title=title, icon=icon, url_path=path, default=default)

    pages = {
        "overview": page(overview.render, "Overview", ":material/space_dashboard:", "overview", default=True),
        "findings": page(findings.render, "Security Findings", ":material/bug_report:", "findings"),
        "vulnerabilities": page(vulnerabilities.render, "Vulnerabilities", ":material/deployed_code:",
                                "vulnerabilities"),
        "secrets": page(secrets.render, "Secrets", ":material/key:", "secrets"),
        "misconfigurations": page(misconfigurations.render, "Misconfigurations", ":material/tune:",
                                  "misconfigurations"),
        "repositories": page(repositories.render, "Repositories", ":material/folder_code:", "repositories"),
        "history": page(history.render, "Scan History", ":material/history:", "history"),
        "reports": page(reports.render, "Reports", ":material/summarize:", "reports"),
        "vapt": page(vapt.render, "VAPT Lab", ":material/science:", "vapt-lab"),
        "settings": page(settings.render, "Settings", ":material/settings:", "settings"),
    }
    PAGES.update(pages)
    nav = st.navigation({
        "Monitor": [pages["overview"], pages["findings"], pages["vulnerabilities"], pages["secrets"],
                    pages["misconfigurations"]],
        "Operate": [pages["repositories"], pages["history"], pages["reports"], pages["vapt"]],
        "System": [pages["settings"]],
    })
    conn = get_conn(cfg)
    sync_roots(cfg, conn)
    with st.sidebar:
        render_sidebar(cfg, conn)
    nav.run()


main()
