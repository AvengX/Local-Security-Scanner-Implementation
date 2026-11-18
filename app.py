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

from dashboard import (code_issues, findings, history, misconfigurations, overview, reports,  # noqa: E402
                       repositories, secrets, settings, vapt, vulnerabilities, web_issues)
from dashboard.common import (PAGES, get_config, get_conn, inject_css, misconfig_relevant, notice,  # noqa: E402
                              render_sidebar, sync_roots)
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
        "code": page(code_issues.render, "Code issues", ":material/code:", "code-issues"),
        "web": page(web_issues.render, "Web app issues", ":material/language:", "web-issues"),
        "misconfigurations": page(misconfigurations.render, "Misconfigurations", ":material/tune:",
                                  "misconfigurations"),
        "repositories": page(repositories.render, "Repositories", ":material/folder_code:", "repositories"),
        "history": page(history.render, "Scan History", ":material/history:", "history"),
        "reports": page(reports.render, "Reports", ":material/summarize:", "reports"),
        "vapt": page(vapt.render, "VAPT Lab", ":material/science:", "vapt-lab"),
        "settings": page(settings.render, "Settings", ":material/settings:", "settings"),
    }
    conn = get_conn(cfg)
    sync_roots(cfg, conn)
    # Hidden while no project has a Dockerfile / Compose / Kubernetes / Helm / Terraform file (nothing to check).
    if not misconfig_relevant(cfg, conn):
        pages.pop("misconfigurations")
    if not cfg.dast.enabled and not conn.execute(
            "SELECT 1 FROM findings WHERE category='WEB' AND status IN ('OPEN','UNVERIFIED') LIMIT 1").fetchone():
        pages.pop("web")
    PAGES.update(pages)
    monitor = [pages[k] for k in ("overview", "findings", "vulnerabilities", "secrets", "code", "web",
                                         "misconfigurations")
               if k in pages]
    nav = st.navigation({
        "Monitor": monitor,
        "Operate": [pages["repositories"], pages["history"], pages["reports"], pages["vapt"]],
        "System": [pages["settings"]],
    })
    with st.sidebar:
        render_sidebar(cfg, conn)
    nav.run()


main()
