"""Dashboard pages rendered headlessly with Streamlit's AppTest against isolated databases."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from streamlit.testing.v1 import AppTest

from conftest import load_fixture
from database import repositories as dao
from database.db import init_db
from engine.comparison_engine import apply_scan_results
from engine.finding_normalizer import Coverage
from engine.report_parser import parse_trivy_data
from engine.repository_discovery import DiscoveredRepo
from services import analytics_service as an
from services import export_service as ex
from utils.validators import SEVERITIES

APP = str(Path(__file__).resolve().parent.parent / "app.py")
PAGES = ["overview", "repositories", "findings", "history", "reports", "settings"]


@pytest.fixture
def env(cfg, tmp_path: Path, monkeypatch):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(cfg.model_dump()), encoding="utf-8")
    monkeypatch.setenv("LSS_CONFIG", str(p))
    cfg.ensure_dirs()
    return cfg


def populate(cfg, failed: bool = False) -> None:
    conn = init_db(cfg.db_path)
    repo_dir = Path(cfg.repository_roots[0]) / "Phoenix"
    repo_dir.mkdir(exist_ok=True)
    dao.sync_discovered(conn, [DiscoveredRepo("Phoenix", str(repo_dir), cfg.repository_roots[0])],
                        cfg.repository_roots)
    rid = dao.list_repositories(conn)[0]["id"]
    cov = Coverage("trivy", "fs", ".", frozenset({"VULNERABILITY", "MISCONFIGURATION", "SECRET"}), frozenset(SEVERITIES))
    run = dao.create_scan_run(conn, rid, "trivy", "fs", ".", "b", os.getpid())
    report = cfg.reports_dir / "r.json"
    report.write_text("{}", encoding="utf-8")
    apply_scan_results(conn, rid, run, cov, parse_trivy_data(load_fixture("trivy_fs.json")))
    dao.finish_scan_run(conn, run, status="COMPLETED_WITH_FINDINGS", finished_at="2026-11-16T01:00:00+00:00",
                        findings_count=4, coverage=cov.key(), report_path=str(report))
    if failed:
        r2 = dao.create_scan_run(conn, rid, "gitleaks", "git", ".", "b", os.getpid())
        dao.finish_scan_run(conn, r2, status="FAILED", finished_at="2026-11-16T02:00:00+00:00",
                            error_message="Gitleaks exited with code 1", report_path=str(cfg.reports_dir / "missing.json"))
    conn.close()


def page_app(page: str) -> AppTest:
    """Render one dashboard page module in isolation (same code path as the navigation)."""
    root = str(Path(APP).parent).replace("\\", "/")
    script = "\n".join([
        "import sys",
        f"sys.path.insert(0, r'{root}')",
        "from dashboard.common import inject_css",
        f"from dashboard import {page}",
        "inject_css()",
        f"{page}.render()",
    ])
    return AppTest.from_string(script, default_timeout=60)


def test_full_app_boots(env) -> None:
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception, at.exception


@pytest.mark.parametrize("page", PAGES)
def test_pages_render_with_empty_database(env, page: str) -> None:
    at = page_app(page).run()
    assert not at.exception, at.exception


@pytest.mark.parametrize("page", PAGES)
def test_pages_render_with_data_and_failed_scan(env, page: str) -> None:
    populate(env, failed=True)
    at = page_app(page).run()
    assert not at.exception, at.exception


def test_findings_page_filters_interactively(env) -> None:
    populate(env)
    at = page_app("findings").run()
    at.multiselect(key="f_sev").set_value(["CRITICAL"]).run()
    assert not at.exception
    assert "2 of 4 findings" in " ".join(m.value for m in at.markdown)


def test_overview_shows_real_counts(env) -> None:
    populate(env, failed=True)
    at = page_app("overview").run()
    html = " ".join(m.value for m in at.markdown)
    assert "Critical" in html and "Failed scans" in html
    assert "Vulnerability DB missing" in html  # freshness surfaced honestly (no DB in test cache)


def test_secret_value_absent_everywhere(env) -> None:
    populate(env)
    conn = init_db(env.db_path)
    df = an.findings_frame(conn)
    assert "SHOULDNEVERBESTORED" not in df.to_csv()
    assert b"SHOULDNEVERBESTORED" not in ex.consolidated_json_bytes(conn)


def test_filtering(env) -> None:
    populate(env)
    conn = init_db(env.db_path)
    df = an.findings_frame(conn)
    assert len(an.filter_findings(df, severities=["CRITICAL"])) == 2
    assert len(an.filter_findings(df, categories=["SECRET"])) == 1
    assert len(an.filter_findings(df, cve="cve-2023-32681")) == 1
    assert len(an.filter_findings(df, package="jinja")) == 1
    assert len(an.filter_findings(df, file="Dockerfile")) == 1
    assert len(an.filter_findings(df, repositories=["Nope"])) == 0
    assert len(an.filter_findings(df, statuses=["RESOLVED"])) == 0


def test_report_export_and_missing_report(env) -> None:
    populate(env, failed=True)
    conn = init_db(env.db_path)
    csv = ex.findings_csv_bytes(an.findings_frame(conn)).decode("utf-8-sig")
    assert csv.splitlines()[0].startswith("id,repository,scanner")
    md = ex.summary_markdown(conn)
    assert "Failed / incomplete scans" in md and "| CRITICAL | 2 |" in md
    assert "<table>" in ex.summary_html(md)
    from services.report_service import list_reports

    entries = list_reports(conn, env.reports_dir)
    assert [e.scanner for e in entries] == ["trivy"]  # missing gitleaks report silently excluded


def test_csv_formula_injection_neutralised() -> None:
    import pandas as pd

    out = ex.findings_csv_bytes(pd.DataFrame([{"id": 1, "title": "=HYPERLINK(\"x\")"}])).decode("utf-8-sig")
    assert "'=HYPERLINK" in out


def test_settings_reject_non_loopback(env) -> None:
    from pydantic import ValidationError

    from utils.config import AppConfig

    with pytest.raises(ValidationError):
        AppConfig.model_validate({"dashboard": {"host": "0.0.0.0"}})
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"repository_roots": ["relative/path"]})
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"scan": {"severities": ["SEVERE"]}})
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"excluded_dirs": ["a/b"]})


def test_dead_running_scan_is_recovered_and_live_one_listed(env) -> None:
    populate(env)
    conn = init_db(env.db_path)
    rid = dao.list_repositories(conn)[0]["id"]
    dead = dao.create_scan_run(conn, rid, "trivy", "fs", ".", "x", 999999)
    live = dao.create_scan_run(conn, rid, "gitleaks", "git", ".", "x", os.getpid())
    from dashboard.common import get_conn, running_jobs

    c = get_conn(env)
    jobs = running_jobs(c)
    assert [j["id"] for j in jobs] == [live] and jobs[0]["scanner"] == "gitleaks:git"
    assert dao.get_scan_run(conn, dead)["status"] == "CANCELLED"
    at = page_app("repositories").run()
    assert not at.exception
    assert any("Scanning now" in i.value for i in at.info)
