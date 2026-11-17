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
PAGES = ["overview", "repositories", "findings", "vulnerabilities", "secrets", "misconfigurations", "history",
         "reports", "vapt", "settings"]


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
    at.multiselect(key="all_sev").set_value(["CRITICAL"]).run()
    assert not at.exception
    assert "2 of 4 findings" in " ".join(m.value for m in at.markdown)


def test_overview_shows_real_counts(env) -> None:
    populate(env, failed=True)
    at = page_app("overview").run()
    html = " ".join(m.value for m in at.markdown)
    assert "Critical" in html and "Failed scans" in html
    assert "Vulnerability database missing" in html  # freshness surfaced honestly (no DB in test cache)


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
    assert "Scanning in progress" in " ".join(m.value for m in at.markdown)


# ---------------------------------------------------------------- redesign (v1.1) regression tests
def test_category_pages_and_clean_vs_no_data_states(env) -> None:
    for page in ("vulnerabilities", "secrets", "misconfigurations"):
        at = page_app(page).run()
        assert not at.exception
        text = " ".join(m.value for m in at.markdown)
        assert "No repository folders configured" in text or "not been discovered" in text or "No scan data" in text
    populate(env)
    for page in ("vulnerabilities", "misconfigurations", "secrets"):
        at = page_app(page).run()
        assert not at.exception, page


def test_no_scan_data_is_not_reported_as_clean(env) -> None:
    conn = init_db(env.db_path)
    repo_dir = Path(env.repository_roots[0]) / "Empty"
    repo_dir.mkdir(exist_ok=True)
    dao.sync_discovered(conn, [DiscoveredRepo("Empty", str(repo_dir), env.repository_roots[0])], env.repository_roots)
    conn.close()
    at = page_app("findings").run()
    text = " ".join(m.value for m in at.markdown)
    assert "No scan data yet" in text and "does not mean" in text


def test_scanner_text_is_escaped_and_unsafe_links_dropped(env) -> None:
    from dashboard import theme as t

    assert "<img" not in t.notice("err", "x", "<img src=x onerror=alert(1)>")
    assert t.safe_url("javascript:alert(1)") is None and t.safe_url("data:text/html,x") is None
    assert t.safe_url("https://avd.aquasec.com/nvd/cve-2023-32681") is not None
    populate(env)
    conn = init_db(env.db_path)
    conn.execute("UPDATE findings SET remediation=?, description=?, reference_url=?",
                 ("<script>alert(1)</script>", "![x](http://example.invalid/beacon.png)", "javascript:alert(1)"))
    conn.commit()
    from dashboard.findings_view import _detail

    row = an.findings_frame(conn).iloc[0]
    script = "\n".join([
        "import sys", f"sys.path.insert(0, r'{str(Path(APP).parent)}')",
        "from database.db import init_db", "from services import analytics_service as an",
        "from dashboard.findings_view import _detail", "from utils.config import load_config",
        "c = init_db(load_config().db_path)", "_detail(c, an.findings_frame(c).iloc[0], 'all')"])
    at = AppTest.from_string(script, default_timeout=60).run()
    html = " ".join(m.value for m in at.markdown)
    assert not at.exception and row is not None
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "javascript:alert" not in html and "<img" not in html


def test_repository_state_and_distinct_counts(env) -> None:
    assert an.repository_state(None) == "NEVER"
    assert an.repository_state("COMPLETED,FAILED") == "FAILED"
    assert an.repository_state("COMPLETED,RUNNING") == "RUNNING"
    assert an.repository_state("COMPLETED_WITH_FINDINGS,COMPLETED") == "COMPLETED_WITH_FINDINGS"
    populate(env, failed=True)
    conn = init_db(env.db_path)
    df = an.repository_table(conn)
    m = an.overview_metrics(conn)
    assert df.iloc[0]["state"] == "FAILED"
    assert int(df["open_findings"].sum()) == sum(m["severity"].values())  # same counting rule everywhere


def test_finding_history_and_index(env) -> None:
    populate(env)
    conn = init_db(env.db_path)
    fid = int(an.findings_frame(conn).iloc[0]["id"])
    hist = an.finding_history(conn, fid)
    assert len(hist) == 1 and hist.iloc[0]["change_type"] == "NEW"
    idx = {r[1] for r in conn.execute("PRAGMA index_list(finding_changes)")}
    assert "ix_changes_finding" in idx


def test_settings_backup_before_save(env, monkeypatch) -> None:
    from dashboard.settings import backup_config
    from utils.config import save_config

    monkeypatch.setattr("dashboard.settings.config_path", lambda: Path(os.environ["LSS_CONFIG"]))
    before = Path(os.environ["LSS_CONFIG"]).read_text(encoding="utf-8")
    dest = backup_config(env)
    assert dest and dest.read_text(encoding="utf-8") == before
    save_config(env, Path(os.environ["LSS_CONFIG"]))
    assert len(list((env.data_dir / "config_backups").glob("config_*.yaml"))) == 1


def test_vapt_page_without_and_with_results(env, tmp_path, monkeypatch) -> None:
    import dashboard.vapt as vapt

    monkeypatch.setattr(vapt, "LAB", tmp_path / "lab")
    script = "\n".join(["import sys", f"sys.path.insert(0, r'{str(Path(APP).parent)}')", "from pathlib import Path",
                        "import dashboard.vapt as v", f"v.LAB = Path(r'{tmp_path / 'lab'}')", "v.render()"])
    res = AppTest.from_string(script, default_timeout=60).run()
    assert not res.exception
    assert "No results yet" in " ".join(m.value for m in res.markdown)
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / "VAPT_TEST_RESULTS.json").write_text('{"started":"2026-11-17T04:28:28+00:00","finished":'
                                                '"2026-11-17T04:29:17+00:00","passed":1,"total":2,"checks":['
                                                '{"phase":"1 Health","name":"a","passed":true,"detail":""},'
                                                '{"phase":"1 Health","name":"b","passed":false,"detail":"x"}]}',
                                                encoding="utf-8")
    res = AppTest.from_string(script, default_timeout=60).run()
    assert not res.exception
    text = " ".join(m.value for m in res.markdown)
    assert "1/2" in text and "Checks by phase" in text and "1 failed" in text  # plain table, no chart


def test_vapt_marker_detects_reused_pid(tmp_path) -> None:
    import json as _json
    import time as _time

    from dashboard.vapt import marker_running
    from utils.security import process_start_time

    marker = tmp_path / "RUNNING.pid"
    assert not marker_running(marker)                                       # no marker
    me = os.getpid()
    marker.write_text(_json.dumps({"pid": me, "start": process_start_time(me)}), encoding="utf-8")
    assert marker_running(marker)                                           # this very process
    marker.write_text(_json.dumps({"pid": me, "start": process_start_time(me) - 500}), encoding="utf-8")
    assert not marker_running(marker)                                       # same PID, different process
    marker.write_text(_json.dumps({"pid": 999999, "start": 1.0}), encoding="utf-8")
    assert not marker_running(marker)                                       # dead process
    marker.write_text(_json.dumps({"pid": me, "start": process_start_time(me)}), encoding="utf-8")
    old = _time.time() - 4 * 3600
    os.utime(marker, (old, old))
    assert not marker_running(marker)                                       # leftover from hours ago
    marker.write_text(str(me), encoding="utf-8")
    assert marker_running(marker)                                           # old PID-only format still read


def test_folder_picker_results(monkeypatch) -> None:
    import subprocess

    from utils import folder_picker as fp

    def fake(out: str, code: int = 0, err: str = ""):
        return lambda *a, **k: subprocess.CompletedProcess(a, code, out, err)

    monkeypatch.setattr(fp.subprocess, "run", fake("D:/STUDY/Projects"))
    assert fp.pick_folder() == str(Path("D:/STUDY/Projects"))  # Tk's forward slashes become a Windows path
    monkeypatch.setattr(fp.subprocess, "run", fake(""))
    assert fp.pick_folder() is None  # cancelled
    monkeypatch.setattr(fp.subprocess, "run", fake("", 1, "TclError: no display"))
    with pytest.raises(fp.FolderPickerError):
        fp.pick_folder()


def test_settings_browse_adds_root(env, tmp_path) -> None:
    picked = tmp_path / "picked_projects"
    picked.mkdir()
    root = str(Path(APP).parent)
    script = "\n".join([
        "import sys", f"sys.path.insert(0, r'{root}')",
        "import utils.folder_picker as fp",
        f"fp.pick_folder = lambda *a, **k: r'{picked}'",
        "from dashboard.common import inject_css", "from dashboard import settings",
        "inject_css()", "settings.render()"])
    at = AppTest.from_string(script, default_timeout=60).run()
    assert not at.exception
    before = at.text_area(key="roots_text").value
    at.button(key="roots_browse").click().run()
    assert not at.exception
    value = at.text_area(key="roots_text").value
    assert str(picked) in value and value.startswith(before.strip())
    # Saving is still an explicit step: config.yaml is unchanged until "Validate and save".
    assert str(picked) not in Path(os.environ["LSS_CONFIG"]).read_text(encoding="utf-8")


def test_selected_row_accepts_row_checkbox_or_cell_click() -> None:
    from types import SimpleNamespace

    from dashboard.common import selected_row

    assert selected_row(None) is None
    assert selected_row(SimpleNamespace(selection={"rows": [], "cells": []})) is None
    assert selected_row(SimpleNamespace(selection={"rows": [2], "cells": []})) == 2      # checkbox
    assert selected_row(SimpleNamespace(selection={"rows": [], "cells": [(4, "title")]})) == 4  # cell click
    assert selected_row(SimpleNamespace(selection=SimpleNamespace(rows=[], cells=[[1, "sev"]]))) == 1


def test_overview_counts_only_monitored_repositories(tmp_path) -> None:  # noqa: ANN001
    from database.db import init_db, transaction, utcnow
    from engine.repository_discovery import DiscoveredRepo
    from services import analytics_service as an

    conn = init_db(tmp_path / "db.sqlite")
    for n in ("Keep", "Gone"):
        (tmp_path / n).mkdir()
    dao.sync_discovered(conn, [DiscoveredRepo(n, str(tmp_path / n), str(tmp_path)) for n in ("Keep", "Gone")],
                        [str(tmp_path)])
    ids = {r["name"]: r["id"] for r in dao.list_repositories(conn)}
    now = utcnow()
    with transaction(conn):
        for name, rid in ids.items():
            run = conn.execute("INSERT INTO scan_runs(repository_id, scanner, scan_type, status, started_at, "
                               "finished_at) VALUES (?,?,?,?,?,?)",
                               (rid, "trivy", "fs", "COMPLETED_WITH_FINDINGS", now, now)).lastrowid
            conn.execute("INSERT INTO findings(repository_id, scanner, scan_type, category, severity, status, "
                         "dedup_key, fingerprint, title, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         (rid, "trivy", "fs", "VULNERABILITY", "HIGH", "OPEN", f"k{rid}", f"f{rid}", "t", now, now))
    # "Gone" is removed from the configured roots.
    dao.sync_discovered(conn, [DiscoveredRepo("Keep", str(tmp_path / "Keep"), str(tmp_path))], [],
                        configured_roots=[str(tmp_path / "Keep")])
    m = an.overview_metrics(conn)
    assert m["repositories"] == 1 and m["total_scans"] == 1 and m["severity"]["HIGH"] == 1
    assert set(an.findings_frame(conn)["repository"]) == {"Keep"}
    assert set(an.scan_history(conn)["repository"]) == {"Keep"}
    assert len(an.findings_frame(conn, ids["Gone"])) == 1  # history kept and still reachable by id


def test_reports_page_generates_audit_report(env) -> None:
    populate(env)
    at = page_app("reports").run()
    assert not at.exception
    assert not [b for b in at.button if b.key == "audit_generate"]  # combined scope -> asks for one repository
    at.selectbox[0].set_value("Phoenix").run()
    gen = [b for b in at.button if b.key == "audit_generate"]
    assert gen
    gen[0].click().run()
    assert not at.exception
    saved = list((env.reports_dir / "exports").glob("*_Phoenix_security_audit.html"))
    assert len(saved) == 1
    doc = saved[0].read_text(encoding="utf-8")
    assert "Security Audit Report" in doc and "5. Detailed vulnerability findings" in doc


def test_empty_vulnerabilities_page_explains_unpinned_requirements(env) -> None:
    conn = init_db(env.db_path)
    repo_dir = Path(env.repository_roots[0]) / "Loose"
    repo_dir.mkdir(exist_ok=True)
    (repo_dir / "requirements.txt").write_text("numpy\npandas\n", encoding="utf-8")
    dao.sync_discovered(conn, [DiscoveredRepo("Loose", str(repo_dir), env.repository_roots[0])], env.repository_roots)
    rid = dao.list_repositories(conn)[0]["id"]
    run = dao.create_scan_run(conn, rid, "trivy", "fs", ".", "b", os.getpid())
    dao.finish_scan_run(conn, run, status="COMPLETED", finished_at="2026-11-16T01:00:00+00:00", findings_count=0)
    conn.close()
    at = page_app("vulnerabilities").run()
    text = " ".join(m.value for m in at.markdown)
    assert "No libraries could be checked" in text and "No known vulnerabilities" not in text
    at = page_app("misconfigurations").run()
    text = " ".join(m.value for m in at.markdown)
    assert "Nothing to check" in text


def test_overview_has_plain_project_table_not_charts(env) -> None:
    populate(env)
    at = page_app("overview").run()
    assert not at.exception
    text = " ".join(m.value for m in at.markdown)
    assert "Problems by project" in text and "Vulnerable libraries" in text
    assert "Severity breakdown" not in text
