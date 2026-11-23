"""The one-page dashboard (scan a folder, get a VAPT PDF), rendered headlessly with Streamlit's AppTest."""

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


# ---------------------------------------------------------------- redesign (v1.1) regression tests
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


def test_folder_picker_results(monkeypatch) -> None:
    import subprocess

    from utils import folder_picker as fp

    def fake(out: str, code: int = 0, err: str = ""):
        return lambda *a, **k: subprocess.CompletedProcess(a, code, out, err)

    monkeypatch.setattr(fp.subprocess, "run", fake("D:/Work/Projects"))
    assert fp.pick_folder() == str(Path("D:/Work/Projects"))  # Tk's forward slashes become a Windows path
    monkeypatch.setattr(fp.subprocess, "run", fake(""))
    assert fp.pick_folder() is None  # cancelled
    monkeypatch.setattr(fp.subprocess, "run", fake("", 1, "TclError: no display"))
    with pytest.raises(fp.FolderPickerError):
        fp.pick_folder()


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


