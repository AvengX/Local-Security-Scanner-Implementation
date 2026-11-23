"""Scan-a-folder flow and the VAPT report (grouped issues, sections, PDF, background job)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from conftest import fake_github_token, have_gitleaks, make_repo, tool
from database import repositories as dao
from database.db import init_db
from engine.report_parser import _cvss
from engine.scan_orchestrator import FolderScanError, ScanOrchestrator
from engine.scanner_health import check_gitleaks
from services import pdf_export
from services import vapt_report as vr

from test_dashboard import env, populate  # noqa: F401 - shared fixture
from test_integration import mocked_trivy  # noqa: F401 - shared fixture

SECTIONS = ["Executive summary", "Scope &amp; methodology", "Findings table", "Finding details", "What's done well",
            "Remediation roadmap", "Not tested in this pass"]


def test_cvss_and_cwe_kept_from_trivy() -> None:
    v = {"CVSS": {"ghsa": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                  "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
         "CweIDs": ["CWE-502"]}
    assert _cvss(v) == {"cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cwe": "502"}
    assert _cvss({}) == {}


def test_report_sections_grouping_and_escaping(env) -> None:  # noqa: ANN001
    populate(env, failed=True)
    conn = init_db(env.db_path)
    conn.execute("UPDATE findings SET title='<script>alert(1)</script>' WHERE category='MISCONFIGURATION'")
    conn.commit()
    rid = dao.list_repositories(conn)[0]["id"]
    d = vr.build_vapt(conn, env, rid)
    page = vr.render_vapt_html(d)
    for s in SECTIONS:
        assert s in page
    assert d["issues"] and d["issues"][0].id.startswith("VAPT-0")
    # Every vulnerable library of one dependency file is one issue.
    vulns = [i for i in d["issues"] if i.category == "VULNERABILITY"]
    assert all(len({r["file_path"] for r in i.rows}) == 1 for i in vulns)
    assert sum(len(i.rows) for i in d["issues"]) <= d["raw_total"]
    assert "A06 Vulnerable &amp; Outdated Components" in page
    assert "<script>alert" not in page and "&lt;script&gt;" in page
    # The failed Gitleaks run is reported as not finished, never as clean.
    assert "did not finish" in page and "No secrets anywhere in the Git history" not in page


def test_report_with_no_findings_says_so(env) -> None:  # noqa: ANN001
    populate(env)
    conn = init_db(env.db_path)
    conn.execute("UPDATE findings SET status='RESOLVED'")
    conn.commit()
    rid = dao.list_repositories(conn)[0]["id"]
    page = vr.render_vapt_html(vr.build_vapt(conn, env, rid))
    assert "No open issues" in page and "VAPT-01" not in page


def test_missing_folder_and_scanner_folder_refused(cfg) -> None:  # noqa: ANN001
    orch = ScanOrchestrator(cfg)
    with pytest.raises(FolderScanError, match="not found"):
        orch.find_projects(r"Z:\does\not\exist")


def test_plain_folder_without_git_is_one_project(cfg, tmp_path: Path) -> None:  # noqa: ANN001
    plain = tmp_path / "plain-project"
    plain.mkdir()
    (plain / "app.py").write_text("print('hi')\n", encoding="utf-8")
    orch = ScanOrchestrator(cfg)
    found = orch.find_projects(f'"{plain}"')  # pasted with quotes, as Windows "Copy as path" does
    assert [(r.name, r.kind) for r in found] == [("plain-project", "folder")]
    jobs = {(j.scanner, j.scan_type) for j in orch.plan_jobs({"name": "plain-project", "path": str(plain),
                                                              "repo_kind": "folder"})}
    assert ("gitleaks", "dir") in jobs and ("gitleaks", "git") not in jobs


@pytest.mark.skipif(not have_gitleaks(), reason="Gitleaks not installed")
@pytest.mark.realtools
def test_scan_folder_end_to_end(cfg, roots: Path, tmp_path: Path, mocked_trivy) -> None:  # noqa: ANN001, F811
    make_repo(roots / "Monitored", {"README.md": "# kept\n"})
    orch = ScanOrchestrator(cfg, trivy_tool=tool("trivy"), gitleaks_tool=check_gitleaks())
    orch.discover()
    token = fake_github_token()
    pasted = tmp_path / "pasted"
    make_repo(pasted / "Shop", {"settings.py": f'TOKEN = "{token}"\n', "requirements.txt": "requests==2.25.0\n"})
    make_repo(pasted / "Blog", {"index.html": "<h1>hi</h1>\n"})

    seen: list[str] = []
    scan = orch.scan_folder(str(pasted), on_project=lambda i, n, r: seen.append(r["name"]))
    assert sorted(p["name"] for p in scan.projects) == ["Blog", "Shop"] and sorted(seen) == ["Blog", "Shop"]
    assert all(r.status in ("COMPLETED", "COMPLETED_WITH_FINDINGS") for r in scan.batch.runs), scan.batch.runs
    conn = init_db(cfg.db_path)
    # Pasting a folder never deactivates the projects that were already being monitored.
    assert {r["name"] for r in dao.list_repositories(conn)} == {"Monitored", "Shop", "Blog"}

    shop = next(p for p in scan.projects if p["name"] == "Shop")
    f = vr.generate_vapt(conn, cfg, shop["id"], pdf=False)
    page = f.html_path.read_text(encoding="utf-8")
    assert f.issues >= 2 and "Shop — Security Assessment (VAPT)" in page
    assert "written in the project" in page and token not in page
    assert "settings.py" in page


@pytest.mark.skipif(pdf_export.find_browser() is None, reason="No Edge / Chrome on this machine")
def test_vapt_pdf_is_created(env) -> None:  # noqa: ANN001
    populate(env)
    conn = init_db(env.db_path)
    rid = dao.list_repositories(conn)[0]["id"]
    f = vr.generate_vapt(conn, env, rid)
    assert f.error is None and f.pdf_path and f.pdf_path.read_bytes()[:5] == b"%PDF-"
    assert vr.list_vapt_reports(env) == [f.pdf_path]


def test_background_job_finishes_and_keeps_results(env, monkeypatch) -> None:  # noqa: ANN001
    from dashboard import scan_job
    from engine import scan_orchestrator as so

    populate(env)
    conn = init_db(env.db_path)
    repo = dao.list_repositories(conn)[0]

    def fake_scan(self, folder, offline=None, on_project=None, on_job=None):  # noqa: ANN001, ANN202
        on_project(1, 1, repo)
        return so.FolderScan(folder, [repo], so.BatchSummary("b", "t"))

    monkeypatch.setattr(so.ScanOrchestrator, "scan_folder", fake_scan)
    monkeypatch.setattr(pdf_export, "find_browser", lambda: None)  # HTML only: fast and browser-independent
    job = scan_job.start("C:/somewhere")
    assert scan_job.start("C:/elsewhere") is job or not scan_job.is_running()  # one scan at a time
    for _ in range(100):
        if not scan_job.is_running():
            break
        time.sleep(0.1)
    assert job.state == "done", job.error
    assert job.results[0]["project"] == "Phoenix" and job.results[0]["pdf"] is None
    assert job.results[0]["error"] and Path(job.results[0]["html"]).is_file()


def test_folder_scan_error_is_shown(env, monkeypatch) -> None:  # noqa: ANN001
    from dashboard import scan_job

    job = scan_job.start(r"Z:\no\such\folder")
    for _ in range(100):
        if not scan_job.is_running():
            break
        time.sleep(0.1)
    assert job.state == "error" and "not found" in (job.error or "")
