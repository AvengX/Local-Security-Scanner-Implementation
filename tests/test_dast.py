"""DAST (built-in web scan): detection against local lab apps, safety rules, persistence and the dashboard page."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from conftest import make_repo
from database import repositories as dao
from database.db import init_db
from engine.dast_scanner import Client, DastScanner, _Stop
from engine.scan_orchestrator import ScanOrchestrator
from utils.config import AppConfig
from utils.validators import validate_dast_url
from vapt.lab_web_app import LabWebApp

ENV_SECRET = "envpw-NotARealPassword-77"


@pytest.fixture
def vuln_app():
    app = LabWebApp("vulnerable", ENV_SECRET).start()
    yield app
    try:
        app.stop()
    except OSError:
        pass


@pytest.fixture
def clean_app():
    app = LabWebApp("clean").start()
    yield app
    app.stop()


def test_detects_planted_web_issues_safely(vuln_app: LabWebApp, tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    ex = DastScanner().scan(vuln_app.url, report, 120)
    assert ex.status == "COMPLETED_WITH_FINDINGS"
    found = {(f.rule_id, f.file_path, f.metadata.get("parameter")) for f in ex.findings}
    for expected in [("DAST-XSS", "/search", "q"), ("DAST-SQLI", "/item", "id"), ("DAST-REDIRECT", "/go", "next"),
                     ("DAST-TRAVERSAL", "/view", "file"), ("DAST-EXPOSED-FILE", "/.env", None),
                     ("DAST-DEBUG", "/console", None), ("DAST-ERROR-LEAK", "/crash", None),
                     ("DAST-DIR-LISTING", "/static/", None), ("DAST-CORS", "/", None), ("DAST-CSP", "/", None),
                     ("DAST-COOKIE-HTTPONLY", "/", None)]:
        assert expected in found, expected
    assert all(f.category == "WEB" and f.scan_target == vuln_app.url and f.remediation for f in ex.findings)
    # Safety: no log-out/delete link followed, no form POSTed, no response content kept.
    assert vuln_app.state.destructive_hits == 0 and vuln_app.state.post_hits == 0
    saved = report.read_text(encoding="utf-8")
    assert ENV_SECRET not in saved
    assert ENV_SECRET not in json.dumps([f.to_dict() for f in ex.findings], default=str)


def test_clean_app_has_no_findings(clean_app: LabWebApp, tmp_path: Path) -> None:
    ex = DastScanner().scan(clean_app.url, tmp_path / "r.json", 120)
    assert ex.status == "COMPLETED" and ex.findings == []


def test_app_not_running_is_skipped(tmp_path: Path) -> None:
    app = LabWebApp("clean").start()
    url = app.url
    app.stop()
    ex = DastScanner().scan(url, tmp_path / "r.json", 30)
    assert ex.status == "SKIPPED" and "Start the app" in (ex.error_message or "")
    assert not (tmp_path / "r.json").exists()


@pytest.mark.parametrize("url", ["http://example.com/", "http://192.168.1.10:5000/", "https://10.0.0.1/",
                                 "ftp://127.0.0.1/", "http://user:pw@127.0.0.1/", "http://127.0.0.1.nip.io/"])
def test_only_local_addresses_are_allowed(url: str) -> None:
    with pytest.raises(ValueError):
        validate_dast_url(url)
    with pytest.raises(ValueError):
        AppConfig.model_validate({"dast": {"targets": [{"repository": "r", "url": url}]}})


def test_local_addresses_are_normalised() -> None:
    assert validate_dast_url("http://LOCALHOST:5000") == "http://localhost:5000/"
    assert validate_dast_url("http://127.0.0.2:8000/app") == "http://127.0.0.2:8000/app"
    assert validate_dast_url("https://[::1]:8443/") == "https://[::1]:8443/"


def test_client_refuses_non_local_hosts_and_respects_budget() -> None:
    client = Client(timeout=2, max_requests=1, deadline=10**12)
    with pytest.raises(ValueError):
        client.request("http://example.com/")
    client.count = 1
    with pytest.raises(_Stop):
        client.request("http://127.0.0.1:9/")


def test_orchestrator_runs_dast_resolves_fixes_and_keeps_issues_when_app_is_down(
        cfg, roots: Path, vuln_app: LabWebApp) -> None:
    cfg.trivy.enabled = cfg.gitleaks.enabled = cfg.sast.enabled = False
    make_repo(roots / "Shop", {"app.py": "print('shop')\n"})
    cfg.dast = cfg.dast.model_validate({"targets": [{"repository": "Shop", "url": vuln_app.url}]})
    orch = ScanOrchestrator(cfg)
    orch.discover()
    conn = init_db(cfg.db_path)
    target = dao.list_repositories(conn)[0]
    runs = orch.scan_repository(target)
    assert [(r.scanner, r.scan_type, r.status) for r in runs] == [("dast", "web", "COMPLETED_WITH_FINDINGS")]

    vuln_app.state.xss_fixed = True
    orch.scan_repository(target)
    status = dict(conn.execute("SELECT rule_id, status FROM findings WHERE category='WEB'").fetchall())
    assert status["DAST-XSS"] == "RESOLVED" and status["DAST-SQLI"] == "OPEN"
    assert orch._dast_seeds(target["id"], vuln_app.url)  # open findings are re-tested first next time

    vuln_app.stop()
    runs = orch.scan_repository(target)
    assert runs[0].status == "SKIPPED"
    rows = conn.execute("SELECT status FROM findings WHERE category='WEB' AND rule_id != 'DAST-XSS'").fetchall()
    assert rows and all(r[0] == "UNVERIFIED" for r in rows)
    conn.close()


def test_web_issues_page_explains_missing_addresses_and_shows_findings(cfg, tmp_path: Path, monkeypatch,
                                                                       vuln_app: LabWebApp) -> None:
    from streamlit.testing.v1 import AppTest

    root = str(Path(__file__).resolve().parent.parent).replace("\\", "/")
    script = f"import sys\nsys.path.insert(0, r'{root}')\nfrom dashboard.common import inject_css\n" \
             "from dashboard import web_issues\ninject_css()\nweb_issues.render()\n"

    def run(config: AppConfig):  # noqa: ANN202
        p = tmp_path / "config.yaml"
        p.write_text(yaml.safe_dump(config.model_dump()), encoding="utf-8")
        monkeypatch.setenv("LSS_CONFIG", str(p))
        return AppTest.from_string(script, default_timeout=60).run()

    cfg.ensure_dirs()
    repo = Path(cfg.repository_roots[0]) / "Shop"
    make_repo(repo, {"app.py": "x = 1\n"})
    ScanOrchestrator(cfg).discover()
    at = run(cfg)
    assert not at.exception
    assert "No web addresses added yet" in " ".join(m.value for m in at.markdown)

    cfg.trivy.enabled = cfg.gitleaks.enabled = cfg.sast.enabled = False
    cfg.dast = cfg.dast.model_validate({"targets": [{"repository": "Shop", "url": vuln_app.url}]})
    orch = ScanOrchestrator(cfg)
    orch.scan_repository(dao.list_repositories(init_db(cfg.db_path))[0])
    at = run(cfg)
    assert not at.exception
    tables = " ".join(d.value.to_string() for d in at.dataframe)
    assert "DAST-XSS" in tables and "/search" in tables
    assert ENV_SECRET not in tables
