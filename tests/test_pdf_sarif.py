"""PDF export (Edge / Chrome headless) and SARIF 2.1.0 export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from database.db import init_db
from services import pdf_export, sarif_export
from services import triage_service as tri

from test_dashboard import env, populate  # noqa: F401 - shared fixture


def test_sarif_structure_and_content(env) -> None:  # noqa: ANN001
    populate(env)
    conn = init_db(env.db_path)
    rid = conn.execute("SELECT id FROM repositories").fetchone()[0]
    data = sarif_export.build_sarif(conn, rid)
    assert data["version"] == "2.1.0" and data["$schema"].endswith("sarif-2.1.0.json")
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Trivy"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning", "note")
        assert res["partialFingerprints"]["lssFingerprint/v1"]
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith(("/", "C:", "D:")) and "\\" not in uri
        assert "Fix:" in res["message"]["text"]
    for rule in run["tool"]["driver"]["rules"]:
        assert float(rule["properties"]["security-severity"]) > 0 and "How to fix" in rule["help"]["text"]
    # Decided findings are not exported.
    before = len(run["results"])
    fid = conn.execute("SELECT id FROM findings WHERE status='OPEN' ORDER BY id LIMIT 1").fetchone()[0]
    tri.set_decision(conn, fid, "FALSE_POSITIVE", "not used in production")
    after = sarif_export.build_sarif(conn, rid)["runs"][0]["results"]
    assert len(after) == before - 1
    assert json.loads(sarif_export.sarif_bytes(conn, rid))["version"] == "2.1.0"


def test_sarif_locations() -> None:
    meta_inst = {"version_source": "installed", "environment": "web/.venv", "environment_kind": "python"}
    loc = sarif_export._location({"category": "VULNERABILITY", "file_path": "installed packages (web/.venv)"},  # noqa: SLF001
                                 meta_inst)
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "web/requirements.txt"
    web = sarif_export._location({"category": "WEB", "file_path": "/api/users", "scan_target": "http://127.0.0.1:5000/"},  # noqa: SLF001
                                 {"method": "GET"})
    assert web["logicalLocations"][0]["fullyQualifiedName"] == "http://127.0.0.1:5000/api/users"
    abs_ = sarif_export._location({"category": "SECRET", "file_path": "C:/Work/app/.env", "line": 3}, {},  # noqa: SLF001
                                  "C:\\Work\\app")
    assert abs_["physicalLocation"]["artifactLocation"]["uri"] == ".env"
    assert abs_["physicalLocation"]["region"]["startLine"] == 3


def test_pdf_errors(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    with pytest.raises(pdf_export.PdfError, match="not found"):
        pdf_export.html_to_pdf(tmp_path / "missing.html")
    page = tmp_path / "r.html"
    page.write_text("<html><body>x</body></html>", encoding="utf-8")
    monkeypatch.setattr(pdf_export, "find_browser", lambda: None)
    with pytest.raises(pdf_export.PdfError, match="Print -> Save as PDF"):
        pdf_export.html_to_pdf(page)


@pytest.mark.skipif(pdf_export.find_browser() is None, reason="No Edge / Chrome on this machine")
def test_pdf_is_created_with_the_installed_browser(tmp_path: Path) -> None:
    page = tmp_path / "report.html"
    page.write_text("<!DOCTYPE html><html><head><style>@page{size:A4}</style></head><body><h1>Security report"
                    "</h1><p>" + "Line of text. " * 400 + "</p></body></html>", encoding="utf-8")
    pdf = pdf_export.html_to_pdf(page)
    assert pdf == page.with_suffix(".pdf") and pdf.read_bytes()[:5] == b"%PDF-" and pdf.stat().st_size > 1000
