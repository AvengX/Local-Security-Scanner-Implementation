"""Built-in code scan for other languages, web-scan login, plain-language explanations, management summary,
Help page and first-run tour."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from engine.code_scanner import RULES, CodeScanner, count_files
from engine.dast_scanner import CHECKS, DastScanner
from services.explain import RULE_TOPIC, TOPICS, URGENCY, explain, risk_level
from utils.config import AppConfig, DastLogin
from vapt.create_lab import CLEAN_JS, CLEAN_TEMPLATE, VULN_JS, VULN_NODE_SERVER, VULN_TEMPLATE
from vapt.lab_web_app import LOGIN_USER, LabWebApp

from test_dashboard import env, populate  # noqa: F401 - shared fixture (isolated config + database)


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


# ------------------------------------------------------------------------------------------- code scan
def test_codescan_finds_planted_patterns_and_stores_no_source(tmp_path: Path) -> None:
    root = _repo(tmp_path / "r", {"web/app.js": VULN_JS, "web/profile.html": VULN_TEMPLATE,
                                  "server.js": VULN_NODE_SERVER})
    report = tmp_path / "rep.json"
    ex = CodeScanner().scan(root, report, 60)
    assert ex.status == "COMPLETED_WITH_FINDINGS"
    got = {(f.rule_id, f.file_path) for f in ex.findings}
    for want in (("JS-EVAL", "web/app.js"), ("JS-INNERHTML", "web/app.js"), ("JS-STORAGE-TOKEN", "web/app.js"),
                 ("TPL-SAFE-FILTER", "web/profile.html"), ("TPL-NO-SRI", "web/profile.html"),
                 ("JS-SQL-CONCAT", "server.js"), ("JS-CMD-INJECTION", "server.js")):
        assert want in got, (want, got)
    assert all(f.line and f.category == "CODE" and f.scanner == "codescan" for f in ex.findings)
    text = report.read_text(encoding="utf-8")
    assert "eval(text)" not in text and "SELECT * FROM" not in text  # source is never copied
    assert json.loads(text)["files_checked"]["JavaScript/TypeScript"] == 2


def test_codescan_clean_code_skipped_folders_and_minified(tmp_path: Path) -> None:
    root = _repo(tmp_path / "r", {"static/clean.js": CLEAN_JS, "templates/index.html": CLEAN_TEMPLATE,
                                  "node_modules/x/index.js": "eval(x)\n", "vendor/y.php": "eval($x);\n",
                                  "static/lib.min.js": "eval(x)\n", ".venv/z.js": "eval(x)\n",
                                  "app/notes.js": "// eval(x) in a comment only\nel.innerHTML = '<b>static</b>';\n"})
    ex = CodeScanner().scan(root, tmp_path / "rep.json", 60, skip_dirs=[".venv"])
    assert ex.status == "COMPLETED" and not ex.findings, [(f.rule_id, f.file_path) for f in ex.findings]
    assert count_files(root, [".venv"]) == {"JavaScript/TypeScript": 2, "HTML templates": 1}


@pytest.mark.parametrize("lang_file,text,rule", [
    ("a.php", "<?php echo $_GET['q']; ?>", "PHP-XSS-ECHO"),
    ("a.php", "$r = mysqli_query($c, \"SELECT * FROM t WHERE id=\" . $_GET['id']);", "PHP-SQL-CONCAT"),
    ("A.java", "stmt.executeQuery(\"SELECT * FROM t WHERE id=\" + id);", "JAVA-SQL-CONCAT"),
    ("a.go", "tls.Config{InsecureSkipVerify: true}", "GO-TLS-OFF"),
    ("a.go", "db.Query(fmt.Sprintf(\"SELECT * FROM t WHERE id=%s\", id))", "GO-SQL-SPRINTF"),
    ("A.cs", "var c = new SqlCommand(\"SELECT * FROM t WHERE id=\" + id, conn);", "CS-SQL-CONCAT"),
    ("a.ts", "https.request({ rejectUnauthorized: false })", "JS-TLS-OFF"),
])
def test_codescan_other_languages(tmp_path: Path, lang_file: str, text: str, rule: str) -> None:
    root = _repo(tmp_path / "r", {lang_file: text + "\n"})
    ex = CodeScanner().scan(root, tmp_path / "rep.json", 60)
    assert rule in {f.rule_id for f in ex.findings}


def test_codescan_is_planned_and_can_be_turned_off(tmp_path: Path) -> None:
    from engine.scan_orchestrator import ScanOrchestrator

    cfg = AppConfig.model_validate({"paths": {"data_dir": str(tmp_path / "d"), "reports_dir": str(tmp_path / "r"),
                                              "logs_dir": str(tmp_path / "l")}})
    jobs = [(j.scanner, j.scan_type) for j in ScanOrchestrator(cfg).plan_jobs({"name": "x", "id": 1})]
    assert ("codescan", "multi") in jobs
    cfg.sast.other_languages = False
    jobs = [(j.scanner, j.scan_type) for j in ScanOrchestrator(cfg).plan_jobs({"name": "x", "id": 1})]
    assert ("codescan", "multi") not in jobs


# ------------------------------------------------------------------------------------------- DAST login
def test_dast_login_reaches_members_area_without_storing_password(tmp_path: Path, monkeypatch) -> None:
    app = LabWebApp("vulnerable", "envsecret-123").start()
    try:
        monkeypatch.setenv("LSS_T_PW", app.state.login_password)
        login = DastLogin(url=app.url + "login", username=LOGIN_USER, password_env="LSS_T_PW")
        ex = DastScanner().scan(app.url, tmp_path / "r.json", 120, login=login)
        assert ex.status == "COMPLETED_WITH_FINDINGS", ex.error_message
        assert ("DAST-XSS", "/account/notes") in {(f.rule_id, f.file_path) for f in ex.findings}
        assert app.state.login_posts == 1 and app.state.post_hits == 0 and app.state.destructive_hits == 0
        text = (tmp_path / "r.json").read_text(encoding="utf-8")
        assert app.state.login_password not in text and json.loads(text)["logged_in"] is True
        # Without login the members area stays out of reach.
        plain = DastScanner().scan(app.url, tmp_path / "p.json", 120)
        assert "/account/notes" not in {f.file_path for f in plain.findings}
    finally:
        app.stop()


def test_dast_login_failures_are_failed_runs(tmp_path: Path, monkeypatch) -> None:
    app = LabWebApp("vulnerable").start()
    try:
        login = DastLogin(url=app.url + "login", username=LOGIN_USER, password_env="LSS_T_PW_MISSING")
        monkeypatch.delenv("LSS_T_PW_MISSING", raising=False)
        ex = DastScanner().scan(app.url, tmp_path / "a.json", 60, login=login)
        assert ex.status == "FAILED" and "not set" in ex.error_message
        monkeypatch.setenv("LSS_T_PW_MISSING", "wrong-password-value")
        ex = DastScanner().scan(app.url, tmp_path / "b.json", 60, login=login)
        assert ex.status == "FAILED" and "Login failed" in ex.error_message
        assert "wrong-password-value" not in ex.error_message
    finally:
        app.stop()


def test_dast_login_config_rules() -> None:
    base = {"repository": "x", "url": "http://127.0.0.1:5000/"}
    ok = AppConfig.model_validate({"dast": {"targets": [{**base, "login": {
        "url": "http://127.0.0.1:5000/login", "username": "tester", "password_env": "LSS_PW"}}]}})
    assert ok.dast.login_for("x", "http://127.0.0.1:5000/").password_env == "LSS_PW"
    with pytest.raises(Exception, match="same app"):
        AppConfig.model_validate({"dast": {"targets": [{**base, "login": {
            "url": "http://127.0.0.1:6000/login", "username": "t", "password_env": "LSS_PW"}}]}})
    with pytest.raises(Exception) as exc:
        AppConfig.model_validate({"dast": {"targets": [{**base, "login": {
            "url": "http://127.0.0.1:5000/login", "username": "t", "password_env": "My Real Pass!"}}]}})
    assert "My Real Pass!" not in str(exc.value)  # a password typed by mistake is never echoed
    with pytest.raises(Exception, match="this computer"):
        AppConfig.model_validate({"dast": {"targets": [{**base, "login": {
            "url": "http://example.com/login", "username": "t", "password_env": "LSS_PW"}}]}})


# ------------------------------------------------------------------------------------------- explanations
def test_every_rule_has_a_specific_explanation() -> None:
    for rule_id in [*CHECKS, *(r.rule_id for r in RULES)]:
        assert rule_id in RULE_TOPIC, rule_id
        assert RULE_TOPIC[rule_id] in TOPICS, rule_id
    for rid in ("B105", "B201", "B301", "B602", "B608", "B701"):
        assert RULE_TOPIC[rid] in TOPICS


@pytest.mark.parametrize("finding,topic", [
    ({"category": "WEB", "rule_id": "DAST-SQLI", "severity": "HIGH", "file_path": "/item",
      "metadata": {"parameter": "id", "evidence": "db error"}}, "sqli"),
    ({"category": "CODE", "rule_id": "JS-EVAL", "severity": "HIGH", "file_path": "a.js", "line": 3,
      "metadata_json": json.dumps({"confidence": "MEDIUM"})}, "code_exec"),
    ({"category": "CODE", "rule_id": "B999", "severity": "LOW", "metadata": {"cwe": 89}}, "sqli"),
    ({"category": "VULNERABILITY", "package_name": "jinja2", "installed_version": "2.10", "fixed_version": "3.1.5",
      "vulnerability_id": "CVE-2024-1", "severity": "HIGH"}, "vulnerable_library"),
    ({"category": "SECRET", "rule_id": "aws-access-token", "severity": "HIGH", "file_path": ".env"}, "secret"),
    ({"category": "MISCONFIGURATION", "rule_id": "DS002", "severity": "HIGH", "title": "root user"},
     "misconfiguration"),
])
def test_explanations_are_complete(finding: dict, topic: str) -> None:
    e = explain(finding)
    assert e.topic == topic
    assert e.what and e.why and e.attack and len(e.fix) >= 2
    assert e.urgency == URGENCY[finding["severity"]]


def test_explanation_details() -> None:
    v = explain({"category": "VULNERABILITY", "package_name": "jinja2", "installed_version": "2.10",
                 "fixed_version": "3.1.5, 2.11.3", "severity": "HIGH", "file_path": "requirements.txt"})
    assert "Update jinja2 to version 3.1.5" in v.fix[0]
    s = explain({"category": "SECRET", "rule_id": "aws-access-token", "severity": "HIGH", "scan_type": "git",
                 "metadata": {"commit": "abcdef1234567"}, "file_path": "a.py", "line": 2})
    assert s.what.startswith("An Amazon") and "Git history" in s.what and s.fix[0].startswith("Revoke")
    w = explain({"category": "WEB", "rule_id": "DAST-XSS", "severity": "HIGH", "file_path": "/search",
                 "metadata": {"parameter": "q", "evidence": "tag reflected"}})
    assert "/search" in w.what and "'q'" in w.what and "tag reflected" in w.what
    low = explain({"category": "CODE", "rule_id": "B608", "severity": "MEDIUM", "metadata": {"confidence": "LOW"}})
    assert "false alarm" in low.note
    assert risk_level({"CRITICAL": 1})[0] == "High risk" and risk_level({})[0] == "No open issues"


# ------------------------------------------------------------------------------------------- reports and UI
def test_management_summary(env) -> None:  # noqa: ANN001
    from database.db import connect
    from services.summary_report import generate_summary
    from utils.config import load_config

    populate(env)
    cfg = load_config(Path(os.environ["LSS_CONFIG"]))
    conn = connect(cfg.db_path)
    name, doc, data = generate_summary(conn, cfg)
    assert name.endswith("_management_summary.html")
    for text in ("Security status summary", "What to fix first", "What was tested", "does not cover"):
        assert text in doc
    assert data["projects"] and data["risk"][0]
    assert "<script" not in doc


def test_help_page_and_tour(env) -> None:  # noqa: ANN001
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_string("import sys; sys.path.insert(0, r'%s')\nfrom dashboard import help\nhelp.render()"
                             % Path(__file__).resolve().parent.parent, default_timeout=60).run()
    assert not at.exception
    text = " ".join(m.value for m in at.markdown)
    assert "Start here" in text and "Glossary" in text and "XSS" in text
    from database.db import connect, get_setting
    from dashboard.tour import STEPS
    from utils.config import load_config

    assert len(STEPS) >= 5
    from database.db import init_db

    conn = init_db(load_config(Path(os.environ["LSS_CONFIG"])).db_path)
    assert not get_setting(conn, "tour_done")
