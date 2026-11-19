"""SAST (Bandit): parsing, secret withholding, exclusions, hardening and the schema migration for 'CODE'."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from engine.runner import ProcessOutcome
from engine.sast_scanner import BanditScanner, exclude_patterns, parse_bandit_data
from engine.scanner_health import ToolStatus, check_bandit
from utils.config import AppConfig

PASSWORD = "pw-NotARealPassword123"


def _result(test_id: str, line: int, text: str, code: str, severity: str = "HIGH", file: str = ".\\app\\db.py") -> dict:
    return {"test_id": test_id, "test_name": "demo_check", "filename": file, "line_number": line,
            "line_range": [line], "issue_severity": severity, "issue_confidence": "HIGH", "issue_text": text,
            "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
            "more_info": "https://bandit.readthedocs.io/", "code": f"{line} {code}\n"}


REPORT = {"errors": [{"filename": ".\\broken.py", "reason": "syntax error while parsing AST from file"}],
          "results": [_result("B608", 10, "Possible SQL injection vector.", "q = 'SELECT %s' % x", "MEDIUM"),
                      _result("B105", 3, f"Possible hardcoded password: '{PASSWORD}'", f'PW = "{PASSWORD}"', "LOW"),
                      _result("B602", 20, "subprocess call with shell=True", "subprocess.call(c, shell=True)"),
                      _result("B602", 30, "subprocess call with shell=True", "subprocess.call(c, shell=True)")]}


def test_parse_maps_fields_and_withholds_passwords() -> None:
    findings, errors = parse_bandit_data(REPORT)
    by = {(f.rule_id, f.line): f for f in findings}
    assert len(findings) == 4  # two identical shell=True lines stay two findings (occurrence counter)
    sqli = by[("B608", 10)]
    assert sqli.category == "CODE" and sqli.severity == "MEDIUM" and sqli.file_path == "app/db.py"
    assert "parameterised" in sqli.remediation and sqli.metadata["cwe"] == 89
    pw = by[("B105", 3)]
    assert PASSWORD not in json.dumps([f.to_dict() for f in findings], default=str)
    assert "withheld" in pw.title
    assert errors == [{"file": "broken.py", "reason": "syntax error while parsing AST from file"}]


def test_identity_survives_code_moving_down() -> None:
    moved = json.loads(json.dumps(REPORT))
    moved["results"][0]["line_number"] = 15
    moved["results"][0]["code"] = "15 q = 'SELECT %s' % x\n"
    a = {f.rule_id + str(f.metadata["occurrence"]): f.fingerprint for f in parse_bandit_data(REPORT)[0]}
    b = {f.rule_id + str(f.metadata["occurrence"]): f.fingerprint for f in parse_bandit_data(moved)[0]}
    assert a == b


def _fake(payload: dict | None, exit_code: int):
    def run(args, timeout, tool, cwd=None):  # noqa: ANN001, ANN202
        if payload is not None:
            Path(args[args.index("-o") + 1]).write_text(json.dumps(payload), encoding="utf-8")
        return ProcessOutcome(exit_code, "", "boom" if exit_code > 1 else "", "t0", "t1", 0.1)
    return run


def _tool() -> ToolStatus:
    return ToolStatus("bandit", True, path="python", version="1.9.4", usable=True)


def test_scan_statuses_and_sanitised_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = tmp_path / "r.json"
    monkeypatch.setattr("engine.sast_scanner.run_process", _fake(REPORT, 1))
    ex = BanditScanner(_tool(), tmp_path / "w").scan(tmp_path, report, 60)
    assert ex.status == "COMPLETED_WITH_FINDINGS" and len(ex.findings) == 4
    assert ex.coverage.categories == {"CODE"} and "could not be parsed" in (ex.error_message or "")
    saved = report.read_text(encoding="utf-8")
    assert PASSWORD not in saved and '"code"' not in saved

    monkeypatch.setattr("engine.sast_scanner.run_process", _fake({"errors": [], "results": []}, 0))
    assert BanditScanner(_tool(), tmp_path / "w").scan(tmp_path, report, 60).status == "COMPLETED"

    monkeypatch.setattr("engine.sast_scanner.run_process", _fake(REPORT, 2))
    ex = BanditScanner(_tool(), tmp_path / "w").scan(tmp_path, report, 60)
    assert ex.status == "FAILED" and not report.exists()

    monkeypatch.setattr("engine.sast_scanner.run_process", _fake({"errors": [], "results": []}, 1))
    assert BanditScanner(_tool(), tmp_path / "w").scan(tmp_path, report, 60).status == "FAILED"


def test_command_always_uses_own_ini(tmp_path: Path) -> None:
    cmd = BanditScanner(_tool(), tmp_path).build_command(tmp_path / "r.json", exclude_patterns([".venv"], []), ["B101"])
    assert cmd[cmd.index("--ini") + 1].endswith("bandit.ini") and (tmp_path / "bandit.ini").is_file()
    assert "-x" in cmd and "-s" in cmd and cmd[cmd.index("-s") + 1] == "B101"


@pytest.mark.skipif(not check_bandit().usable, reason="Bandit not installed")
def test_real_bandit_skips_venv_and_ignores_repo_config(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".venv" / "lib").mkdir(parents=True)
    (repo / "app.py").write_text("import subprocess\nsubprocess.call('ls ' + x, shell=True)\n", encoding="utf-8")
    (repo / ".venv" / "lib" / "dep.py").write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
    (repo / ".bandit").write_text("[bandit]\nskips: B602,B404\n", encoding="utf-8")  # must be ignored
    ex = BanditScanner(check_bandit(), tmp_path / "w").scan(repo, tmp_path / "r.json", 120,
                                                            exclude_patterns([".venv"], []))
    assert ex.status == "COMPLETED_WITH_FINDINGS"
    assert {f.rule_id for f in ex.findings} >= {"B602"}
    assert all(".venv" not in (f.file_path or "") for f in ex.findings)


def test_config_validates_skip_tests() -> None:
    assert AppConfig.model_validate({"sast": {"skip_tests": ["b101", "B101"]}}).sast.skip_tests == ["B101"]
    with pytest.raises(ValueError):
        AppConfig.model_validate({"sast": {"skip_tests": ["assert"]}})


def test_migrations_add_code_and_web_categories_and_keep_rows(tmp_path: Path) -> None:
    from database.db import init_db
    from utils.paths import SCHEMA_PATH

    db = tmp_path / "old.db"
    old_schema = SCHEMA_PATH.read_text(encoding="utf-8").replace("'MISCONFIGURATION','CODE','WEB','LICENSE'",
                                                                 "'MISCONFIGURATION','LICENSE'")
    conn = sqlite3.connect(db)
    conn.executescript(old_schema)
    conn.execute("INSERT INTO settings(key, value) VALUES('schema_version', '1')")
    conn.execute("INSERT INTO repositories(name, path, path_key, discovered_at, last_seen_at) "
                 "VALUES('r', 'C:/r', 'c:/r', 'a', 'a')")
    conn.execute("INSERT INTO scan_runs(repository_id, scanner, scan_type, status) VALUES(1, 'trivy', 'fs', 'COMPLETED')")
    conn.execute("INSERT INTO findings(repository_id, fingerprint, dedup_key, scanner, scan_type, category, severity, "
                 "first_seen, last_seen, status) VALUES(1, 'f', 'd', 'trivy', 'fs', 'SECRET', 'HIGH', 'a', 'a', 'OPEN')")
    conn.execute("INSERT INTO finding_changes(scan_run_id, finding_id, change_type, severity, changed_at) "
                 "VALUES(1, 1, 'NEW', 'HIGH', 'a')")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO findings(repository_id, fingerprint, dedup_key, scanner, scan_type, category, "
                     "severity, first_seen, last_seen, status) VALUES(1, 'g', 'd', 'bandit', 'python', 'CODE', 'LOW', "
                     "'a', 'a', 'OPEN')")
    conn.close()

    conn = init_db(db)
    assert conn.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0] == "4"
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM finding_changes").fetchone()[0] == 1
    conn.execute("INSERT INTO findings(repository_id, fingerprint, dedup_key, scanner, scan_type, category, severity, "
                 "first_seen, last_seen, status) VALUES(1, 'g', 'd', 'bandit', 'python', 'CODE', 'LOW', 'a', 'a', 'OPEN')")
    conn.execute("INSERT INTO findings(repository_id, fingerprint, dedup_key, scanner, scan_type, category, severity, "
                 "first_seen, last_seen, status) VALUES(1, 'h', 'd', 'dast', 'web', 'WEB', 'LOW', 'a', 'a', 'OPEN')")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    conn.close()


def test_assert_in_test_files_is_not_reported() -> None:
    data = {"errors": [], "results": [_result("B101", 4, "Use of assert detected.", "assert x", "LOW", "./tests/test_a.py"),
                                      _result("B101", 9, "Use of assert detected.", "assert y", "LOW", "./app/core.py")]}
    findings, _ = parse_bandit_data(data)
    assert [(f.rule_id, f.file_path) for f in findings] == [("B101", "app/core.py")]
