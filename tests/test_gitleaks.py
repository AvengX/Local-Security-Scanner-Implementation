"""Gitleaks wrapper: mocked execution plus real-binary tests against a disposable repository."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import fake_github_token, fake_process, git, have_gitleaks, load_fixture, make_repo, tool
from engine.gitleaks_scanner import LEAKS_EXIT_CODE, GitleaksScanner
from engine.scanner_health import ToolStatus, check_gitleaks


def test_command_shape(tmp_path: Path, all_flags) -> None:
    cmd = GitleaksScanner(tool("gitleaks")).build_command("git", tmp_path, tmp_path / "r.json",
                                                          log_opts="--all", max_target_megabytes=5)
    assert cmd[1:3] == ["git", str(tmp_path)]
    assert "--redact" in cmd and cmd[cmd.index("--exit-code") + 1] == str(LEAKS_EXIT_CODE)
    assert "--log-opts=--all" in cmd and "--max-target-megabytes" in cmd
    with pytest.raises(ValueError):
        GitleaksScanner(tool("gitleaks")).build_command("detect", tmp_path, tmp_path / "r.json")


def test_findings_detected(tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.gitleaks_scanner.run_process",
                        fake_process(load_fixture("gitleaks.json"), exit_code=LEAKS_EXIT_CODE))
    ex = GitleaksScanner(tool("gitleaks")).scan("git", tmp_path, tmp_path / "r.json", 60)
    assert ex.status == "COMPLETED_WITH_FINDINGS" and len(ex.findings) == 1
    assert ex.coverage.categories == {"SECRET"}


def test_empty_findings(tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.gitleaks_scanner.run_process", fake_process([], exit_code=0))
    ex = GitleaksScanner(tool("gitleaks")).scan("dir", tmp_path, tmp_path / "r.json", 60)
    assert ex.status == "COMPLETED" and ex.findings == []


def test_invalid_json(tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.gitleaks_scanner.run_process", fake_process(None, raw="[{oops", exit_code=0))
    ex = GitleaksScanner(tool("gitleaks")).scan("git", tmp_path, tmp_path / "r.json", 60)
    assert ex.status == "FAILED"


def test_inconsistent_exit_code(tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.gitleaks_scanner.run_process", fake_process([], exit_code=LEAKS_EXIT_CODE))
    ex = GitleaksScanner(tool("gitleaks")).scan("git", tmp_path, tmp_path / "r.json", 60)
    assert ex.status == "FAILED"


def test_fatal_error_exit(tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.gitleaks_scanner.run_process",
                        fake_process(None, exit_code=1, stderr="fatal: detected dubious ownership in repository"))
    ex = GitleaksScanner(tool("gitleaks")).scan("git", tmp_path, tmp_path / "r.json", 60)
    assert ex.status == "FAILED" and "safe.directory" in ex.error_message


def test_missing_executable(tmp_path) -> None:
    ex = GitleaksScanner(ToolStatus("gitleaks", False, error="Gitleaks is not installed")).scan(
        "git", tmp_path, tmp_path / "r.json", 60)
    assert ex.status == "FAILED" and "not installed" in ex.error_message


def test_timeout(tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.gitleaks_scanner.run_process", fake_process(None, timed_out=True))
    ex = GitleaksScanner(tool("gitleaks")).scan("git", tmp_path, tmp_path / "r.json", 60)
    assert ex.status == "TIMED_OUT"


def test_missing_config_file(tmp_path) -> None:
    ex = GitleaksScanner(tool("gitleaks")).scan("git", tmp_path, tmp_path / "r.json", 60,
                                                config_path=str(tmp_path / "nope.toml"))
    assert ex.status == "FAILED"


# ----------------------------------------------------------------------------- real binary
needs_gitleaks = pytest.mark.skipif(not have_gitleaks(), reason="Gitleaks not installed")


@pytest.mark.realtools
@needs_gitleaks
def test_real_dummy_secret_in_history_and_dir(tmp_path: Path) -> None:
    token = fake_github_token()
    repo = make_repo(tmp_path / "leaky", {"app/config.py": f'GITHUB_TOKEN = "{token}"\n'})
    # Remove from the working tree: history scan must still find it, dir scan must not.
    (repo / "app" / "config.py").write_text("GITHUB_TOKEN = None\n", encoding="utf-8")
    git(repo, "commit", "-qam", "remove token")
    scanner = GitleaksScanner(check_gitleaks())

    hist = scanner.scan("git", repo, tmp_path / "git.json", 120)
    assert hist.status == "COMPLETED_WITH_FINDINGS", hist.error_message
    assert any(f.rule_id == "github-pat" for f in hist.findings)
    assert token not in (tmp_path / "git.json").read_text(encoding="utf-8")  # --redact honoured
    assert token not in json.dumps([f.to_dict() for f in hist.findings])

    cur = scanner.scan("dir", repo, tmp_path / "dir.json", 120)
    assert cur.status == "COMPLETED", cur.error_message


@pytest.mark.realtools
@needs_gitleaks
def test_real_clean_repo(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "clean", {"main.py": "print('hello')\n"})
    ex = GitleaksScanner(check_gitleaks()).scan("git", repo, tmp_path / "r.json", 120)
    assert ex.status == "COMPLETED" and ex.findings == [], ex.error_message


@pytest.mark.realtools
@needs_gitleaks
def test_real_allowlist_config(tmp_path: Path) -> None:
    token = fake_github_token()
    repo = make_repo(tmp_path / "allow", {"fixtures/sample.py": f'T = "{token}"\n'})
    cfg = tmp_path / "gitleaks.toml"
    cfg.write_text('[extend]\nuseDefault = true\n\n[allowlist]\npaths = [\'\'\'fixtures/\'\'\']\n', encoding="utf-8")
    ex = GitleaksScanner(check_gitleaks()).scan("dir", repo, tmp_path / "r.json", 120, config_path=str(cfg))
    assert ex.status == "COMPLETED", ex.error_message
