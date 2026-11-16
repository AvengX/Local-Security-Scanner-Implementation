"""Trivy wrapper with mocked process execution (and an optional real-binary smoke test)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import fake_process, have_trivy, load_fixture, tool
from engine.scanner_health import DbFreshness, ToolStatus, describe_os_error, trivy_db_freshness
from engine.trivy_scanner import TrivyOptions, TrivyScanner


def opts(cfg, offline: bool = False) -> TrivyOptions:
    return TrivyOptions.from_config(cfg, offline=offline)


def test_fs_command_uses_arg_list_and_flags(cfg, tmp_path: Path, all_flags) -> None:
    s = TrivyScanner(tool("trivy"))
    cmd = s.build_fs_command(tmp_path / "repo", tmp_path / "r.json", opts(cfg))
    assert isinstance(cmd, list) and cmd[1] == "fs" and cmd[-1] == str(tmp_path / "repo")
    assert cmd[cmd.index("--scanners") + 1] == "vuln,misconfig,secret"
    assert cmd[cmd.index("--format") + 1] == "json"
    assert cmd[cmd.index("--exit-code") + 1] == "0"
    assert cmd[cmd.index("--timeout") + 1] == "120s"
    assert "--skip-db-update" not in cmd


def test_offline_flags(cfg, tmp_path: Path, all_flags) -> None:
    cmd = TrivyScanner(tool("trivy")).build_fs_command(tmp_path, tmp_path / "r.json", opts(cfg, offline=True))
    for flag in ("--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-check-update"):
        assert flag in cmd
    assert "--skip-policy-update" not in cmd  # superseded by --skip-check-update when available


def test_unsupported_flags_dropped(cfg, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.supported_flags",
                        lambda e, s: frozenset({"--format", "--output", "--scanners", "--timeout", "--skip-db-update"}))
    cmd = TrivyScanner(tool("trivy")).build_fs_command(tmp_path, tmp_path / "r.json", opts(cfg, offline=True))
    assert "--skip-db-update" in cmd and "--offline-scan" not in cmd and "--exit-code" not in cmd


def test_image_reference_validated(cfg, tmp_path: Path, all_flags) -> None:
    s = TrivyScanner(tool("trivy"))
    assert s.build_image_command("nginx:1.27", tmp_path / "r.json", opts(cfg))[-1] == "nginx:1.27"
    for bad in ("--help", "nginx;rm -rf /", "a b"):
        with pytest.raises(ValueError):
            s.build_image_command(bad, tmp_path / "r.json", opts(cfg))


def test_successful_scan_with_findings(cfg, tmp_path: Path, all_flags, trivy_db, monkeypatch) -> None:
    runner = fake_process(load_fixture("trivy_fs.json"))
    monkeypatch.setattr("engine.trivy_scanner.run_process", runner)
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.status == "COMPLETED_WITH_FINDINGS"
    cats = sorted(f.category for f in ex.findings)
    assert cats == ["MISCONFIGURATION", "SECRET", "VULNERABILITY", "VULNERABILITY"]
    assert ex.tool_version == "9.9.9" and ex.database_updated_at
    assert ex.coverage and ex.coverage.categories == {"VULNERABILITY", "MISCONFIGURATION", "SECRET"}


def test_clean_scan(cfg, tmp_path: Path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process({"SchemaVersion": 2, "Results": []}))
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.status == "COMPLETED" and ex.findings == []


def test_misconfig_only_config_scan(cfg, tmp_path: Path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process(load_fixture("trivy_fs.json")))
    ex = TrivyScanner(tool("trivy")).scan_config(tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.coverage.categories == {"MISCONFIGURATION"}
    assert any(f.category == "MISCONFIGURATION" for f in ex.findings)


def test_missing_executable(cfg, tmp_path: Path) -> None:
    ex = TrivyScanner(ToolStatus("trivy", False, error="Trivy is not installed")).scan_fs(
        tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.status == "FAILED" and "not installed" in ex.error_message


def test_blocked_executable_message() -> None:
    err = OSError("[WinError 4551] An Application Control policy has blocked this file")
    err.winerror = 4551  # type: ignore[attr-defined]
    assert "Smart App Control" in describe_os_error(err, "trivy")


def test_launch_error(cfg, tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process(None, launch_error="blocked"))
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.status == "FAILED" and ex.error_message == "blocked"


def test_timeout(cfg, tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process(None, timed_out=True))
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.status == "TIMED_OUT" and not ex.findings


def test_nonzero_exit_is_execution_error_even_with_report(cfg, tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process",
                        fake_process(load_fixture("trivy_fs.json"), exit_code=1, stderr="FATAL error: boom"))
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.status == "FAILED" and "boom" in ex.error_message and ex.findings == []


def test_invalid_report(cfg, tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process(None, raw="{broken"))
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.status == "FAILED" and "not valid JSON" in ex.error_message


def test_missing_report_file(cfg, tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process(None))
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg))
    assert ex.status == "FAILED" and "not produced" in ex.error_message


def test_offline_db_missing_preflight(cfg, tmp_path, all_flags, monkeypatch) -> None:
    runner = fake_process({"SchemaVersion": 2, "Results": []})
    monkeypatch.setattr("engine.trivy_scanner.run_process", runner)
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg, offline=True))
    assert ex.status == "FAILED" and "Offline mode" in ex.error_message
    assert runner.calls == []  # never launched


def test_offline_db_error_from_trivy(cfg, tmp_path, all_flags, trivy_db, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process(
        None, exit_code=1, stderr="--skip-db-update cannot be specified on the first run"))
    ex = TrivyScanner(tool("trivy")).scan_fs(tmp_path, tmp_path / "r.json", opts(cfg, offline=True))
    assert ex.status == "FAILED" and "update-databases" in ex.error_message


def test_db_freshness(tmp_path: Path, trivy_db: Path) -> None:
    fresh = trivy_db_freshness(str(tmp_path / "trivy-cache"), 72)
    assert isinstance(fresh, DbFreshness) and fresh.present and not fresh.stale
    trivy_db.write_text('{"Version":2,"UpdatedAt":"2020-01-01T00:00:00Z"}')
    stale = trivy_db_freshness(str(tmp_path / "trivy-cache"), 72)
    assert stale.stale and "STALE" in stale.message
    missing = trivy_db_freshness(str(tmp_path / "none"), 72)
    assert not missing.present and missing.stale


def test_sbom_no_comparison(cfg, tmp_path, all_flags, monkeypatch) -> None:
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process({"bomFormat": "CycloneDX"}))
    ex = TrivyScanner(tool("trivy")).generate_sbom(tmp_path, tmp_path / "sbom.cdx.json", opts(cfg))
    assert ex.status == "COMPLETED" and ex.coverage is None
    assert "cyclonedx" in ex.command


@pytest.mark.realtools
@pytest.mark.skipif(not have_trivy(), reason="Trivy not installed or blocked by OS policy")
def test_real_trivy_config_scan(cfg, tmp_path: Path) -> None:  # pragma: no cover - environment dependent
    from engine.scanner_health import check_trivy

    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM alpine:3.10\nRUN echo hi\n")
    ex = TrivyScanner(check_trivy()).scan_config(repo, tmp_path / "out.json", opts(cfg))
    assert ex.status in ("COMPLETED", "COMPLETED_WITH_FINDINGS"), ex.error_message
