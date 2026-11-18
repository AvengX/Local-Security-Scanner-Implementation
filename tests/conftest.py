"""Shared fixtures: isolated config, disposable Git repositories and scanner mocks."""

from __future__ import annotations

import json
import secrets
import string
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.runner import ProcessOutcome  # noqa: E402
from engine.scanner_health import ToolStatus  # noqa: E402
from utils.config import AppConfig  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"

ALL_FLAGS = frozenset({
    "--format", "--output", "--severity", "--timeout", "--cache-dir", "--quiet", "--no-progress",
    "--skip-version-check", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-check-update",
    "--skip-dirs", "--scanners", "--exit-code", "--redact", "--no-banner", "--log-level", "--max-target-megabytes",
})


def fake_github_token() -> str:
    """Random, syntactically valid-looking but meaningless token (never a real credential)."""
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "init.defaultBranch=main", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def make_repo(path: Path, files: dict[str, str] | None = None, commit: bool = True) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")
    for rel, content in (files or {"README.md": "# demo\n"}).items():
        f = path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    if commit:
        git(path, "add", "-A")
        git(path, "commit", "-q", "-m", "initial")
    return path


def fake_process(report_payload: object | None, exit_code: int = 0, stderr: str = "", timed_out: bool = False,
                 launch_error: str | None = None, raw: str | None = None) -> Callable[..., ProcessOutcome]:
    """Build a run_process replacement that writes the payload to the --output / --report-path file."""
    calls: list[list[str]] = []

    def _run(args: list[str], timeout: int, tool: str, cwd: Path | None = None) -> ProcessOutcome:
        calls.append(args)
        if launch_error:
            return ProcessOutcome(None, "", "", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", 0,
                                  launch_error=launch_error)
        flag = "--output" if "--output" in args else "--report-path"
        if flag in args and not timed_out and (report_payload is not None or raw is not None):
            out = Path(args[args.index(flag) + 1])
            out.write_text(raw if raw is not None else json.dumps(report_payload), encoding="utf-8")
        return ProcessOutcome(None if timed_out else exit_code, "", stderr, "2026-01-01T00:00:00+00:00",
                              "2026-01-01T00:00:01+00:00", 1.0, timed_out=timed_out)

    _run.calls = calls  # type: ignore[attr-defined]
    return _run


def load_fixture(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def have_gitleaks() -> bool:
    from engine.scanner_health import check_gitleaks
    return check_gitleaks().usable


def have_trivy() -> bool:
    from engine.scanner_health import check_trivy
    return check_trivy().usable


def tool(name: str) -> ToolStatus:
    return ToolStatus(name, True, path=f"C:/fake/{name}.exe", version="9.9.9", usable=True)


@pytest.fixture
def roots(tmp_path: Path) -> Path:
    r = tmp_path / "roots"
    r.mkdir()
    return r


@pytest.fixture
def cfg(tmp_path: Path, roots: Path) -> AppConfig:
    app = tmp_path / "app"
    return AppConfig.model_validate({
        "repository_roots": [str(roots)],
        "paths": {"data_dir": str(app / "data"), "reports_dir": str(app / "reports"), "logs_dir": str(app / "logs")},
        "scan": {"timeout_seconds": 120, "concurrency": 1},
        "trivy": {"cache_dir": str(tmp_path / "trivy-cache")},
        "sast": {"enabled": False},  # tests that need the code scan enable it explicitly
    })


@pytest.fixture
def all_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend the installed tool's --help documents every flag we use."""
    monkeypatch.setattr("engine.trivy_scanner.supported_flags", lambda exe, sub: ALL_FLAGS)
    monkeypatch.setattr("engine.gitleaks_scanner.supported_flags", lambda exe, sub: ALL_FLAGS)


@pytest.fixture
def trivy_db(tmp_path: Path) -> Path:
    """A fresh fake Trivy DB metadata file in the test cache dir."""
    from datetime import datetime, timezone

    meta = tmp_path / "trivy-cache" / "db" / "metadata.json"
    meta.parent.mkdir(parents=True)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    meta.write_text(json.dumps({"Version": 2, "UpdatedAt": now, "DownloadedAt": now, "NextUpdate": now}))
    return meta


@pytest.fixture(autouse=True)
def _reset_cancel():
    import logging

    from engine.runner import CANCEL_EVENT
    CANCEL_EVENT.clear()
    logging.getLogger().setLevel(logging.DEBUG)  # exercise every log call (catches bad `extra` keys)
    yield
    CANCEL_EVENT.clear()
