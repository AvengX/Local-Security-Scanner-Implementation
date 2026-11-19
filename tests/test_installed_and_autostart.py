"""Installed-versions check (.venv / node_modules metadata) and auto-start of web apps for the web scan."""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

from engine import installed_scanner as inst
from engine.app_launcher import AppLauncher, LaunchError, is_listening, split_command
from utils.config import AppConfig
from vapt.create_lab import CLEAN_SERVE


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _meta(name: str, version: str) -> str:
    return f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nlong description\n"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------------------------------- installed versions
def test_find_environments(tmp_path: Path) -> None:
    repo = _write(tmp_path / "r", {
        ".venv/pyvenv.cfg": "home = x\n", "web/venv/pyvenv.cfg": "home = x\n",
        "front/package.json": "{}", "front/node_modules/a/package.json": json.dumps({"name": "a", "version": "1.0.0"}),
        "locked/package.json": "{}", "locked/package-lock.json": "{}", "locked/node_modules/b/package.json": "{}",
        "deep/a/b/c/d/venv/pyvenv.cfg": "home = x\n",
    })
    assert inst.find_environments(repo) == [("node", "front/node_modules"), ("python", ".venv"),
                                            ("python", "web/venv")]


def test_python_versions_read_from_metadata_and_pinned_skipped(tmp_path: Path) -> None:
    repo = _write(tmp_path / "r", {
        "requirements.txt": "Jinja2==2.10\nflask\nnumpy>=1.24  # comment\n",
        ".venv/pyvenv.cfg": "home = x\n",
        ".venv/Lib/site-packages/flask-0.12.2.dist-info/METADATA": _meta("Flask", "0.12.2"),
        ".venv/Lib/site-packages/jinja2-2.10.dist-info/METADATA": _meta("Jinja2", "2.10"),
        ".venv/Lib/site-packages/numpy-1.26.4.dist-info/METADATA": _meta("numpy", "1.26.4"),
        ".venv/Lib/site-packages/evil-1.0.dist-info/METADATA": _meta("evil; rm -rf /", "1.0"),
    })
    env = inst.collect(repo, "python", ".venv", [".venv"])
    assert env.packages == {"Flask": "0.12.2", "numpy": "1.26.4"} and env.skipped_pinned == 1
    work = inst.write_manifest(env, tmp_path / "work")
    assert (work / "requirements.txt").read_text(encoding="utf-8") == "Flask==0.12.2\nnumpy==1.26.4\n"


def test_node_versions_and_manifest(tmp_path: Path) -> None:
    repo = _write(tmp_path / "r", {
        "package.json": "{}",
        "node_modules/lodash/package.json": json.dumps({"name": "lodash", "version": "4.17.15"}),
        "node_modules/@scope/pkg/package.json": json.dumps({"name": "@scope/pkg", "version": "2.0.0"}),
        "node_modules/.bin/x": "",
    })
    env = inst.collect(repo, "node", "node_modules", [])
    assert env.packages == {"lodash": "4.17.15", "@scope/pkg": "2.0.0"}
    lock = json.loads((inst.write_manifest(env, tmp_path / "w") / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["lockfileVersion"] == 3 and lock["packages"]["node_modules/lodash"]["version"] == "4.17.15"


def test_installed_job_planned_only_when_an_environment_exists(tmp_path: Path) -> None:
    from engine.scan_orchestrator import ScanOrchestrator

    cfg = AppConfig.model_validate({"paths": {"data_dir": str(tmp_path / "d"), "reports_dir": str(tmp_path / "rp"),
                                              "logs_dir": str(tmp_path / "l")}})
    repo = _write(tmp_path / "proj", {"app.py": "x = 1\n"})
    orch = ScanOrchestrator(cfg)
    assert not [j for j in orch.plan_jobs({"name": "p", "id": 1, "path": str(repo)}) if j.scan_type == "installed"]
    _write(repo, {".venv/pyvenv.cfg": "home = x\n"})
    jobs = [(j.scan_type, j.target) for j in orch.plan_jobs({"name": "p", "id": 1, "path": str(repo)})]
    assert ("installed", "python:.venv") in jobs
    cfg.trivy.installed_versions = False
    assert not [j for j in orch.plan_jobs({"name": "p", "id": 1, "path": str(repo)}) if j.scan_type == "installed"]


def test_installed_explanation_mentions_environment() -> None:
    from services.explain import explain

    e = explain({"category": "VULNERABILITY", "package_name": "Flask", "installed_version": "0.12.2",
                 "fixed_version": "2.2.5", "severity": "HIGH", "file_path": "installed packages (.venv)",
                 "metadata": {"version_source": "installed", "environment": ".venv"}})
    assert "installed in .venv" in e.what and "requirements.txt" in e.fix[0]


# ------------------------------------------------------------------------------------- auto-start
def _serve(tmp_path: Path) -> tuple[Path, int, str]:
    repo = _write(tmp_path / "app", {"serve.py": CLEAN_SERVE})
    port = _free_port()
    return repo, port, f"http://127.0.0.1:{port}/"


def test_launcher_starts_and_stops_the_app(tmp_path: Path) -> None:
    repo, port, url = _serve(tmp_path)
    launcher = AppLauncher(f'"{sys.executable}" serve.py {port}', repo, url, 30, tmp_path / "logs" / "app.log")
    with launcher:
        assert launcher.started and is_listening(url)
    assert not is_listening(url)


def test_launcher_never_touches_an_app_that_is_already_running(tmp_path: Path) -> None:
    from vapt.lab_web_app import LabWebApp

    app = LabWebApp("clean").start()
    try:
        launcher = AppLauncher("this-program-does-not-exist", tmp_path, app.url, 5, tmp_path / "l.log")
        with launcher:
            assert launcher.already_running and not launcher.started
        assert is_listening(app.url)  # still running afterwards
    finally:
        app.stop()


def test_launcher_failures(tmp_path: Path) -> None:
    url = f"http://127.0.0.1:{_free_port()}/"
    with pytest.raises(LaunchError, match="single program"):
        split_command("python app.py && del x", tmp_path)
    with pytest.raises(LaunchError, match="not found"):
        split_command("no-such-program-xyz app.py", tmp_path)
    crash = _write(tmp_path / "c", {"crash.py": "raise SystemExit(3)\n"})
    with pytest.raises(LaunchError, match="exited right after starting"):
        AppLauncher(f'"{sys.executable}" crash.py', crash, url, 15, tmp_path / "c.log").start()
    idle = _write(tmp_path / "i", {"idle.py": "import time\ntime.sleep(60)\n"})
    launcher = AppLauncher(f'"{sys.executable}" idle.py', idle, url, 5, tmp_path / "i.log")
    with pytest.raises(LaunchError, match="did not answer"):
        launcher.start()
    assert launcher.proc is not None and launcher.proc.poll() is not None  # stopped after the failure


def test_orchestrator_web_scan_auto_starts_and_reports_it(tmp_path: Path) -> None:
    from engine.scan_orchestrator import Job, ScanOrchestrator

    repo, port, url = _serve(tmp_path)
    cfg = AppConfig.model_validate({
        "paths": {"data_dir": str(tmp_path / "d"), "reports_dir": str(tmp_path / "rp"), "logs_dir": str(tmp_path / "l")},
        "dast": {"targets": [{"repository": "app", "url": url, "start_command": f'"{sys.executable}" serve.py {port}'}]},
    })
    orch = ScanOrchestrator(cfg)
    ex = orch._scan_web(Job("dast", "web", url), repo, tmp_path / "r.json", None, "app")  # noqa: SLF001
    assert ex.status == "COMPLETED", ex.error_message
    assert "started the app" in ex.error_message and not ex.findings
    assert not is_listening(url)
    bad = AppConfig.model_validate({
        "paths": {"data_dir": str(tmp_path / "d2"), "reports_dir": str(tmp_path / "rp2"),
                  "logs_dir": str(tmp_path / "l2")},
        "dast": {"targets": [{"repository": "app", "url": url, "start_command": "no-such-program-xyz",
                              "start_wait": 5}]},
    })
    ex = ScanOrchestrator(bad)._scan_web(Job("dast", "web", url), repo, tmp_path / "r2.json", None, "app")  # noqa: SLF001
    assert ex.status == "FAILED" and "Could not start the app" in ex.error_message and ex.coverage is not None
