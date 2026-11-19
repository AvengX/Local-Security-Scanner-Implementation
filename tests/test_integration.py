"""End-to-end: discovery -> orchestrated scans -> SQLite -> comparison -> analytics/exports -> CLI.

Gitleaks runs for real when installed (disposable repos with a random fake token). Trivy is mocked here
because its execution depends on the host (a separate real-binary test lives in test_trivy.py).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from conftest import fake_github_token, fake_process, git, have_gitleaks, load_fixture, make_repo, tool
from database import repositories as dao
from database.db import init_db
from engine.locks import JobLock
from engine.scan_orchestrator import ScanOrchestrator
from engine.scanner_health import ToolStatus, check_gitleaks
from services import analytics_service as an
from services import export_service as ex
from services.report_service import list_reports, read_report_for_run
from utils.security import safe_report_path

needs_gitleaks = pytest.mark.skipif(not have_gitleaks(), reason="Gitleaks not installed")


def gitleaks_only(cfg):
    cfg.trivy.enabled = False
    return cfg


@pytest.fixture
def mocked_trivy(monkeypatch, all_flags, trivy_db):
    runner = fake_process(load_fixture("trivy_fs.json"))
    monkeypatch.setattr("engine.trivy_scanner.run_process", runner)
    return runner


@needs_gitleaks
@pytest.mark.realtools
def test_full_pipeline_real_gitleaks(cfg, roots: Path, mocked_trivy) -> None:
    token = fake_github_token()
    make_repo(roots / "Phoenix", {"settings.py": f'TOKEN = "{token}"\n', "requirements.txt": "requests==2.25.0\n"})
    make_repo(roots / "Website", {"index.html": "<h1>hi</h1>\n"})
    orch = ScanOrchestrator(cfg, trivy_tool=tool("trivy"), gitleaks_tool=check_gitleaks())

    batch = orch.scan_all()
    assert batch.repositories == 2, batch.errors
    statuses = {(r.repository, r.scanner, r.scan_type): r.status for r in batch.runs}
    assert statuses[("Phoenix", "gitleaks", "git")] == "COMPLETED_WITH_FINDINGS"
    assert statuses[("Phoenix", "gitleaks", "dir")] == "COMPLETED_WITH_FINDINGS"
    assert statuses[("Website", "gitleaks", "git")] == "COMPLETED"
    assert statuses[("Phoenix", "trivy", "fs")] == "COMPLETED_WITH_FINDINGS"

    conn = orch.connect()
    # No secret value anywhere in the DB, logs or raw reports.
    assert token not in "\n".join(conn.iterdump())
    for p in cfg.reports_dir.rglob("*.json"):
        assert token not in p.read_text(encoding="utf-8")
    m = an.overview_metrics(conn)
    assert m["repositories"] == 2 and m["repositories_scanned"] == 2
    assert m["category"]["SECRET"] >= 1 and m["severity"]["CRITICAL"] >= 1

    # Remove the secret from the working tree; history still has it.
    (roots / "Phoenix" / "settings.py").write_text("TOKEN = None\n", encoding="utf-8")
    git(roots / "Phoenix", "commit", "-qam", "remove")
    batch2 = orch.scan_all()
    runs2 = {(r.repository, r.scanner, r.scan_type): r for r in batch2.runs}
    assert runs2[("Phoenix", "gitleaks", "dir")].resolved >= 1
    assert runs2[("Phoenix", "gitleaks", "git")].resolved == 0  # still in history
    trend = an.change_trend(conn)
    assert set(trend["change_type"]) == {"NEW", "RESOLVED"}

    # Exports
    paths = ex.export_bundle(conn, cfg.reports_dir)
    assert {p.suffix for p in paths} == {".md", ".html", ".json", ".csv"}
    data = json.loads(next(p for p in paths if p.suffix == ".json").read_text(encoding="utf-8"))
    assert data["findings"] and token not in json.dumps(data)
    assert list_reports(conn, cfg.reports_dir, scanner="gitleaks")


def test_scanner_failure_isolated_and_not_clean(cfg, roots: Path, monkeypatch, all_flags, trivy_db) -> None:
    make_repo(roots / "A")
    make_repo(roots / "B")
    calls = {"n": 0}
    ok = fake_process({"SchemaVersion": 2, "Results": []})
    bad = fake_process(None, exit_code=1, stderr="FATAL: scan error")

    def alternate(args, timeout, tool, cwd=None):
        calls["n"] += 1
        return (bad if calls["n"] == 1 else ok)(args, timeout, tool, cwd)

    monkeypatch.setattr("engine.trivy_scanner.run_process", alternate)
    cfg.gitleaks.enabled = False
    batch = ScanOrchestrator(cfg, trivy_tool=tool("trivy")).scan_all()
    assert sorted(r.status for r in batch.runs) == ["COMPLETED", "FAILED"]
    assert batch.failed == 1


def test_failed_rescan_keeps_old_findings(cfg, roots: Path, monkeypatch, all_flags, trivy_db) -> None:
    make_repo(roots / "A")
    cfg.gitleaks.enabled = False
    orch = ScanOrchestrator(cfg, trivy_tool=tool("trivy"))
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process(load_fixture("trivy_fs.json")))
    orch.scan_all()
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process(None, timed_out=True))
    batch = orch.scan_all()
    assert batch.runs[0].status == "TIMED_OUT"
    conn = orch.connect()
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status='RESOLVED'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status='UNVERIFIED'").fetchone()[0] == 4
    assert an.overview_metrics(conn)["failed_scans_latest"] == 1


def test_missing_tool_marked_failed(cfg, roots: Path) -> None:
    make_repo(roots / "A")
    cfg.trivy.enabled = False
    orch = ScanOrchestrator(cfg, gitleaks_tool=ToolStatus("gitleaks", False, error="Gitleaks is not installed"))
    batch = orch.scan_all()
    assert {r.status for r in batch.runs} == {"FAILED"}
    assert all("not installed" in (r.error or "") for r in batch.runs)


def test_repo_outside_roots_skipped(cfg, roots: Path, tmp_path: Path) -> None:
    outside = make_repo(tmp_path / "elsewhere")
    gitleaks_only(cfg)
    orch = ScanOrchestrator(cfg, gitleaks_tool=tool("gitleaks"))
    conn = orch.connect()
    from engine.repository_discovery import DiscoveredRepo

    dao.sync_discovered(conn, [DiscoveredRepo("elsewhere", str(outside), str(tmp_path))], [])
    repo = dao.find_repositories(conn, name="elsewhere")[0]
    runs = orch.scan_repository(repo)
    assert {r.status for r in runs} == {"SKIPPED"}


def test_concurrent_scan_of_same_repo_skipped(cfg, roots: Path) -> None:
    make_repo(roots / "A")
    gitleaks_only(cfg)
    orch = ScanOrchestrator(cfg, gitleaks_tool=tool("gitleaks"))
    orch.discover()
    conn = orch.connect()
    repo = dao.list_repositories(conn)[0]
    conn.execute("INSERT INTO repo_locks(repository_id, pid, acquired_at) VALUES (?,?,datetime('now'))",
                 (repo["id"], os.getppid()))
    conn.execute("UPDATE repo_locks SET acquired_at=?", (__import__("database.db", fromlist=["utcnow"]).utcnow(),))
    runs = orch.scan_repository(repo)
    assert {r.status for r in runs} == {"SKIPPED"}
    assert "in progress" in runs[0].error


def test_overlapping_scan_all_jobs_prevented(cfg, roots: Path) -> None:
    make_repo(roots / "A")
    gitleaks_only(cfg)
    lock = JobLock(cfg.data_dir / "scan_all.lock")
    cfg.ensure_dirs()
    lock.path.write_text(json.dumps({"pid": os.getppid(), "started_at": "now"}))
    batch = ScanOrchestrator(cfg, gitleaks_tool=tool("gitleaks")).scan_all()
    assert batch.runs == [] and "Another scan job" in batch.errors[0]
    lock.path.write_text(json.dumps({"pid": 999999, "started_at": "old"}))  # stale -> reclaimed
    lock.acquire()
    lock.release()
    assert not lock.path.exists()


def test_concurrency_two_workers(cfg, roots: Path, monkeypatch, all_flags, trivy_db) -> None:
    for n in "ABCD":
        make_repo(roots / n)
    cfg.gitleaks.enabled = False
    cfg.scan.concurrency = 2
    monkeypatch.setattr("engine.trivy_scanner.run_process", fake_process({"SchemaVersion": 2, "Results": []}))
    batch = ScanOrchestrator(cfg, trivy_tool=tool("trivy")).scan_all()
    assert len(batch.runs) == 4 and {r.status for r in batch.runs} == {"COMPLETED"}


def test_report_path_traversal_blocked(cfg, tmp_path: Path) -> None:
    cfg.ensure_dirs()
    (cfg.reports_dir / "ok.json").write_text("{}")
    (tmp_path / "secret.txt").write_text("x")
    assert safe_report_path("ok.json", cfg.reports_dir).name == "ok.json"
    for bad in ("../secret.txt", str(tmp_path / "secret.txt"), "..\\..\\secret.txt"):
        with pytest.raises(PermissionError):
            safe_report_path(bad, cfg.reports_dir)
    conn = init_db(cfg.db_path)
    (tmp_path / "R").mkdir()
    from engine.repository_discovery import DiscoveredRepo

    dao.sync_discovered(conn, [DiscoveredRepo("R", str(tmp_path / "R"), str(tmp_path))], [])
    rid = dao.list_repositories(conn)[0]["id"]
    run = dao.create_scan_run(conn, rid, "trivy", "fs", ".", None, os.getpid())
    dao.finish_scan_run(conn, run, status="COMPLETED", report_path=str(tmp_path / "secret.txt"))
    with pytest.raises(PermissionError):
        read_report_for_run(conn, run, cfg.reports_dir)
    assert list_reports(conn, cfg.reports_dir) == []  # unsafe entries are hidden


# ----------------------------------------------------------------------------- CLI
def write_cfg(tmp_path: Path, cfg) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(cfg.model_dump()), encoding="utf-8")
    return p


def test_cli_commands(cfg, roots: Path, tmp_path: Path, capsys, monkeypatch) -> None:
    import run_scan

    make_repo(roots / "Phoenix")
    cfg.trivy.enabled = False
    if not have_gitleaks():
        cfg.gitleaks.enabled = False
        cfg.trivy.enabled = True
    p = write_cfg(tmp_path, cfg)
    base = ["--config", str(p)]
    assert run_scan.main(base + ["discover"]) == 0
    assert "Phoenix" in capsys.readouterr().out
    code = run_scan.main(base + ["scan-repo", "--name", "Phoenix"])
    out = capsys.readouterr().out
    assert code in (0, 1) and "Scan batch" in out
    assert run_scan.main(base + ["scan-repo", "--name", "Nope"]) == 2
    assert run_scan.main(base + ["status"]) == 0
    assert "Repositories: 1" in capsys.readouterr().out
    assert run_scan.main(base + ["report", "--repository", "Phoenix", "--format", "md,csv"]) == 0
    assert len(list((cfg.reports_dir / "exports").glob("*Phoenix*"))) == 2
    assert run_scan.main(base + ["report", "--format", "pdf"]) == 2
    run_scan.main(base + ["health"])
    assert "gitleaks" in capsys.readouterr().out
    assert run_scan.main(base + ["schedule", "--frequency", "weekly", "--day", "MON", "--time", "03:30",
                                 "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "Register-ScheduledTask" in out and "Weekly -DaysOfWeek Monday" in out and "dry run" in out
    assert "IgnoreNew" in out  # overlapping scheduled runs are prevented
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert run_scan.main(base + ["schedule", "--frequency", "daily"]) == 0
    assert "no task created" in capsys.readouterr().out
    assert run_scan.main(base + ["prune"]) == 0
    assert run_scan.main(base + ["update-databases"]) in (0, 1)  # trivy may be blocked/missing


def test_cli_invalid_config(tmp_path: Path, capsys) -> None:
    import run_scan

    p = tmp_path / "bad.yaml"
    p.write_text("dashboard:\n  host: 0.0.0.0\n", encoding="utf-8")
    assert run_scan.main(["--config", str(p), "status"]) == 2
    assert "loopback" in capsys.readouterr().out


def test_preflight_failure_keeps_started_at(cfg, roots: Path) -> None:
    make_repo(roots / "A")
    cfg.gitleaks.enabled = False
    orch = ScanOrchestrator(cfg, trivy_tool=ToolStatus("trivy", True, path="x", usable=False, error="blocked"))
    batch = orch.scan_all()
    run = dao.get_scan_run(orch.connect(), batch.runs[0].run_id)
    assert run["status"] == "FAILED" and run["started_at"] and run["finished_at"]
    assert run["error_message"] == "blocked"


def test_schedule_command_handles_long_and_quoted_paths(monkeypatch) -> None:
    from pathlib import Path as P

    from services import scheduling_service as sch

    deep = P("C:/" + "/".join(["very long folder name"] * 12) + "/O'Brien")
    monkeypatch.setattr(sch, "PROJECT_ROOT", deep)
    cmd = sch.build_create_command("daily", "02:00")
    script = cmd[-1]
    assert len(script) > 261 and "O''Brien" in script and "-Daily -At '02:00'" in script
    with pytest.raises(ValueError):
        sch.build_create_command("daily", "25:00")


# ----------------------------------------------------------------------------- scan skip folders
def test_trivy_receives_root_and_nested_skip_globs(cfg, roots: Path, monkeypatch, all_flags, trivy_db) -> None:
    make_repo(roots / "A")
    cfg.gitleaks.enabled = False
    cfg.scan.skip_dirs = [".venv", "node_modules"]
    runner = fake_process({"SchemaVersion": 2, "Results": []})
    monkeypatch.setattr("engine.trivy_scanner.run_process", runner)
    ScanOrchestrator(cfg, trivy_tool=tool("trivy")).scan_all()
    args = runner.calls[0]
    skipped = [args[i + 1] for i, a in enumerate(args) if a == "--skip-dirs"]
    assert {".venv", "**/.venv", "node_modules", "**/node_modules"} <= set(skipped)


def test_gitleaks_config_preserves_repo_and_user_configs(cfg, roots: Path, tmp_path: Path) -> None:
    repo = make_repo(roots / "A")
    orch = ScanOrchestrator(cfg, gitleaks_tool=tool("gitleaks"))
    report = cfg.reports_dir / "r.json"
    text = Path(orch._gitleaks_config(repo, report)).read_text(encoding="utf-8")
    assert "useDefault = true" in text and r"\.venv" in text and "node_modules" in text
    (repo / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    assert f"path = '''{(repo / '.gitleaks.toml').as_posix()}'''" in Path(orch._gitleaks_config(repo, report)).read_text()
    user = tmp_path / "mine.toml"
    user.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    cfg.gitleaks.config_path = str(user)
    assert user.as_posix() in Path(orch._gitleaks_config(repo, report)).read_text()
    cfg.scan.skip_dirs = []
    assert orch._gitleaks_config(repo, report) == str(user)  # nothing to add -> user's file unchanged


def test_gitleaks_absolute_paths_made_relative(tmp_path: Path) -> None:
    from engine.report_parser import parse_gitleaks_data

    item = dict(load_fixture("gitleaks.json")[0], File=str(tmp_path / "app" / "x.py"), Commit="")
    [f] = parse_gitleaks_data([item], scan_type="dir", base=tmp_path)
    assert f.file_path == "app/x.py"
    [g] = parse_gitleaks_data([item], scan_type="dir", base=tmp_path / "other")
    assert g.file_path.endswith("x.py")  # outside base: left as reported


@needs_gitleaks
@pytest.mark.realtools
def test_real_dependency_folders_skipped(cfg, roots: Path) -> None:
    from conftest import have_trivy
    from engine.scanner_health import check_trivy

    repo = make_repo(roots / "proj", {"app/main.py": f'T = "{fake_github_token()}"\n'})
    for rel in (".venv/Lib/site-packages/leak.py", "web/node_modules/pkg/leak.js", "sub/.venv/leak.py"):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(f'T = "{fake_github_token()}"\n', encoding="utf-8")
    cfg.gitleaks.modes = ["dir"]
    cfg.trivy.enabled = have_trivy()
    orch = ScanOrchestrator(cfg, trivy_tool=check_trivy() if cfg.trivy.enabled else None,
                            gitleaks_tool=check_gitleaks())
    batch = orch.scan_all()
    assert all(r.status in ("COMPLETED", "COMPLETED_WITH_FINDINGS") for r in batch.runs), batch.runs
    paths = {r[0] for r in orch.connect().execute("SELECT file_path FROM findings WHERE category='SECRET'")}
    assert paths == {"app/main.py"}, paths
    assert not list((cfg.data_dir / "tmp").glob("*.toml"))  # generated config cleaned up


def test_sast_job_runs_and_resolves_fixed_code(cfg, roots: Path) -> None:
    """Bandit runs as part of a repository scan; fixing the code marks the issue RESOLVED on the next scan."""
    from engine.scanner_health import check_bandit

    if not check_bandit().usable:
        pytest.skip("Bandit not installed")
    cfg.trivy.enabled = False
    cfg.gitleaks.enabled = False
    cfg.sast.enabled = True
    repo = make_repo(roots / "Code", {"app.py": "import subprocess\n\n\ndef run(c):\n    subprocess.call(c, shell=True)\n",
                                      ".venv/lib/x.py": "import pickle\npickle.loads(b'')\n"})
    orch = ScanOrchestrator(cfg)
    orch.discover()
    conn = init_db(cfg.db_path)
    target = dao.list_repositories(conn)[0]
    runs = orch.scan_repository(target)
    assert [(r.scanner, r.status) for r in runs] == [("bandit", "COMPLETED_WITH_FINDINGS"), ("codescan", "COMPLETED")]
    rows = conn.execute("SELECT rule_id, file_path, status FROM findings WHERE category='CODE'").fetchall()
    assert ("B602", "app.py", "OPEN") in [tuple(r) for r in rows]
    assert all(".venv" not in r["file_path"] for r in rows)
    (repo / "app.py").write_text("import subprocess\n\n\ndef run(c):\n    subprocess.call([c])\n", encoding="utf-8")
    orch.scan_repository(target)
    status = conn.execute("SELECT status FROM findings WHERE rule_id='B602'").fetchone()[0]
    assert status == "RESOLVED"
    conn.close()
