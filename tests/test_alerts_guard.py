"""Alerts after scan batches, and the pre-commit secret guard."""

from __future__ import annotations

import json
import secrets
import string
import subprocess
import threading
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from conftest import have_gitleaks
from database.db import init_db
from services import alert_service as al
from services import secret_guard as sg
from services import triage_service as tri
from utils.config import AppConfig

from test_dashboard import env, page_app, populate  # noqa: F401 - shared fixture


# ------------------------------------------------------------------------------------------- alerts
def test_alert_built_from_new_findings_of_the_batch(env) -> None:  # noqa: ANN001
    populate(env)
    conn = init_db(env.db_path)
    a = al.build_alert(conn, "b", "LOW")
    assert a and a["new_count"] >= 1 and a["projects"]
    worst = a["severity"]
    assert al.build_alert(conn, "other-batch", "LOW") is None
    title, body = al.alert_text(a)
    assert f"{a['new_count']} new" in title and worst.title() in title and "Phoenix" in body
    # Severity threshold and decided findings are respected.
    high = al.build_alert(conn, "b", "HIGH")
    crit_ids = [r[0] for r in conn.execute("SELECT id FROM findings WHERE severity IN ('CRITICAL','HIGH')")]
    for fid in crit_ids:
        tri.set_decision(conn, fid, "ACCEPTED_RISK", "accepted for the test", date.today() + timedelta(days=5))
    assert high is not None and al.build_alert(conn, "b", "HIGH") is None


def test_process_batch_records_and_marks_read(env, monkeypatch) -> None:  # noqa: ANN001
    populate(env)
    conn = init_db(env.db_path)
    sent = []
    monkeypatch.setattr(al, "notify_windows", lambda t, b: sent.append((t, b)) or "")
    cfg = AppConfig.model_validate({**env.model_dump(), "alerts": {"min_severity": "LOW"}})
    aid = al.process_batch(conn, cfg, "b")
    assert aid and sent and sent[0][0].startswith("Security scan:")
    row = conn.execute("SELECT delivered, read_at FROM alerts WHERE id=?", (aid,)).fetchone()
    assert row["delivered"] == "windows" and row["read_at"] is None
    assert [x["id"] for x in al.unread(conn)] == [aid]
    assert al.mark_read(conn) == 1 and not al.unread(conn)
    off = AppConfig.model_validate({**env.model_dump(), "alerts": {"enabled": False}})
    assert al.process_batch(conn, off, "b") is None


def test_webhook_payload_has_no_secret_values() -> None:
    got: list[dict] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        alert = {"severity": "HIGH", "new_count": 1, "projects": {"p": {"severity": {"HIGH": 1},
                                                                        "category": {"SECRET": 1}}},
                 "top": [{"severity": "HIGH", "item": "aws-access-token in app/aws.py", "repository": "p",
                          "category": "SECRET"}]}
        title, body = al.alert_text(alert)
        assert al.post_webhook(f"http://127.0.0.1:{srv.server_address[1]}/", title, body, alert) == ""
        assert got and got[0]["new_count"] == 1 and "aws-access-token in app/aws.py" in got[0]["text"]
    finally:
        srv.shutdown()
    assert al.post_webhook("http://127.0.0.1:9/", "t", "b", alert).startswith("webhook failed")


def test_webhook_must_be_https() -> None:
    with pytest.raises(Exception, match="https"):
        AppConfig.model_validate({"alerts": {"webhook_url": "http://example.com/hook"}})
    assert AppConfig.model_validate({"alerts": {"webhook_url": "https://example.com/h"}}).alerts.webhook_url


# ------------------------------------------------------------------------------------------- secret guard
def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "t@example.invalid"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    return repo


def test_guard_install_status_remove_and_keeps_other_hook(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    assert sg.status(repo).state == "not_installed"
    hooks = sg.hooks_dir(repo)
    (hooks / "pre-commit").write_text("#!/bin/sh\necho previous\n", encoding="utf-8")
    assert sg.status(repo).state == "other_hook"
    st = sg.install(repo, "C:/fake/gitleaks.exe")
    assert st.state == "installed" and (hooks / sg.PREVIOUS).read_text(encoding="utf-8").endswith("previous\n")
    text = (hooks / "pre-commit").read_bytes()
    assert b"\r\n" not in text and b"--pre-commit --staged --redact" in text
    assert sg.install(repo, None).state == "installed"  # idempotent
    assert sg.remove(repo).state == "other_hook"
    assert (hooks / "pre-commit").read_text(encoding="utf-8").endswith("previous\n")
    assert not (hooks / sg.PREVIOUS).exists()


def test_guard_refuses_custom_hooks_path_and_non_git(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", ".husky"], check=True)
    assert sg.status(repo).state == "custom_hooks_path"
    with pytest.raises(sg.GuardError, match="core.hooksPath"):
        sg.install(repo, None)
    plain = tmp_path / "plain"
    plain.mkdir()
    assert sg.status(plain).state == "not_git"


@pytest.mark.skipif(not have_gitleaks(), reason="Gitleaks not installed")
def test_guard_blocks_a_commit_with_a_secret(tmp_path: Path) -> None:
    from engine.scanner_health import check_gitleaks

    repo = _repo(tmp_path)
    sg.install(repo, check_gitleaks().path)
    token = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (repo / "leak.py").write_text(f'TOKEN = "{token}"\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "leak.py"], check=True)
    blocked = subprocess.run(["git", "-C", str(repo), "commit", "-m", "leak"], capture_output=True, text=True)
    assert blocked.returncode != 0 and "BLOCKED" in blocked.stderr
    assert token not in blocked.stdout + blocked.stderr  # the value is never printed
    subprocess.run(["git", "-C", str(repo), "reset", "-q"], check=True)
    (repo / "leak.py").unlink()
    (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "ok.py"], check=True)
    ok = subprocess.run(["git", "-C", str(repo), "commit", "-m", "ok"], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
