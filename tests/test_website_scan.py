"""Testing a live website on its own: the allowed-hosts list, the safety checks and the website-only report."""

from __future__ import annotations

import http.server
import threading
from pathlib import Path

import pytest

from database.db import init_db
from engine.dast_scanner import Client
from engine.scan_orchestrator import FolderScanError, ScanOrchestrator
from services import vapt_report as vr
from utils import validators as v
from utils.config import AppConfig, DastConfig


@pytest.fixture(autouse=True)
def _reset_hosts():
    yield
    v.set_allowed_web_hosts([])  # the list is process-wide; never leak it into other tests


def test_outside_site_needs_allowed_host() -> None:
    with pytest.raises(ValueError, match="dast.allowed_hosts"):
        v.validate_dast_url("https://staging.example.com/")
    d = DastConfig.model_validate({"allowed_hosts": ["Staging.Example.com"],
                                   "targets": [{"repository": "site", "url": "https://staging.example.com:3001/"}]})
    assert d.allowed_hosts == ["staging.example.com"]
    assert v.validate_dast_url("https://staging.example.com/x") == "https://staging.example.com/x"
    assert not v.is_allowed_web_host("example.com") and not v.is_allowed_web_host("evil.staging.example.com.attacker")
    DastConfig()  # loading a config without the list removes the permission again
    assert not v.is_allowed_web_host("staging.example.com")


@pytest.mark.parametrize("bad", ["*.example.com", "https://example.com", "example.com:443", "example.com/x", ""])
def test_allowed_hosts_are_exact_names(bad: str) -> None:
    with pytest.raises(ValueError):
        DastConfig.model_validate({"allowed_hosts": [bad]})


def test_outside_site_never_gets_a_start_command() -> None:
    with pytest.raises(ValueError, match="start_command"):
        DastConfig.model_validate({"allowed_hosts": ["staging.example.com"], "targets": [
            {"repository": "site", "url": "https://staging.example.com/", "start_command": "python app.py"}]})


def test_client_refuses_hosts_not_listed() -> None:
    import time

    client = Client(5, 10, time.monotonic() + 30)
    with pytest.raises(ValueError, match="not allowed"):
        client.request("https://example.com/")
    assert client.count == 0  # refused before anything was sent


def test_scan_website_refuses_unlisted_host(cfg: AppConfig) -> None:
    with pytest.raises(FolderScanError, match="allowed_hosts"):
        ScanOrchestrator(cfg).scan_website(["https://example.com/"])


class _Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<html><body><h1>Shop</h1><a href='/about'>About</a></body></html>"
        self.send_response(200 if self.path in ("/", "/about") else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # noqa: ANN002
        pass


def test_website_scan_end_to_end(cfg: AppConfig) -> None:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Page)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/"
    try:
        orch = ScanOrchestrator(cfg)
        assert [(j.scanner, j.target) for j in orch.plan_jobs({"name": "127.0.0.1", "repo_kind": "website"})] == []
        scan = orch.scan_website([url, url])
    finally:
        server.shutdown()
    assert [p["name"] for p in scan.projects] == ["127.0.0.1"] and scan.projects[0]["repo_kind"] == "website"
    assert [(r.scanner, r.status) for r in scan.batch.runs] == [("dast", "COMPLETED_WITH_FINDINGS")]
    assert Path(scan.projects[0]["path"]).is_relative_to(cfg.data_dir / "websites")
    conn = init_db(cfg.db_path)
    try:
        f = vr.generate_vapt(conn, cfg, scan.projects[0]["id"], pdf=False)
    finally:
        conn.close()
    page = f.html_path.read_text(encoding="utf-8")
    assert f.html_path.name.startswith("127.0.0.1_VAPT_") and f.html_path.suffix == ".html"
    assert f.issues >= 1 and "Live website only" in page and url in page
    assert "Content-Security-Policy" in page  # the missing header was found
    assert "Dependency scan" not in page  # no code sections for a website-only test
