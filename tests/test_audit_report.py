"""Detailed audit report: data accuracy, dependency paths, deduplication, escaping and secret safety."""

from __future__ import annotations

import json
from pathlib import Path

from database import repositories as dao
from database.db import init_db, transaction, utcnow
from engine.repository_discovery import DiscoveredRepo
from engine.scanner_health import ToolStatus
from services import audit_report as audit

PLANTED = "ghp_" + "Z" * 36  # must never reach the report


def test_version_helpers() -> None:
    assert audit.split_fixed("4.17.19, 3.10.1") == ["4.17.19", "3.10.1"]
    assert audit.minimum_fix("3.9.0", ["4.17.19", "3.10.1"]) == "3.10.1"
    assert audit.minimum_fix("4.0.0", ["4.17.19", "3.10.1"]) == "4.17.19"
    assert audit.minimum_fix("1.0", []) is None


def test_best_cvss_prefers_severity_source() -> None:
    cvss = {"nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/N"}, "ghsa": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/G"},
            "old": {"V2Score": 10.0}}
    assert audit.best_cvss(cvss, "ghsa")["score"] == 7.5
    assert audit.best_cvss(cvss, None)["score"] == 9.8          # highest modern score
    assert audit.best_cvss({"x": {"V2Score": 5.0}}, None)["version"] == "2.0"
    assert audit.best_cvss({}, None) is None


def test_safe_url_strips_credentials_and_bad_schemes() -> None:
    assert audit._safe_url("https://user:token@github.com/o/r.git") == "https://github.com/o/r.git"
    assert audit._safe_url("javascript:alert(1)") is None
    assert audit._safe_url("git@github.com:o/r.git") is None


def _trivy_report(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "SchemaVersion": 2,
        "Results": [
            {"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm",
             "Packages": [
                 {"ID": "app-ui@1.0.0", "Name": "app-ui", "Version": "1.0.0", "Relationship": "root",
                  "DependsOn": ["axios@1.9.0"]},
                 {"ID": "axios@1.9.0", "Name": "axios", "Version": "1.9.0", "Relationship": "direct",
                  "DependsOn": ["form-data@4.0.2"]},
                 {"ID": "form-data@4.0.2", "Name": "form-data", "Version": "4.0.2", "Relationship": "indirect"},
                 {"ID": "vite@6.3.4", "Name": "vite", "Version": "6.3.4", "Relationship": "direct", "Dev": True},
             ],
             "Vulnerabilities": [
                 {"VulnerabilityID": "CVE-2025-7783", "VendorIDs": ["GHSA-fjxv-7rqg-78g4"], "PkgID": "form-data@4.0.2",
                  "PkgName": "form-data", "InstalledVersion": "4.0.2", "FixedVersion": "4.0.4, 3.0.4",
                  "Severity": "CRITICAL", "SeveritySource": "ghsa", "CweIDs": ["CWE-330"],
                  "VendorSeverity": {"ghsa": 4, "nvd": 3},
                  "CVSS": {"ghsa": {"V40Score": 9.4, "V40Vector": "CVSS:4.0/AV:N"}},
                  "PublishedDate": "2025-07-18T17:15:44Z", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2025-7783",
                  "References": ["https://github.com/advisories/GHSA-fjxv-7rqg-78g4", "javascript:alert(1)"]},
                 {"VulnerabilityID": "CVE-2026-1", "PkgID": "vite@6.3.4", "PkgName": "vite", "InstalledVersion": "6.3.4",
                  "FixedVersion": "6.4.4", "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 8.2}}},
             ]},
            {"Target": "src/config.js", "Class": "secret",
             "Secrets": [{"RuleID": "github-pat", "Match": f"token = {PLANTED}", "StartLine": 3}]},
        ],
    }), encoding="utf-8")


def _setup(tmp_path: Path, cfg):  # noqa: ANN001, ANN202
    conn = init_db(cfg.db_path)
    repo_dir = tmp_path / "app-ui"
    repo_dir.mkdir()
    dao.sync_discovered(conn, [DiscoveredRepo("app-ui", str(repo_dir), str(tmp_path))], [str(tmp_path)])
    rid = dao.list_repositories(conn)[0]["id"]
    report = cfg.reports_dir / "app-ui_1" / "trivy_fs.json"
    _trivy_report(report)
    now = utcnow()

    def finding(cat, sev, *, vid=None, rule=None, pkg=None, ver=None, fixed=None, path=None, line=None,
                scan_type="fs", scanner="trivy", desc=None, meta=None, key=None):  # noqa: ANN001, ANN202
        conn.execute(
            "INSERT INTO findings(repository_id, fingerprint, dedup_key, scanner, scan_type, category, severity, "
            "vulnerability_id, rule_id, package_name, installed_version, fixed_version, file_path, line, title, "
            "description, metadata_json, first_seen, last_seen, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, key or f"{cat}{vid}{rule}{scan_type}{path}", key or f"{cat}{vid}{rule}{path}", scanner, scan_type,
             cat, sev, vid, rule, pkg, ver, fixed, path, line, vid or rule, desc, json.dumps(meta or {}), now, now,
             "OPEN"))

    with transaction(conn):
        for scanner, stype, rpath, code in (("trivy", "fs", str(report), 0), ("trivy", "config", None, 0),
                                            ("gitleaks", "git", None, 2)):
            conn.execute("INSERT INTO scan_runs(repository_id, scanner, scan_type, status, started_at, finished_at, "
                         "duration, exit_code, tool_version, report_path) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (rid, scanner, stype, "COMPLETED_WITH_FINDINGS", now, now, 1.0, code, "1.0", rpath))
        finding("VULNERABILITY", "CRITICAL", vid="CVE-2025-7783", pkg="form-data", ver="4.0.2", fixed="4.0.4, 3.0.4",
                path="package-lock.json", desc="<script>alert('x')</script> boundary issue",
                meta={"target": "package-lock.json", "pkg_id": "form-data@4.0.2"})
        finding("VULNERABILITY", "HIGH", vid="CVE-2026-1", pkg="vite", ver="6.3.4", fixed="6.4.4",
                path="package-lock.json", meta={"target": "package-lock.json", "pkg_id": "vite@6.3.4"})
        finding("SECRET", "HIGH", rule="github-pat", path="src/config.js", line=3, scanner="gitleaks", scan_type="git",
                meta={"commit": "abcdef1234567890", "commit_date": "2026-01-02T03:04:05Z"})
        for st in ("fs", "config"):  # the same check reported by two Trivy scan types
            finding("MISCONFIGURATION", "HIGH", rule="DS-0002", path="Dockerfile", line=1, scan_type=st,
                    desc="Image runs as root", meta={"resource": "Dockerfile"})
    tools = {n: {"tool": ToolStatus(n, False), "path": None, "version": "1.0", "sha256": None}
             for n in ("trivy", "gitleaks")}
    git = {"commit": "c0ffee" * 6, "branch": "main", "commit_date": "2026-01-01T00:00:00Z",
           "commit_subject": "init", "remote": "https://github.com/o/app-ui"}
    return conn, rid, tools, git


def test_audit_report_content(tmp_path: Path, cfg) -> None:  # noqa: ANN001
    conn, rid, tools, git = _setup(tmp_path, cfg)
    data = audit.build_audit(conn, cfg, rid, tools=tools, git=git)

    fd = next(v for v in data["vulns"] if v["package_name"] == "form-data")
    assert fd["relation"] == "indirect" and fd["path"] == ["axios@1.9.0", "form-data@4.0.2"]
    assert fd["min_fix"] == "4.0.4" and fd["cvss"]["score"] == 9.4 and fd["cwe"] == ["CWE-330"]
    assert fd["vendor_severity"] == {"ghsa": "CRITICAL", "nvd": "HIGH"}
    assert all(u.startswith("https://") for u in fd["references"])      # javascript: link dropped
    vite = next(v for v in data["vulns"] if v["package_name"] == "vite")
    assert vite["scope"] == "dev" and vite["relation"] == "direct"
    assert len(data["misconfs"]) == 1 and data["misconfs"][0]["scan_types"] == {"fs", "config"}
    assert len(data["active"]) == 4                                     # 2 vulns + 1 secret + 1 merged misconfig
    assert audit.scan_status(data)[0] == "COMPLETED"

    doc = audit.render_audit_html(data)
    for section in ("1. Repository details", "2. Executive summary", "5. Detailed vulnerability findings",
                    "7. Direct versus transitive", "9. Secrets", "11. Code issues", "13. Methodology"):
        assert section in doc
    assert "package-lock.json &gt; axios@1.9.0 &gt; form-data@4.0.2" in doc
    assert "npm install vite@6.4.4" in doc and "overrides" in doc       # transitive -> override advice
    assert "<script>alert" not in doc and "&lt;script&gt;" in doc      # descriptions are escaped
    assert PLANTED not in doc and "javascript:" not in doc
    assert "Git history" in doc and "abcdef123456" in doc


def test_audit_without_scans_says_so(tmp_path: Path, cfg) -> None:  # noqa: ANN001
    conn = init_db(cfg.db_path)
    (tmp_path / "empty").mkdir()
    dao.sync_discovered(conn, [DiscoveredRepo("empty", str(tmp_path / "empty"), str(tmp_path))], [str(tmp_path)])
    rid = dao.list_repositories(conn)[0]["id"]
    tools = {n: {"tool": ToolStatus(n, False), "path": None, "version": None, "sha256": None} for n in ("trivy", "gitleaks")}
    data = audit.build_audit(conn, cfg, rid, tools=tools, git={})
    assert audit.scan_status(data)[0] == "NO SCAN DATA"
    assert "posture is unknown" in audit.render_audit_html(data)
