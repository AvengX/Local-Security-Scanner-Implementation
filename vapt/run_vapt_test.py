"""End-to-end VAPT acceptance test for Local Security Scanner.

Builds the intentionally vulnerable lab (vapt/create_lab.py), then drives the REAL application through its
CLI (`run_scan.py`) exactly as a user would, and verifies the results with PASS/FAIL checks:

  Phase 1  tool health                      Phase 5  remediation -> finding RESOLVED
  Phase 2  discovery                        Phase 6  offline scan with cached DB
  Phase 3  full scan (all scanners + DAST)  Phase 7  report export (incl. management summary)
  Phase 4  detection checks + explanations  Phase 8  secret-leak audit of DB, reports and logs

The DAST checks run against two small web apps (vapt/lab_web_app.py) started on 127.0.0.1 by this test: one
deliberately unsafe (with a members area behind a sign-in form, scanned with a test account), one done right.

Results: vapt_lab/VAPT_TEST_RESULTS.md and .json. Exit code 0 only if every check passes.
Scope note: static scanning plus a safe, GET-only web scan of local lab apps. It is not a manual penetration
test (no exploitation beyond detection) — see docs/VAPT_TEST.md.
"""

from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import subprocess
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from vapt.create_lab import _rmtree, create_lab, fix_sql_injection, upgrade_python_dependency  # noqa: E402
from vapt.lab_web_app import LOGIN_USER, LabWebApp  # noqa: E402

LOGIN_ENV = "LSS_VAPT_LOGIN_PASSWORD"

REPOS = {"vuln-python-app", "vuln-node-app", "insecure-infra", "clean-app"}
SUCCESS = ("COMPLETED", "COMPLETED_WITH_FINDINGS")


@dataclass
class Check:
    phase: str
    name: str
    passed: bool
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    commands: list[dict] = field(default_factory=list)

    def add(self, phase: str, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append(Check(phase, name, bool(passed), detail))
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {name}" + (f" - {detail}" if detail else ""))
        return bool(passed)


class Vapt:
    def __init__(self, lab: Path, python: str) -> None:
        self.lab = lab
        self.python = python
        self.cfg_path = lab / "config.vapt.yaml"
        self.app = lab / "app"
        self.r = Report()
        self.web_vuln: LabWebApp | None = None
        self.web_clean: LabWebApp | None = None

    # ------------------------------------------------------------------ helpers
    def cli(self, *args: str, timeout: int = 3600) -> tuple[int, str]:
        cmd = [self.python, str(PROJECT / "run_scan.py"), "--config", str(self.cfg_path), *args]
        t0 = time.monotonic()
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, cwd=PROJECT)
        out = proc.stdout + proc.stderr
        self.r.commands.append({"command": "run_scan.py " + " ".join(args), "exit": proc.returncode,
                                "seconds": round(time.monotonic() - t0, 1)})
        print(f"  $ run_scan.py {' '.join(args)}  -> exit {proc.returncode} ({time.monotonic() - t0:.1f}s)")
        return proc.returncode, out

    def db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.app / "data" / "security_scanner.db")
        conn.row_factory = sqlite3.Row
        return conn

    def q(self, sql: str, *params: object) -> list[sqlite3.Row]:
        with self.db() as c:
            return c.execute(sql, params).fetchall()

    def runs(self, repo: str, min_id: int = 0, max_id: int = 10**9) -> list[sqlite3.Row]:
        return self.q("SELECT s.* FROM scan_runs s JOIN repositories r ON r.id=s.repository_id "
                      "WHERE r.name=? AND s.id>? AND s.id<=? ORDER BY s.id", repo, min_id, max_id)

    def findings(self, repo: str, where: str = "1=1", *params: object) -> list[sqlite3.Row]:
        return self.q("SELECT f.* FROM findings f JOIN repositories r ON r.id=f.repository_id "
                      f"WHERE r.name=? AND {where}", repo, *params)  # noqa: S608 - constant fragments

    def max_run_id(self) -> int:
        return self.q("SELECT COALESCE(MAX(id),0) m FROM scan_runs")[0]["m"]

    # ------------------------------------------------------------------ phases
    def setup(self) -> dict:
        print("\n== Setup: building VAPT lab")
        _rmtree(self.app)
        meta = create_lab(self.lab)
        self.web_vuln = LabWebApp("vulnerable", meta["secrets"]["dast_env_password"],
                                  meta["secrets"]["dast_login_password"]).start()
        os.environ[LOGIN_ENV] = meta["secrets"]["dast_login_password"]  # inherited by the CLI; never in config
        self.web_clean = LabWebApp("clean").start()
        with socket.socket() as sock:  # a free port for the app the scanner must start by itself
            sock.bind(("127.0.0.1", 0))
            self.auto_port = sock.getsockname()[1]
        self.auto_url = f"http://127.0.0.1:{self.auto_port}/"
        cfg = {
            "repository_roots": [meta["targets"]],
            "paths": {"data_dir": str(self.app / "data"), "reports_dir": str(self.app / "reports"),
                      "logs_dir": str(self.app / "logs")},
            "scan": {"timeout_seconds": 900, "concurrency": 1, "offline": False, "db_freshness_hours": 72},
            "trivy": {"scan_types": ["fs", "config"], "scanners": ["vuln", "misconfig", "secret"],
                      "generate_sbom": True},
            "gitleaks": {"modes": ["git", "dir"]},
            "alerts": {"enabled": True, "min_severity": "HIGH", "windows_notification": False},
            "dast": {"targets": [{"repository": "vuln-python-app", "url": self.web_vuln.url,
                                  "login": {"url": self.web_vuln.url + "login", "username": LOGIN_USER,
                                            "password_env": LOGIN_ENV}},
                                 {"repository": "clean-app", "url": self.web_clean.url},
                                 {"repository": "clean-app", "url": self.auto_url,
                                  "start_command": f"{self.python} serve.py {self.auto_port}", "start_wait": 60}]},
        }
        self.cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
        print(f"  lab: {meta['targets']}")
        print(f"  web apps: {self.web_vuln.url} (unsafe), {self.web_clean.url} (clean)")
        return meta

    def phase_health(self) -> bool:
        print("\n== Phase 1: tool health")
        code, out = self.cli("health")
        trivy_ok = "trivy     OK" in out
        self.r.add("1 Health", "Trivy installed and allowed to run", trivy_ok,
                   next((ln.strip() for ln in out.splitlines() if ln.strip().startswith("trivy")), ""))
        self.r.add("1 Health", "Gitleaks installed and runnable", "gitleaks  OK" in out)
        self.r.add("1 Health", "Bandit (SAST) installed and runnable", "bandit    OK" in out)
        self.r.add("1 Health", "Web scan (DAST) built in and ready", "dast      OK" in out)
        self.r.add("1 Health", "Code scan for other languages built in and ready", "codescan  OK" in out)
        db_line = next((ln.strip() for ln in out.splitlines() if "Vulnerability DB" in ln), "")
        self.r.add("1 Health", "Trivy vulnerability DB cached and fresh",
                   "No cached" not in db_line and "STALE" not in db_line, db_line)
        return trivy_ok

    def phase_discovery(self) -> None:
        print("\n== Phase 2: discovery")
        code, _ = self.cli("discover")
        names = {r["name"] for r in self.q("SELECT name FROM repositories WHERE active=1")}
        self.r.add("2 Discovery", "discover command succeeds", code == 0)
        self.r.add("2 Discovery", "All 4 lab repositories discovered", names == REPOS, ", ".join(sorted(names)))

    def phase_scan(self) -> int:
        print("\n== Phase 3: full scan (Trivy fs + config + SBOM, Gitleaks git + dir, Bandit, code scan, DAST)")
        code, out = self.cli("scan-all")
        self.scan_out = out
        last = self.max_run_id()
        bad = self.q("SELECT r.name, s.scanner, s.scan_type, s.status, s.error_message FROM scan_runs s "
                     "JOIN repositories r ON r.id=s.repository_id WHERE s.status NOT IN (?,?)", *SUCCESS)
        self.r.add("3 Scan", "scan-all exits 0 (no failed scanner runs)", code == 0, f"exit {code}")
        self.r.add("3 Scan", "Every scanner run succeeded", not bad,
                   "; ".join(f"{b['name']} {b['scanner']}:{b['scan_type']}={b['status']} {b['error_message'] or ''}"
                             for b in bad)[:400])
        total = self.q("SELECT COUNT(*) c FROM scan_runs")[0]["c"]
        self.r.add("3 Scan", "32 scanner runs recorded (4 repos x 7 jobs + 3 web addresses + 1 installed env)",
                   total == 32,
                   f"{total} runs")
        meta_ok = self.q("SELECT COUNT(*) c FROM scan_runs WHERE tool_version IS NULL OR "
                         "(scanner='trivy' AND database_updated_at IS NULL)")[0]["c"] == 0
        self.r.add("3 Scan", "Tool version and Trivy DB timestamp recorded on every run", meta_ok)
        return last

    def phase_detection(self, secrets: dict[str, str]) -> None:
        print("\n== Phase 4: detection checks")
        f = self.findings
        cve = f("vuln-python-app", "vulnerability_id='CVE-2023-32681'")
        self.r.add("4 Detection", "Python: requests 2.25.0 CVE-2023-32681 detected", bool(cve),
                   cve[0]["severity"] + " fixed in " + (cve[0]["fixed_version"] or "?") if cve else "")
        pkgs = {r["package_name"] for r in f("vuln-python-app", "category='VULNERABILITY'")}
        self.r.add("4 Detection", "Python: vulnerabilities in >= 3 pinned packages", len(pkgs) >= 3,
                   ", ".join(sorted(p for p in pkgs if p)))
        high = f("vuln-python-app", "category='VULNERABILITY' AND severity IN ('CRITICAL','HIGH')")
        self.r.add("4 Detection", "Python: at least one CRITICAL/HIGH vulnerability", bool(high), f"{len(high)} found")
        lodash = f("vuln-node-app", "package_name='lodash' AND category='VULNERABILITY'")
        self.r.add("4 Detection", "Node: lodash 4.17.15 CVEs detected from package-lock.json", bool(lodash),
                   ", ".join(sorted({r["vulnerability_id"] for r in lodash})))
        minimist = f("vuln-node-app", "package_name='minimist'")
        self.r.add("4 Detection", "Node: minimist 1.2.0 CVE detected", bool(minimist))

        mis = f("insecure-infra", "category='MISCONFIGURATION'")
        files = {r["file_path"] for r in mis}
        for path in ("Dockerfile", "k8s/deployment.yaml", "terraform/main.tf"):
            self.r.add("4 Detection", f"IaC: misconfiguration found in {path}", path in files,
                       f"{sum(1 for r in mis if r['file_path'] == path)} findings")
        self.r.add("4 Detection", "IaC: 'trivy config' scan type also reports misconfigurations",
                   any(r["scan_type"] == "config" for r in mis))
        priv = [r for r in mis if r["file_path"] == "k8s/deployment.yaml" and "rivileg" in (r["title"] or "")]
        self.r.add("4 Detection", "IaC: privileged Kubernetes container flagged", bool(priv))
        sg = [r for r in mis if r["file_path"] == "terraform/main.tf" and
              any(k in (r["title"] or "").lower() for k in ("ingress", "public", "0.0.0.0", "security group"))]
        self.r.add("4 Detection", "IaC: world-open security group / public S3 flagged", bool(sg))

        gl_git = f("vuln-python-app", "scanner='gitleaks' AND scan_type='git'")
        gl_dir = f("vuln-python-app", "scanner='gitleaks' AND scan_type='dir'")
        self.r.add("4 Detection", "Secrets: AWS access key detected (Gitleaks)",
                   any("aws" in (r["rule_id"] or "") for r in gl_git + gl_dir))
        self.r.add("4 Detection", "Secrets: GitHub token detected (Gitleaks)",
                   any("github" in (r["rule_id"] or "") for r in gl_git + gl_dir))
        self.r.add("4 Detection", "Secrets: token removed from code still found in Git history",
                   any(r["file_path"] == "app/settings.py" for r in gl_git))
        self.r.add("4 Detection", "Secrets: history-only token NOT reported by working-tree scan",
                   not any(r["file_path"] == "app/settings.py" for r in gl_dir))
        venv_hits = f("vuln-python-app", "file_path LIKE '%.venv%' AND scan_type != 'installed'")
        self.r.add("4 Detection", "Installed-dependency folder (.venv) skipped by Trivy and Gitleaks", not venv_hits,
                   f"{len(venv_hits)} findings inside .venv")
        self.r.add("4 Detection", "Working-tree secret paths are repository-relative",
                   all(not (r["file_path"] or "").startswith(("C:", "D:", "/")) for r in gl_dir))
        tr_sec = f("vuln-python-app", "scanner='trivy' AND category='SECRET'")
        self.r.add("4 Detection", "Secrets: Trivy secret scanner also detects planted credentials", bool(tr_sec),
                   ", ".join(sorted({r["rule_id"] for r in tr_sec})))
        self.r.add("4 Detection", "Secrets: remediation advises revoke and rotate",
                   all("revoke and rotate" in (r["remediation"] or "") for r in gl_git + gl_dir + tr_sec))

        code = f("vuln-python-app", "category='CODE'")
        rules = {r["rule_id"] for r in code}
        for rule, what in (("B608", "SQL built from strings (SQL injection)"), ("B602", "shell=True command"),
                           ("B301", "pickle.loads on untrusted data"), ("B506", "unsafe yaml.load"),
                           ("B105", "hardcoded password")):
            hit = [r for r in code if r["rule_id"] == rule]
            self.r.add("4 Detection", f"SAST: {what} detected ({rule})", bool(hit),
                       f"{hit[0]['file_path']}:{hit[0]['line']} {hit[0]['severity']}" if hit else ", ".join(sorted(rules)))
        self.r.add("4 Detection", "SAST: code issues carry file, line and remediation",
                   bool(code) and all((r["file_path"] or "").startswith("app/") and r["line"] and r["remediation"]
                                     for r in code), f"{len(code)} code issues in {len({r['file_path'] for r in code})} files")
        self.r.add("4 Detection", "SAST: Bandit reports nothing for repositories without Python",
                   not f("insecure-infra", "category='CODE'")
                   and not f("vuln-node-app", "category='CODE' AND scanner='bandit'"))
        other = f("vuln-python-app", "scanner='codescan'") + f("vuln-node-app", "scanner='codescan'")
        for rule, path, what in (("JS-EVAL", "app/static/app.js", "JavaScript eval()"),
                                 ("JS-INNERHTML", "app/static/app.js", "JavaScript innerHTML from a variable"),
                                 ("JS-STORAGE-TOKEN", "app/static/app.js", "token saved in localStorage"),
                                 ("TPL-SAFE-FILTER", "app/templates/profile.html", "template |safe (escaping off)"),
                                 ("TPL-NO-SRI", "app/templates/profile.html", "CDN script without integrity"),
                                 ("JS-SQL-CONCAT", "server.js", "Node SQL built from a template string"),
                                 ("JS-CMD-INJECTION", "server.js", "Node exec() with a variable")):
            hit = [r for r in other if r["rule_id"] == rule and r["file_path"] == path]
            self.r.add("4 Detection", f"Code scan (other languages): {what} detected ({rule})", bool(hit),
                       f"{path}:{hit[0]['line']} {hit[0]['severity']}" if hit else
                       ", ".join(sorted({r['rule_id'] for r in other})))

        web = f("vuln-python-app", "category='WEB'")
        checks = {r["rule_id"]: r for r in web}
        for rule, what in (("DAST-XSS", "reflected XSS"), ("DAST-SQLI", "SQL injection (database error)"),
                           ("DAST-REDIRECT", "open redirect"), ("DAST-TRAVERSAL", "path traversal"),
                           ("DAST-EXPOSED-FILE", "exposed .env file"), ("DAST-DEBUG", "debugger console exposed"),
                           ("DAST-ERROR-LEAK", "stack trace in error page"), ("DAST-DIR-LISTING", "directory listing"),
                           ("DAST-CORS", "CORS allows any origin"), ("DAST-COOKIE-HTTPONLY", "cookie without HttpOnly"),
                           ("DAST-CSP", "missing security headers")):
            hit = checks.get(rule)
            self.r.add("4 Detection", f"DAST: {what} detected ({rule})", hit is not None,
                       f"{hit['file_path']} {hit['severity']}" if hit else ", ".join(sorted(checks)))
        self.r.add("4 Detection", "DAST: issues carry page, evidence and remediation",
                   bool(web) and all(r["file_path"] and r["remediation"] and '"evidence"' in (r["metadata_json"] or "")
                                     for r in web), f"{len(web)} web app issues")
        assert self.web_vuln is not None
        self.r.add("4 Detection", "DAST: never followed log-out/delete links or sent POST requests",
                   self.web_vuln.state.destructive_hits == 0 and self.web_vuln.state.post_hits == 0,
                   f"{self.web_vuln.state.destructive_hits} destructive GETs, {self.web_vuln.state.post_hits} POSTs")
        member = [r for r in web if r["rule_id"] == "DAST-XSS" and r["file_path"] == "/account/notes"]
        self.r.add("4 Detection", "DAST login: XSS behind the sign-in form found with the test account", bool(member),
                   member[0]["severity"] if member else ", ".join(sorted({r['file_path'] for r in web})))
        self.r.add("4 Detection", "DAST login: exactly one sign-in POST per web scan, no other POST",
                   self.web_vuln.state.login_posts == 1 and self.web_vuln.state.post_hits == 0,
                   f"{self.web_vuln.state.login_posts} sign-in POST(s)")
        from engine.dast_scanner import DastScanner
        from utils.config import DastLogin

        os.environ["LSS_VAPT_WRONG_PW"] = "not-the-password"
        try:
            bad = DastScanner().scan(self.web_vuln.url, self.lab / "wrong_login.json", 120, login=DastLogin(
                url=self.web_vuln.url + "login", username=LOGIN_USER, password_env="LSS_VAPT_WRONG_PW"))
        finally:
            os.environ.pop("LSS_VAPT_WRONG_PW", None)
        self.r.add("4 Detection", "DAST login: a wrong test password makes the web scan FAIL (nothing resolved)",
                   bad.status == "FAILED" and "Login failed" in (bad.error_message or ""),
                   f"{bad.status}: {bad.error_message}")
        refused = subprocess.run([self.python, "-c", "from utils.config import AppConfig; AppConfig.model_validate("
                                  "{'dast': {'targets': [{'repository': 'x', 'url': 'http://example.com/'}]}})"],
                                 capture_output=True, text=True, cwd=PROJECT)
        self.r.add("4 Detection", "DAST: non-local addresses are refused by the configuration",
                   refused.returncode != 0 and "limited to apps on this computer" in refused.stderr)

        inst = f("vuln-python-app", "scan_type='installed'")
        flask = [r for r in inst if (r["package_name"] or "").lower() == "flask"]
        self.r.add("4 Detection", "Installed versions: unpinned Flask 0.12.2 in .venv checked and its CVEs found",
                   bool(flask) and all(r["installed_version"] == "0.12.2" for r in flask),
                   ", ".join(sorted({r["vulnerability_id"] for r in flask})))
        note = self.q("SELECT s.error_message FROM scan_runs s JOIN repositories r ON r.id=s.repository_id WHERE "
                      "r.name='vuln-python-app' AND s.scan_type='installed' ORDER BY s.id DESC LIMIT 1")
        self.r.add("4 Detection", "Installed versions: Jinja2 (pinned in requirements.txt) skipped, not double-counted",
                   not any((r["package_name"] or "").lower() == "jinja2" for r in inst)
                   and bool(note) and "1 already pinned" in (note[0]["error_message"] or ""),
                   note[0]["error_message"] if note else "no run")
        auto = self.q("SELECT status, error_message FROM scan_runs WHERE scanner='dast' AND scan_target=? "
                      "ORDER BY id DESC LIMIT 1", self.auto_url)
        from engine.app_launcher import is_listening

        self.r.add("4 Detection", "Auto-start: the scanner started the stopped app, scanned it and stopped it again",
                   bool(auto) and auto[0]["status"] in SUCCESS and "started the app" in (auto[0]["error_message"] or "")
                   and not is_listening(self.auto_url), (auto[0]["status"] + ": " + (auto[0]["error_message"] or ""))
                   if auto else "no run")
        clean = f("clean-app")
        clean_runs = self.runs("clean-app")
        self.r.add("4 Detection", "Clean control repo: zero findings (no false positives)", not clean,
                   f"{len(clean)} findings")
        self.r.add("4 Detection", "Clean control repo: runs marked COMPLETED (not 'with findings')",
                   all(r["status"] == "COMPLETED" for r in clean_runs if r["scan_type"] != "sbom"))

        sboms = list((self.app / "reports").rglob("*.cdx.json"))
        ok = len(sboms) == 4 and all(json.loads(p.read_text(encoding="utf-8")).get("bomFormat") == "CycloneDX"
                                     for p in sboms)
        self.r.add("4 Detection", "CycloneDX SBOM generated for each repository", ok, f"{len(sboms)} SBOMs")
        dup = self.q("SELECT COUNT(*) - COUNT(DISTINCT repository_id || fingerprint) d FROM findings")[0]["d"]
        self.r.add("4 Detection", "No duplicate findings stored", dup == 0)

        from services.explain import explain

        rows = [dict(r) for r in self.q("SELECT * FROM findings")]
        expl = [(r, explain(r)) for r in rows]
        complete = [r for r, e in expl if e.what and e.why and e.attack and len(e.fix) >= 2 and e.urgency]
        self.r.add("4 Explain", "Every finding has a plain-language explanation (what, why, attack, fix steps, when)",
                   bool(rows) and len(complete) == len(rows), f"{len(complete)}/{len(rows)} findings")
        generic = sorted({r["rule_id"] for r, e in expl if r["category"] in ("CODE", "WEB") and e.topic == "generic"})
        self.r.add("4 Explain", "Every code and web issue maps to a specific explanation (no generic text)",
                   not generic, ", ".join(generic))
        sec = [e for r, e in expl if r["category"] == "SECRET"]
        self.r.add("4 Explain", "Secret explanations say to revoke first and never show the value",
                   bool(sec) and all("Revoke" in e.fix[0] and not any(v in e.what for v in secrets.values())
                                     for e in sec))

    def phase_remediation(self) -> None:
        print("\n== Phase 5: remediation (upgrade requests -> rescan)")
        upgrade_python_dependency(self.lab)
        before = self.max_run_id()
        code, _ = self.cli("scan-repo", "--name", "vuln-python-app")
        cve = self.findings("vuln-python-app", "vulnerability_id='CVE-2023-32681'")
        self.r.add("5 Remediation", "Rescan of single repository succeeds", code == 0, f"exit {code}")
        self.r.add("5 Remediation", "Fixed CVE-2023-32681 marked RESOLVED",
                   bool(cve) and cve[0]["status"] == "RESOLVED", cve[0]["status"] if cve else "missing")
        hist = self.findings("vuln-python-app", "scanner='gitleaks' AND scan_type='git' AND file_path='app/settings.py'")
        self.r.add("5 Remediation", "Secret still in Git history stays OPEN (not falsely resolved)",
                   bool(hist) and all(r["status"] == "OPEN" for r in hist))
        others = self.findings("vuln-python-app", "category='VULNERABILITY' AND status='OPEN'")
        self.r.add("5 Remediation", "Unfixed vulnerabilities remain OPEN", bool(others), f"{len(others)} open")
        fix_sql_injection(self.lab)
        code2, _ = self.cli("scan-repo", "--name", "vuln-python-app")
        sqli = self.findings("vuln-python-app", "category='CODE' AND rule_id='B608'")
        self.r.add("5 Remediation", "Fixed SQL injection (B608) marked RESOLVED after code change",
                   code2 == 0 and bool(sqli) and all(r["status"] == "RESOLVED" for r in sqli),
                   ", ".join(r["status"] for r in sqli) or "missing")
        still = self.findings("vuln-python-app", "category='CODE' AND rule_id='B602' AND status='OPEN'")
        self.r.add("5 Remediation", "Unfixed code issue (shell=True) stays OPEN with its history", bool(still))
        resolved_count = self.q("SELECT SUM(resolved_count) s FROM scan_runs WHERE id>?", before)[0]["s"] or 0
        assert self.web_vuln is not None
        self.web_vuln.state.xss_fixed = True  # the app now escapes the search term
        code3, _ = self.cli("scan-repo", "--name", "vuln-python-app")
        xss = self.findings("vuln-python-app", "category='WEB' AND rule_id='DAST-XSS' AND file_path='/search'")
        self.r.add("5 Remediation", "Fixed XSS in the running app marked RESOLVED after rescan",
                   code3 == 0 and bool(xss) and all(r["status"] == "RESOLVED" for r in xss),
                   ", ".join(r["status"] for r in xss) or "missing")
        sqli_web = self.findings("vuln-python-app", "category='WEB' AND rule_id='DAST-SQLI' AND status='OPEN'")
        self.r.add("5 Remediation", "Unfixed web issue (SQL injection) stays OPEN", bool(sqli_web))
        self.web_vuln.stop()  # app no longer running: findings must not be marked resolved
        self.cli("scan-repo", "--name", "vuln-python-app")
        last = self.q("SELECT status FROM scan_runs WHERE scanner='dast' AND scan_target=? ORDER BY id DESC LIMIT 1",
                      self.web_vuln.url)
        web_now = self.findings("vuln-python-app", "category='WEB' AND NOT (rule_id='DAST-XSS' AND file_path='/search')")
        self.r.add("5 Remediation", "App not running: web scan SKIPPED and its issues become UNVERIFIED (not resolved)",
                   bool(last) and last[0]["status"] == "SKIPPED" and bool(web_now)
                   and all(r["status"] == "UNVERIFIED" for r in web_now),
                   (last[0]["status"] if last else "no run") + f", {len(web_now)} kept")
        self.r.add("5 Remediation", "Scan run records resolved count", resolved_count >= 1, str(resolved_count))

    def phase_offline(self) -> None:
        print("\n== Phase 6: offline scan (cached DB only)")
        before = self.max_run_id()
        code, _ = self.cli("scan-all", "--offline", "--no-discover")
        tr = self.q("SELECT status, offline FROM scan_runs WHERE id>? AND scanner='trivy' AND scan_type='fs'", before)
        self.r.add("6 Offline", "Offline scan-all exits 0", code == 0, f"exit {code}")
        self.r.add("6 Offline", "Trivy fs runs succeed offline and are flagged offline",
                   len(tr) == 4 and all(r["status"] in SUCCESS and r["offline"] == 1 for r in tr),
                   ", ".join(f"{r['status']}/offline={r['offline']}" for r in tr))
        cve = self.findings("vuln-node-app", "package_name='lodash' AND status='OPEN'")
        self.r.add("6 Offline", "Offline scan still detects vulnerabilities (lodash)", bool(cve))

    def phase_triage(self) -> None:
        print("\n== Phase 6b: triage (false positive / accepted risk)")
        from datetime import date, timedelta

        from database.db import init_db
        from services import analytics_service as an
        from services import triage_service as tri

        conn = init_db(self.app / "data" / "security_scanner.db")
        try:
            fp = conn.execute("SELECT f.id FROM findings f JOIN repositories r ON r.id=f.repository_id WHERE "
                              "r.name='vuln-node-app' AND f.package_name='minimist' AND f.status='OPEN' "
                              "ORDER BY f.id LIMIT 1").fetchone()
            ar = conn.execute("SELECT f.id FROM findings f JOIN repositories r ON r.id=f.repository_id WHERE "
                              "r.name='vuln-node-app' AND f.package_name='lodash' AND f.status='OPEN' "
                              "ORDER BY f.id LIMIT 1").fetchone()
            if not fp or not ar:
                self.r.add("6b Triage", "Lab findings available for triage", False, "minimist/lodash not open")
                return
            before = sum(an.overview_metrics(conn)["severity"].values())
            tri.set_decision(conn, fp[0], "FALSE_POSITIVE", "VAPT lab: marked as a false positive on purpose")
            tri.set_decision(conn, ar[0], "ACCEPTED_RISK", "VAPT lab: accepted on purpose",
                             date.today() + timedelta(days=30))
            after = sum(an.overview_metrics(conn)["severity"].values())
        finally:
            conn.close()
        code, _ = self.cli("scan-repo", "--name", "vuln-node-app")
        conn = init_db(self.app / "data" / "security_scanner.db")
        try:
            kept = tri.get_decision(conn, fp[0])
            status = conn.execute("SELECT status FROM findings WHERE id=?", (fp[0],)).fetchone()[0]
            still = sum(an.overview_metrics(conn)["severity"].values())
            self.r.add("6b Triage", "Decided findings leave the open counts (and stay out after a rescan)",
                       after == before - 2 and still == after and code == 0, f"{before} -> {after} -> {still}")
            self.r.add("6b Triage", "A false-positive decision survives a rescan; the scan status is untouched",
                       bool(kept) and kept["decision"] == "FALSE_POSITIVE" and status == "OPEN",
                       f"{kept['decision'] if kept else 'lost'} / {status}")
            expired = tri.expire_due(conn, today=date.today() + timedelta(days=30))
            back = sum(an.overview_metrics(conn)["severity"].values())
            self.r.add("6b Triage", "An accepted risk expires on its review date and counts again",
                       expired == 1 and back == still + 1 and [h["action"] for h in tri.history(conn, ar[0])]
                       == ["ACCEPTED_RISK", "EXPIRED"], f"{expired} expired, open {still} -> {back}")
        finally:
            conn.close()

    def phase_alerts_guard(self, secrets: dict[str, str]) -> None:
        print("\n== Phase 6c: alerts and pre-commit secret guard")
        first = self.q("SELECT * FROM alerts ORDER BY id LIMIT 1")
        self.r.add("6c Alerts", "The first full scan raised an alert for new serious problems",
                   bool(first) and first[0]["severity"] == "CRITICAL" and first[0]["new_count"] > 0
                   and "ALERT #" in getattr(self, "scan_out", ""),
                   f"{first[0]['new_count']} new, worst {first[0]['severity']}" if first else "no alert")
        payload = " ".join(r["summary_json"] for r in self.q("SELECT summary_json FROM alerts"))
        self.r.add("6c Alerts", "Alerts contain counts and names only - no secret values",
                   bool(payload) and not any(v in payload for v in secrets.values()))
        repo = Path(self.lab / "targets" / "clean-app")
        code, out = self.cli("guard", "install", "--name", "clean-app")
        hook_ok = code == 0 and "secret guard On" in out
        token = secrets["github_pat_current"]
        leak = repo / "guard_test.py"
        leak.write_text(f'TOKEN = "{token}"\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "guard_test.py"], capture_output=True)
        blocked = subprocess.run(["git", "-C", str(repo), "-c", "user.email=lab@example.invalid", "-c",
                                  "user.name=lab", "commit", "-m", "guard test"], capture_output=True, text=True)
        subprocess.run(["git", "-C", str(repo), "reset", "-q"], capture_output=True)
        leak.unlink(missing_ok=True)
        self.r.add("6c Guard", "Secret guard installed and blocks a commit containing a token (value not shown)",
                   hook_ok and blocked.returncode != 0 and "BLOCKED" in blocked.stderr
                   and token not in blocked.stdout + blocked.stderr,
                   f"exit {blocked.returncode}")
        code, out = self.cli("guard", "remove", "--name", "clean-app")
        self.r.add("6c Guard", "Secret guard can be removed again", code == 0 and "secret guard Off" in out)

    def phase_reports(self) -> None:
        print("\n== Phase 7: reports")
        code, out = self.cli("report")
        exports = list((self.app / "reports" / "exports").glob("*"))
        self.r.add("7 Reports", "report command writes md/html/json/csv", code == 0 and
                   {p.suffix for p in exports} >= {".md", ".html", ".json", ".csv"}, f"{len(exports)} files")
        code, out = self.cli("status")
        self.r.add("7 Reports", "status command summarises posture", code == 0 and "Repositories: 4" in out)
        before = set((self.app / "reports" / "exports").glob("*_management_summary.html"))
        code, out = self.cli("summary")
        new = sorted(set((self.app / "reports" / "exports").glob("*_management_summary.html")) - before)
        doc = new[-1].read_text(encoding="utf-8") if new else ""
        self.r.add("7 Reports", "Management summary written in plain language (risk level, what to fix first, "
                                "what was tested)",
                   code == 0 and all(x in doc for x in ("What to fix first", "What was tested", "risk",
                                                        "does not cover")), new[-1].name if new else out[-200:])
        raw = list((self.app / "reports").rglob("*_run*.json"))
        self.r.add("7 Reports", "Raw Trivy, Gitleaks, Bandit, code-scan and DAST JSON reports kept locally",
                   any("_trivy_" in p.name for p in raw) and any("_gitleaks_" in p.name for p in raw)
                   and any("_bandit_" in p.name for p in raw) and any("_dast_" in p.name for p in raw)
                   and any("_codescan_" in p.name for p in raw),
                   f"{len(raw)} raw reports")

    def phase_leak_audit(self, secrets: dict[str, str]) -> None:
        print("\n== Phase 8: secret-leak audit")
        leaks = []
        for p in self.app.rglob("*"):
            if p.is_file():
                data = p.read_bytes()
                for name, value in secrets.items():
                    if value.encode() in data:
                        leaks.append(f"{name} in {p.relative_to(self.app)}")
        self.r.add("8 Leak audit", "No planted secret value in database, raw reports, exports or logs",
                   not leaks, "; ".join(leaks[:5]))
        log = self.app / "logs" / "scanner.log"
        self.r.add("8 Leak audit", "Structured log written", log.is_file() and log.stat().st_size > 0)

    # ------------------------------------------------------------------ output
    def write_results(self, started: str) -> Path:
        passed = sum(c.passed for c in self.r.checks)
        total = len(self.r.checks)
        lines = ["# VAPT Test Results — Local Security Scanner", "",
                 f"Started: {started}  ", f"Finished: {datetime.now(timezone.utc).isoformat(timespec='seconds')}  ",
                 f"Lab: `{self.lab / 'targets'}`  ", f"Result: **{passed}/{total} checks passed** — "
                 f"{'PASS' if passed == total else 'FAIL'}", "",
                 "Scope: static scanning (dependencies, IaC, secrets, code in Python and other languages) plus a "
                 "safe GET-only web scan (DAST) of two lab apps on 127.0.0.1, including a members area reached with a "
                 "test account. No manual penetration testing or exploitation.", "",
                 "| Phase | Check | Result | Detail |", "|---|---|---|---|"]
        for c in self.r.checks:
            lines.append(f"| {c.phase} | {c.name} | {'PASS' if c.passed else '**FAIL**'} | "
                         f"{c.detail.replace('|', '/')} |")
        lines += ["", "## Commands executed", "", "| Command | Exit | Seconds |", "|---|---|---|"]
        lines += [f"| `{c['command']}` | {c['exit']} | {c['seconds']} |" for c in self.r.commands]
        md = self.lab / "VAPT_TEST_RESULTS.md"
        md.write_text("\n".join(lines) + "\n", encoding="utf-8")
        finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
        (self.lab / "VAPT_TEST_RESULTS.json").write_text(json.dumps(
            {"started": started, "finished": finished, "passed": passed, "total": total,
             "checks": [vars(c) for c in self.r.checks], "commands": self.r.commands}, indent=2), encoding="utf-8")
        # One line per run so the dashboard can show historical VAPT results (the lab itself is recreated).
        failed = [c.name for c in self.r.checks if not c.passed]
        with open(self.lab / "history.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"started": started, "finished": finished, "passed": passed, "total": total,
                                 "failed": failed[:20]}) + "\n")
        return md

    def run(self) -> int:
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.lab.mkdir(parents=True, exist_ok=True)
        marker = self.lab / "RUNNING.pid"  # lets the dashboard show that a test is in progress
        # PID + process start time: a later process that happens to reuse the PID is not mistaken for this test.
        from utils.security import process_start_time

        marker.write_text(json.dumps({"pid": os.getpid(), "start": process_start_time(os.getpid())}),
                          encoding="utf-8")
        try:
            return self._run(started)
        finally:
            marker.unlink(missing_ok=True)
            os.environ.pop(LOGIN_ENV, None)
            for web in (self.web_vuln, self.web_clean):
                if web is not None:
                    try:
                        web.stop()
                    except OSError:
                        pass

    def _run(self, started: str) -> int:
        meta = self.setup()
        secrets: dict[str, str] = meta["secrets"]  # type: ignore[assignment]
        trivy_ok = self.phase_health()
        self.phase_discovery()
        self.phase_scan()
        self.phase_detection(secrets)
        self.phase_remediation()
        if trivy_ok:
            self.phase_offline()
        else:
            self.r.add("6 Offline", "Offline scan (requires runnable Trivy)", False, "skipped: Trivy unavailable")
        self.phase_triage()
        self.phase_alerts_guard(secrets)
        self.phase_reports()
        self.phase_leak_audit(secrets)
        md = self.write_results(started)
        passed = sum(c.passed for c in self.r.checks)
        print(f"\n== RESULT: {passed}/{len(self.r.checks)} checks passed -> {md}")
        return 0 if passed == len(self.r.checks) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the Local Security Scanner VAPT acceptance test")
    ap.add_argument("--lab", default=str(PROJECT / "vapt_lab"), help="Lab directory (recreated each run)")
    args = ap.parse_args()
    py = PROJECT / ".venv" / "Scripts" / "python.exe"
    return Vapt(Path(args.lab).resolve(), str(py if py.is_file() else sys.executable)).run()


if __name__ == "__main__":
    sys.exit(main())
