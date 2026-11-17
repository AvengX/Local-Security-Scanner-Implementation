"""End-to-end VAPT acceptance test for Local Security Scanner.

Builds the intentionally vulnerable lab (vapt/create_lab.py), then drives the REAL application through its
CLI (`run_scan.py`) exactly as a user would, and verifies the results with PASS/FAIL checks:

  Phase 1  tool health                      Phase 5  remediation -> finding RESOLVED
  Phase 2  discovery                        Phase 6  offline scan with cached DB
  Phase 3  full scan (Trivy + Gitleaks)     Phase 7  report export
  Phase 4  detection checks                 Phase 8  secret-leak audit of DB, reports and logs

Results: vapt_lab/VAPT_TEST_RESULTS.md and .json. Exit code 0 only if every check passes.
Scope note: this validates the vulnerability-assessment (static scanning) part of VAPT. It does not perform
penetration testing (no network attacks, no exploitation) — see docs/VAPT_TEST.md.
"""

from __future__ import annotations

import argparse
import json
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

from vapt.create_lab import _rmtree, create_lab, upgrade_python_dependency  # noqa: E402

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
        cfg = {
            "repository_roots": [meta["targets"]],
            "paths": {"data_dir": str(self.app / "data"), "reports_dir": str(self.app / "reports"),
                      "logs_dir": str(self.app / "logs")},
            "scan": {"timeout_seconds": 900, "concurrency": 1, "offline": False, "db_freshness_hours": 72},
            "trivy": {"scan_types": ["fs", "config"], "scanners": ["vuln", "misconfig", "secret"],
                      "generate_sbom": True},
            "gitleaks": {"modes": ["git", "dir"]},
        }
        self.cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
        print(f"  lab: {meta['targets']}")
        return meta

    def phase_health(self) -> bool:
        print("\n== Phase 1: tool health")
        code, out = self.cli("health")
        trivy_ok = "trivy     OK" in out
        self.r.add("1 Health", "Trivy installed and allowed to run", trivy_ok,
                   next((ln.strip() for ln in out.splitlines() if ln.strip().startswith("trivy")), ""))
        self.r.add("1 Health", "Gitleaks installed and runnable", "gitleaks  OK" in out)
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
        print("\n== Phase 3: full scan (Trivy fs + config + SBOM, Gitleaks git + dir)")
        code, out = self.cli("scan-all")
        last = self.max_run_id()
        bad = self.q("SELECT r.name, s.scanner, s.scan_type, s.status, s.error_message FROM scan_runs s "
                     "JOIN repositories r ON r.id=s.repository_id WHERE s.status NOT IN (?,?)", *SUCCESS)
        self.r.add("3 Scan", "scan-all exits 0 (no failed scanner runs)", code == 0, f"exit {code}")
        self.r.add("3 Scan", "Every scanner run succeeded", not bad,
                   "; ".join(f"{b['name']} {b['scanner']}:{b['scan_type']}={b['status']} {b['error_message'] or ''}"
                             for b in bad)[:400])
        total = self.q("SELECT COUNT(*) c FROM scan_runs")[0]["c"]
        self.r.add("3 Scan", "20 scanner runs recorded (4 repos x 5 jobs)", total == 20, f"{total} runs")
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
        venv_hits = f("vuln-python-app", "file_path LIKE '%.venv%'")
        self.r.add("4 Detection", "Installed-dependency folder (.venv) skipped by Trivy and Gitleaks", not venv_hits,
                   f"{len(venv_hits)} findings inside .venv")
        self.r.add("4 Detection", "Working-tree secret paths are repository-relative",
                   all(not (r["file_path"] or "").startswith(("C:", "D:", "/")) for r in gl_dir))
        tr_sec = f("vuln-python-app", "scanner='trivy' AND category='SECRET'")
        self.r.add("4 Detection", "Secrets: Trivy secret scanner also detects planted credentials", bool(tr_sec),
                   ", ".join(sorted({r["rule_id"] for r in tr_sec})))
        self.r.add("4 Detection", "Secrets: remediation advises revoke and rotate",
                   all("revoke and rotate" in (r["remediation"] or "") for r in gl_git + gl_dir + tr_sec))

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
        resolved_count = self.q("SELECT SUM(resolved_count) s FROM scan_runs WHERE id>?", before)[0]["s"] or 0
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

    def phase_reports(self) -> None:
        print("\n== Phase 7: reports")
        code, out = self.cli("report")
        exports = list((self.app / "reports" / "exports").glob("*"))
        self.r.add("7 Reports", "report command writes md/html/json/csv", code == 0 and
                   {p.suffix for p in exports} >= {".md", ".html", ".json", ".csv"}, f"{len(exports)} files")
        code, out = self.cli("status")
        self.r.add("7 Reports", "status command summarises posture", code == 0 and "Repositories: 4" in out)
        raw = list((self.app / "reports").rglob("*_run*.json"))
        self.r.add("7 Reports", "Raw Trivy and Gitleaks JSON reports kept locally",
                   any("_trivy_" in p.name for p in raw) and any("_gitleaks_" in p.name for p in raw),
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
                 "Scope: vulnerability assessment by static scanning (dependencies, IaC, secrets). "
                 "No penetration testing / network attacks were performed.", "",
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
