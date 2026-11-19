"""Detailed per-repository security audit report (print-ready HTML; use the browser's Print → Save as PDF).

Everything comes from local data only:
* the findings database (status, first/last seen, secrets without values, misconfigurations),
* the latest successful scan runs (tool versions, exit codes, timings, offline flag),
* the raw Trivy JSON of the latest successful ``trivy fs`` run (CVSS, CWE, dates, references, package graph),
* read-only ``git`` metadata of the repository.

Nothing is fabricated: values that are not recorded are shown as "not recorded" with the reason.
Secret values are never present — they are not stored by the scanner in the first place.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import sqlite3
import subprocess
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from utils.config import AppConfig
from utils.security import safe_report_path
from utils.validators import SEVERITIES
from utils.version import __version__

ACTIVE = ("OPEN", "UNVERIFIED")
SUCCESS = ("COMPLETED", "COMPLETED_WITH_FINDINGS")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
NA = "not recorded"
_DESC_LIMIT = 1400
TRIVY_SEVERITY_SCALE = {0: "UNKNOWN", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}  # VendorSeverity ints
DEV_FLAG_ECOSYSTEMS =("npm", "yarn", "pnpm", "bun", "composer")  # lockfiles that record a dev flag


# ----------------------------------------------------------------------------------------- helpers
def _e(value: Any, empty: str = "—") -> str:
    if value is None or value == "" or value == []:
        return empty
    return html.escape(str(value))


def _vkey(version: str | None) -> tuple[int, ...]:
    """Numeric sort key for package versions (robust to npm/pip/semver strings)."""
    return tuple(int(x) for x in re.findall(r"\d+", version or "")[:6])


def split_fixed(fixed: str | None) -> list[str]:
    return [f.strip() for f in re.split(r"[,|]", fixed or "") if f.strip()]


def minimum_fix(installed: str | None, fixed: list[str]) -> str | None:
    """Lowest fixed version above the installed one (falls back to the lowest listed)."""
    if not fixed:
        return None
    above = [f for f in fixed if _vkey(f) > _vkey(installed)]
    return min(above or fixed, key=_vkey)


def best_cvss(cvss: dict | None, source: str | None) -> dict | None:
    """Pick the CVSS entry used for display: the severity source's v4/v3 score, else the highest v4/v3, else v2."""
    entries = []
    for src, d in (cvss or {}).items():
        if not isinstance(d, dict):
            continue
        for ver, sk, vk in (("4.0", "V40Score", "V40Vector"), ("3.x", "V3Score", "V3Vector"),
                            ("2.0", "V2Score", "V2Vector")):
            if isinstance(d.get(sk), (int, float)):
                entries.append({"source": src, "version": ver, "score": float(d[sk]), "vector": d.get(vk)})
    if not entries:
        return None
    modern = [x for x in entries if x["version"] != "2.0"]
    preferred = [x for x in modern if x["source"] == source]
    pool = preferred or modern or entries
    return max(pool, key=lambda x: x["score"])


def _safe_url(url: Any) -> str | None:
    if not isinstance(url, str):
        return None
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))  # drops any user:password@


def _link(url: Any) -> str:
    safe = _safe_url(url)
    return f"<a href='{html.escape(safe)}'>{html.escape(safe)}</a>" if safe else "—"


def _ts(value: str | None) -> str:
    if not value:
        return "—"
    text = re.sub(r"\.\d+", "", str(value)).replace("T", " ")
    text = re.sub(r"(\+00:00|Z)$", " UTC", text)
    return text[:25]


@lru_cache(maxsize=8)
def _sha256(path: str, mtime: float, size: int) -> str:  # noqa: ARG001 — mtime/size make the cache key safe
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def file_sha256(path: str | Path | None) -> str | None:
    try:
        p = Path(path) if path else None
        if not p or not p.is_file():
            return None
        st = p.stat()
        return _sha256(str(p), st.st_mtime, st.st_size)
    except OSError:
        return None


def _git(repo: Path, *args: str) -> str | None:
    """Read-only git query (same hardening as discovery: no fsmonitor, no window, no shell).

    Only plumbing that never runs repository-configured programs is used (rev-parse, log, remote get-url);
    ``git status`` is deliberately avoided because it can invoke filters defined in the repository's config."""
    from engine.scanner_health import CREATE_NO_WINDOW, resolve_executable

    git = resolve_executable("git")
    if not git:
        return None
    try:
        proc = subprocess.run([git, "-c", "core.fsmonitor=false", "-C", str(repo), *args],  # noqa: S603
                              capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace",
                              shell=False, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None


def git_metadata(repo_path: str) -> dict[str, str | None]:
    repo = Path(repo_path)
    info = {"commit": _git(repo, "rev-parse", "HEAD"), "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
            "commit_date": None, "commit_subject": None, "remote": None}
    log = _git(repo, "log", "-1", "--format=%cI%x1f%s")
    if log and "\x1f" in log:
        info["commit_date"], info["commit_subject"] = log.split("\x1f", 1)
    info["remote"] = _safe_url(_git(repo, "remote", "get-url", "origin"))
    return info


# ----------------------------------------------------------------------------------------- raw Trivy data
@dataclass
class TrivyRaw:
    path: Path | None = None
    vulns: dict[tuple[str, str, str], dict] = field(default_factory=dict)
    targets: list[dict] = field(default_factory=list)
    packages: dict[str, dict[str, dict]] = field(default_factory=dict)   # target -> pkg id -> package
    parents: dict[str, dict[str, list[str]]] = field(default_factory=dict)  # target -> child id -> parent ids
    packages_listed: bool = False
    package_targets: int = 0          # results that describe dependencies (lang-pkgs / os-pkgs)
    error: str | None = None

    @property
    def graph_missing(self) -> bool:
        """True when dependency manifests were scanned but the report carries no package list (older scan)."""
        return self.package_targets > 0 and not self.packages_listed


def load_trivy_raw(report_path: str | None, reports_dir: Path) -> TrivyRaw:
    raw = TrivyRaw()
    if not report_path:
        raw.error = "no raw report recorded for the latest Trivy filesystem scan"
        return raw
    try:
        raw.path = safe_report_path(report_path, reports_dir)
        data = json.loads(raw.path.read_text(encoding="utf-8"))
    except (PermissionError, FileNotFoundError, OSError, ValueError) as exc:
        raw.error = f"raw Trivy report unavailable ({exc.__class__.__name__})"
        return raw
    for res in data.get("Results") or []:
        if not isinstance(res, dict):
            continue
        target = str(res.get("Target") or "")
        pkgs = res.get("Packages")
        if str(res.get("Class")) in ("lang-pkgs", "os-pkgs"):
            raw.package_targets += 1
        if isinstance(pkgs, list):
            raw.packages_listed = True
            by_id = {str(p.get("ID") or f"{p.get('Name')}@{p.get('Version')}"): p for p in pkgs if isinstance(p, dict)}
            raw.packages[target] = by_id
            parents: dict[str, list[str]] = defaultdict(list)
            for pid, p in by_id.items():
                for child in p.get("DependsOn") or []:
                    parents[str(child)].append(pid)
            raw.parents[target] = parents
        vulns = res.get("Vulnerabilities") or []
        for v in vulns:
            if isinstance(v, dict):
                raw.vulns[(str(v.get("VulnerabilityID")), str(v.get("PkgName")), str(v.get("InstalledVersion")))] = \
                    {**v, "_target": target, "_type": res.get("Type"),
                     "_pkg_id": str(v.get("PkgID") or f"{v.get('PkgName')}@{v.get('InstalledVersion')}")}
        raw.targets.append({"target": target, "class": res.get("Class"), "type": res.get("Type"),
                            "packages": len(pkgs) if isinstance(pkgs, list) else None,
                            "vulnerabilities": len(vulns),
                            "misconfigurations": sum(1 for m in res.get("Misconfigurations") or []
                                                     if str(m.get("Status", "FAIL")).upper() == "FAIL"),
                            "secrets": len(res.get("Secrets") or [])})
    return raw


def dependency_path(raw: TrivyRaw, target: str, pkg_id: str | None) -> tuple[str, list[str]]:
    """(relationship, shortest path from a direct dependency) for a package inside one manifest/lockfile."""
    pkgs = raw.packages.get(target)
    if not pkgs or not pkg_id or pkg_id not in pkgs:
        return "unknown", []
    parents = raw.parents.get(target, {})
    rel = pkgs[pkg_id].get("Relationship")
    if not rel:
        # Plain requirement lists (e.g. requirements.txt) carry no graph: every listed package is declared directly.
        rel = "direct" if not parents else "unknown"
    rel = str(rel)
    if rel in ("direct", "root", "workspace"):
        return rel, [pkg_id]
    seen, queue = {pkg_id}, deque([[pkg_id]])
    while queue:
        path = queue.popleft()
        head = path[0]
        if str(pkgs.get(head, {}).get("Relationship")) in ("direct", "workspace") and len(path) > 1:
            return rel, path
        for parent in parents.get(head, []):
            if parent not in seen and len(path) < 25:
                seen.add(parent)
                queue.append([parent, *path])
    return rel, []


# ----------------------------------------------------------------------------------------- data model
def _latest_runs(conn: sqlite3.Connection, repo_id: int) -> tuple[list[dict], list[dict]]:
    attempts = [dict(r) for r in conn.execute(
        "SELECT * FROM scan_runs WHERE id IN (SELECT MAX(id) FROM scan_runs WHERE repository_id=? AND status NOT IN "
        "('PENDING','RUNNING') GROUP BY scanner, scan_type, scan_target) ORDER BY scanner, scan_type", (repo_id,))]
    ok = [dict(r) for r in conn.execute(
        f"SELECT * FROM scan_runs WHERE id IN (SELECT MAX(id) FROM scan_runs WHERE repository_id=? AND status IN "
        f"({','.join(repr(s) for s in SUCCESS)}) GROUP BY scanner, scan_type, scan_target) ORDER BY scanner, scan_type",
        (repo_id,))]
    return attempts, ok


def _tool_info(cfg: AppConfig) -> dict[str, dict]:
    from engine.scanner_health import check_bandit, check_gitleaks, check_trivy

    out = {}
    for name, tool in (("trivy", check_trivy(cfg.trivy.executable)), ("gitleaks", check_gitleaks(cfg.gitleaks.executable))):
        out[name] = {"tool": tool, "path": tool.path, "version": tool.version, "sha256": file_sha256(tool.path)}
    bandit = check_bandit()  # a Python package run with the scanner's interpreter: no separate binary to hash
    out["bandit"] = {"tool": bandit, "path": "python -m bandit" if bandit.installed else None,
                     "version": bandit.version, "sha256": None}
    if cfg.dast.enabled:
        from engine.scanner_health import check_dast

        dast = check_dast()
        out["dast"] = {"tool": dast, "path": "built-in", "version": dast.version, "sha256": None}
    if cfg.sast.enabled and cfg.sast.other_languages:
        from engine.scanner_health import check_codescan

        cs = check_codescan()
        out["codescan"] = {"tool": cs, "path": "built-in", "version": cs.version, "sha256": None}
    return out


def _commands(cfg: AppConfig, tools: dict[str, dict]) -> list[tuple[str, str]]:
    from engine.gitleaks_scanner import GitleaksScanner
    from engine.trivy_scanner import TrivyOptions, TrivyScanner

    cmds: list[tuple[str, str]] = []

    def show(argv: list[str], exe: str) -> str:
        argv = [exe, *argv[1:]]
        if cfg.trivy.cache_dir:
            argv = ["<cache-dir>" if a == cfg.trivy.cache_dir else a for a in argv]
        return " ".join(f'"{a}"' if " " in a else a for a in argv)

    if cfg.trivy.enabled and tools["trivy"]["tool"].installed:
        opts = TrivyOptions.from_config(cfg)
        for name in cfg.scan.skip_dirs:
            opts.skip_dirs += [name, f"**/{name}"]
        argv = TrivyScanner(tools["trivy"]["tool"]).build_fs_command(Path("<repo-root>"), Path("<report.json>"), opts)
        cmds.append(("Trivy filesystem", show(argv, "trivy")))
    if cfg.gitleaks.enabled and tools["gitleaks"]["tool"].installed:
        for mode in cfg.gitleaks.modes:
            argv = GitleaksScanner(tools["gitleaks"]["tool"]).build_command(
                mode, Path("<repo-root>"), Path("<report.json>"), "<gitleaks.toml>" if cfg.gitleaks.config_path else None,
                cfg.gitleaks.log_opts, cfg.gitleaks.max_target_megabytes)
            cmds.append((f"Gitleaks {mode}", show(argv, "gitleaks")))
    if cfg.sast.enabled and tools.get("bandit", {}).get("tool") and tools["bandit"]["tool"].installed:
        from engine.sast_scanner import BanditScanner, exclude_patterns

        argv = BanditScanner(tools["bandit"]["tool"], cfg.data_dir / "tmp").build_command(
            Path("<report.json>"), exclude_patterns(cfg.scan.skip_dirs, []), cfg.sast.skip_tests)
        argv = ["<generated bandit.ini>" if a.endswith("bandit.ini") else a for a in argv]
        cmds.append(("Bandit code scan (run inside <repo-root>)", show(argv, "python")))
    if cfg.trivy.enabled and cfg.trivy.installed_versions:
        cmds.append(("Trivy, installed versions", "for each .venv / venv / node_modules (without a lockfile): exact "
                     "versions read from package metadata into a temporary requirements.txt / package-lock.json, then "
                     "trivy fs --scanners vuln on that file (packages already pinned in requirements.txt skipped)"))
    if cfg.sast.enabled and cfg.sast.other_languages:
        cmds.append(("Code scan, other languages (built in)", "pattern rules for JavaScript/TypeScript, HTML templates, "
                     "PHP, Java, Go and C#, read as text inside <repo-root> (skip folders as for Bandit)"))
    if cfg.dast.enabled and cfg.dast.targets:
        logins = sum(1 for t in cfg.dast.targets if t.login)
        cmds.append(("Web scan (DAST, built in)", f"GET-only crawl of each configured local address · max "
                     f"{cfg.dast.max_pages} pages, {cfg.dast.max_requests} requests, {cfg.dast.request_timeout}s per "
                     "response" + (f" · {logins} address(es) sign in first with a test account (one POST to the "
                                   "login form; password from an environment variable)" if logins else "")))
    return cmds


def build_audit(conn: sqlite3.Connection, cfg: AppConfig, repository_id: int,
                tools: dict[str, dict] | None = None, git: dict | None = None) -> dict[str, Any]:
    repo_row = conn.execute("SELECT * FROM repositories WHERE id=?", (repository_id,)).fetchone()
    if not repo_row:
        raise LookupError(f"Repository id {repository_id} not found")
    repo = dict(repo_row)
    attempts, ok_runs = _latest_runs(conn, repository_id)
    tools = tools if tools is not None else _tool_info(cfg)
    git = git if git is not None else git_metadata(repo["path"])

    trivy_fs = next((r for r in ok_runs if r["scanner"] == "trivy" and r["scan_type"] == "fs"), None)
    raw = load_trivy_raw(trivy_fs["report_path"] if trivy_fs else None, cfg.reports_dir)

    rows = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE repository_id=? ORDER BY id", (repository_id,))]
    for r in rows:
        try:
            r["meta"] = json.loads(r.get("metadata_json") or "{}")
        except ValueError:
            r["meta"] = {}
    from services.triage_service import decisions as triage_decisions

    decided = triage_decisions(conn, repository_id)
    decided_ids = {x["id"] for x in decided}
    active = [r for r in rows if r["status"] in ACTIVE and r["id"] not in decided_ids]
    resolved = [r for r in rows if r["status"] == "RESOLVED"]

    vulns = [_enrich_vuln(r, raw) for r in active if r["category"] == "VULNERABILITY"]
    vulns.sort(key=lambda v: (SEV_RANK.get(v["severity"], 9), -(v["cvss"]["score"] if v["cvss"] else -1),
                              v["package_name"] or "", v["vulnerability_id"] or ""))
    secrets = sorted((r for r in active if r["category"] == "SECRET"),
                     key=lambda r: (SEV_RANK.get(r["severity"], 9), r["file_path"] or "", r["line"] or 0))
    misconfs = sorted(_merge_misconfigs([r for r in active if r["category"] == "MISCONFIGURATION"]),
                      key=lambda r: (SEV_RANK.get(r["severity"], 9), r["file_path"] or "", r["line"] or 0))
    code = sorted((r for r in active if r["category"] == "CODE"),
                  key=lambda r: (SEV_RANK.get(r["severity"], 9), r["file_path"] or "", r["line"] or 0))
    web = sorted((r for r in active if r["category"] == "WEB"),
                 key=lambda r: (SEV_RANK.get(r["severity"], 9), r["scan_target"] or "", r["file_path"] or ""))
    others = [r for r in active if r["category"] not in ("VULNERABILITY", "SECRET", "MISCONFIGURATION", "CODE",
                                                         "WEB")]
    # One entry per real issue: the same configuration check reported by both 'trivy fs' and 'trivy config'
    # is counted once.
    active = [*vulns, *secrets, *misconfs, *code, *web, *others]

    return {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "app_version": __version__, "repo": repo, "git": git, "tools": tools, "commands": _commands(cfg, tools),
        "attempts": attempts, "ok_runs": ok_runs, "trivy_fs": trivy_fs, "raw": raw,
        "active": active, "resolved": resolved, "vulns": vulns, "packages": _package_groups(vulns),
        "secrets": secrets, "misconfs": misconfs, "code": code, "web": web, "others": others, "offline": cfg.scan.offline,
        "decisions": decided,
        "skip_dirs": list(cfg.scan.skip_dirs), "reports_dir": cfg.reports_dir,
    }


def _merge_misconfigs(rows: list[dict]) -> list[dict]:
    """Collapse the same check on the same file/line/resource reported by several Trivy scan types."""
    merged: dict[tuple, dict] = {}
    for r in rows:
        key = (r["rule_id"], r["file_path"], r["line"], r["meta"].get("resource"))
        if key in merged:
            m = merged[key]
            m["scan_types"].add(r["scan_type"])
            if r["status"] == "OPEN":
                m["status"] = "OPEN"
            m["first_seen"] = min(m["first_seen"], r["first_seen"])
        else:
            merged[key] = {**r, "scan_types": {r["scan_type"]}}
    return list(merged.values())


def _enrich_vuln(r: dict, raw: TrivyRaw) -> dict:
    v = dict(r)
    detail = raw.vulns.get((str(r["vulnerability_id"]), str(r["package_name"]), str(r["installed_version"])))
    v["in_latest_report"] = detail is not None
    detail = detail or {}
    target = detail.get("_target") or r["meta"].get("target") or r["file_path"] or ""
    pkg_id = detail.get("_pkg_id") or r["meta"].get("pkg_id") or f"{r['package_name']}@{r['installed_version']}"
    v["target"], v["ecosystem"] = target, detail.get("_type")
    v["cvss"] = best_cvss(detail.get("CVSS"), detail.get("SeveritySource"))
    v["cvss_all"] = [
        f"{src.upper()} {ver}: {d.get(vk)} ({d.get(sk)})"
        for src, d in (detail.get("CVSS") or {}).items() if isinstance(d, dict)
        for ver, sk, vk in (("v4.0", "V40Score", "V40Vector"), ("v3", "V3Score", "V3Vector"), ("v2", "V2Score", "V2Vector"))
        if d.get(vk)]
    v["severity_source"] = detail.get("SeveritySource")
    v["vendor_severity"] = {k: TRIVY_SEVERITY_SCALE.get(n, str(n))
                            for k, n in (detail.get("VendorSeverity") or {}).items()} if detail else {}
    v["cwe"] = detail.get("CweIDs") or []
    v["aliases"] = detail.get("VendorIDs") or []
    v["published"], v["modified"] = detail.get("PublishedDate"), detail.get("LastModifiedDate")
    v["references"] = [u for u in (_safe_url(x) for x in [detail.get("PrimaryURL"), *(detail.get("References") or [])]) if u]
    v["fix_status"] = detail.get("Status")
    v["fixed_list"] = split_fixed(r["fixed_version"])
    v["min_fix"] = minimum_fix(r["installed_version"], v["fixed_list"])
    pkg = raw.packages.get(target, {}).get(pkg_id or "", {})
    v["relation"], v["path"] = dependency_path(raw, target, pkg_id)
    eco = str(detail.get("_type") or "").lower()
    if pkg.get("Dev"):
        v["scope"] = "dev"
    elif pkg and eco in DEV_FLAG_ECOSYSTEMS:
        v["scope"] = "runtime"
    else:
        v["scope"] = "unknown"
    v["description"] = r["description"]
    return v


def _package_groups(vulns: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for v in vulns:
        key = (v["package_name"], v["installed_version"], v["target"])
        g = groups.setdefault(key, {"package": v["package_name"], "installed": v["installed_version"],
                                    "target": v["target"], "ecosystem": v["ecosystem"], "relation": v["relation"],
                                    "scope": v["scope"], "path": v["path"], "findings": [], "no_fix": 0})
        g["findings"].append(v)
        if not v["min_fix"]:
            g["no_fix"] += 1
    out = []
    for g in groups.values():
        f = g["findings"]
        g["worst"] = min((x["severity"] for x in f), key=lambda s: SEV_RANK.get(s, 9))
        scores = [x["cvss"]["score"] for x in f if x["cvss"]]
        g["max_cvss"] = max(scores) if scores else None
        fixes = [x["min_fix"] for x in f if x["min_fix"]]
        g["upgrade_to"] = max(fixes, key=_vkey) if fixes else None
        out.append(g)
    out.sort(key=lambda g: (SEV_RANK.get(g["worst"], 9), -(g["max_cvss"] or -1), -len(g["findings"]), g["package"] or ""))
    return out


# ----------------------------------------------------------------------------------------- narrative
def _found_in(r: dict) -> str:
    return "Git history" if r["scan_type"] == "git" else "Working tree"


def scan_status(d: dict) -> tuple[str, str]:
    failed = [a for a in d["attempts"] if a["status"] not in SUCCESS and a["status"] != "SKIPPED"]
    if not d["ok_runs"]:
        return "NO SCAN DATA", "No scanner has completed successfully for this repository; nothing can be concluded."
    if failed:
        names = ", ".join(f"{a['scanner']} {a['scan_type']} ({a['status'].lower()})" for a in failed)
        return "INCOMPLETE", f"The latest attempt of {names} did not succeed; results below come from earlier successful runs."
    if d["active"]:
        return "COMPLETED", f"{len(d['active'])} active finding(s)"
    return "COMPLETED", "no active findings"


def executive_summary(d: dict) -> list[str]:
    vulns, pk, secrets, mis = d["vulns"], d["packages"], d["secrets"], d["misconfs"]
    sev = Counter(r["severity"] for r in d["active"])
    paras: list[str] = []
    if not d["ok_runs"]:
        return ["No successful scan is recorded for this repository, so its security posture is unknown. "
                "Run a scan from the Repositories page and generate this report again."]
    sev_txt = ", ".join(f"{sev.get(s, 0)} {s.title()}" for s in SEVERITIES)
    advisories = len({v["vulnerability_id"] for v in vulns})
    paras.append(
        f"The scanners report <b>{len(d['active'])}</b> active finding(s) for <b>{_e(d['repo']['name'])}</b>: "
        f"{len(vulns)} dependency vulnerabilit{'y' if len(vulns) == 1 else 'ies'} in {len(pk)} package/version "
        f"combination(s) ({advisories} distinct advisories), {len(secrets)} potential secret(s), "
        f"{len(d.get('code', []))} code issue(s), {len(d.get('web', []))} web app issue(s) and {len(mis)} "
        f"misconfiguration(s). By severity: {sev_txt}."
        + (f" {len(d['resolved'])} earlier finding(s) have been confirmed resolved by later scans." if d["resolved"] else ""))
    crit = [v for v in vulns if v["severity"] == "CRITICAL"][:3]
    if crit:
        bits = []
        for v in crit:
            via = (" via " + " &gt; ".join(_e(p) for p in v["path"])) if len(v["path"]) > 1 else ""
            score = f"CVSS {v['cvss']['score']:.1f}, " if v["cvss"] else ""
            fix = f"fixed in {_e(v['min_fix'])}" if v["min_fix"] else "no fix published yet"
            bits.append(f"{_e(v['package_name'])} {_e(v['installed_version'])} ({score}{_e(v['title'])}){via} — {fix}")
        paras.append(f"<b>Critical finding(s) ({len([v for v in vulns if v['severity'] == 'CRITICAL'])}):</b> "
                     + "; ".join(bits) + ".")
    if pk:
        top = max(pk, key=lambda g: len(g["findings"]))
        share = 100 * len(top["findings"]) / max(1, len(vulns))
        line = (f"<b>Largest source of risk:</b> {_e(top['package'])} {_e(top['installed'])} "
                f"({_e(top['relation'])} dependency) accounts for {len(top['findings'])} of {len(vulns)} "
                f"vulnerability finding(s) ({share:.0f}%), worst {top['worst'].title()}")
        if top["upgrade_to"] and not top["no_fix"]:
            line += f". Upgrading to {_e(top['upgrade_to'])} or later is calculated to clear all of them"
        paras.append(line + ". A rescan after upgrading confirms the result.")
        with_fix = sum(1 for v in vulns if v["min_fix"])
        direct = sum(1 for g in pk if g["relation"] in ("direct", "root", "workspace"))
        known = sum(1 for g in pk if g["relation"] != "unknown")
        paras.append(f"{with_fix} of {len(vulns)} vulnerability finding(s) have a published fixed version. "
                     + (f"{direct} of {len(pk)} affected package/version combination(s) are direct dependencies "
                        f"and {known - direct} are transitive" + (f"; {len(pk) - known} could not be classified" if known < len(pk) else "")
                        + "." if known else "Direct/transitive status is not recorded for these packages."))
    if secrets:
        wt = sum(1 for s in secrets if _found_in(s) == "Working tree")
        unv = sum(1 for s in secrets if s["status"] == "UNVERIFIED")
        paras.append(f"<b>Secrets:</b> {len(secrets)} potential credential(s) — {wt} in the current files, "
                     f"{len(secrets) - wt} only in Git history. Secret values are never stored or shown; treat each "
                     "as exposed until it is revoked and rotated."
                     + (f" {unv} of them are UNVERIFIED (a later scan did not cover them), so they are kept for review "
                        "rather than assumed fixed." if unv else ""))
    if mis:
        paras.append(f"<b>Misconfigurations:</b> {len(mis)} infrastructure / container setting(s) fail a Trivy check; "
                     "see section 10 for the exact resource and recommended setting.")
    code = d.get("code", [])
    if code:
        top = Counter(r["rule_id"] for r in code).most_common(3)
        paras.append(f"<b>Code issues (SAST):</b> {len(code)} risky pattern(s) in the project's own Python code, "
                     "found by Bandit without running the code. Most frequent checks: "
                     + ", ".join(f"{_e(k)} ({n})" for k, n in top) + ". See section 11 for each file, line and fix.")
    web = d.get("web", [])
    if web:
        worst = Counter(r["severity"] for r in web)
        paras.append(f"<b>Web app issues (DAST):</b> {len(web)} problem(s) found by testing the running application "
                     f"through its web address ({', '.join(f'{worst[s]} {s.title()}' for s in SEVERITIES if worst[s])})."
                     " See section 12 for each page and fix.")
    if not d["active"]:
        paras.append("No active vulnerabilities, secrets, code issues, web app issues or misconfigurations were "
                     "reported by the latest successful scans. This is a clean result for the scanned scope, not missing "
                     "data (see section 1 and the limitations in section 14).")
    return paras


# ----------------------------------------------------------------------------------------- HTML
_CSS = """
@page { size: A4; margin: 16mm 13mm 18mm;
  @bottom-left { content: "__FOOTER__"; font: 8pt 'Segoe UI', Arial, sans-serif; color: #6b7280; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt 'Segoe UI', Arial, sans-serif; color: #6b7280; } }
* { box-sizing: border-box; }
body { font: 10pt/1.45 'Segoe UI', Arial, sans-serif; color: #111827; margin: 0 auto; max-width: 1000px; padding: 24px; }
h1 { font-size: 21pt; margin: 0 0 2px; } h2 { font-size: 13.5pt; margin: 26px 0 8px; padding-bottom: 4px;
  border-bottom: 2px solid #1f2937; break-after: avoid; } h3 { font-size: 11pt; margin: 14px 0 6px; break-after: avoid; }
.sub { color: #4b5563; margin-bottom: 10px; } .status { display: inline-block; padding: 5px 10px; border-radius: 4px;
  font-weight: 700; letter-spacing: .03em; margin: 6px 0 4px; }
.st-COMPLETED { background: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0; }
.st-INCOMPLETE, .st-NO { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 12px; font-size: 8.8pt; break-inside: auto; }
th, td { border: 1px solid #d1d5db; padding: 4px 6px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { background: #f3f4f6; font-weight: 600; } tr { break-inside: avoid; }
table.kv th { width: 27%; } .num { text-align: right; white-space: nowrap; }
.sev { font-weight: 700; white-space: nowrap; } .CRITICAL { color: #b91c1c; } .HIGH { color: #c2410c; }
.MEDIUM { color: #a16207; } .LOW { color: #1d4ed8; } .UNKNOWN { color: #6b7280; }
.finding { border: 1px solid #d1d5db; border-left: 4px solid #9ca3af; padding: 6px 10px 2px; margin: 10px 0;
  break-inside: avoid; } .finding.CRITICAL { border-left-color: #b91c1c; } .finding.HIGH { border-left-color: #c2410c; }
.finding.MEDIUM { border-left-color: #ca8a04; } .finding.LOW { border-left-color: #1d4ed8; }
.finding h3 { margin: 2px 0 6px; } .finding table { margin: 4px 0 6px; }
code, .mono { font-family: Consolas, 'Courier New', monospace; font-size: 8.5pt; overflow-wrap: anywhere; } .muted { color: #6b7280; }
.note { background: #f9fafb; border: 1px solid #e5e7eb; padding: 6px 10px; font-size: 9pt; }
ol li, ul li { margin: 3px 0; } a { color: #1d4ed8; text-decoration: none; }
.toc { columns: 2; font-size: 9.5pt; } .page-break { break-before: page; }
@media print { body { padding: 0; max-width: none; } a { color: #111827; } }
"""


def _sev(s: str) -> str:
    return f"<span class='sev {html.escape(s)}'>{html.escape(s)}</span>"


def _kv(rows: list[tuple[str, Any]]) -> str:
    return "<table class='kv'>" + "".join(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"


def _table(headers: list[str], rows: list[list[str]], num: set[int] | None = None) -> str:
    num = num or set()
    head = "".join(f"<th{' class=num' if i in num else ''}>{_e(h)}</th>" for i, h in enumerate(headers))
    body = "".join("<tr>" + "".join(f"<td{' class=num' if i in num else ''}>{c}</td>" for i, c in enumerate(r)) + "</tr>"
                   for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _clip(text: str | None) -> str:
    if not text:
        return "—"
    t = " ".join(str(text).split())
    return _e(t[:_DESC_LIMIT]) + (" … <span class='muted'>[truncated; full text in the raw report and the advisory]</span>"
                                  if len(t) > _DESC_LIMIT else "")


def render_audit_html(d: dict) -> str:
    repo, git, raw = d["repo"], d["git"], d["raw"]
    status, status_note = scan_status(d)
    gen = _ts(d["generated_at"])
    commit = git.get("commit") or repo.get("current_commit")
    footer = re.sub(r"[\"\\\n<>]", "", f"Security Audit · {repo['name']} · commit {(commit or 'n/a')[:12]} · {gen[:10]}")
    s: list[str] = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
                    f"<title>Security Audit — {_e(repo['name'])}</title>"
                    f"<style>{_CSS.replace('__FOOTER__', footer + ' · Confidential')}</style></head><body>"]
    tv = d["tools"]["trivy"]["version"] or "?"
    gv = d["tools"]["gitleaks"]["version"] or "?"
    bv = d["tools"].get("bandit", {}).get("version") or "?"
    s.append(f"<h1>Security Audit Report</h1><div class='sub'>{_e(repo['name'])} — Trivy {_e(tv)} · Gitleaks {_e(gv)} · "
             f"Bandit {_e(bv)} · "
             f"Local Security Scanner {_e(d['app_version'])}</div>"
             f"<div class='status st-{status.split()[0]}'>SCAN STATUS: {_e(status)} — {_e(status_note)}</div>"
             f"<div class='muted'>Generated {gen} · Confidential — generated locally from scanner output; "
             f"secret values are never included.</div>")
    sections = ["Repository details and scan metadata", "Executive summary", "Findings and deduplicated counts",
                "Severity distribution and affected packages", "Detailed vulnerability findings",
                "Advisory IDs and CVSS scores", "Direct versus transitive classification",
                "Fixed versions and remediation guidance", "Secrets", "Misconfigurations",
                "Code issues (static analysis)", "Web app issues (dynamic testing)",
                "Authoritative advisory references",
                "Methodology, scan limitations and raw results"]
    s.append("<h2>Contents</h2><ol class='toc'>" + "".join(f"<li><a href='#s{i}'>{t}</a></li>"
                                                         for i, t in enumerate(sections, 1)) + "</ol>")

    def h2(i: int) -> str:
        return f"<h2 id='s{i}'>{i}. {sections[i - 1]}</h2>"

    # 1 -------------------------------------------------------------- metadata
    run_rows = []
    for a in d["attempts"]:
        run_rows.append([f"#{a['id']}", _e(f"{a['scanner']} {a['scan_type']}"), _e(a["status"]), _ts(a["started_at"]),
                         _e(f"{a['duration']:.1f}s" if a["duration"] is not None else None), _e(a["exit_code"]),
                         _e(a["tool_version"]), "yes" if a["offline"] else "no",
                         _e(a["findings_count"]), _e(a["error_message"])])
    tf = d["trivy_fs"]
    pk_count = (sum(t["packages"] or 0 for t in raw.targets) if raw.packages_listed
                else ("none recorded — either no dependency manifest was found, or the scan predates package "
                      "listing (older scans only list manifests that had findings); rescan to be sure")
                if d["trivy_fs"] and not raw.package_targets and not raw.error
                else None)
    meta = [
        ("Repository", _e(repo["name"])), ("Local path", f"<span class='mono'>{_e(repo['path'])}</span>"),
        ("Remote (origin)", _link(git.get("remote")) if git.get("remote") else NA),
        ("Branch", _e(git.get("branch") or repo.get("current_branch"), NA)),
        ("Scanned commit SHA", f"<span class='mono'>{_e(commit, NA)}</span>"),
        ("Commit date / message", _e(" - ".join(x for x in (git.get("commit_date"), git.get("commit_subject") and
                                                             f'"{git["commit_subject"]}"') if x), NA)),
        ("Report generated (UTC)", gen),
        ("Latest successful scans", _e(", ".join(f"{r['scanner']} {r['scan_type']} #{r['id']} at {_ts(r['finished_at'])}"
                                                 for r in d["ok_runs"]), "none")),
    ]
    if d["tools"].get("bandit"):
        meta.append(("Bandit version", _e(d["tools"]["bandit"]["version"], "not installed")
                     + " <span class='muted'>(Python package in the scanner's environment)</span>"))
    for name in ("trivy", "gitleaks"):
        t = d["tools"][name]
        meta.append((f"{name.title()} version / binary",
                     f"{_e(t['version'], 'not installed')} · <span class='mono'>{_e(t['path'], '')}</span>"))
        meta.append((f"{name.title()} binary SHA-256",
                     f"<span class='mono'>{_e(t['sha256'], NA)}</span> <span class='muted'>(computed locally; not compared "
                     f"with the vendor's published checksums)</span>"))
    for label, cmd in d["commands"]:
        meta.append((f"Command — {label}", f"<code>{_e(cmd)}</code>"))
    meta += [
        ("Vulnerability database", _e(f"Trivy DB, updated {_ts(tf['database_updated_at'])}" if tf and tf.get("database_updated_at")
                                      else "Trivy DB (update time not recorded)") + (" · offline scan (cached DB only)"
                                                                                      if tf and tf.get("offline") else "")),
        ("Files analysed by Trivy", _e(", ".join(f"{t['target']} ({t['type'] or t['class']})" for t in raw.targets),
                                       raw.error or "none")),
        ("Packages extracted", _e(pk_count, "not recorded — the scan predates package listing; rescan to include it")),
        ("Folders skipped while scanning", _e(", ".join(d["skip_dirs"]))),
    ]
    s.append(h2(1) + _kv(meta) + "<h3>Latest attempt of each scanner</h3>"
             + _table(["Run", "Scanner", "Status", "Started", "Duration", "Exit", "Version", "Offline", "Findings", "Error"],
                      run_rows, {4, 5, 8}))

    # 2 -------------------------------------------------------------- executive summary
    s.append(h2(2) + "".join(f"<p>{p}</p>" for p in executive_summary(d)))

    # 3 -------------------------------------------------------------- counts
    vulns, pk = d["vulns"], d["packages"]
    distinct_pk = sorted({g["package"] for g in pk if g["package"]})
    adv = {v["vulnerability_id"] for v in vulns}
    multi = [a for a, c in Counter(v["vulnerability_id"] for v in vulns).items() if c > 1]
    direct = sum(1 for g in pk if g["relation"] in ("direct", "root", "workspace"))
    unknown_rel = sum(1 for g in pk if g["relation"] == "unknown")
    dev = sum(1 for g in pk if g["scope"] == "dev")
    unk_scope = sum(1 for g in pk if g["scope"] == "unknown")
    by_status = Counter(r["status"] for r in d["active"])
    s.append(h2(3) + _table(["Metric", "Count", "Notes"], [
        ["Active findings (all categories)", str(len(d["active"])),
         f"OPEN {by_status.get('OPEN', 0)} · UNVERIFIED {by_status.get('UNVERIFIED', 0)}. Resolved (not counted): {len(d['resolved'])}."],
        ["Vulnerability findings", str(len(vulns)), "One per advisory per affected package/version, as reported by Trivy."],
        ["Affected package/version combinations", str(len(pk)), "Deduplicated by (package, version, manifest)."],
        ["Distinct packages", str(len(distinct_pk)), _e(", ".join(distinct_pk))],
        ["Distinct advisories", str(len(adv)), (f"{len(multi)} advisory(ies) match more than one package/version: "
                                               f"{_e(', '.join(multi))}." if multi else "Each advisory matches one package/version.")],
        ["Direct / transitive (package/version)", f"{direct} / {len(pk) - direct - unknown_rel}",
         f"Not classified: {unknown_rel}. From the package graph Trivy recorded; see section 7."],
        ["Runtime / dev-only (package/version)", f"{len(pk) - dev - unk_scope} / {dev}",
         f"Unknown: {unk_scope}. Taken from the lockfile 'dev' flag where the ecosystem records it."],
        ["Vulnerability findings with a published fix", f"{sum(1 for v in vulns if v['min_fix'])} / {len(vulns)}", ""],
        ["Potential secrets", str(len(d["secrets"])),
         f"Working tree {sum(1 for x in d['secrets'] if _found_in(x) == 'Working tree')} · Git history "
         f"{sum(1 for x in d['secrets'] if _found_in(x) == 'Git history')}. Values never stored."],
        ["Misconfigurations", str(len(d["misconfs"])), "Failed Trivy configuration checks."],
        ["Code issues (SAST)", str(len(d.get("code", []))), "Risky patterns in the project's own Python code (Bandit)."],
        ["Web app issues (DAST)", str(len(d.get("web", []))), "Found by testing the running app through its address."],
        ["Decided findings (not counted above)", str(len(d.get("decisions", []))),
         "Marked by a person as false positive, accepted risk or archived; listed below with the reason."],
    ], {1}))
    if d.get("decisions"):
        from services.triage_service import DECISIONS

        s.append("<h3>Decisions recorded (false positives, accepted risks, archived)</h3><p>These are still reported "
                 "by the scanners but were reviewed by a person. They are excluded from every count in this report. "
                 "Accepted risks return automatically on their review date.</p>")
        s.append(_table(["Decision", "Severity", "Finding", "Location", "Reason", "Review on", "Decided"],
                        [[_e(DECISIONS.get(x["decision"], x["decision"])), _sev(x["severity"]),
                          _e(x["vulnerability_id"] or x["rule_id"] or x["title"]),
                          f"<span class='mono'>{_e(x['file_path'])}{':' + str(x['line']) if x['line'] else ''}</span>",
                          _e(x["reason"]), _e(x["review_by"]), _e(_ts(x["decided_at"]))]
                         for x in d["decisions"][:200]]))

    # 4 -------------------------------------------------------------- severity distribution
    rows4 = []
    total = max(1, len(d["active"]))
    for sv in SEVERITIES:
        cat = Counter(r["category"] for r in d["active"] if r["severity"] == sv)
        n = sum(cat.values())
        rows4.append([_sev(sv), str(cat.get("VULNERABILITY", 0)), str(len({v["vulnerability_id"] for v in vulns if v["severity"] == sv})),
                      str(cat.get("SECRET", 0)), str(cat.get("MISCONFIGURATION", 0)), str(cat.get("CODE", 0)),
                      str(cat.get("WEB", 0)), str(n),
                      f"{100 * n / total:.1f}%"])
    rows4.append(["<b>Total</b>", str(len(vulns)), str(len(adv)), str(len(d["secrets"])), str(len(d["misconfs"])),
                  str(len(d.get("code", []))), str(len(d.get("web", []))), str(len(d["active"])),
                  "100%" if d["active"] else "—"])
    s.append(h2(4) + "<p>Severity labels are the ones Trivy assigns (from its vendor severity source, shown per finding in "
             "section 5). CVSS scores are listed alongside; the two can differ.</p>"
             + _table(["Severity", "Vulnerabilities", "Distinct advisories", "Secrets", "Misconfigurations", "Code",
                       "Web", "All", "Share"], rows4, {1, 2, 3, 4, 5, 6, 7, 8}))
    if pk:
        s.append("<h3>Affected packages at a glance</h3>" + _table(
            ["Package", "Installed", "Manifest", "Scope", "Relation", "Findings", "Highest", "Upgrade to (clears all listed)"],
            [[_e(g["package"]), _e(g["installed"]), f"<span class='mono'>{_e(g['target'])}</span>", _e(g["scope"]),
              _e(g["relation"]), str(len(g["findings"])),
              _sev(g["worst"]) + (f" {g['max_cvss']:.1f}" if g["max_cvss"] is not None else ""),
              _e(g["upgrade_to"], "no fix published") + (f" <span class='muted'>({g['no_fix']} without a fix)</span>"
                                                          if g["no_fix"] and g["upgrade_to"] else "")]
             for g in pk], {5})
            + "<p class='muted'>'Upgrade to' is the highest of the lowest fixed versions above the installed version across "
              "the package's advisories. It is calculated from the advisory data, not verified by installing it.</p>")

    # 5 -------------------------------------------------------------- detailed vulnerabilities
    s.append(h2(5))
    if not vulns:
        s.append("<p>No active dependency vulnerabilities.</p>")
    else:
        s.append(f"<p>All {len(vulns)} active vulnerability findings, sorted by severity and then CVSS score. Each block is "
                 "one advisory against one installed package/version.</p>")
    for i, v in enumerate(vulns, 1):
        c = v["cvss"]
        cvss_txt = (f"Score {c['score']:.1f} (CVSS {c['version']}, source {html.escape(c['source'])})"
                    + (f"<br><span class='mono'>{_e(c['vector'])}</span>" if c.get("vector") else "")) if c else NA
        if v["cvss_all"] and len(v["cvss_all"]) > 1:
            cvss_txt += "<br><span class='muted'>All vectors: " + "; ".join(_e(x) for x in v["cvss_all"]) + "</span>"
        vendor = ", ".join(f"{k}: {val}" for k, val in v["vendor_severity"].items())
        path = (f"<span class='mono'>{_e(v['target'])} &gt; " + " &gt; ".join(_e(p) for p in v["path"]) + "</span>"
                if v["path"] else ("not recorded — rescan to include the package graph" if d["raw"].graph_missing
                                   else "no path recorded by Trivy for this package"))
        score = f" {c['score']:.1f}" if c else ""
        s.append(f"<div class='finding {html.escape(v['severity'])}'><h3>#{i} {_e(v['vulnerability_id'])} | "
                 f"{_e(v['package_name'])}@{_e(v['installed_version'])} | {_sev(v['severity'])}{score}</h3>" + _kv([
                     ("Summary", _e(v["title"])),
                     ("Package / ecosystem", f"{_e(v['package_name'])} ({_e(v['ecosystem'], 'ecosystem not recorded')}), "
                                             f"installed {_e(v['installed_version'])}"),
                     ("Advisory IDs", _e(", ".join([v["vulnerability_id"], *v["aliases"]]))),
                     ("CVSS", cvss_txt),
                     ("Severity source", _e(f"Trivy label from '{v['severity_source']}'" if v["severity_source"] else None, NA)
                      + (f" · vendor ratings: {_e(vendor)}" if vendor else "")),
                     ("CWE", _e(", ".join(v["cwe"]), NA)),
                     ("Fixed versions", (_e(", ".join(v["fixed_list"])) + f" — minimum fix for installed version: "
                                         f"{_e(v['min_fix'])}") if v["fixed_list"] else "No fixed version published"),
                     ("Scope / relation", f"{_e(v['scope'])}; {_e(v['relation'])}"),
                     ("Dependency path", path),
                     ("Location", f"<span class='mono'>{_e(v['target'])}</span>"
                                  + (f" → <span class='mono'>{_e(v['file_path'])}</span>"
                                     if v["file_path"] and v["file_path"] != v["target"] else "")),
                     ("Status", f"{_e(v['status'])} · first seen {_ts(v['first_seen'])} · last seen {_ts(v['last_seen'])}"
                                + ("" if v["in_latest_report"] else
                                   " · <span class='muted'>not in the latest raw report (details limited to the database)</span>")),
                     ("Description", _clip(v["description"])),
                     ("Published / modified", f"{_ts(v['published'])[:10]} / {_ts(v['modified'])[:10]}"
                      if v["published"] or v["modified"] else NA),
                 ]) + "</div>")

    # 6 -------------------------------------------------------------- advisories
    advis: dict[str, dict] = {}
    for v in vulns:
        a = advis.setdefault(v["vulnerability_id"], {"v": v, "affects": []})
        a["affects"].append(f"{v['package_name']}@{v['installed_version']}")
    s.append(h2(6) + ("<p>No advisories.</p>" if not advis else
             "<p>One row per distinct advisory. 'Affects' lists every installed package/version it matched.</p>" + _table(
        ["Advisory", "Aliases", "CVSS", "Version", "Severity", "Vendor ratings", "CWE", "Affects"],
        [[_e(k), _e(", ".join(a["v"]["aliases"])), _e(f"{a['v']['cvss']['score']:.1f}" if a["v"]["cvss"] else None),
          _e(a["v"]["cvss"]["version"] if a["v"]["cvss"] else None), _sev(a["v"]["severity"]),
          _e(", ".join(f"{x}: {y}" for x, y in a["v"]["vendor_severity"].items())), _e(", ".join(a["v"]["cwe"])),
          _e(", ".join(sorted(set(a["affects"]))))] for k, a in advis.items()], {2})))

    # 7 -------------------------------------------------------------- direct / transitive
    s.append(h2(7) + "<p>Relationship and dependency paths come from the package graph Trivy records from the lockfile "
             "(<code>--list-all-pkgs</code>). Only the shortest path from a direct dependency is shown; other paths may "
             "exist. Packages were not installed, so paths are inferred from the lockfile and not checked with the package "
             "manager. Plain requirement files (for example <code>requirements.txt</code>) carry no graph, so their "
             "packages are listed as direct.</p>")
    if pk:
        s.append(_table(["Package@version", "Relation", "Scope", "Shortest path"],
                        [[_e(f"{g['package']}@{g['installed']}"), _e(g["relation"]), _e(g["scope"]),
                          (f"<span class='mono'>{_e(g['target'])} &gt; " + " &gt; ".join(_e(p) for p in g["path"]) + "</span>")
                          if g["path"] else NA] for g in pk]))
    else:
        s.append("<p>No affected packages.</p>")

    # 8 -------------------------------------------------------------- remediation
    s.append(h2(8))
    if pk:
        rows8 = []
        for g in pk:
            rows8.append([_e(g["package"]), _e(g["installed"]), _e(g["upgrade_to"], "none published"),
                          str(len(g["findings"])), _remediation_text(g)])
        s.append(_table(["Package", "Installed", "Upgrade to", "Clears", "How"], rows8, {3}))
        s.append("<p class='note'>After upgrading, commit the updated manifest/lockfile and run a new scan. The scanner "
                 "marks a finding RESOLVED only when a successful scan of the same scope no longer reports it.</p>")
    else:
        s.append("<p>No dependency upgrades required.</p>")
    if d["secrets"]:
        s.append("<h3>Secrets</h3><ol><li>Revoke or rotate the credential at its provider first — assume it is exposed."
                 "</li><li>Remove it from the code and load it from an environment variable or a secret store; keep local "
                 "secret files (for example <code>.env</code>, <code>secrets.toml</code>) in <code>.gitignore</code>.</li>"
                 "<li>For secrets found in <b>Git history</b>, rewriting history (for example with git filter-repo) only "
                 "helps after rotation, because existing clones keep the old commits.</li></ol>")
    if d["misconfs"]:
        s.append("<h3>Misconfigurations</h3><p>Apply the resolution listed for each item in section 10 and rescan.</p>")
    if d.get("code"):
        s.append("<h3>Code issues</h3><p>Change the code as described for each item in section 11 and rescan. If an "
                 "item is a confirmed false positive, mark it with a <code># nosec Bxxx</code> comment explaining why.</p>")
    if d.get("web"):
        s.append("<h3>Web app issues</h3><p>Apply the fix listed for each item in section 12, restart the app and "
                 "rescan the project while the app is running.</p>")

    # 9 -------------------------------------------------------------- secrets
    s.append(h2(9) + "<p>Potential credentials found by Gitleaks (commit history and current files) and Trivy's secret "
             "scanner. <b>Secret values are never stored, so they cannot appear in this report.</b></p>")
    if d["secrets"]:
        s.append(_table(["#", "Rule", "Severity", "Status", "File : line", "Found in", "Commit", "Scanner", "First seen"],
                        [[str(i), _e(r["rule_id"]), _sev(r["severity"]), _e(r["status"]),
                          f"<span class='mono'>{_e(r['file_path'])}{':' + str(r['line']) if r['line'] else ''}</span>",
                          _found_in(r), _e(((r["meta"].get("commit") or "")[:12]) or None)
                          + (f"<br><span class='muted'>{_e(_ts(r['meta'].get('commit_date')))}</span>"
                             if r["meta"].get("commit_date") else ""),
                          _e(f"{r['scanner']} {r['scan_type']}"), _ts(r["first_seen"])]
                         for i, r in enumerate(d["secrets"], 1)], {0}))
    else:
        s.append("<p>No active potential secrets.</p>")

    # 10 ------------------------------------------------------------- misconfigurations
    s.append(h2(10))
    if d["misconfs"]:
        for i, r in enumerate(d["misconfs"], 1):
            s.append(f"<div class='finding {html.escape(r['severity'])}'><h3>#{i} {_e(r['rule_id'])} | "
                     f"{_e(r['file_path'])} | {_sev(r['severity'])}</h3>" + _kv([
                         ("Check", _e(r["title"])), ("Location", f"<span class='mono'>{_e(r['file_path'])}"
                                                                 f"{':' + str(r['line']) if r['line'] else ''}</span>"),
                         ("Resource", _e(r["meta"].get("resource"), NA)), ("Type", _e(r["meta"].get("type"), NA)),
                         ("Finding", _clip(r["description"])), ("Resolution", _e(r["remediation"], NA)),
                         ("Reference", _link(r["reference_url"])),
                         ("Reported by", _e(", ".join(f"trivy {t}" for t in sorted(r["scan_types"])))),
                         ("Status", f"{_e(r['status'])} · first seen {_ts(r['first_seen'])}")]) + "</div>")
    else:
        s.append("<p>No active misconfigurations.</p>")

    # 11 ------------------------------------------------------------- code issues
    code = d.get("code", [])
    s.append(h2(11) + "<p>Security bugs in the project's own code: Python found by Bandit, other languages "
             "(JavaScript/TypeScript, HTML templates, PHP, Java, Go, C#) by the built-in check. The code is read, "
             "never run. Source code is not copied into this report.</p>")
    if code:
        s.append(_table(["#", "Check", "Severity", "Confidence", "Issue", "File : line", "Fix", "Status"],
                        [[str(i), _e(r["rule_id"]) + (f"<br><span class='muted'>CWE-{_e(r['meta'].get('cwe'))}</span>"
                                                      if r["meta"].get("cwe") else ""),
                          _sev(r["severity"]), _e(str(r["meta"].get("confidence") or "").title() or None),
                          _e(r["title"]),
                          f"<span class='mono'>{_e(r['file_path'])}{':' + str(r['line']) if r['line'] else ''}</span>",
                          _e(r["remediation"]) + (f"<br>{_link(r['reference_url'])}" if _safe_url(r["reference_url"]) else ""),
                          _e(r["status"])] for i, r in enumerate(code, 1)], {0}))
    else:
        s.append("<p>No active code issues.</p>")

    # 12 ------------------------------------------------------------- web app issues (DAST)
    web = d.get("web", [])
    s.append(h2(12) + "<p>Problems found by the built-in web scan, which tests the running application through its "
             "address (GET requests only, apps on this computer only). Page contents are not copied into this "
             "report.</p>")
    if web:
        s.append(_table(["#", "Check", "Severity", "Issue", "Page", "Evidence", "Fix", "Status"],
                        [[str(i), _e(r["rule_id"]) + (f"<br><span class='muted'>CWE-{_e(r['meta'].get('cwe'))}</span>"
                                                      if r["meta"].get("cwe") else ""),
                          _sev(r["severity"]), _e(r["title"]),
                          f"<span class='mono'>{_e(r['meta'].get('url') or r['file_path'])}</span>"
                          + (f"<br><span class='muted'>parameter {_e(r['meta'].get('parameter'))}</span>"
                             if r["meta"].get("parameter") else ""),
                          _e(r["meta"].get("evidence")), _e(r["remediation"]), _e(r["status"])]
                         for i, r in enumerate(web, 1)], {0}))
    else:
        s.append("<p>No active web app issues" + ("" if any(r["scanner"] == "dast" for r in d["ok_runs"]) else
                                                   " (no web address was tested for this project)") + ".</p>")

    # 13 ------------------------------------------------------------- references
    s.append(h2(13))
    if advis:
        items = []
        for k, a in advis.items():
            refs = list(dict.fromkeys(a["v"]["references"]))[:8]
            items.append(f"<li><b>{_e(k)}</b> ({_e(a['v']['package_name'])}): "
                         + (" · ".join(_link(u) for u in refs) if refs else _link(a["v"]["reference_url"])) + "</li>")
        s.append("<ul>" + "".join(items) + "</ul>")
    mis_refs = [r for r in d["misconfs"] if _safe_url(r["reference_url"])]
    if mis_refs:
        s.append("<h3>Configuration checks</h3><ul>" + "".join(
            f"<li><b>{_e(r['rule_id'])}</b>: {_link(r['reference_url'])}</li>"
            for r in {x["rule_id"]: x for x in mis_refs}.values()) + "</ul>")
    if not advis and not mis_refs:
        s.append("<p>No advisories to reference.</p>")

    # 12 ------------------------------------------------------------- methodology
    steps = [
        "Discovered the repository under the configured roots (read-only; repositories are never modified).",
        "Ran the scanners with the commands listed in section 1 as local child processes with a timeout. Gitleaks runs "
        "with <code>--redact</code>; Trivy's secret matches are discarded during parsing. No data is uploaded"
        + (" (offline mode: cached vulnerability database only)." if d["offline"] else
           "; Trivy only downloads its vulnerability database."),
        "Parsed the JSON reports into one record per finding, removed duplicates and stored them in the local SQLite "
        "database with first-seen / last-seen dates.",
        "Compared each successful scan with the previous one of the same scope: findings no longer reported become "
        "RESOLVED; findings a later scan failed to cover become UNVERIFIED (never silently resolved).",
        "Ran Bandit on the project's Python files (installed libraries such as .venv are skipped); a repository's own "
        "<code>.bandit</code> file is ignored and code snippets are removed from the saved report. Ran the built-in "
        "pattern check on JavaScript/TypeScript, HTML templates, PHP, Java, Go and C# files (minified files and "
        "node_modules/vendor skipped; source text is never copied into the report).",
        "Tested each configured local web address of the running app with the built-in DAST scan: GET requests only, "
        "same-site links only (log-out / delete links skipped), response bodies never stored. Where a test-account "
        "login is configured, the scan first signs in with exactly one POST to the app's own login form (password "
        "read from an environment variable, never stored) and also tests the pages behind it.",
        "Built this report from the database plus the raw JSON of the latest successful Trivy filesystem scan (CVSS, "
        "CWE, dates, references, package graph) and read-only git metadata.",
    ]
    limits = [
        "Dependency vulnerabilities are found in manifests/lockfiles Trivy recognises. Unpinned requirements "
        "(for example <code>numpy&gt;=1.24</code>) are only checked when the project has its own installed "
        "environment (.venv / venv / node_modules), whose exact versions are then checked instead.",
        "Dependency paths and dev/runtime scope are inferred from the lockfile; packages were not installed.",
        "'Upgrade to' versions are calculated from advisory data and not verified by installing them.",
        "Severity is Trivy's label; CVSS is the severity source's v4/v3 score where available, else the highest listed.",
        f"Folders skipped while scanning: {_e(', '.join(d['skip_dirs']))}. Findings inside them are not reported.",
        "Secret detection is pattern-based: it can miss custom secrets and can flag test or example values.",
        "UNVERIFIED findings were seen before but not re-checked by a later successful scan; they are kept for review.",
        "Code analysis (SAST) covers Python in depth (Bandit) and the most common risky patterns in JavaScript/"
        "TypeScript, HTML templates, PHP, Java, Go and C# (built-in rules); it cannot find logic flaws such as missing "
        "access checks. Lines marked <code># nosec</code> are not reported by Bandit. Penetration testing of the "
        "running application is limited to the built-in web scan: it tests pages reachable without logging in (or "
        "with the configured test account), sends GET requests only apart from the one sign-in, and does not "
        "replace manual penetration testing.",
    ]
    if raw.error:
        limits.insert(0, f"Detailed advisory data is limited: {html.escape(raw.error)}.")
    if raw.graph_missing:
        limits.insert(0, "The latest Trivy scan predates package-graph recording; rescan to add dependency paths and "
                         "package counts.")
    raw_rows = []
    for r in d["ok_runs"]:
        try:
            p = safe_report_path(r["report_path"], d["reports_dir"]) if r["report_path"] else None
        except (PermissionError, FileNotFoundError):
            p = None
        raw_rows.append([f"#{r['id']}", _e(f"{r['scanner']} {r['scan_type']}"),
                         f"<span class='mono'>{_e(Path(r['report_path']).name if r['report_path'] else None)}</span>",
                         _e(f"{p.stat().st_size:,} bytes" if p else None), f"<span class='mono'>{_e(file_sha256(p), NA)}</span>"])
    s.append(h2(14) + "<h3>Method</h3><ol>" + "".join(f"<li>{x}</li>" for x in steps) + "</ol><h3>Limitations</h3><ul>"
             + "".join(f"<li>{x}</li>" for x in limits) + "</ul><h3>Raw results (kept locally)</h3>"
             + (_table(["Run", "Scanner", "Report file", "Size", "SHA-256"], raw_rows) if raw_rows else "<p>None.</p>")
             + "<p class='muted'>To save as PDF: open this file in a browser and choose Print → Save as PDF.</p>"
             + "</body></html>")
    return "".join(s)


def _remediation_text(g: dict) -> str:
    pkg, to, eco = g["package"] or "", g["upgrade_to"], (g["ecosystem"] or "").lower()
    if not to:
        return "No fixed version is published. Assess exploitability, apply vendor mitigations, or replace the package."
    transitive = g["relation"] not in ("direct", "root", "workspace", "unknown")
    if eco in ("npm", "yarn", "pnpm", "node-pkg"):
        cmd = f"npm install {pkg}@{to}" if not transitive else \
            f"upgrade the parent package, or add \"overrides\": {{\"{pkg}\": \"{to}\"}} to package.json"
    elif eco in ("pip", "pipenv", "poetry", "uv", "python-pkg"):
        cmd = f"set {pkg}>={to} in the requirements file, then pip install -r requirements.txt"
    elif eco in ("gomod", "gobinary"):
        cmd = f"go get {pkg}@v{to.lstrip('v')} && go mod tidy"
    elif eco in ("cargo",):
        cmd = f"cargo update -p {pkg} --precise {to}"
    elif eco in ("composer",):
        cmd = f"composer require {pkg}:^{to}"
    else:
        cmd = f"upgrade {pkg} to {to} or later with the project's package manager"
    return f"<code>{_e(cmd)}</code>" + (" <span class='muted'>(transitive — prefer upgrading the parent)</span>"
                                        if transitive else "")


# ----------------------------------------------------------------------------------------- public API
def audit_filename(repo_name: str, generated_at: str | None = None) -> str:
    stamp = re.sub(r"[^0-9TZ]", "", (generated_at or datetime.now(timezone.utc).isoformat())[:19]) + "Z"
    return f"{stamp}_{re.sub(r'[^A-Za-z0-9._-]+', '_', repo_name)[:60]}_security_audit.html"


def generate_audit(conn: sqlite3.Connection, cfg: AppConfig, repository_id: int) -> tuple[str, str, dict]:
    """Return (filename, html, data) for one repository."""
    data = build_audit(conn, cfg, repository_id)
    return audit_filename(data["repo"]["name"], data["generated_at"]), render_audit_html(data), data


def save_audit(conn: sqlite3.Connection, cfg: AppConfig, repository_id: int) -> Path:
    from services.export_service import write_export

    name, doc, _ = generate_audit(conn, cfg, repository_id)
    return write_export(cfg.reports_dir, name, doc)
