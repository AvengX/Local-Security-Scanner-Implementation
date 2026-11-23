"""VAPT report for one project, laid out like a professional security assessment and printed to PDF.

Sections: executive summary (counts + overall posture), scope & methodology, findings table, finding details,
what's done well, remediation roadmap, not tested in this pass.

Raw scanner results are grouped into readable issues (VAPT-01, VAPT-02, ...): all vulnerable libraries of one
dependency file form one issue, the same kind of code problem in several places forms one issue, and so on.
Only safe data is used: secret values are never stored, so they can never appear in the report.
"""

from __future__ import annotations

import html
import json
import os
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services.explain import LOCAL_SECRET_FILE, RULE_TOPIC, SECRET_KINDS, TOPICS, _topic_for, explain, risk_level
from utils.config import AppConfig
from utils.version import __version__

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEV_RANK = {s: i for i, s in enumerate(SEVS)}
SEV_LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Info"}
SEV_COLOR = {"CRITICAL": "#C62828", "HIGH": "#D32F2F", "MEDIUM": "#C77700", "LOW": "#5F6B7A", "UNKNOWN": "#5F6B7A"}
ACTIVE = ("OPEN", "UNVERIFIED")
OK = ("COMPLETED", "COMPLETED_WITH_FINDINGS")
CONF_RANK = {"Confirmed": 0, "Likely": 1, "Needs verification": 2}

OWASP = {
    "A01": "A01 Broken Access Control", "A02": "A02 Cryptographic Failures", "A03": "A03 Injection",
    "A04": "A04 Insecure Design", "A05": "A05 Security Misconfiguration",
    "A06": "A06 Vulnerable & Outdated Components", "A07": "A07 Identification & Authentication Failures",
    "A08": "A08 Software & Data Integrity Failures", "A09": "A09 Security Logging & Monitoring Failures",
}
TOPIC_OWASP = {
    "xss": "A03", "xss_dom": "A03", "xss_template": "A03", "sqli": "A03", "cmd": "A03", "code_exec": "A03",
    "subprocess": "A03", "traversal": "A01", "redirect": "A01", "cors": "A01", "api_auth": "A01",
    "dir_listing": "A01", "exposed_file": "A01", "permissions": "A01", "postmessage": "A08",
    "deserialization": "A08", "yaml": "A08", "sri": "A08", "weak_hash": "A02", "weak_random": "A02",
    "tls_off": "A02", "cleartext": "A02", "hardcoded_password": "A07", "secret": "A07", "storage_token": "A04",
    "tmpfile": "A04", "assert": "A04", "timeout": "A04", "swallowed_error": "A09",
    "vulnerable_library": "A06", "misconfiguration": "A05", "license": "",
    **{t: "A05" for t in ("csp", "clickjack", "nosniff", "hsts", "version", "cookie_httponly", "cookie_samesite",
                          "cookie_secure", "debug", "error_leak", "trace", "api_docs", "bind_all", "noopener",
                          "partial_path")},
}
TOPIC_TITLE = {
    "xss": "Cross-site scripting (XSS): visitor input is placed into pages unescaped",
    "xss_dom": "DOM-based XSS: JavaScript builds HTML from variables (innerHTML and similar)",
    "xss_template": "Template output escaping switched off (|safe, Markup, autoescape off)",
    "sqli": "SQL injection: database queries built from request text",
    "cmd": "Command injection: operating-system commands built from variables",
    "code_exec": "Dynamic code execution (eval / exec / new Function)",
    "traversal": "Path traversal: file paths built from request values",
    "redirect": "Open redirect: visitors can be sent to any address",
    "deserialization": "Unsafe deserialization (pickle and similar formats)",
    "yaml": "Unsafe YAML loading (yaml.load)",
    "hardcoded_password": "Hard-coded password or key in source code",
    "weak_hash": "Weak hashing (MD5 / SHA-1) used for security",
    "weak_random": "Predictable random values used where security matters",
    "tls_off": "HTTPS certificate checking switched off",
    "cleartext": "Content loaded or sent over plain http://",
    "sri": "Third-party scripts loaded without an integrity check (SRI)",
    "csp": "No Content-Security-Policy header",
    "clickjack": "Pages can be framed by other sites (clickjacking)",
    "nosniff": "X-Content-Type-Options: nosniff header missing",
    "hsts": "HTTPS site without HSTS",
    "version": "Server software and version disclosed to every visitor",
    "cookie_httponly": "Cookies readable by JavaScript (HttpOnly missing)",
    "cookie_samesite": "Cookies without a SameSite setting",
    "cookie_secure": "Cookies without the Secure flag",
    "cors": "CORS allows any website to read responses",
    "exposed_file": "Sensitive files can be downloaded from the web server",
    "dir_listing": "Directory listing enabled on the web server",
    "debug": "Debug mode / interactive debugger enabled",
    "error_leak": "Error pages leak internal details (stack traces)",
    "trace": "HTTP TRACE method enabled",
    "postmessage": "postMessage sends data to any origin ('*')",
    "storage_token": "Login tokens or passwords kept in browser storage",
    "noopener": "Links open new tabs without rel=\"noopener\"",
    "api_auth": "API endpoint answers without the login its description requires",
    "api_docs": "Interactive API documentation publicly reachable",
    "bind_all": "Server listens on all network interfaces (0.0.0.0)",
    "assert": "assert used as a security check",
    "swallowed_error": "Errors caught and silently ignored",
    "timeout": "Network requests without a timeout",
    "tmpfile": "Predictable temporary file names",
    "permissions": "Files created with world-writable permissions",
    "subprocess": "External programs started from code (review inputs)",
    "partial_path": "Programs started by short name instead of a full path",
}
PROBE_TOPICS = {"csp", "clickjack", "nosniff", "hsts", "version", "cookie_httponly", "cookie_samesite",
                "cookie_secure", "cors", "debug", "error_leak", "trace", "api_docs", "bind_all", "noopener",
                "misconfiguration", "dir_listing", "exposed_file", "timeout", "cleartext", "sri"}

LANG_EXT = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
            ".ts": "TypeScript", ".tsx": "TypeScript", ".vue": "Vue", ".html": "HTML templates",
            ".htm": "HTML templates", ".jinja": "HTML templates", ".j2": "HTML templates", ".php": "PHP",
            ".java": "Java", ".kt": "Kotlin", ".go": "Go", ".cs": "C#", ".rb": "Ruby", ".rs": "Rust",
            ".c": "C/C++", ".cpp": "C/C++", ".h": "C/C++", ".sql": "SQL", ".sh": "Shell", ".ps1": "PowerShell"}
MANIFESTS = ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
             "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "pom.xml", "build.gradle", "go.mod",
             "composer.json", "Gemfile", "Cargo.toml")
INFRA = re.compile(r"(?i)^(dockerfile.*|docker-compose.*\.ya?ml|compose\.ya?ml|.*\.tf|chart\.yaml|nginx.*\.conf)$")


def _e(x: Any) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def _s(x: Any) -> str:
    return "" if x is None else str(x)


def _meta(r: dict[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(r.get("metadata_json") or "{}")
    except (TypeError, ValueError):
        return {}


def _first_sentence(text: str, limit: int = 260) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    out = m.group(1) if m else text
    return out if len(out) <= limit else out[: limit - 1].rstrip() + "…"


def _loc(r: dict[str, Any]) -> str:
    path = _s(r.get("file_path")).replace("\\", "/")
    if r.get("category") == "WEB":
        meta = r["meta"]
        return f"{meta.get('method') or 'GET'} {path or '/'}" + (f" (parameter {meta['parameter']})"
                                                                 if meta.get("parameter") else "")
    return path + (f":{r['line']}" if r.get("line") else "")


# --------------------------------------------------------------------------------------------- data model
@dataclass
class Issue:
    key: tuple
    category: str
    topic: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    id: str = ""

    @property
    def severity(self) -> str:
        return min((r["severity"] for r in self.rows), key=lambda s: SEV_RANK.get(s, 9))

    @property
    def cvss(self) -> tuple[float, str] | None:
        best = None
        for r in self.rows:
            score = r["meta"].get("cvss_score")
            if score and (best is None or float(score) > best[0]):
                best = (float(score), _s(r["meta"].get("cvss_vector")))
        return best

    @property
    def owasp(self) -> str:
        return OWASP.get(TOPIC_OWASP.get(self.topic, ""), "—" if self.topic != "license" else "Licence (legal)")

    @property
    def locations(self) -> list[str]:
        seen: dict[str, None] = {}
        for r in sorted(self.rows, key=lambda r: (SEV_RANK.get(r["severity"], 9), _loc(r))):
            seen.setdefault(_loc(r), None)
        return list(seen)

    @property
    def confidence(self) -> str:
        return min((_confidence(self.category, r) for r in self.rows), key=lambda c: CONF_RANK[c])

    @property
    def effort(self) -> str:
        if self.category == "VULNERABILITY":
            if all(r.get("fixed_version") for r in self.rows):
                return "S (hours)" if len(self.rows) < 25 else "M (1–3 days)"
            return "M (1–3 days)"
        if self.category == "SECRET":
            return "S (hours)"
        if self.topic in PROBE_TOPICS or self.category == "MISCONFIGURATION":
            return "S (hours)"
        return "M (1–3 days)" if len(self.locations) > 3 else "S (hours)"

    @property
    def roadmap(self) -> str:
        return {"CRITICAL": "Fix now", "HIGH": "Fix now", "MEDIUM": "Next sprint"}.get(self.severity, "Backlog")


def _confidence(cat: str, r: dict[str, Any]) -> str:
    meta = r["meta"]
    if cat == "WEB":
        return "Confirmed"
    if cat == "VULNERABILITY":
        return "Likely" if meta.get("version_source") == "installed" else "Confirmed"
    if cat == "SECRET":
        if r.get("scan_type") == "git":
            return "Confirmed"
        return "Needs verification" if LOCAL_SECRET_FILE.search(_s(r.get("file_path"))) else "Likely"
    if cat in ("MISCONFIGURATION", "LICENSE"):
        return "Confirmed"
    return "Likely" if _s(meta.get("confidence")).upper() == "HIGH" else "Needs verification"


def _secret_kind(rule: str) -> str:
    rule = rule.lower()
    return next((name for pat, name in SECRET_KINDS if re.search(pat, rule)), "password, key or token")


def _group(rows: list[dict[str, Any]]) -> list[Issue]:
    issues: dict[tuple, Issue] = {}
    seen_conf: set[tuple] = set()
    for r in rows:
        cat = r["category"]
        if cat == "VULNERABILITY":
            key, topic = ("VULNERABILITY", _s(r.get("file_path")).replace("\\", "/")), "vulnerable_library"
        elif cat == "SECRET":
            key, topic = ("SECRET", _secret_kind(_s(r.get("rule_id")))), "secret"
        elif cat in ("MISCONFIGURATION", "LICENSE"):
            ident = (r.get("rule_id"), r.get("file_path"), r.get("line"))
            if ident in seen_conf:  # the same setting can be reported by two Trivy modes
                continue
            seen_conf.add(ident)
            topic = "license" if cat == "LICENSE" else "misconfiguration"
            key = (cat, _s(r.get("rule_id")) or _s(r.get("title")))
        else:
            topic = _topic_for(r, r["meta"]) or RULE_TOPIC.get(_s(r.get("rule_id")).upper(), "")
            key = (cat, topic or _s(r.get("rule_id")) or _s(r.get("title")))
        issues.setdefault(key, Issue(key, cat, topic or "generic")).rows.append(r)
    out = sorted(issues.values(), key=lambda i: (SEV_RANK.get(i.severity, 9), -(i.cvss or (0, ""))[0],
                                                 -len(i.rows), _title(i)))
    width = max(2, len(str(len(out))))
    for n, issue in enumerate(out, 1):
        issue.id = f"VAPT-{n:0{width}d}"
    return out


# --------------------------------------------------------------------------------------------- wording
def _sev_counts(rows: list[dict[str, Any]]) -> str:
    c = Counter(r["severity"] for r in rows)
    return ", ".join(f"{c[s]} {SEV_LABEL[s].lower()}" for s in SEVS if c.get(s))


def _title(i: Issue) -> str:
    r0 = i.rows[0]
    if i.category == "VULNERABILITY":
        pkgs = {(r.get("package_name"), r.get("installed_version")) for r in i.rows}
        where = _s(r0.get("file_path")).replace("\\", "/") or "dependencies"
        n = len({p for p, _ in pkgs})
        return f"Vulnerable dependencies in {where} ({n} package{'s' if n != 1 else ''})"
    if i.category == "SECRET":
        hist = any(r.get("scan_type") == "git" for r in i.rows)
        n = len(i.locations)
        return (f"{i.key[1][0].upper()}{i.key[1][1:]} written in the project"
                + (" and its Git history" if hist else "") + (f" ({n} places)" if n > 1 else ""))
    if i.category in ("MISCONFIGURATION", "LICENSE"):
        return _s(r0.get("title")) or _s(r0.get("rule_id"))
    title = TOPIC_TITLE.get(i.topic) or _s(r0.get("title")) or _s(r0.get("rule_id")) or "Security issue"
    return title


def _description(i: Issue) -> str:
    r0 = i.rows[0]
    if i.category == "VULNERABILITY":
        worst = sorted(i.rows, key=lambda r: (SEV_RANK.get(r["severity"], 9), -float(r["meta"].get("cvss_score")
                                                                                       or 0)))[0]
        pkgs = {r.get("package_name") for r in i.rows}
        text = (f"{len(pkgs)} third-party package(s) used by the project have publicly known security flaws "
                f"({len(i.rows)} advisories: {_sev_counts(i.rows)}). The most serious is "
                f"{worst.get('package_name')} {_s(worst.get('installed_version'))} "
                f"({worst.get('vulnerability_id')}): {_first_sentence(_s(worst.get('title')), 180).rstrip('.')}.")
        if any(r["meta"].get("version_source") == "installed" for r in i.rows):
            text += (" These versions were read from the installed environment because the dependency file does "
                     "not pin exact versions.")
        return text
    if i.category == "SECRET":
        hist = [r for r in i.rows if r.get("scan_type") == "git"]
        text = (f"A {i.key[1]} appears to be written directly in the project's files instead of being read from "
                "a protected setting.")
        if hist:
            text += " It is also in the Git history, so deleting it from today's file does not remove it."
        return text + " The value itself is never stored or shown by the scanner - only where it is."
    if i.category in ("MISCONFIGURATION", "LICENSE"):
        return _first_sentence(_s(r0.get("description")) or explain(r0).what, 400)
    topic = TOPICS.get(i.topic)
    return topic.what if topic else _first_sentence(_s(r0.get("description")) or explain(r0).what, 400)


def _impact(i: Issue) -> str:
    ex = explain(i.rows[0])
    return f"{ex.attack} {ex.why}".strip()


def _fix(i: Issue) -> list[str]:
    if i.category == "VULNERABILITY":
        ups: dict[str, str] = {}
        none: list[str] = []
        for r in sorted(i.rows, key=lambda r: SEV_RANK.get(r["severity"], 9)):
            pkg, fixed = _s(r.get("package_name")), _s(r.get("fixed_version")).split(",")[0].strip()
            if fixed:
                ups.setdefault(pkg, f"{pkg} {_s(r.get('installed_version'))} → {fixed}")
            elif pkg not in ups:
                none.append(pkg)
        steps = []
        if ups:
            items = list(ups.values())
            steps.append("Upgrade: " + "; ".join(items[:10]) + (f"; and {len(items) - 10} more" if len(items) > 10
                                                               else "") + ".")
        none = sorted(set(none) - set(ups))
        if none:
            steps.append(f"No fixed version yet for {', '.join(none[:6])}: check whether the app uses the affected "
                         "feature, apply the advisory's workaround or replace the package.")
        steps += ["Pin exact versions in the lock / requirements file, reinstall and run the tests.",
                  "Re-scan to confirm the advisories are gone."]
        return steps
    return [s for s in explain(i.rows[0]).fix]


def _evidence(i: Issue) -> str:
    if i.category == "VULNERABILITY":
        rows = sorted(i.rows, key=lambda r: (SEV_RANK.get(r["severity"], 9),
                                             -float(r["meta"].get("cvss_score") or 0)))
        body = "".join(
            f"<tr><td>{_e(r.get('package_name'))}</td><td>{_e(r.get('installed_version'))}</td>"
            f"<td>{_e(_s(r.get('fixed_version')).split(',')[0] or '—')}</td><td>{_e(r.get('vulnerability_id'))}</td>"
            f"<td style='color:{SEV_COLOR[r['severity']]}'>{SEV_LABEL[r['severity']]}</td>"
            f"<td>{_e(r['meta'].get('cvss_score') or '—')}</td></tr>" for r in rows[:15])
        more = f"<p class='muted'>…and {len(rows) - 15} more advisories.</p>" if len(rows) > 15 else ""
        return ("<table class='mini'><tr><th>Package</th><th>Installed</th><th>Fixed in</th><th>Advisory</th>"
                f"<th>Severity</th><th>CVSS</th></tr>{body}</table>{more}")
    items = []
    for r in i.rows[:8]:
        meta, line = r["meta"], _e(_loc(r))
        if i.category == "SECRET":
            commit = _s(meta.get("commit"))[:8]
            line += f" — in Git history, commit <code>{_e(commit)}</code>" if commit else " — in the current files"
        elif i.category == "WEB" and meta.get("evidence"):
            line += f" — {_e(_first_sentence(_s(meta['evidence']), 220))}"
        elif r.get("title") and i.category in ("CODE", "MISCONFIGURATION"):
            line += f" — {_e(_first_sentence(_s(r.get('title')), 160))}"
        items.append(f"<li>{line}</li>")
    more = f"<li class='muted'>…and {len(i.rows) - 8} more.</li>" if len(i.rows) > 8 else ""
    return f"<ul class='ev'>{''.join(items)}{more}</ul>"


# --------------------------------------------------------------------------------------------- project facts
def _components(path: Path, skip: set[str]) -> dict[str, Any]:
    langs: Counter[str] = Counter()
    manifests: set[str] = set()
    infra: set[str] = set()
    files = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d.lower() not in skip and d != ".git"]
        for name in filenames:
            files += 1
            ext = os.path.splitext(name)[1].lower()
            if ext in LANG_EXT:
                langs[LANG_EXT[ext]] += 1
            if name in MANIFESTS:
                manifests.add(name)
            if INFRA.match(name):
                infra.add(name)
        if files > 50000:
            break
    return {"files": files, "langs": langs, "manifests": sorted(manifests), "infra": sorted(infra)}


def _when(ts: str | None) -> str:
    if not ts:
        return "—"
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%d %b %Y %H:%M")
    except ValueError:
        return ts


def build_vapt(conn: sqlite3.Connection, cfg: AppConfig, repository_id: int) -> dict[str, Any]:
    repo = conn.execute("SELECT * FROM repositories WHERE id=?", (repository_id,)).fetchone()
    if repo is None:
        raise ValueError(f"Unknown project id {repository_id}")
    repo = dict(repo)
    last = conn.execute("SELECT batch_id FROM scan_runs WHERE repository_id=? ORDER BY id DESC LIMIT 1",
                        (repository_id,)).fetchone()
    runs = [dict(r) for r in conn.execute("SELECT * FROM scan_runs WHERE repository_id=? AND batch_id=? ORDER BY id",
                                          (repository_id, last[0]))] if last else []

    skip = {d.lower() for d in [*cfg.scan.skip_dirs, *cfg.excluded_dirs]}
    decided = {r[0] for r in conn.execute("SELECT finding_id FROM finding_triage")}
    rows = []
    for r in conn.execute("SELECT * FROM findings WHERE repository_id=? AND status IN ('OPEN','UNVERIFIED')",
                          (repository_id,)):
        r = dict(r)
        parts = {p.lower() for p in re.split(r"[\\/]", r.get("file_path") or "")}
        if r["id"] in decided or (r["category"] != "WEB" and skip & parts):
            continue
        r["meta"] = _meta(r)
        rows.append(r)
    issues = _group(rows)
    counts = Counter(i.severity for i in issues)

    comp = _components(Path(repo["path"]), skip) if Path(repo["path"]).is_dir() else {
        "files": 0, "langs": Counter(), "manifests": [], "infra": []}
    started = min((r["started_at"] for r in runs if r.get("started_at")), default=None)
    finished = max((r["finished_at"] for r in runs if r.get("finished_at")), default=None)
    return {"repo": repo, "runs": runs, "issues": issues, "counts": counts, "raw_total": len(rows),
            "components": comp, "started": started, "finished": finished,
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "cfg": cfg}


# --------------------------------------------------------------------------------------------- sections
def _ran(runs: list[dict], scanner: str, scan_type: str | None = None) -> list[dict]:
    return [r for r in runs if r["scanner"] == scanner and (scan_type is None or r["scan_type"] == scan_type)]


def _status_note(rs: list[dict]) -> str:
    if not rs:
        return " <span class='muted'>(not run)</span>"
    bad = [r for r in rs if r["status"] not in OK]
    if bad:
        return f" <span class='bad'>(did not finish: {_e(_first_sentence(_s(bad[0].get('error_message')), 140))})</span>"
    return ""


def _ver(rs: list[dict]) -> str:
    v = next((_s(r.get("tool_version")) for r in rs if r.get("tool_version")), "")
    return f" {v.split()[0]}" if v else ""


def _scope(d: dict[str, Any]) -> list[tuple[str, str]]:
    repo, runs, comp, cfg = d["repo"], d["runs"], d["components"], d["cfg"]
    target = _e(repo["path"]) + f" ({comp['files']:,} files"
    if repo.get("current_branch"):
        target += f"; Git branch {_e(repo['current_branch'])}"
    if repo.get("current_commit"):
        target += f", commit {_e(_s(repo['current_commit'])[:8])}"
    target += ")" if repo.get("repo_kind") != "folder" else "; not a Git repository)"
    langs = ", ".join(f"{_e(k)} ({v})" for k, v in comp["langs"].most_common(8)) or "No source files recognised"
    parts = [langs]
    if comp["manifests"]:
        parts.append("dependency files: " + ", ".join(_e(m) for m in comp["manifests"]))
    if comp["infra"]:
        parts.append("deployment files: " + ", ".join(_e(m) for m in comp["infra"][:8]))
    fs, inst = _ran(runs, "trivy", "fs"), _ran(runs, "trivy", "installed")
    dep = f"Trivy{_ver(fs)}: every dependency / lock file checked against public advisories" + _status_note(fs)
    if inst:
        dep += "; exact installed versions in " + ", ".join(_e(r["scan_target"].split(":", 1)[-1]) for r in inst) \
               + _status_note(inst)
    gd, gg = _ran(runs, "gitleaks", "dir"), _ran(runs, "gitleaks", "git")
    sec = f"Gitleaks{_ver(gd or gg)}: project files" + _status_note(gd)
    sec += ("; full Git history" + _status_note(gg)) if repo.get("repo_kind") != "folder" else ""
    sec += ". Values are redacted - never stored or shown."
    bd, cs = _ran(runs, "bandit"), _ran(runs, "codescan")
    code = (f"Bandit{_ver(bd)} for Python" + _status_note(bd) + "; built-in rules for JavaScript/TypeScript, HTML "
            "templates, PHP, Java, Go and C#" + _status_note(cs))
    cf = _ran(runs, "trivy", "config")
    conf = "Trivy config checks: Dockerfile, Compose, Kubernetes, Helm, Terraform" + _status_note(cf)
    web = _ran(runs, "dast")
    if web:
        tgts = ", ".join(_e(r["scan_target"]) for r in web)
        login = any(cfg.dast.login_for(repo["name"], r["scan_target"]) for r in web)
        dyn = (f"Safe GET-only probes of {tgts} on this computer" + (" (signed in with a test account)"
                                                                       if login else "") +
               ": security headers, cookies, exposed files, debug pages, error leaks, CORS, XSS, SQL errors, "
               "open redirect, path traversal" + _status_note(web))
    else:
        dyn = "<span class='muted'>Not run - no local web address is configured for this project.</span>"
    return [
        ("Target", target), ("Components", "; ".join(parts)), ("Dependency scan", dep), ("Secret scan", sec),
        ("Static code review", code), ("Configuration review", conf), ("Dynamic (localhost only)", dyn),
        ("Rules", "Read-only: no file in the project was changed. Web probes go only to this computer. Nothing "
                  "is uploaded. Secrets are never stored or shown - only where they are."),
        ("Scoring", "Severity from each tool. CVSS 3.1 base score where the advisory publishes one (— otherwise). "
                    "Confidence: Confirmed (exact version match, live probe or Git history), Likely (pattern found "
                    "in code), Needs verification (a person should look)."),
        ("Scan time", f"{_when(d['started'])} – {_when(d['finished'])}"),
    ]


def _strengths(d: dict[str, Any]) -> tuple[list[str], list[str]]:
    runs, issues, comp, repo = d["runs"], d["issues"], d["components"], d["repo"]
    cats = Counter()
    for i in issues:
        for r in i.rows:
            cats[(r["scanner"], r["scan_type"])] += 1
    ok = lambda rs: bool(rs) and all(r["status"] in OK for r in rs)  # noqa: E731
    good = []
    if ok(_ran(runs, "gitleaks", "dir")) and not any(i.category == "SECRET" and any(
            r["scan_type"] != "git" for r in i.rows) for i in issues):
        good.append("No passwords, keys or tokens found in the project files.")
    if ok(_ran(runs, "gitleaks", "git")) and not any(r["scan_type"] == "git" for i in issues for r in i.rows):
        good.append("No secrets anywhere in the Git history.")
    if ok(_ran(runs, "trivy", "fs")) and not any(i.category == "VULNERABILITY" and i.rows[0]["scan_type"] == "fs"
                                                 for i in issues):
        if comp["manifests"]:
            good.append("No known-vulnerable libraries in the dependency files ("
                        + ", ".join(comp["manifests"][:4]) + ").")
    if ok(_ran(runs, "trivy", "installed")) and not any(
            i.category == "VULNERABILITY" and i.rows[0]["scan_type"] == "installed" for i in issues):
        good.append("Installed library versions have no known flaws.")
    if comp["langs"].get("Python") and ok(_ran(runs, "bandit")) and not cats.get(("bandit", "python")):
        good.append("No risky Python code patterns found by static analysis.")
    others = sum(v for k, v in comp["langs"].items() if k not in ("Python", "SQL", "Shell", "PowerShell"))
    if others and ok(_ran(runs, "codescan")) and not cats.get(("codescan", "multi")):
        good.append("No risky patterns found in JavaScript / template / other-language code.")
    if comp["infra"] and ok(_ran(runs, "trivy", "config")) and not any(i.category == "MISCONFIGURATION"
                                                                       for i in issues):
        good.append("Deployment files (" + ", ".join(comp["infra"][:3]) + ") pass the hardening checks.")
    web = _ran(runs, "dast")
    if ok(web) and not any(i.category == "WEB" for i in issues):
        good.append("The running web app passed every live check (headers, cookies, exposed files, injection "
                    "probes).")
    elif ok(web):
        present = {i.topic for i in issues if i.category == "WEB"}
        hdr = [n for t, n in (("csp", "Content-Security-Policy"), ("clickjack", "anti-framing"),
                              ("nosniff", "nosniff"), ("hsts", "HSTS")) if t not in present]
        if hdr:
            good.append("Security headers in place: " + ", ".join(hdr) + ".")
        inj = [n for t, n in (("xss", "XSS"), ("sqli", "SQL injection"), ("traversal", "path traversal"),
                              ("redirect", "open redirect")) if t not in present]
        if inj:
            good.append("Live probes found no " + ", ".join(inj) + ".")
    gi = Path(repo["path"]) / ".gitignore"
    try:
        if gi.is_file() and re.search(r"(?m)^\s*/?\.env\b", gi.read_text(encoding="utf-8", errors="ignore")):
            good.append(".env files are listed in .gitignore, so local secrets stay out of Git.")
    except OSError:
        pass

    weak: Counter[str] = Counter()
    label = {"VULNERABILITY": "Outdated third-party libraries", "SECRET": "Secrets written in files",
             "MISCONFIGURATION": "Unsafe deployment settings", "LICENSE": "Licences to review"}
    for i in issues:
        name = label.get(i.category) or (TOPIC_TITLE.get(i.topic, _title(i)).split(":")[0])
        weak[name] += len(i.rows) if i.category == "VULNERABILITY" else len(i.locations)
    weak_out = [f"{k} ({v} {('advisories' if v != 1 else 'advisory') if k.startswith('Outdated') else ('places' if v != 1 else 'place')})"
                for k, v in weak.most_common(5)]
    return good, weak_out


def _not_tested(d: dict[str, Any]) -> list[str]:
    runs, cfg = d["runs"], d["cfg"]
    out = []
    names = {"trivy": "Dependency / configuration scan", "gitleaks": "Secret scan", "bandit": "Python code review",
             "codescan": "Code review (other languages)", "dast": "Live web testing"}
    for r in runs:
        if r["status"] not in OK:
            out.append(f"{names.get(r['scanner'], r['scanner'])} ({r['scan_type']}) did not finish: "
                       f"{_first_sentence(_s(r.get('error_message')) or r['status'], 200)}")
    web = _ran(runs, "dast")
    if not web:
        out.append("The running web application (pages, forms, APIs): no local web address is configured for this "
                   "project, so no live probes were sent.")
    elif not any(cfg.dast.login_for(d["repo"]["name"], r["scan_target"]) for r in web):
        out.append("Pages behind sign-in: no test account is configured, so only public pages were probed.")
    if not cfg.sast.enabled:
        out.append("Source code review (switched off in the settings).")
    out += [
        "Business-logic and access-control flaws that need a person to judge (for example one user reading "
        "another user's data, or skipping a payment step).",
        "Production or staging infrastructure: TLS certificates, firewalls / WAF, servers and cloud accounts.",
        "Denial-of-service and load testing; brute-force attacks on logins.",
        "Container images and third-party services (unless listed in the settings).",
    ]
    return out


# --------------------------------------------------------------------------------------------- HTML
CSS = """
@page { size: A4; margin: 14mm 13mm 16mm; }
* { box-sizing: border-box; }
body { font-family: 'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,sans-serif; color:#1A1A1A;
       background:#fff; margin:0; font-size:10.5pt; line-height:1.5; }
.page { max-width: 1040px; margin: 0 auto; padding: 28px 24px; }
h1 { font-size: 21pt; font-weight: 600; margin: 0 0 8px; line-height:1.25; }
h2 { font-size: 15pt; font-weight: 600; margin: 34px 0 14px; break-after: avoid; }
.lead { color:#333; margin: 0 0 22px; }
.toc { border:1px solid #DDD; border-radius:10px; padding:12px 18px; margin: 0 0 8px; }
.toc .h { color:#777; font-size:9pt; margin-bottom:4px; }
.toc a { display:block; color:#555; text-decoration:none; padding:1px 0; }
.counts { display:grid; grid-template-columns: repeat(5, 1fr); gap: 10px 18px; margin: 6px 0 18px; }
.counts .n { font-size: 20pt; line-height:1.1; }
.counts .l { color:#333; }
.box { border-radius: 10px; padding: 12px 16px 12px 16px; margin: 10px 0; break-inside: avoid; }
.box b.t { display:block; margin-bottom:4px; }
.warn { background:#FBF1E1; color:#7A4A00; } .warn b.t { color:#B86E00; }
.danger { background:#FCE8E6; color:#7F1D1D; } .danger b.t { color:#C62828; }
.good { background:#E8F5E9; color:#1B5E20; } .good b.t { color:#2E7D32; }
.info { background:#E8F1FB; color:#0B3D74; } .info b.t { color:#1565C0; }
table { border-collapse: collapse; width:100%; }
.kv td { vertical-align: top; padding: 4px 10px 4px 0; }
.kv td:first-child { color:#777; width: 160px; white-space: nowrap; }
.ft { border:1px solid #E2E2E2; border-radius: 8px; overflow:hidden; font-size: 9.5pt; }
.ft th { text-align:left; font-weight:500; background:#FAFAFA; }
.ft th, .ft td { border-bottom:1px solid #E6E6E6; border-right:1px solid #EEE; padding: 7px 9px; vertical-align: top; }
.ft tr { break-inside: avoid; }
.sev { font-weight: 500; white-space: nowrap; }
.ft td:first-child { white-space: nowrap; }
.card { border-top:1px solid #E6E6E6; padding: 14px 0 6px; }
.card h3, .card b { break-after: avoid; }
.card .kv, .card p, .card li, .mini tr { break-inside: avoid; }
.card h3 { font-size: 12.5pt; font-weight: 600; margin: 0 0 8px; }
.card .kv td:first-child { width: 120px; }
.card p { margin: 8px 0; }
.card ol { margin: 4px 0 8px 20px; padding:0; }
code { font-family: 'Cascadia Code', Consolas, monospace; font-size: 9pt; background:#F3F3F3; padding:0 3px;
       border-radius:3px; }
.mini { font-size: 9pt; margin: 6px 0; } .mini th, .mini td { border-bottom: 1px solid #EEE; padding: 3px 8px 3px 0;
       text-align:left; }
.mini th { color:#777; font-weight: 500; }
.ev { margin: 4px 0 8px 18px; padding: 0; } .ev li { margin: 2px 0; word-break: break-word; }
.muted { color:#888; } .bad { color:#C62828; }
.cols { display:grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.panel { border:1px solid #E2E2E2; border-radius:10px; padding: 12px 16px; break-inside: avoid; }
.panel h4 { margin: 0 0 8px; font-size: 11pt; font-weight: 600; }
.panel ul { list-style:none; margin:0; padding:0; } .panel li { margin: 6px 0 6px 26px; position:relative; }
.panel li:before { position:absolute; left:-26px; top:0; width:18px; text-align:center; border-radius:4px;
       font-weight:700; }
.plus li:before { content:'+'; color:#2E7D32; background:#E8F5E9; }
.minus li:before { content:'–'; color:#C62828; background:#FCE8E6; }
.road td:first-child { white-space: nowrap; }
.footer { margin-top: 30px; color:#888; font-size: 8.5pt; border-top:1px solid #EEE; padding-top: 8px; }
ul.plain { margin: 8px 0 0 18px; padding:0; } ul.plain li { margin: 5px 0; }
@media print { .page { padding: 0; max-width: none; } a { color: inherit; } }
"""


def render_vapt_html(d: dict[str, Any]) -> str:
    repo, issues, counts = d["repo"], d["issues"], d["counts"]
    date = datetime.fromisoformat(d["generated"]).astimezone().strftime("%d %b %Y").lstrip("0")
    name = repo["name"]
    covered = ["dependencies", "secrets", "source code", "deployment configuration"]
    if _ran(d["runs"], "dast"):
        covered.append("the running web app on localhost")
    lead = (f"Automated read-only review of {_e(name)}: {', '.join(covered[:-1])} and {covered[-1]}. "
            "No code or configuration was changed.")
    sections = ["Executive summary", "Scope & methodology", "Findings table", "Finding details", "What's done well",
                "Remediation roadmap", "Not tested in this pass"]
    toc = "".join(f"<a href='#s{n}'>{s}</a>" for n, s in enumerate(sections))

    count_html = "".join(f"<div><div class='n'>{counts.get(s, 0)}</div><div class='l'>{SEV_LABEL[s]}</div></div>"
                         for s in SEVS)
    label, _, sentence = risk_level({s: counts.get(s, 0) for s in SEVS})
    cls = "danger" if counts.get("CRITICAL") else "warn" if counts.get("HIGH") or counts.get("MEDIUM") else "good"
    top = [i for i in issues if i.severity in ("CRITICAL", "HIGH")][:4]
    posture = sentence
    if top:
        posture += " Biggest risks: " + "; ".join(f"{i.id} ({_e(_title(i))})" for i in top) + "."
    fix_now = [i for i in issues if i.roadmap == "Fix now"]
    if fix_now:
        small = sum(1 for i in fix_now if i.effort.startswith("S"))
        posture += (f" {len(fix_now)} issue(s) should be fixed before any production or customer exposure"
                    + (f"; {small} of them {'is a small fix' if small == 1 else 'are small fixes'} (hours)." if small else "."))
    if issues:
        posture += (f" The report groups {d['raw_total']} individual scanner results into {len(issues)} issues.")

    scope = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in _scope(d))

    if issues:
        rows = "".join(
            f"<tr><td>{i.id}</td><td>{_e(_title(i))}</td><td class='sev' style='color:{SEV_COLOR[i.severity]}'>"
            f"{SEV_LABEL[i.severity]}</td><td>{_e(_cvss_text(i))}</td><td>{_e(i.owasp)}</td></tr>" for i in issues)
        table = ("<table class='ft'><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS 3.1</th><th>OWASP</th>"
                 f"</tr>{rows}</table>")
        details = "".join(_card(i) for i in issues)
    else:
        table = "<div class='box good'><b class='t'>No open issues.</b>None of the checks that ran found a problem.</div>"
        details = "<p class='muted'>Nothing to detail.</p>"

    good, weak = _strengths(d)
    good_html = "".join(f"<li>{_e(g)}</li>" for g in good) or "<li class='muted'>Nothing to highlight yet.</li>"
    weak_html = "".join(f"<li>{_e(w)}</li>" for w in weak) or "<li class='muted'>None found.</li>"

    phases = [("Fix now (this week)", "#C62828", "Fix now",
               "Upgrade the affected libraries, rotate any exposed key, and make the small code or config changes."),
              ("Next sprint", "#B86E00", "Next sprint",
               "Plan these in; add a test for each fix so it cannot come back."),
              ("Backlog", "#1A1A1A", "Backlog", "Low-risk hardening. Re-scan regularly (for example weekly).")]
    road = ""
    for label_p, color, key, note in phases:
        ids = [i.id for i in issues if i.roadmap == key]
        road += (f"<tr><td style='color:{color}'>{label_p}</td><td>{_e(', '.join(ids) or '—')}</td>"
                 f"<td>{_e(note if ids else 'Nothing in this phase.')}</td></tr>")

    nt = "".join(f"<li>{_e(x)}</li>" for x in _not_tested(d))
    gen = _when(d["generated"])
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>{_e(name)} — Security Assessment (VAPT) — {_e(date)}</title><style>{CSS}</style></head><body><div class="page">
<h1>{_e(name)} — Security Assessment (VAPT) — {_e(date)}</h1>
<p class="lead">{lead}</p>
<div class="toc"><div class="h">On this page</div>{toc}</div>
<h2 id="s0">Executive summary</h2>
<div class="counts">{count_html}</div>
<div class="box {cls}"><b class="t">Overall posture: {_e(label)}.</b>{posture}</div>
<h2 id="s1">Scope &amp; methodology</h2>
<table class="kv">{scope}</table>
<h2 id="s2">Findings table</h2>
{table}
<h2 id="s3">Finding details</h2>
{details}
<h2 id="s4">What's done well</h2>
<div class="cols"><div class="panel plus"><h4>Strengths observed</h4><ul>{good_html}</ul></div>
<div class="panel minus"><h4>Recurring weak spots</h4><ul>{weak_html}</ul></div></div>
<h2 id="s5">Remediation roadmap</h2>
<table class="ft road"><tr><th>Phase</th><th>Items</th><th>Notes</th></tr>{road}</table>
<h2 id="s6">Not tested in this pass</h2>
<div class="box info"><b class="t">Not tested in this pass (automated, read-only scan).</b>These areas carry residual
risk until a follow-up review covers them.</div>
<ul class="plain">{nt}</ul>
<div class="footer">Generated {_e(gen)} by Local Security Scanner {__version__}. Automated assessment: results should
be confirmed by the team that owns the code. Secret values are never included.</div>
</div></body></html>"""


def _cvss_text(i: Issue) -> str:
    c = i.cvss
    if not c:
        return "—"
    vec = c[1].replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
    return f"{c[0]:.1f}" + (f" — {vec}" if vec else "")


def _card(i: Issue) -> str:
    locs = i.locations
    loc = "; ".join(_e(x) for x in locs[:6]) + (f"; +{len(locs) - 6} more" if len(locs) > 6 else "")
    cv = i.cvss
    kv = [("CVSS 3.1", _e(f"{cv[0]:.1f} ({cv[1]})" if cv and cv[1] else f"{cv[0]:.1f}" if cv else "—")),
          ("OWASP", _e(i.owasp)), ("Location", loc or "—"), ("Confidence", i.confidence), ("Effort", i.effort),
          ("Roadmap", i.roadmap)]
    kv_html = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in kv)
    steps = "".join(f"<li>{_e(s)}</li>" for s in _fix(i))
    return (f"<div class='card'><h3>{i.id} · <span style='color:{SEV_COLOR[i.severity]}'>{SEV_LABEL[i.severity]}"
            f"</span> · {_e(_title(i))}</h3><table class='kv'>{kv_html}</table>"
            f"<p><b>Description.</b> {_e(_description(i))}</p>"
            f"<div><b>Evidence.</b> {_evidence(i)}</div>"
            f"<p><b>Impact.</b> {_e(_impact(i))}</p>"
            f"<div><b>Fix.</b><ol>{steps}</ol></div></div>")


# --------------------------------------------------------------------------------------------- files
@dataclass
class VaptFile:
    project: str
    html_path: Path
    pdf_path: Path | None
    counts: dict[str, int]
    issues: int
    error: str | None = None


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "project"


def reports_folder(cfg: AppConfig) -> Path:
    p = cfg.reports_dir / "vapt"
    p.mkdir(parents=True, exist_ok=True)
    return p


def generate_vapt(conn: sqlite3.Connection, cfg: AppConfig, repository_id: int, pdf: bool = True) -> VaptFile:
    """Write the HTML report and (by default) print it to PDF with the Edge / Chrome already installed."""
    d = build_vapt(conn, cfg, repository_id)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = reports_folder(cfg) / f"{_safe(d['repo']['name'])}_VAPT_{stamp}"
    html_path = base.with_suffix(".html")
    html_path.write_text(render_vapt_html(d), encoding="utf-8")
    out = VaptFile(d["repo"]["name"], html_path, None, {s: d["counts"].get(s, 0) for s in SEVS}, len(d["issues"]))
    if pdf:
        from services.pdf_export import PdfError, html_to_pdf

        try:
            out.pdf_path = html_to_pdf(html_path)
        except PdfError as exc:
            out.error = str(exc)
    return out


def list_vapt_reports(cfg: AppConfig, limit: int = 30) -> list[Path]:
    folder = cfg.reports_dir / "vapt"
    if not folder.is_dir():
        return []
    return sorted(folder.glob("*_VAPT_*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
