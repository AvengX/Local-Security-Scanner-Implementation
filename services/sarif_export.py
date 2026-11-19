"""SARIF 2.1.0 export: the standard format for security results that GitHub code scanning, Azure DevOps and the
VS Code SARIF Viewer understand.

One SARIF "run" per tool (Trivy, Gitleaks, Bandit, built-in code scan, built-in web scan). Only open, undecided
findings are exported (the same set the dashboard counts). Each result has a stable ``partialFingerprints`` value
(the scanner's fingerprint) so code-scanning services track it across uploads, and rules carry
``security-severity`` so GitHub shows Critical / High / Medium / Low. Secret values are never included (they are
never stored); messages are the plain-language "what was found" text.

Locations: file findings point at the file and line, relative to the repository root (as GitHub expects).
Vulnerabilities point at the dependency file; vulnerabilities read from an installed environment point at the
project's requirements.txt / package.json. Web findings have no file, so they carry the page as a logical
location and point at the repository root.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from services.explain import explain
from utils.version import __version__

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNKNOWN": "note"}
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "2.0", "UNKNOWN": "1.0"}
TOOLS = {
    "trivy": ("Trivy", "https://trivy.dev/"),
    "gitleaks": ("Gitleaks", "https://github.com/gitleaks/gitleaks"),
    "bandit": ("Bandit", "https://bandit.readthedocs.io/"),
    "codescan": ("Local Security Scanner code scan", "https://github.com/AvengX/Local-Security-Scanner-Implementation"),
    "dast": ("Local Security Scanner web scan", "https://github.com/AvengX/Local-Security-Scanner-Implementation"),
}


def _rule_id(r: dict[str, Any]) -> str:
    return str(r.get("vulnerability_id") or r.get("rule_id") or r.get("title") or "finding")[:200]


def _relative(path: str, repo_path: str) -> str:
    """Repository-relative path (GitHub maps results to files by it); absolute paths inside the repo are cut."""
    root = repo_path.replace("\\", "/").rstrip("/")
    if root and path.lower().startswith(root.lower() + "/"):
        return path[len(root) + 1:]
    return path.lstrip("/") if not re.match(r"^[A-Za-z]:/", path) else path


def _location(r: dict[str, Any], meta: dict[str, Any], repo_path: str = "") -> dict[str, Any]:
    raw = (r.get("file_path") or "").replace("\\", "/")
    path = raw if r["category"] == "WEB" else _relative(raw, repo_path)
    if r["category"] == "WEB":
        return {"physicalLocation": {"artifactLocation": {"uri": ".", "uriBaseId": "%SRCROOT%"}},
                "logicalLocations": [{"name": f"{meta.get('method') or 'GET'} {path or '/'}", "kind": "resource",
                                      "fullyQualifiedName": (r.get("scan_target") or "").rstrip("/") + (path or "/")}]}
    if meta.get("version_source") == "installed":
        path = "package.json" if meta.get("environment_kind") == "node" else "requirements.txt"
        env = str(meta.get("environment") or "").strip("/")
        parent = env.rsplit("/", 1)[0] if "/" in env else ""
        path = f"{parent}/{path}" if parent else path
    loc: dict[str, Any] = {"artifactLocation": {"uri": path or ".", "uriBaseId": "%SRCROOT%"}}
    line = r.get("line")
    if isinstance(line, int) and line > 0:
        loc["region"] = {"startLine": line}
    return {"physicalLocation": loc}


def build_sarif(conn: sqlite3.Connection, repository_id: int) -> dict[str, Any]:
    rows = [dict(x) for x in conn.execute(
        "SELECT f.* FROM findings f WHERE f.repository_id=? AND f.status IN ('OPEN','UNVERIFIED') AND f.id NOT IN "
        "(SELECT finding_id FROM finding_triage) ORDER BY f.scanner, f.id", (repository_id,))]
    repo = conn.execute("SELECT path FROM repositories WHERE id=?", (repository_id,)).fetchone()
    repo_path = str(repo[0]) if repo else ""
    runs = []
    for scanner in sorted({r["scanner"] for r in rows}):
        name, uri = TOOLS.get(scanner, (scanner, ""))
        rules: dict[str, dict[str, Any]] = {}
        results = []
        for r in (x for x in rows if x["scanner"] == scanner):
            try:
                meta = json.loads(r.get("metadata_json") or "{}")
            except ValueError:
                meta = {}
            e = explain({**r, "file_path": _relative((r.get("file_path") or "").replace("\\", "/"), repo_path),
                         "metadata": meta})
            rid = _rule_id(r)
            rule = rules.get(rid)
            if rule is None or float(SECURITY_SEVERITY[r["severity"]]) > float(
                    rule["properties"]["security-severity"]):
                rules[rid] = {
                    "id": rid, "name": rid.replace("-", " "),
                    "shortDescription": {"text": (r.get("title") or rid)[:250]},
                    "fullDescription": {"text": e.what.split(" Found ")[0][:1000]},
                    "help": {"text": "Why it matters: " + e.why + "\n\nHow to fix:\n" +
                             "\n".join(f"{i}. {s}" for i, s in enumerate(e.fix, 1)),
                             "markdown": f"**Why it matters:** {e.why}\n\n**How to fix:**\n" +
                             "\n".join(f"{i}. {s}" for i, s in enumerate(e.fix, 1))},
                    **({"helpUri": r["reference_url"]} if str(r.get("reference_url") or "").startswith(
                        ("https://", "http://")) else {}),
                    "properties": {"security-severity": SECURITY_SEVERITY[r["severity"]],
                                   "tags": ["security", r["category"].lower()]
                                   + ([f"external/cwe/cwe-{meta['cwe']}"] if meta.get("cwe") else [])},
                }
            results.append({
                "ruleId": rid, "level": LEVEL.get(r["severity"], "note"),
                "message": {"text": f"{e.what} Fix: {e.fix[0]}"[:2000]},
                "locations": [_location(r, meta, repo_path)],
                "partialFingerprints": {"lssFingerprint/v1": r["fingerprint"]},
                "properties": {"severity": r["severity"], "status": r["status"], "category": r["category"],
                               **({"package": r["package_name"], "installedVersion": r["installed_version"],
                                   "fixedVersion": r["fixed_version"]} if r["category"] == "VULNERABILITY" else {})},
            })
        runs.append({"tool": {"driver": {"name": name, "informationUri": uri, "rules": list(rules.values()),
                                         "properties": {"exportedBy": f"Local Security Scanner {__version__}"}}},
                     "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Repository root"}}},
                     "results": results})
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": runs}


def sarif_bytes(conn: sqlite3.Connection, repository_id: int) -> bytes:
    return json.dumps(build_sarif(conn, repository_id), indent=1).encode("utf-8")
