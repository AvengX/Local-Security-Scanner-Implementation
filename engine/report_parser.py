"""Parse Trivy and Gitleaks JSON reports into normalised findings.

Secret values are never copied: Trivy ``Match``/``Code`` and Gitleaks ``Secret``/``Match`` fields are dropped.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from engine.finding_normalizer import SECRET_REMEDIATION, NormalizedFinding, deduplicate


class ReportParseError(ValueError):
    """Raised when a scanner report is missing, unreadable or structurally invalid."""


def _load_json(path: Path) -> Any:
    if not path.is_file():
        raise ReportParseError(f"Report file was not produced: {path.name}")
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        raise ReportParseError(f"Report file is empty: {path.name}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReportParseError(f"Report is not valid JSON ({path.name}): {exc.msg} at line {exc.lineno}") from exc


# --------------------------------------------------------------------------------------------- Trivy
def parse_trivy_report(path: Path, scan_type: str = "fs", scan_target: str = ".") -> list[NormalizedFinding]:
    data = _load_json(path)
    return parse_trivy_data(data, scan_type=scan_type, scan_target=scan_target)


def parse_trivy_data(data: Any, scan_type: str = "fs", scan_target: str = ".") -> list[NormalizedFinding]:
    if not isinstance(data, dict) or ("Results" not in data and "SchemaVersion" not in data):
        raise ReportParseError("Unexpected Trivy report structure (missing SchemaVersion/Results)")
    results = data.get("Results") or []
    if not isinstance(results, list):
        raise ReportParseError("Trivy 'Results' must be a list")

    out: list[NormalizedFinding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        for vuln in result.get("Vulnerabilities") or []:
            out.append(_trivy_vuln(vuln, target, scan_type, scan_target))
        for mis in result.get("Misconfigurations") or []:
            if str(mis.get("Status", "FAIL")).upper() != "FAIL":
                continue  # PASS / EXCEPTION entries are not findings
            out.append(_trivy_misconfig(mis, target, scan_type, scan_target))
        for sec in result.get("Secrets") or []:
            out.append(_trivy_secret(sec, target, scan_type, scan_target))
        for lic in result.get("Licenses") or []:
            out.append(_trivy_license(lic, target, scan_type, scan_target))
    return deduplicate(out)


def _trivy_vuln(v: dict, target: str, scan_type: str, scan_target: str) -> NormalizedFinding:
    pkg = v.get("PkgName")
    installed = v.get("InstalledVersion")
    fixed = v.get("FixedVersion") or None
    vid = v.get("VulnerabilityID")
    pkg_path = v.get("PkgPath") or target
    if fixed:
        remediation = f"Upgrade {pkg} from {installed} to {fixed} (or later) and re-scan."
    else:
        remediation = (f"No fixed version of {pkg} is published yet. Assess exploitability, apply vendor "
                       "mitigations or replace the dependency, and monitor for a fix.")
    return NormalizedFinding(
        scanner="trivy", scan_type=scan_type, scan_target=scan_target, category="VULNERABILITY",
        severity=v.get("Severity"), vulnerability_id=vid, package_name=pkg, installed_version=installed,
        fixed_version=fixed, file_path=pkg_path, title=v.get("Title") or vid,
        description=v.get("Description"), remediation=remediation, reference_url=v.get("PrimaryURL"),
        metadata={"status": v.get("Status"), "pkg_id": v.get("PkgID"), "target": target,
                  "data_source": (v.get("DataSource") or {}).get("Name")},
        identity=(vid, pkg, installed, pkg_path),
    )


def _trivy_misconfig(m: dict, target: str, scan_type: str, scan_target: str) -> NormalizedFinding:
    cause = m.get("CauseMetadata") or {}
    rule = m.get("AVDID") or m.get("ID")
    line = cause.get("StartLine") or None
    return NormalizedFinding(
        scanner="trivy", scan_type=scan_type, scan_target=scan_target, category="MISCONFIGURATION",
        severity=m.get("Severity"), rule_id=rule, file_path=target, line=line,
        title=m.get("Title") or rule, description=m.get("Message") or m.get("Description"),
        remediation=m.get("Resolution"), reference_url=m.get("PrimaryURL"),
        metadata={"type": m.get("Type"), "id": m.get("ID"), "resource": cause.get("Resource"),
                  "end_line": cause.get("EndLine")},
        identity=(rule, target, cause.get("Resource"), line),
    )


def _trivy_secret(s: dict, target: str, scan_type: str, scan_target: str) -> NormalizedFinding:
    rule = s.get("RuleID")
    line = s.get("StartLine") or None
    # Deliberately ignore s["Match"] and s["Code"] which contain (masked) secret material.
    return NormalizedFinding(
        scanner="trivy", scan_type=scan_type, scan_target=scan_target, category="SECRET",
        severity=s.get("Severity"), rule_id=rule, file_path=target, line=line,
        title=s.get("Title") or rule, description=f"Potential {s.get('Category') or 'secret'} detected "
        f"({rule}) in {target}" + (f" at line {line}" if line else "") + ". Value withheld.",
        remediation=SECRET_REMEDIATION,
        metadata={"secret_category": s.get("Category"), "end_line": s.get("EndLine")},
        identity=(rule, target, line),
    )


def _trivy_license(lic: dict, target: str, scan_type: str, scan_target: str) -> NormalizedFinding:
    name = lic.get("Name")
    pkg = lic.get("PkgName")
    file_path = lic.get("FilePath") or target
    return NormalizedFinding(
        scanner="trivy", scan_type=scan_type, scan_target=scan_target, category="LICENSE",
        severity=lic.get("Severity"), rule_id=name, package_name=pkg, file_path=file_path,
        title=f"License {name}" + (f" in {pkg}" if pkg else ""),
        description=f"License classified as {lic.get('Category')}.",
        remediation="Review license obligations with your legal/compliance policy.",
        reference_url=lic.get("Link"), metadata={"license_category": lic.get("Category")},
        identity=(name, pkg, file_path),
    )


# ------------------------------------------------------------------------------------------ Gitleaks
def parse_gitleaks_report(path: Path, scan_type: str = "git", base: Path | None = None) -> list[NormalizedFinding]:
    data = _load_json(path)
    return parse_gitleaks_data(data, scan_type=scan_type, base=base)


def _relative_to_base(file_path: str | None, base: Path | None) -> str | None:
    """Gitleaks 'dir' mode reports absolute paths; make them repository-relative like 'git' mode and Trivy."""
    if not file_path or base is None or not os.path.isabs(file_path):
        return file_path
    try:
        rel = os.path.relpath(file_path, base)
    except ValueError:  # different drive
        return file_path
    return file_path if rel.startswith("..") else rel


def parse_gitleaks_data(data: Any, scan_type: str = "git", base: Path | None = None) -> list[NormalizedFinding]:
    if data is None:
        return []
    if not isinstance(data, list):
        raise ReportParseError("Unexpected Gitleaks report structure (expected a JSON array)")
    out: list[NormalizedFinding] = []
    for item in data:
        if not isinstance(item, dict):
            raise ReportParseError("Unexpected Gitleaks finding entry (expected an object)")
        rule = item.get("RuleID")
        file_path = _relative_to_base(item.get("File"), base)
        line = item.get("StartLine") or None
        commit = item.get("Commit") or ""
        # Never read item["Secret"] / item["Match"].
        out.append(NormalizedFinding(
            scanner="gitleaks", scan_type=scan_type, category="SECRET", severity="HIGH",
            rule_id=rule, file_path=file_path, line=line,
            title=item.get("Description") or rule,
            description=(f"Gitleaks rule '{rule}' matched in {file_path}" + (f" at line {line}" if line else "")
                         + (f" (commit {commit[:12]})" if commit else "") + ". Secret value withheld."),
            remediation=SECRET_REMEDIATION,
            metadata={"commit": commit, "commit_date": item.get("Date"), "author": item.get("Author"),
                      "tags": item.get("Tags") or [], "entropy": item.get("Entropy"),
                      "gitleaks_fingerprint": item.get("Fingerprint"), "link": item.get("Link")},
            identity=(rule, file_path, commit, line),
        ))
    return deduplicate(out)
