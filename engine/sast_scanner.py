"""SAST (static application security testing) with Bandit: security bugs in the project's own Python code.

Bandit parses source files into an AST and never imports or runs them. It is installed in the scanner's own
virtual environment (requirements.txt) and runs offline.

Hardening:
* Our own ``--ini`` file is always passed, so a ``.bandit`` file inside a scanned repository (or inside one of
  its dependencies) can never change targets, exclusions or skipped checks.
* Code snippets from the report are never stored. Bandit's hardcoded-password checks (B105/B106/B107) print the
  suspected password in their message, so those messages are replaced by a fixed text.
* Exit codes: 0 = no issues, 1 = issues found, anything else = execution failure.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from engine.finding_normalizer import Coverage, NormalizedFinding, deduplicate
from engine.report_parser import ReportParseError, _load_json
from engine.runner import ScanExecution, run_process, stderr_excerpt
from engine.scanner_health import ToolStatus
from utils.logger import get_logger
from utils.security import sha256_hex

log = get_logger(__name__)

ISSUES_EXIT_CODE = 1
CATEGORY = "CODE"
SCAN_TYPE = "python"
PASSWORD_TESTS = {"B105", "B106", "B107"}  # their issue_text contains the suspected password value

# Plain-language fixes for the checks that come up most often; everything else links to Bandit's docs.
REMEDIATION: dict[str, str] = {
    "B101": "assert statements are removed when Python runs with -O; use an explicit if/raise for security checks.",
    "B102": "Avoid exec(); there is almost always a safer, explicit way to do the same thing.",
    "B103": "Do not make files world-writable; use the narrowest permissions that work (e.g. 0o600 / 0o644).",
    "B104": "The server listens on every network interface. Bind to 127.0.0.1 unless it must be reachable from "
            "other machines.",
    "B105": "A password appears to be written in the code. Move it to an environment variable or a secrets store "
            "and rotate it if it is real.",
    "B106": "A password appears to be passed as a literal argument. Read it from configuration or a secrets store.",
    "B107": "A function has a hardcoded default password. Remove the default and require the caller to supply it.",
    "B108": "Hardcoded /tmp paths can be hijacked; use the tempfile module.",
    "B110": "An exception is silently ignored (try/except: pass). Log it or handle it so failures are visible.",
    "B113": "HTTP request without a timeout can hang forever; pass timeout=… to requests calls.",
    "B201": "Flask runs with debug=True, which allows remote code execution through the debugger. Disable it "
            "outside local development.",
    "B301": "pickle can run arbitrary code when loading untrusted data. Use JSON, or only unpickle data you created.",
    "B303": "MD5/SHA1 are broken for security use. Use hashlib.sha256 or better (or usedforsecurity=False if not "
            "for security).",
    "B311": "The random module is predictable. Use the secrets module for tokens, passwords and keys.",
    "B324": "MD5/SHA1 are broken for security use. Use hashlib.sha256 or better (or usedforsecurity=False if not "
            "for security).",
    "B307": "eval() runs arbitrary code. Use ast.literal_eval for data, or explicit parsing.",
    "B403": "pickle can run arbitrary code when loading untrusted data. Prefer JSON for data from outside.",
    "B501": "TLS certificate checking is turned off (verify=False), allowing man-in-the-middle attacks. Remove it.",
    "B506": "yaml.load can create arbitrary Python objects. Use yaml.safe_load.",
    "B602": "A shell command is built with shell=True; user input could inject extra commands. Pass an argument "
            "list with shell=False.",
    "B603": "Check that the program and arguments passed to subprocess cannot be controlled by a user.",
    "B605": "os.system / os.popen run through a shell; use subprocess with an argument list instead.",
    "B607": "A program is started by a partial path, so a different program on PATH could run. Use a full path.",
    "B608": "An SQL query is built from strings, which allows SQL injection. Use parameterised queries "
            "(cursor.execute(sql, params)) or the ORM.",
    "B701": "Jinja2 autoescape is off, which allows cross-site scripting. Use autoescape=True or select_autoescape().",
}


def is_test_file(path: str) -> bool:
    """tests/…, test/…, test_x.py, x_test.py and conftest.py: files whose job is to assert."""
    parts = path.lower().split("/")
    name = parts[-1]
    return (any(p in ("tests", "test") for p in parts[:-1]) or name.startswith("test_") or name.endswith("_test.py")
            or name == "conftest.py")


def _rel(filename: str) -> str:
    p = filename.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _issue_line(item: dict[str, Any]) -> str:
    """Source text of the flagged line, used only to build an identity hash (never stored)."""
    want = item.get("line_number")
    for raw in str(item.get("code") or "").splitlines():
        num, _, text = raw.partition(" ")
        if num.isdigit() and int(num) == want:
            return re.sub(r"\s+", " ", text).strip()
    return ""


def parse_bandit_data(data: Any) -> tuple[list[NormalizedFinding], list[dict[str, str]]]:
    """(findings, files Bandit could not parse) from a Bandit JSON report."""
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ReportParseError("Unexpected Bandit report structure (missing 'results')")
    out: list[NormalizedFinding] = []
    seen: dict[tuple[str, str, str], int] = {}
    for item in data["results"]:
        if not isinstance(item, dict):
            raise ReportParseError("Unexpected Bandit result entry (expected an object)")
        test_id = str(item.get("test_id") or "B000")
        file_path = _rel(str(item.get("filename") or ""))
        if test_id == "B101" and is_test_file(file_path):
            continue  # assert is how tests work; B101 only matters in application code (python -O drops asserts)
        line = item.get("line_number") or None
        # Identity: rule + file + the flagged line's text (so a finding keeps its history when code above it
        # moves), plus an occurrence counter for identical lines in one file.
        line_hash = sha256_hex(_issue_line(item))[:16]
        key = (test_id, file_path, line_hash)
        seen[key] = seen.get(key, 0) + 1
        if test_id in PASSWORD_TESTS:
            text = "Possible hardcoded password (value withheld)"
        else:
            text = str(item.get("issue_text") or item.get("test_name") or test_id)
        cwe = item.get("issue_cwe") or {}
        name = str(item.get("test_name") or "").replace("_", " ")
        out.append(NormalizedFinding(
            scanner="bandit", scan_type=SCAN_TYPE, category=CATEGORY,
            severity=str(item.get("issue_severity") or "UNKNOWN"),
            rule_id=test_id, file_path=file_path, line=line,
            title=text,
            description=f"Bandit check {test_id} ({name}) flagged {file_path}" + (f" line {line}" if line else "")
                        + f". Confidence: {str(item.get('issue_confidence') or 'UNKNOWN').title()}.",
            remediation=REMEDIATION.get(test_id, "Review this code; see the Bandit documentation link for "
                                                 "the risk and the safe alternative."),
            reference_url=item.get("more_info"),
            metadata={"confidence": item.get("issue_confidence"), "test_name": item.get("test_name"),
                      "cwe": cwe.get("id"), "cwe_link": cwe.get("link"),
                      "line_range": item.get("line_range"), "occurrence": seen[key]},
            identity=(test_id, file_path, line_hash, seen[key]),
            dedup_key=sha256_hex("CODE", ".", test_id, file_path, line_hash, seen[key]),
        ))
    errors = [{"file": _rel(str(e.get("filename") or "")), "reason": str(e.get("reason") or "")[:200]}
              for e in data.get("errors") or [] if isinstance(e, dict)]
    return deduplicate(out), errors


def sanitize_report(report: Path, data: dict[str, Any]) -> None:
    """Rewrite the saved Bandit report without source snippets or password values, so nothing secret is kept on
    disk (the same rule as Gitleaks --redact)."""
    for item in data.get("results") or []:
        if isinstance(item, dict):
            item.pop("code", None)
            if str(item.get("test_id")) in PASSWORD_TESTS:
                item["issue_text"] = "Possible hardcoded password (value withheld)"
    report.write_text(json.dumps(data, indent=1), encoding="utf-8")


def exclude_patterns(skip_dirs: list[str], app_dirs_inside: list[str]) -> list[str]:
    """Bandit -x entries. Bandit excludes a file when an entry is a substring of its path, so each folder name
    is wrapped in path separators (matches the folder at any depth, never a file that merely contains it)."""
    out = []
    for name in skip_dirs:
        if "," not in name:
            out.append(f"{os.sep}{name}{os.sep}")
    for rel in app_dirs_inside:
        if "," not in rel:
            out.append(f".{os.sep}{rel.replace('/', os.sep)}{os.sep}")
    return list(dict.fromkeys(out))


class BanditScanner:
    def __init__(self, tool: ToolStatus, work_dir: Path) -> None:
        self.tool = tool
        self.work_dir = work_dir

    def _ini(self) -> Path:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        ini = self.work_dir / "bandit.ini"
        if not ini.is_file():
            ini.write_text("# Generated by Local Security Scanner. Passed with --ini so repository .bandit files "
                           "are never used.\n[bandit]\n", encoding="utf-8")
        return ini

    def build_command(self, report: Path, excludes: list[str], skip_tests: list[str]) -> list[str]:
        args = [self.tool.path or sys.executable, "-m", "bandit", "-r", ".", "-f", "json", "-o", str(report),
                "-q", "--ini", str(self._ini())]
        if excludes:
            args += ["-x", ",".join(excludes)]
        if skip_tests:
            args += ["-s", ",".join(skip_tests)]
        return args

    def scan(self, target: Path, report: Path, timeout: int, excludes: list[str] | None = None,
             skip_tests: list[str] | None = None) -> ScanExecution:
        from utils.validators import SEVERITIES

        cov = Coverage("bandit", SCAN_TYPE, ".", frozenset({CATEGORY}), frozenset(SEVERITIES))
        ex = ScanExecution("bandit", SCAN_TYPE, ".", "PENDING", cov, tool_version=self.tool.version)
        if not self.tool.installed or not self.tool.usable:
            ex.status, ex.error_message = "FAILED", self.tool.error or "Bandit is not installed"
            return ex
        args = self.build_command(report, excludes or [], skip_tests or [])
        ex.command, ex.report_path = args, str(report)
        outcome = run_process(args, timeout=timeout, tool="bandit", cwd=target)
        ex.started_at, ex.finished_at, ex.duration = outcome.started_at, outcome.finished_at, outcome.duration
        ex.exit_code = outcome.exit_code
        if outcome.launch_error:
            ex.status, ex.error_message = "FAILED", outcome.launch_error
            return ex
        if outcome.timed_out or outcome.cancelled:
            report.unlink(missing_ok=True)  # never keep a partial, unsanitised report
        if outcome.timed_out:
            ex.status, ex.error_message = "TIMED_OUT", f"Bandit exceeded the {timeout}s timeout"
            return ex
        if outcome.cancelled:
            ex.status, ex.error_message = "CANCELLED", "Scan cancelled"
            return ex
        if outcome.exit_code not in (0, ISSUES_EXIT_CODE):
            report.unlink(missing_ok=True)  # may hold unsanitised snippets
            ex.status = "FAILED"
            ex.error_message = (f"Bandit exited with code {outcome.exit_code}: "
                                f"{stderr_excerpt(outcome.stderr or outcome.stdout)}")
            return ex
        try:
            data = _load_json(report)
            ex.findings, errors = parse_bandit_data(data)
            sanitize_report(report, data)
        except ReportParseError as exc:
            report.unlink(missing_ok=True)
            ex.status, ex.error_message = "FAILED", str(exc)
            return ex
        if outcome.exit_code == ISSUES_EXIT_CODE and not ex.findings:
            ex.status = "FAILED"
            ex.error_message = "Bandit reported issues but the JSON report contained none (inconsistent output)"
            return ex
        if errors:
            # Not a failure: other files were checked. Recorded so the dashboard can say which files were skipped.
            names = ", ".join(e["file"] for e in errors[:5]) + (" …" if len(errors) > 5 else "")
            ex.error_message = f"{len(errors)} file(s) could not be parsed and were not checked: {names}"
            log.warning("Bandit could not parse some files", extra={"count": len(errors)})
        ex.status = "COMPLETED_WITH_FINDINGS" if ex.findings else "COMPLETED"
        return ex
