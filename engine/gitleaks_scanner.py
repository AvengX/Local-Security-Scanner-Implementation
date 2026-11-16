"""Gitleaks wrapper: Git history (``gitleaks git``) and working-tree content (``gitleaks dir``).

Exit-code semantics: we pass ``--exit-code 2`` so that 0 = no leaks, 2 = leaks found, anything else
(1 = fatal error) = execution failure. ``--redact`` keeps secret values out of stdout/stderr and the
JSON report.
"""

from __future__ import annotations

from pathlib import Path

from engine.finding_normalizer import Coverage
from engine.report_parser import ReportParseError, parse_gitleaks_report
from engine.runner import ScanExecution, run_process, stderr_excerpt
from engine.scanner_health import ToolStatus, supported_flags
from utils.logger import get_logger
from utils.validators import SEVERITIES

log = get_logger(__name__)

LEAKS_EXIT_CODE = 2


class GitleaksScanner:
    def __init__(self, tool: ToolStatus) -> None:
        self.tool = tool

    def build_command(self, mode: str, target: Path, report: Path, config_path: str | None = None,
                      log_opts: str | None = None, max_target_megabytes: int | None = None) -> list[str]:
        if mode not in ("git", "dir"):
            raise ValueError(f"Unsupported Gitleaks mode: {mode}")
        supported = supported_flags(self.tool.path, mode) if self.tool.path else frozenset()

        def ok(flag: str) -> bool:
            return flag in supported if supported else True

        args = [self.tool.path or "gitleaks", mode, str(target), "--report-format", "json",
                "--report-path", str(report), "--exit-code", str(LEAKS_EXIT_CODE)]
        if ok("--redact"):
            args.append("--redact")
        if ok("--no-banner"):
            args.append("--no-banner")
        if ok("--log-level"):
            args += ["--log-level", "warn"]
        if config_path:
            args += ["--config", config_path]
        if max_target_megabytes and ok("--max-target-megabytes"):
            args += ["--max-target-megabytes", str(max_target_megabytes)]
        if mode == "git" and log_opts:
            args.append(f"--log-opts={log_opts}")
        return args

    def scan(self, mode: str, target: Path, report: Path, timeout: int, config_path: str | None = None,
             log_opts: str | None = None, max_target_megabytes: int | None = None) -> ScanExecution:
        cov = Coverage("gitleaks", mode, ".", frozenset({"SECRET"}), frozenset(SEVERITIES))
        ex = ScanExecution("gitleaks", mode, ".", "PENDING", cov, tool_version=self.tool.version)
        if not self.tool.installed or not self.tool.path:
            ex.status, ex.error_message = "FAILED", self.tool.error or "Gitleaks is not installed"
            return ex
        if not self.tool.usable:
            ex.status, ex.error_message = "FAILED", self.tool.error or "Gitleaks is not usable"
            return ex
        if config_path and not Path(config_path).is_file():
            ex.status, ex.error_message = "FAILED", f"Gitleaks config not found: {config_path}"
            return ex

        args = self.build_command(mode, target, report, config_path, log_opts, max_target_megabytes)
        ex.command, ex.report_path = args, str(report)
        outcome = run_process(args, timeout=timeout, tool="gitleaks")
        ex.started_at, ex.finished_at, ex.duration = outcome.started_at, outcome.finished_at, outcome.duration
        ex.exit_code = outcome.exit_code
        if outcome.launch_error:
            ex.status, ex.error_message = "FAILED", outcome.launch_error
            return ex
        if outcome.timed_out:
            ex.status, ex.error_message = "TIMED_OUT", f"Gitleaks exceeded the {timeout}s timeout"
            return ex
        if outcome.cancelled:
            ex.status, ex.error_message = "CANCELLED", "Scan cancelled"
            return ex
        if outcome.exit_code not in (0, LEAKS_EXIT_CODE):
            err = stderr_excerpt(outcome.stderr or outcome.stdout)
            if "dubious ownership" in err.lower():
                err = ("Git refused the repository (dubious ownership). If you trust it, run "
                       f"'git config --global --add safe.directory \"{target}\"'. Details: " + err)
            ex.status, ex.error_message = "FAILED", f"Gitleaks exited with code {outcome.exit_code}: {err}"
            return ex
        try:
            ex.findings = parse_gitleaks_report(report, scan_type=mode, base=target)
        except ReportParseError as exc:
            ex.status, ex.error_message = "FAILED", str(exc)
            return ex
        if outcome.exit_code == LEAKS_EXIT_CODE and not ex.findings:
            ex.status = "FAILED"
            ex.error_message = "Gitleaks reported leaks but the JSON report contained none (inconsistent output)"
            return ex
        ex.status = "COMPLETED_WITH_FINDINGS" if ex.findings else "COMPLETED"
        return ex
