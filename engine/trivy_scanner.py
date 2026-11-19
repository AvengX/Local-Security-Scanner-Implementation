"""Trivy wrapper: filesystem (vuln/misconfig/secret/license), config, image scans and SBOM generation.

Working directory: filesystem scans run with the repository as the working directory and target ".".
Trivy (verified on 0.76, Windows) resolves relative --skip-dirs patterns against the working directory,
so an absolute target path would silently disable skipping.

Exit-code semantics: we never pass ``--exit-code`` with a non-zero value, so Trivy exits 0 whether or not
findings exist. Any non-zero exit therefore means an execution error. Findings are determined solely from
the parsed JSON report.
"""

from __future__ import annotations

import dataclasses

from dataclasses import dataclass
from pathlib import Path

from engine.finding_normalizer import Coverage
from engine.report_parser import ReportParseError, parse_trivy_report
from engine.runner import ScanExecution, run_process, stderr_excerpt
from engine.scanner_health import ToolStatus, supported_flags, trivy_db_freshness
from utils.config import AppConfig
from utils.logger import get_logger
from utils.security import is_safe_cli_value, is_safe_image_ref
from utils.validators import TRIVY_SCANNERS

log = get_logger(__name__)

_DB_MISSING_MARKERS = ("--skip-db-update cannot be specified on the first run",
                       "first run cannot skip downloading db", "db not found", "vulnerability db is missing",
                       "failed to download vulnerability db", "the first run cannot skip")
# Signs that Trivy could not reach its download server (no internet, DNS failure, proxy, TLS...).
_NETWORK_MARKERS = ("no such host", "dial tcp", "i/o timeout", "connection refused", "connection reset",
                    "tls handshake", "network is unreachable", "oci repository error", "failed to download",
                    "context deadline exceeded", "proxyconnect")


@dataclass
class TrivyOptions:
    scanners: list[str]
    severities: list[str]
    timeout: int
    offline: bool
    cache_dir: str | None
    skip_dirs: list[str]

    @classmethod
    def from_config(cls, cfg: AppConfig, offline: bool | None = None) -> "TrivyOptions":
        return cls(list(cfg.trivy.scanners), list(cfg.scan.severities), cfg.scan.timeout_seconds,
                   cfg.scan.offline if offline is None else offline, cfg.trivy.cache_dir,
                   list(cfg.trivy.skip_dirs))


class TrivyScanner:
    def __init__(self, tool: ToolStatus, freshness_hours: int = 72) -> None:
        self.tool = tool
        self.freshness_hours = freshness_hours

    # ------------------------------------------------------------------ command construction
    def _flags(self, sub: str) -> frozenset[str]:
        return supported_flags(self.tool.path, sub) if self.tool.path else frozenset()

    def _common(self, sub: str, opts: TrivyOptions, report: Path, fmt: str = "json") -> list[str]:
        supported = self._flags(sub)

        def ok(flag: str) -> bool:
            # If help parsing failed (empty set) keep only flags present in every Trivy >= 0.50.
            return flag in supported if supported else flag in {"--format", "--output", "--severity",
                                                                    "--timeout", "--cache-dir", "--quiet"}

        args = [self.tool.path or "trivy", sub, "--format", fmt, "--output", str(report),
                "--timeout", f"{opts.timeout}s"]
        if ok("--quiet"):
            args.append("--quiet")
        if ok("--no-progress"):
            args.append("--no-progress")
        if fmt == "json" and ok("--severity"):
            args += ["--severity", ",".join(opts.severities)]
        if opts.cache_dir and ok("--cache-dir"):
            args += ["--cache-dir", opts.cache_dir]
        if ok("--skip-version-check"):
            args.append("--skip-version-check")
        if ok("--disable-telemetry"):
            args.append("--disable-telemetry")
        if opts.offline:
            for flag in ("--skip-db-update", "--skip-java-db-update", "--offline-scan",
                         "--skip-check-update", "--skip-policy-update"):
                if ok(flag) and not (flag == "--skip-policy-update" and "--skip-check-update" in supported):
                    args.append(flag)
        for d in opts.skip_dirs:
            if is_safe_cli_value(d) and ok("--skip-dirs"):
                args += ["--skip-dirs", d]
        return args

    def build_fs_command(self, target: Path, report: Path, opts: TrivyOptions) -> list[str]:
        scanners = [s for s in opts.scanners if s in TRIVY_SCANNERS]
        args = self._common("fs", opts, report)
        args += ["--scanners", ",".join(scanners)]
        # Record every package with its relationship (direct/indirect), dev flag and DependsOn graph so the
        # audit report can show dependency paths. Findings are unaffected.
        if "--list-all-pkgs" in self._flags("fs"):
            args.append("--list-all-pkgs")
        if "--exit-code" in self._flags("fs"):
            args += ["--exit-code", "0"]
        return [*args, str(target)]

    def build_config_command(self, target: Path, report: Path, opts: TrivyOptions) -> list[str]:
        return [*self._common("config", opts, report), str(target)]

    def build_image_command(self, image: str, report: Path, opts: TrivyOptions) -> list[str]:
        if not is_safe_image_ref(image):
            raise ValueError(f"Unsafe or invalid image reference: {image!r}")
        scanners = [s for s in opts.scanners if s in TRIVY_SCANNERS]
        return [*self._common("image", opts, report), "--scanners", ",".join(scanners), image]

    def build_sbom_command(self, target: Path, report: Path, opts: TrivyOptions) -> list[str]:
        sbom_opts = TrivyOptions(["vuln"], opts.severities, opts.timeout, opts.offline, opts.cache_dir,
                                 opts.skip_dirs)
        return [*self._common("fs", sbom_opts, report, fmt="cyclonedx"), str(target)]

    def build_update_db_command(self, cache_dir: str | None, java: bool = False) -> list[str]:
        args = [self.tool.path or "trivy", "image", "--download-java-db-only" if java else "--download-db-only"]
        if cache_dir:
            args += ["--cache-dir", cache_dir]
        if "--no-progress" in self._flags("image"):
            args.append("--no-progress")
        return args

    # ------------------------------------------------------------------ execution
    def _categories(self, scan_type: str, opts: TrivyOptions) -> frozenset[str]:
        if scan_type == "config":
            return frozenset({"MISCONFIGURATION"})
        return frozenset(TRIVY_SCANNERS[s] for s in opts.scanners if s in TRIVY_SCANNERS)

    def _base(self, scan_type: str, target: str, opts: TrivyOptions, coverage: bool = True) -> ScanExecution:
        cov = Coverage("trivy", scan_type, target, self._categories(scan_type, opts),
                       frozenset(opts.severities)) if coverage else None
        fresh = trivy_db_freshness(opts.cache_dir, self.freshness_hours)
        return ScanExecution("trivy", scan_type, target, "PENDING", cov, tool_version=self.tool.version,
                             database_updated_at=fresh.updated_at, offline=opts.offline)

    def _preflight(self, ex: ScanExecution, opts: TrivyOptions, needs_db: bool) -> bool:
        if not self.tool.installed or not self.tool.path:
            ex.status, ex.error_message = "FAILED", self.tool.error or "Trivy is not installed"
            return False
        if not self.tool.usable:
            ex.status, ex.error_message = "FAILED", self.tool.error or "Trivy is not usable"
            return False
        if opts.offline and needs_db and not trivy_db_freshness(opts.cache_dir, self.freshness_hours).present:
            ex.status = "FAILED"
            ex.error_message = ("Offline mode: no cached Trivy vulnerability DB is available. Run "
                                "'python run_scan.py update-databases' while online first.")
            return False
        return True

    def _execute(self, ex: ScanExecution, args: list[str], report: Path, opts: TrivyOptions,
                 parse: bool = True, cwd: Path | None = None) -> ScanExecution:
        ex.command = args
        ex.report_path = str(report)
        outcome = run_process(args, timeout=opts.timeout + 120, tool="trivy", cwd=cwd)
        ex.started_at, ex.finished_at, ex.duration = outcome.started_at, outcome.finished_at, outcome.duration
        ex.exit_code = outcome.exit_code
        if outcome.launch_error:
            ex.status, ex.error_message = "FAILED", outcome.launch_error
            return ex
        if outcome.timed_out:
            ex.status, ex.error_message = "TIMED_OUT", f"Trivy exceeded the {opts.timeout}s timeout"
            return ex
        if outcome.cancelled:
            ex.status, ex.error_message = "CANCELLED", "Scan cancelled"
            return ex
        if outcome.exit_code != 0:
            err = stderr_excerpt(outcome.stderr or outcome.stdout)
            low = err.lower()
            if any(m in low for m in _DB_MISSING_MARKERS):
                err = ("Trivy vulnerability DB is missing or could not be downloaded. Run "
                       "'python run_scan.py update-databases' while online. Details: " + err)
            ex.status, ex.error_message = "FAILED", f"Trivy exited with code {outcome.exit_code}: {err}"
            return ex
        if not parse:
            if not report.is_file():
                ex.status, ex.error_message = "FAILED", "Trivy did not produce the expected output file"
            else:
                ex.status = "COMPLETED"
            return ex
        try:
            ex.findings = parse_trivy_report(report, scan_type=ex.scan_type, scan_target=ex.scan_target)
        except ReportParseError as exc:
            ex.status, ex.error_message = "FAILED", str(exc)
            return ex
        ex.status = "COMPLETED_WITH_FINDINGS" if ex.findings else "COMPLETED"
        return ex

    def _run_with_fallback(self, ex: ScanExecution, build, report: Path, opts: TrivyOptions,  # noqa: ANN001
                           parse: bool = True, cwd: Path | None = None) -> ScanExecution:
        """Run online; if Trivy only failed because it could not download its DB/checks and a cached DB
        exists, rerun once with the cached data. The rerun is recorded as offline (never hidden)."""
        ex = self._execute(ex, build(opts), report, opts, parse=parse, cwd=cwd)
        if opts.offline or ex.status != "FAILED" or ex.exit_code in (None, 0):
            return ex
        low = (ex.error_message or "").lower()
        if not any(m in low for m in _NETWORK_MARKERS):
            return ex
        if not trivy_db_freshness(opts.cache_dir, self.freshness_hours).present:
            return ex
        first_error = ex.error_message
        log.warning("Trivy could not download updates; retrying with the cached vulnerability DB",
                    extra={"scan_type": ex.scan_type, "error": (first_error or "")[:300]})
        cached = dataclasses.replace(opts, offline=True)
        report.unlink(missing_ok=True)
        ex.status, ex.error_message, ex.offline = "PENDING", None, True
        ex = self._execute(ex, build(cached), report, cached, parse=parse, cwd=cwd)
        if ex.status == "FAILED":
            ex.error_message = f"{ex.error_message} (after download failure: {first_error})"
        return ex

    def scan_fs(self, target: Path, report: Path, opts: TrivyOptions) -> ScanExecution:
        ex = self._base("fs", ".", opts)
        if not self._preflight(ex, opts, needs_db="vuln" in opts.scanners):
            return ex
        return self._run_with_fallback(ex, lambda o: self.build_fs_command(Path("."), report, o), report, opts,
                                       cwd=target)

    def scan_installed(self, work: Path, report: Path, opts: TrivyOptions, target: str) -> ScanExecution:
        """Vulnerability scan of a generated manifest listing the exactly installed versions of one environment
        (see engine/installed_scanner.py). ``target`` is e.g. 'python:.venv'."""
        o = dataclasses.replace(opts, scanners=["vuln"])
        ex = self._base("installed", target, o)
        if not self._preflight(ex, o, needs_db=True):
            return ex
        return self._run_with_fallback(ex, lambda op: self.build_fs_command(Path("."), report, op), report, o,
                                       cwd=work)

    def scan_config(self, target: Path, report: Path, opts: TrivyOptions) -> ScanExecution:
        ex = self._base("config", ".", opts)
        if not self._preflight(ex, opts, needs_db=False):
            return ex
        return self._run_with_fallback(ex, lambda o: self.build_config_command(Path("."), report, o), report, opts,
                                       cwd=target)

    def scan_image(self, image: str, report: Path, opts: TrivyOptions) -> ScanExecution:
        ex = self._base("image", image, opts)
        if not is_safe_image_ref(image):
            ex.status, ex.error_message = "FAILED", f"Invalid image reference: {image!r}"
            return ex
        if not self._preflight(ex, opts, needs_db="vuln" in opts.scanners):
            return ex
        return self._run_with_fallback(ex, lambda o: self.build_image_command(image, report, o), report, opts)

    def generate_sbom(self, target: Path, report: Path, opts: TrivyOptions) -> ScanExecution:
        ex = self._base("sbom", ".", opts, coverage=False)
        if not self._preflight(ex, opts, needs_db=False):
            return ex
        return self._run_with_fallback(ex, lambda o: self.build_sbom_command(Path("."), report, o), report, opts,
                                       parse=False, cwd=target)

    def update_databases(self, cache_dir: str | None, timeout: int = 1800) -> list[tuple[str, bool, str]]:
        results: list[tuple[str, bool, str]] = []
        if not self.tool.usable or not self.tool.path:
            return [("trivy-db", False, self.tool.error or "Trivy unavailable")]
        for name, java in (("trivy-db", False), ("trivy-java-db", True)):
            out = run_process(self.build_update_db_command(cache_dir, java), timeout=timeout, tool="trivy")
            if out.launch_error:
                results.append((name, False, out.launch_error))
            elif out.timed_out:
                results.append((name, False, "timed out"))
            else:
                ok = out.exit_code == 0
                results.append((name, ok, "updated" if ok else stderr_excerpt(out.stderr)))
        return results
