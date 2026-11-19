"""Tool discovery, version detection, flag support checks and vulnerability-DB freshness."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from utils.security import redact

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

_BLOCKED_MARKERS = ("application control policy", "blocked by your administrator", "winerror 4551",
                    "smart app control", "[winerror 1260]")


@dataclass
class ToolStatus:
    name: str
    installed: bool
    path: str | None = None
    version: str | None = None
    usable: bool = False
    error: str | None = None


@dataclass
class DbFreshness:
    present: bool
    updated_at: str | None = None
    downloaded_at: str | None = None
    next_update: str | None = None
    age_hours: float | None = None
    stale: bool = True
    message: str = ""
    java_db_present: bool = False
    extra: dict[str, object] = field(default_factory=dict)


def _winget_candidates(exe: str) -> list[Path]:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return []
    out = [Path(local) / "Microsoft" / "WinGet" / "Links" / exe]
    pkgs = Path(local) / "Microsoft" / "WinGet" / "Packages"
    if pkgs.is_dir():
        out.extend(sorted(pkgs.glob(f"*/{exe}")))
    return out


def resolve_executable(name: str, configured: str | None = None) -> str | None:
    """Find a tool: configured path, PATH, then common Windows install locations (winget/scoop/choco)."""
    if configured:
        p = Path(os.path.expandvars(configured)).expanduser()
        return str(p) if p.is_file() else None
    exe = f"{name}.exe" if os.name == "nt" else name
    found = shutil.which(name)
    if found:
        return found
    candidates = _winget_candidates(exe)
    home = Path.home()
    candidates += [home / "scoop" / "shims" / exe, Path(r"C:\ProgramData\chocolatey\bin") / exe]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


def run_tool(args: list[str], timeout: int = 60, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run a tool with an argument list (never shell=True)."""
    return subprocess.run(  # noqa: S603 - argument list, validated executable
        args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        cwd=cwd, shell=False, creationflags=CREATE_NO_WINDOW,
    )


def describe_os_error(exc: OSError, tool: str) -> str:
    text = str(exc).lower()
    if any(m in text for m in _BLOCKED_MARKERS) or getattr(exc, "winerror", None) in (4551, 1260):
        return (f"{tool} is installed but Windows blocked it from running (Smart App Control / "
                "Application Control policy). Allow the binary or use a signed build; the scanner will "
                "not bypass this policy.")
    if isinstance(exc, FileNotFoundError):
        return f"{tool} executable not found"
    return f"{tool} could not be started: {redact(str(exc))}"


def _version(path: str, args: list[str], pattern: str, tool: str) -> ToolStatus:
    try:
        proc = run_tool([path, *args], timeout=30)
    except OSError as exc:
        return ToolStatus(tool, True, path, usable=False, error=describe_os_error(exc, tool))
    except subprocess.TimeoutExpired:
        return ToolStatus(tool, True, path, usable=False, error=f"{tool} version check timed out")
    text = (proc.stdout or "") + (proc.stderr or "")
    m = re.search(pattern, text)
    if proc.returncode != 0 or not m:
        return ToolStatus(tool, True, path, usable=False,
                          error=f"{tool} version check failed (exit {proc.returncode}): {redact(text[:300])}")
    return ToolStatus(tool, True, path, version=m.group(1), usable=True)


def check_trivy(configured: str | None = None) -> ToolStatus:
    path = resolve_executable("trivy", configured)
    if not path:
        return ToolStatus("trivy", False, error="Trivy is not installed (winget install AquaSecurity.Trivy)")
    return _version(path, ["--version"], r"Version:\s*v?([0-9][^\s]*)", "trivy")


def check_gitleaks(configured: str | None = None) -> ToolStatus:
    path = resolve_executable("gitleaks", configured)
    if not path:
        return ToolStatus("gitleaks", False, error="Gitleaks is not installed (winget install Gitleaks.Gitleaks)")
    return _version(path, ["version"], r"v?([0-9]+\.[0-9]+\.[0-9]+[^\s]*)", "gitleaks")


def check_bandit() -> ToolStatus:
    """Bandit is a Python package in the scanner's own environment (requirements.txt), run as 'python -m bandit'."""
    import importlib.util
    import sys

    if importlib.util.find_spec("bandit") is None:
        return ToolStatus("bandit", False, error="Bandit is not installed (run scripts\\install.ps1 or "
                                                 "'pip install -r requirements.txt')")
    status = _version(sys.executable, ["-m", "bandit", "--version"], r"bandit\s+v?([0-9][^\s]*)", "bandit")
    return status


def check_git() -> ToolStatus:
    path = resolve_executable("git")
    if not path:
        return ToolStatus("git", False, error="Git is not installed")
    return _version(path, ["--version"], r"git version ([0-9][^\s]*)", "git")


@lru_cache(maxsize=16)
def supported_flags(executable: str, subcommand: str) -> frozenset[str]:
    """Return the long flags documented in ``<tool> <subcommand> --help`` for the installed version."""
    try:
        proc = run_tool([executable, subcommand, "--help"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return frozenset()
    return frozenset(re.findall(r"(--[a-z0-9][a-z0-9\-]*)", (proc.stdout or "") + (proc.stderr or "")))


def default_trivy_cache_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "trivy"
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "trivy"


def _parse_ts(value: str | None) -> datetime | None:
    if not value or value.startswith("0001-"):
        return None
    try:
        v = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(v)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def trivy_db_freshness(cache_dir: str | None, threshold_hours: int) -> DbFreshness:
    """Read Trivy's cached DB metadata from disk (no network, no process launch)."""
    root = Path(os.path.expandvars(cache_dir)) if cache_dir else default_trivy_cache_dir()
    meta_path = root / "db" / "metadata.json"
    java_present = (root / "java-db" / "metadata.json").is_file()
    if not meta_path.is_file():
        return DbFreshness(False, stale=True, java_db_present=java_present,
                           message=f"No cached Trivy vulnerability DB found in {root}. Run "
                                   "'python run_scan.py update-databases' while online.")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return DbFreshness(False, stale=True, message=f"Trivy DB metadata unreadable: {exc}")
    updated = _parse_ts(meta.get("UpdatedAt"))
    downloaded = _parse_ts(meta.get("DownloadedAt"))
    age = (datetime.now(timezone.utc) - updated).total_seconds() / 3600 if updated else None
    stale = age is None or age > threshold_hours
    msg = (f"Trivy DB updated {age:.0f}h ago" if age is not None else "Trivy DB age unknown")
    if stale:
        msg += f" — STALE (threshold {threshold_hours}h). Results may miss recently published vulnerabilities."
    return DbFreshness(True, updated.isoformat() if updated else None,
                       downloaded.isoformat() if downloaded else None, meta.get("NextUpdate"),
                       round(age, 1) if age is not None else None, stale, msg, java_present,
                       {"schema_version": meta.get("Version")})


def check_codescan() -> ToolStatus:
    """The code scan for other languages is built into the scanner: nothing to install, always runnable."""
    from engine.code_scanner import ENGINE_VERSION

    return ToolStatus("codescan", True, path="built-in", version=ENGINE_VERSION, usable=True)


def check_dast() -> ToolStatus:
    """The web scan (DAST) is built into the scanner: nothing to install, always runnable."""
    from engine.dast_scanner import ENGINE_VERSION

    return ToolStatus("dast", True, path="built-in", version=ENGINE_VERSION, usable=True)
