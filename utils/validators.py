"""Reusable validation functions for configuration and user input."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
CATEGORIES: tuple[str, ...] = ("VULNERABILITY", "SECRET", "MISCONFIGURATION", "CODE", "LICENSE", "OTHER")
TRIVY_SCANNERS: dict[str, str] = {
    "vuln": "VULNERABILITY",
    "misconfig": "MISCONFIGURATION",
    "secret": "SECRET",
    "license": "LICENSE",
}
TRIVY_SCAN_TYPES: tuple[str, ...] = ("fs", "config")
GITLEAKS_MODES: tuple[str, ...] = ("git", "dir")

_DIR_NAME = re.compile(r"^[^<>:\"/\\|?*\x00-\x1f]+$")
_REPO_NAME = re.compile(r"^[^<>:\"/\\|?*\x00-\x1f]{1,255}$")
_SCHEDULE_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def validate_severities(values: list[str]) -> list[str]:
    cleaned = [v.strip().upper() for v in values if v and v.strip()]
    bad = [v for v in cleaned if v not in SEVERITIES]
    if bad:
        raise ValueError(f"Unknown severities: {bad}. Allowed: {list(SEVERITIES)}")
    if not cleaned:
        raise ValueError("At least one severity must be selected")
    # Keep canonical order, no duplicates.
    return [s for s in SEVERITIES if s in cleaned]


def validate_dir_name(name: str) -> str:
    name = name.strip()
    if not name or not _DIR_NAME.match(name) or name in (".", ".."):
        raise ValueError(f"Invalid directory name for exclusion: {name!r} (names only, no paths)")
    return name


def validate_root(path: str) -> str:
    p = Path(path.strip().strip('"'))
    if not p.is_absolute():
        raise ValueError(f"Repository root must be an absolute path: {path!r}")
    return str(p)


def validate_loopback_host(host: str) -> str:
    if host == "localhost":
        return host
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise ValueError("Dashboard host must be a loopback address (127.0.0.1, ::1 or localhost)")


def validate_repo_name(name: str) -> str:
    if not _REPO_NAME.match(name or ""):
        raise ValueError(f"Invalid repository name: {name!r}")
    return name


def validate_schedule_time(value: str) -> str:
    if not _SCHEDULE_TIME.match(value):
        raise ValueError("Time must be HH:MM in 24-hour format")
    return value
