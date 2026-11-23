"""Reusable validation functions for configuration and user input."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
CATEGORIES: tuple[str, ...] = ("VULNERABILITY", "SECRET", "MISCONFIGURATION", "CODE", "WEB", "LICENSE", "OTHER")
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


def is_loopback_host(host: str | None) -> bool:
    """localhost, 127.0.0.0/8 or ::1. Other names are refused (they could resolve anywhere)."""
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


_WEB_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
_ALLOWED_WEB_HOSTS: frozenset[str] = frozenset()


def normalize_web_host(name: str) -> str:
    """One exact host name for dast.allowed_hosts: no scheme, port, path or wildcard."""
    host = (name or "").strip().lower().rstrip(".")
    if not _WEB_HOST.match(host):
        raise ValueError(f"allowed_hosts entries are exact host names such as app.example.com "
                         f"(no http://, port, path or *): {name!r}")
    return host


def set_allowed_web_hosts(hosts: "list[str] | tuple[str, ...]") -> None:
    """Outside websites the web scan may contact (set from dast.allowed_hosts each time the config loads)."""
    global _ALLOWED_WEB_HOSTS
    _ALLOWED_WEB_HOSTS = frozenset(normalize_web_host(h) for h in hosts)


def allowed_web_hosts() -> frozenset[str]:
    return _ALLOWED_WEB_HOSTS


def is_allowed_web_host(host: str | None) -> bool:
    """This computer, or a host listed exactly in dast.allowed_hosts."""
    if is_loopback_host(host):
        return True
    return bool(host) and host.lower().rstrip(".") in _ALLOWED_WEB_HOSTS


def validate_dast_url(url: str) -> str:
    """A web address the DAST scan may test: http(s), this computer or an allowed host, no credentials/fragment."""
    raw = (url or "").strip()
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"Web scan address must start with http:// or https://: {raw!r}")
    if parts.username or parts.password:
        raise ValueError("Web scan address must not contain a user name or password")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in web scan address: {raw!r}") from exc
    if not is_allowed_web_host(parts.hostname):
        raise ValueError(f"Web scan is limited to apps on this computer (localhost, 127.0.0.1 or ::1) and the "
                         f"websites listed in dast.allowed_hosts: {raw!r} - add {parts.hostname} to "
                         f"dast.allowed_hosts in config.yaml if you are authorised to test it")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{port}" if port else "")
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
