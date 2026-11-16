"""Filesystem path helpers (Windows-aware)."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH: Path = PROJECT_ROOT / "config.yaml"
EXAMPLE_CONFIG_PATH: Path = PROJECT_ROOT / "config.example.yaml"
SCHEMA_PATH: Path = PROJECT_ROOT / "database" / "schema.sql"


def config_path() -> Path:
    """Return the active configuration file path (``LSS_CONFIG`` overrides the default)."""
    override = os.environ.get("LSS_CONFIG")
    return Path(override).expanduser().resolve() if override else DEFAULT_CONFIG_PATH


def resolve_app_path(value: str | Path) -> Path:
    """Resolve a configured path: env vars and ``~`` are expanded; relative paths are project-relative."""
    expanded = Path(os.path.expandvars(os.path.expanduser(str(value))))
    if not expanded.is_absolute():
        expanded = PROJECT_ROOT / expanded
    return expanded.resolve()


def normalize_key(path: str | Path) -> str:
    """Case- and separator-normalised key used for de-duplicating paths on Windows."""
    return os.path.normcase(os.path.normpath(os.path.abspath(str(path))))


def is_within(child: str | Path, parent: str | Path) -> bool:
    """True if ``child`` is ``parent`` or located inside it (after resolving)."""
    try:
        child_r = Path(child).resolve()
        parent_r = Path(parent).resolve()
    except (OSError, RuntimeError):
        return False
    c, p = normalize_key(child_r), normalize_key(parent_r)
    return c == p or c.startswith(p.rstrip("\\/") + os.sep)


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def to_posix_rel(path: str) -> str:
    """Normalise a scanner-reported file path to forward slashes without a leading './'."""
    p = (path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p
