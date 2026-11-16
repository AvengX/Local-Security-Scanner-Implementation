"""Recursive Git repository discovery across configured roots (no symlink/junction following)."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from engine.scanner_health import CREATE_NO_WINDOW, resolve_executable
from utils.logger import get_logger
from utils.paths import is_within, normalize_key

log = get_logger(__name__)


@dataclass
class DiscoveredRepo:
    name: str
    path: str
    root: str
    kind: str = "repository"  # repository | worktree_or_submodule
    current_branch: str | None = None
    current_commit: str | None = None


@dataclass
class DiscoveryResult:
    repositories: list[DiscoveredRepo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    missing_roots: list[str] = field(default_factory=list)
    skipped_links: int = 0


def _is_link(entry: os.DirEntry[str]) -> bool:
    try:
        if entry.is_symlink():
            return True
        is_junction = getattr(entry, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return True


def git_marker(directory: Path) -> str | None:
    """Return 'repository' if ``directory/.git`` is a git dir, 'worktree_or_submodule' for a valid gitfile."""
    marker = directory / ".git"
    try:
        if marker.is_dir():
            return "repository" if (marker / "HEAD").exists() or (marker / "objects").is_dir() else None
        if marker.is_file():
            head = marker.read_text(encoding="utf-8", errors="replace")[:4096].strip()
            return "worktree_or_submodule" if head.lower().startswith("gitdir:") else None
    except OSError:
        return None
    return None


def git_metadata(path: str, timeout: int = 15) -> tuple[str | None, str | None]:
    """Read current branch and HEAD commit (read-only git invocations)."""
    git = resolve_executable("git")
    if not git:
        return None, None
    base = [git, "-c", "core.fsmonitor=false", "-C", path]

    def run(*args: str) -> str | None:
        try:
            proc = subprocess.run(  # noqa: S603
                [*base, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, shell=False, creationflags=CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None

    return run("rev-parse", "--abbrev-ref", "HEAD"), run("rev-parse", "HEAD")


def discover_repositories(roots: Iterable[str], excluded_dirs: Iterable[str], *, max_depth: int = 10,
                          follow_symlinks: bool = False, protected_dirs: Iterable[Path] = (),
                          capture_metadata: bool = True) -> DiscoveryResult:
    """Walk each root breadth-first, collecting git repositories (including nested ones)."""
    result = DiscoveryResult()
    excluded = {e.lower() for e in excluded_dirs}
    protected = [Path(p) for p in protected_dirs]
    seen: set[str] = set()

    for root_str in roots:
        root = Path(root_str)
        if not root.is_dir():
            result.missing_roots.append(root_str)
            result.errors.append(f"Repository root not found or not a directory: {root_str}")
            continue
        stack: list[tuple[Path, int]] = [(root, 0)]
        visited_dirs: set[str] = set()
        while stack:
            current, depth = stack.pop()
            key = normalize_key(current)
            if key in visited_dirs:
                continue
            visited_dirs.add(key)
            if any(is_within(current, p) for p in protected):
                continue

            kind = git_marker(current)
            if kind and key not in seen:
                seen.add(key)
                result.repositories.append(DiscoveredRepo(current.name or str(current), str(current),
                                                          str(root), kind))
            if depth >= max_depth:
                continue
            try:
                with os.scandir(current) as it:
                    entries = list(it)
            except PermissionError:
                result.errors.append(f"Permission denied: {current}")
                continue
            except OSError as exc:
                result.errors.append(f"Cannot read {current}: {exc.strerror or exc}")
                continue
            for entry in entries:
                name_l = entry.name.lower()
                if name_l == ".git" or name_l in excluded:
                    continue
                try:
                    if not entry.is_dir(follow_symlinks=follow_symlinks):
                        continue
                except OSError:
                    continue
                if not follow_symlinks and _is_link(entry):
                    result.skipped_links += 1
                    continue
                stack.append((Path(entry.path), depth + 1))

    if capture_metadata:
        for repo in result.repositories:
            repo.current_branch, repo.current_commit = git_metadata(repo.path)
    result.repositories.sort(key=lambda r: r.path.lower())
    log.info("Discovery complete", extra={"repositories": len(result.repositories),
                                          "errors": len(result.errors)})
    return result
