"""Check the library versions that are actually installed, when the project does not pin them.

Trivy can only look up known flaws for exact versions. Many projects list libraries without one
(``numpy>=1.24``, or just ``streamlit``), so those libraries were never checked. Their exact versions are known,
though: they are installed in the project's own virtual environment (``.venv``, ``venv`` ...) or in
``node_modules``.

This module reads those versions from package metadata only - ``*.dist-info/METADATA`` for Python and
``node_modules/*/package.json`` for Node.js. Nothing is imported, executed or installed. It writes the versions
to a temporary requirements.txt / package-lock.json and lets Trivy check that file. Packages that are already
pinned exactly in a requirements.txt Trivy reads are skipped (they are checked by the normal scan), so nothing is
counted twice.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

PRUNE = {".git", "node_modules", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist",
         "build", "site-packages"}
MAX_DEPTH = 3
NODE_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,80}$")


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Environment:
    kind: str                 # "python" | "node"
    path: str                 # repository-relative folder (".venv", "landing-page/venv", "web/node_modules")
    packages: dict[str, str] = field(default_factory=dict)   # name -> exact version
    skipped_pinned: int = 0   # already pinned in requirements.txt (checked by the normal scan)

    @property
    def target(self) -> str:
        return f"{self.kind}:{self.path}"


def find_environments(repo: Path, max_depth: int = MAX_DEPTH) -> list[tuple[str, str]]:
    """(kind, relative path) of Python virtual environments and Node.js node_modules folders without a lockfile."""
    out: list[tuple[str, str]] = []
    if not repo.is_dir():
        return out
    for cur, dirs, files in os.walk(repo):
        rel_parts = Path(cur).relative_to(repo).parts
        if "pyvenv.cfg" in files and rel_parts:
            out.append(("python", "/".join(rel_parts)))
            dirs[:] = []
            continue
        if "package.json" in files and "node_modules" in dirs and not set(files) & set(NODE_LOCKS):
            out.append(("node", "/".join((*rel_parts, "node_modules"))))
        dirs[:] = [d for d in dirs if d not in PRUNE and not (d.startswith(".") and d not in (".venv", ".env"))
                   and len(rel_parts) < max_depth]
    return sorted(out)


def _site_packages(env: Path) -> list[Path]:
    found = [env / "Lib" / "site-packages"] + sorted((env / "lib").glob("python*/site-packages"))
    return [p for p in found if p.is_dir()]


def read_python_env(env: Path) -> dict[str, str]:
    pkgs: dict[str, str] = {}
    for sp in _site_packages(env):
        for meta in sp.glob("*.dist-info/METADATA"):
            name = version = None
            try:
                with meta.open(encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.startswith("Name:"):
                            name = line[5:].strip()
                        elif line.startswith("Version:"):
                            version = line[8:].strip()
                        if (name and version) or not line.strip():
                            break
            except OSError:
                continue
            if name and version and _NAME.match(name) and _VERSION.match(version):
                pkgs[name] = version
    return pkgs


def read_node_modules(nm: Path) -> dict[str, str]:
    pkgs: dict[str, str] = {}
    if not nm.is_dir():
        return pkgs
    candidates = [p for p in nm.iterdir() if p.is_dir() and not p.name.startswith(".")]
    expanded: list[Path] = []
    for p in candidates:
        expanded += [q for q in p.iterdir() if q.is_dir()] if p.name.startswith("@") else [p]
    for p in expanded:
        try:
            data = json.loads((p / "package.json").read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        name, version = data.get("name"), data.get("version")
        if isinstance(name, str) and isinstance(version, str) and _VERSION.match(version) and \
                re.match(r"^(@[a-z0-9._-]+/)?[a-z0-9._-]{1,200}$", name, re.I):
            pkgs[name] = version
    return pkgs


def pinned_requirements(repo: Path, skip_dirs: list[str]) -> set[tuple[str, str]]:
    """(canonical name, version) pinned with == in files named requirements.txt (the ones Trivy reads)."""
    skip = {d.lower() for d in skip_dirs} | {".git", "node_modules"}
    pins: set[tuple[str, str]] = set()
    for cur, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d.lower() not in skip]
        if "requirements.txt" in files:
            try:
                text = (Path(cur) / "requirements.txt").read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for raw in text.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)\s*(?:[;#].*)?$",
                             raw)
                if m:
                    pins.add((canonical(m.group(1)), m.group(2)))
    return pins


def collect(repo: Path, kind: str, rel: str, skip_dirs: list[str]) -> Environment:
    env = Environment(kind, rel)
    folder = repo / rel
    if kind == "python":
        pkgs = read_python_env(folder)
        pins = pinned_requirements(repo, skip_dirs)
        for name, ver in pkgs.items():
            if (canonical(name), ver) in pins:
                env.skipped_pinned += 1
            else:
                env.packages[name] = ver
    else:
        env.packages = read_node_modules(folder)
    return env


def write_manifest(env: Environment, work: Path) -> Path:
    """Temporary manifest with exact versions for Trivy. Returns the folder to scan."""
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    if env.kind == "python":
        lines = [f"{n}=={v}" for n, v in sorted(env.packages.items(), key=lambda kv: kv[0].lower())]
        (work / "requirements.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        packages = {"": {"name": "installed-node-modules", "version": "0.0.0"}}
        for n, v in env.packages.items():
            packages[f"node_modules/{n}"] = {"version": v}
        lock = {"name": "installed-node-modules", "version": "0.0.0", "lockfileVersion": 3, "requires": True,
                "packages": packages}
        (work / "package-lock.json").write_text(json.dumps(lock, indent=1), encoding="utf-8")
        (work / "package.json").write_text(json.dumps({"name": "installed-node-modules", "version": "0.0.0"}),
                                           encoding="utf-8")
    return work
