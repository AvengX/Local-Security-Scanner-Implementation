"""What the scanners could actually check in each repository (read-only file inspection).

Explains empty Vulnerabilities / Misconfigurations pages honestly:
* Trivy only finds vulnerable libraries in dependency files it can read, and only for packages with an exact
  version (``numpy==1.26.4``; plain ``numpy`` or ``numpy>=1.24`` cannot be matched to advisories).
* Trivy only finds unsafe settings in infrastructure files (Dockerfile, docker-compose, Kubernetes, Helm, Terraform).
Nothing here modifies a repository; files are only listed and requirement files are read as text.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from engine.code_scanner import EXT_LANG

LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm",
    "poetry.lock": "poetry", "Pipfile.lock": "pipenv", "uv.lock": "uv", "pdm.lock": "pdm",
    "go.sum": "go", "Cargo.lock": "cargo", "composer.lock": "composer", "Gemfile.lock": "bundler",
    "packages.lock.json": "nuget", "gradle.lockfile": "gradle", "mix.lock": "hex", "pubspec.lock": "pub",
}
NEEDS_LOCK = {"package.json": ("npm", ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")),
              "pyproject.toml": ("python", ("poetry.lock", "uv.lock", "pdm.lock")),
              "Pipfile": ("pipenv", ("Pipfile.lock",)), "Cargo.toml": ("cargo", ("Cargo.lock",)),
              "composer.json": ("composer", ("composer.lock",)), "Gemfile": ("bundler", ("Gemfile.lock",))}
DIRECT_MANIFESTS = {"pom.xml": "maven", "go.mod": "go"}
CONFIG_PATTERNS = {
    "Dockerfile": ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "*.dockerfile"),
    "Docker Compose": ("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml"),
    "Terraform": ("*.tf", "*.tf.json"),
    "Helm": ("Chart.yaml",),
    "Kubernetes": ("kustomization.yaml", "kustomization.yml"),
    "CloudFormation": ("*.template.yaml", "*.template.json", "template.yaml"),
    "Azure ARM / Bicep": ("azuredeploy.json", "*.bicep"),
}
_REQ = re.compile(r"^requirements.*\.txt$", re.I)
CODE_SKIP = {"dist", "build", "coverage", "vendor", "bower_components", "bin", "obj", "target", "site-packages"}


@dataclass
class DependencyFile:
    path: str
    ecosystem: str
    total: int | None = None          # declared packages (requirement files only)
    pinned: int | None = None         # packages with an exact version Trivy can check
    unpinned_examples: list[str] = field(default_factory=list)
    checkable: bool = True
    note: str = ""


@dataclass
class RepoCoverage:
    repository: str
    dependency_files: list[DependencyFile] = field(default_factory=list)
    config_files: list[tuple[str, str]] = field(default_factory=list)  # (kind, relative path)
    truncated: bool = False
    python_files: int = 0           # .py files the code scan (Bandit) can check
    other_files: dict[str, int] = field(default_factory=dict)  # language -> files the built-in code scan reads

    @property
    def checkable_files(self) -> int:
        return sum(1 for d in self.dependency_files if d.checkable)


def parse_requirements(text: str) -> tuple[int, int, list[str]]:
    """(declared, exactly pinned, examples of unpinned) for a pip requirements file."""
    total = pinned = 0
    unpinned: list[str] = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-r", "-c", "--", "-i", "-f")):
            continue
        total += 1
        if line.startswith("-e") or "://" in line or line.startswith("git+"):
            unpinned.append(line.split("/")[-1][:40] + " (installed from a URL)")
            continue
        spec = line.split(";", 1)[0].strip()
        if re.search(r"===?\s*[0-9][^*,]*$", spec) and "," not in spec:
            pinned += 1
        else:
            unpinned.append(spec[:40])
    return total, pinned, unpinned


def inspect_repository(name: str, path: str, skip_dirs: list[str], max_depth: int = 8,
                       max_files: int = 60) -> RepoCoverage:
    cov = RepoCoverage(name)
    root = Path(path)
    skip = {d.lower() for d in skip_dirs} | {".git", ".hg", ".svn"}
    if not root.is_dir():
        return cov
    seen = 0
    for cur, dirs, files in os.walk(root):
        depth = len(Path(cur).relative_to(root).parts)
        dirs[:] = [d for d in dirs if d.lower() not in skip and not d.startswith(".") and depth < max_depth]
        names = set(files)
        cov.python_files += sum(1 for f in files if f.endswith(".py"))
        for f in files:
            lang = EXT_LANG.get(os.path.splitext(f)[1].lower())
            if lang and ".min." not in f.lower() and not set(Path(cur).relative_to(root).parts) & CODE_SKIP:
                cov.other_files[lang] = cov.other_files.get(lang, 0) + 1
        if cov.truncated:
            continue  # keep counting Python files, stop listing dependency / config files
        for fname in sorted(files):
            rel = (Path(cur) / fname).relative_to(root).as_posix()
            entry: DependencyFile | None = None
            if _REQ.match(fname):
                try:
                    total, pinned, unp = parse_requirements((Path(cur) / fname).read_text(encoding="utf-8",
                                                                                         errors="replace"))
                except OSError:
                    total, pinned, unp = 0, 0, []
                entry = DependencyFile(rel, "pip", total, pinned, unp[:4], checkable=pinned > 0)
                if fname.lower() != "requirements.txt":
                    # Trivy's pip analyser only reads files named exactly requirements.txt.
                    entry.checkable = False
                    entry.pinned = 0
                    entry.note = ("Trivy only reads files named exactly requirements.txt, so this file is not "
                                  "checked. Rename or copy it to e.g. train/requirements.txt to include it.")
                elif total and not pinned:
                    entry.note = "No exact versions, so these packages can't be checked."
                elif unp:
                    entry.note = f"{len(unp)} package(s) without an exact version are skipped."
            elif fname in LOCKFILES:
                entry = DependencyFile(rel, LOCKFILES[fname], note="Lockfile: exact versions of every package.")
            elif fname in NEEDS_LOCK:
                eco, locks = NEEDS_LOCK[fname]
                if not names.intersection(locks):
                    entry = DependencyFile(rel, eco, checkable=False,
                                           note=f"No lockfile next to it ({' / '.join(locks[:2])}), so exact "
                                                "versions are unknown and nothing can be checked.")
            elif fname in DIRECT_MANIFESTS:
                entry = DependencyFile(rel, DIRECT_MANIFESTS[fname], note="Versions read from the manifest.")
            if entry:
                cov.dependency_files.append(entry)
            for kind, pats in CONFIG_PATTERNS.items():
                if any(fnmatch.fnmatch(fname, p) for p in pats):
                    cov.config_files.append((kind, rel))
                    break
            if entry or (cov.config_files and cov.config_files[-1][1] == rel):
                seen += 1
                if seen >= max_files:
                    cov.truncated = True
                    break
    return cov
