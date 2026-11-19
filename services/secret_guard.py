"""Pre-commit secret guard: a Git hook that stops a commit when the staged changes contain a password, key or token.

It prevents the leak instead of finding it afterwards (once a secret is committed it stays in the Git history).
The hook runs Gitleaks on the staged changes only (``gitleaks git --pre-commit --staged --redact``), so it is
fast and never prints the secret value.

Installing is an explicit, per-project action (Repositories page or ``run_scan.py guard install``) - the scanner
otherwise never changes a project. Safety rules:
* Only ``.git/hooks/pre-commit`` is written (the folder Git uses for this repository, also for worktrees).
* An existing pre-commit hook that is not ours is kept: it is renamed to ``pre-commit.lss-previous`` and still runs
  first; removing the guard puts it back.
* Projects that use a custom hooks folder (``core.hooksPath``, e.g. Husky) are not touched - the hook would have to
  go into tracked files; the user is told how to add it there instead.
* If Gitleaks is missing or fails, the commit is allowed with a clear warning (the guard never blocks work because
  of a tool problem). ``git commit --no-verify`` skips it once.
"""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

MARKER = "# Local Security Scanner secret guard"
PREVIOUS = "pre-commit.lss-previous"
CREATE_NO_WINDOW = 0x08000000


class GuardError(RuntimeError):
    pass


@dataclass
class GuardStatus:
    state: str          # installed | not_installed | other_hook | custom_hooks_path | not_git
    detail: str
    hook: Path | None = None

    @property
    def label(self) -> str:
        return {"installed": "On", "not_installed": "Off", "other_hook": "Off (another pre-commit hook exists)",
                "custom_hooks_path": "Not possible here (custom hooks folder)", "not_git": "Not a Git project"
                }[self.state]


def _git(repo: Path, *args: str) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=20,
                           creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def hooks_dir(repo: Path) -> Path | None:
    path = _git(repo, "rev-parse", "--git-path", "hooks")
    if path is None:
        return None
    p = Path(path)
    return p if p.is_absolute() else (repo / p)


def status(repo: Path) -> GuardStatus:
    if _git(repo, "rev-parse", "--is-inside-work-tree") != "true":
        return GuardStatus("not_git", "This folder is not a Git working tree.")
    custom = _git(repo, "config", "--get", "core.hooksPath")
    folder = hooks_dir(repo)
    hook = folder / "pre-commit" if folder else None
    if hook and hook.is_file() and MARKER in hook.read_text(encoding="utf-8", errors="replace"):
        return GuardStatus("installed", "Commits are checked for secrets before they are made.", hook)
    if custom:
        return GuardStatus("custom_hooks_path", f"This project keeps its Git hooks in '{custom}' (core.hooksPath, "
                           "for example Husky). Add this line to that pre-commit hook instead: "
                           "gitleaks git --pre-commit --staged --redact", hook)
    if hook and hook.is_file():
        return GuardStatus("other_hook", "A pre-commit hook already exists. Installing keeps it: it is renamed to "
                           f"{PREVIOUS} and still runs before the secret check.", hook)
    return GuardStatus("not_installed", "Commits are not checked for secrets.", hook)


def hook_script(gitleaks_path: str | None) -> str:
    exe = (gitleaks_path or "").replace("\\", "/").replace("'", "")
    return f"""#!/bin/sh
{MARKER} - blocks commits that contain passwords, keys or tokens.
# Installed by Local Security Scanner. Remove it from the Repositories page (Secret guard -> Remove),
# with 'python run_scan.py guard remove --name <project>', or by deleting this file.
# Skip it once (for example a confirmed false positive): git commit --no-verify
HOOKS_DIR="$(dirname "$0")"
if [ -f "$HOOKS_DIR/{PREVIOUS}" ]; then
  sh "$HOOKS_DIR/{PREVIOUS}" "$@" || exit $?
fi
GITLEAKS='{exe}'
if [ -z "$GITLEAKS" ] || [ ! -f "$GITLEAKS" ]; then
  GITLEAKS="$(command -v gitleaks 2>/dev/null)"
fi
if [ -z "$GITLEAKS" ]; then
  echo "secret guard: Gitleaks was not found - this commit was NOT checked for secrets." >&2
  exit 0
fi
"$GITLEAKS" git --pre-commit --staged --redact --no-banner --exit-code 1 .
status=$?
if [ "$status" -eq 1 ]; then
  echo "" >&2
  echo "secret guard: commit BLOCKED - a password, key or token was found in the staged changes (value hidden above)." >&2
  echo "  Remove it, keep it in an environment variable or a git-ignored .env file, then commit again." >&2
  echo "  A test value? Add the comment  gitleaks:allow  on that line. A real key? Revoke it first." >&2
  exit 1
fi
if [ "$status" -ne 0 ]; then
  echo "secret guard: Gitleaks failed (exit $status) - this commit was NOT checked for secrets." >&2
fi
exit 0
"""


def install(repo: Path, gitleaks_path: str | None) -> GuardStatus:
    st = status(repo)
    if st.state == "installed":
        return st
    if st.state in ("not_git", "custom_hooks_path"):
        raise GuardError(st.detail)
    assert st.hook is not None
    st.hook.parent.mkdir(parents=True, exist_ok=True)
    if st.state == "other_hook":
        prev = st.hook.with_name(PREVIOUS)
        if prev.exists():
            raise GuardError(f"{prev} already exists; resolve it by hand first.")
        st.hook.rename(prev)
    st.hook.write_bytes(hook_script(gitleaks_path).encode("utf-8"))  # LF line endings for Git's sh
    st.hook.chmod(st.hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return status(repo)


def remove(repo: Path) -> GuardStatus:
    st = status(repo)
    if st.state != "installed" or st.hook is None:
        return st
    st.hook.unlink()
    prev = st.hook.with_name(PREVIOUS)
    if prev.is_file():
        prev.rename(st.hook)
    return status(repo)
