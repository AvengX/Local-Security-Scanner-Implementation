"""Native Windows folder picker for the dashboard.

The dashboard only listens on 127.0.0.1, so the browser and the Streamlit server are on the same PC and a
native dialog opened by the server appears on the user's own screen. The dialog runs in a short-lived child
process (Tk is not thread-safe inside Streamlit) and returns the chosen absolute path, or None if cancelled.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_SCRIPT = r"""
import sys, tkinter as tk
from tkinter import filedialog
root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)   # keep the dialog in front of the browser
root.update()
path = filedialog.askdirectory(parent=root, title=sys.argv[1], initialdir=sys.argv[2] or None, mustexist=True)
root.destroy()
sys.stdout.write(path or "")
"""

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class FolderPickerError(RuntimeError):
    """The dialog could not be shown (no desktop session, Tk missing, timeout...)."""


def pick_folder(title: str = "Select a folder", initial_dir: str | None = None, timeout: int = 600) -> str | None:
    """Open the OS folder dialog and return the selected folder as a Windows path (None if cancelled)."""
    start = initial_dir if initial_dir and Path(initial_dir).is_dir() else ""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed interpreter and inline script, no shell
            [sys.executable, "-I", "-c", _SCRIPT, title, start], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, shell=False, creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise FolderPickerError("The folder dialog was open too long and was closed.") from exc
    except OSError as exc:
        raise FolderPickerError(f"Could not open the folder dialog: {exc}") from exc
    if proc.returncode != 0:
        raise FolderPickerError((proc.stderr or "The folder dialog failed to start.").strip()[-300:])
    chosen = proc.stdout.strip()
    return str(Path(chosen)) if chosen else None  # Path() turns Tk's forward slashes into D:\style paths
