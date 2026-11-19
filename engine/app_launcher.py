"""Start a project's web app for the web scan, and stop it afterwards.

Used only when the user configured a start command for a web address (Settings -> Web scan). Rules:
* If something already answers at the address, nothing is started and nothing is stopped - the user's own
  running app is never touched.
* The command comes from the user's own configuration. It is split into a program and arguments and started
  without a shell, in the project folder (or a sub-folder of it), with no console window.
* The address is loopback-only (validated in the configuration), so the scanner only waits for a local app.
* The app's output goes to logs/apps/<project>.log on this computer - never into the database or reports.
* Stopping kills the whole process tree (Flask's reloader starts a child process) and verifies the port is free.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from engine.runner import CANCEL_EVENT
from utils.logger import get_logger

log = get_logger(__name__)
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200


class LaunchError(Exception):
    pass


def _port(url: str) -> tuple[str, int]:
    p = urlsplit(url)
    return p.hostname or "127.0.0.1", p.port or (443 if p.scheme == "https" else 80)


def is_listening(url: str, timeout: float = 1.0) -> bool:
    host, port = _port(url)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host.strip("[]"), port))
            return True
        except OSError:
            return False


def split_command(command: str, cwd: Path) -> list[str]:
    """Program + arguments. A relative program path (e.g. .venv\\Scripts\\python.exe) is resolved inside cwd;
    a bare name (python, npm, flask) is looked up on PATH."""
    command = command.strip()
    if not command:
        raise LaunchError("No start command configured")
    if re.search(r"[|&;<>`]|\$\(", command):
        raise LaunchError("The start command must be a single program with arguments (no |, &, ;, <, > or "
                          "backticks). Put anything more complex in a script and start that.")
    parts = [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'" else p
             for p in shlex.split(command, posix=False)]
    prog = parts[0]
    local = (cwd / prog)
    if any(sep in prog for sep in ("/", "\\")) or local.is_file():
        resolved = local if local.is_file() else Path(prog)
        if not resolved.is_file():
            raise LaunchError(f"Start program not found: {prog}")
        parts[0] = str(resolved.resolve())
    else:
        found = shutil.which(prog)
        if not found:
            raise LaunchError(f"Start program '{prog}' was not found on PATH")
        parts[0] = found
    return parts


class AppLauncher:
    def __init__(self, command: str, cwd: Path, url: str, wait_seconds: int, log_file: Path) -> None:
        self.command, self.cwd, self.url, self.wait = command, cwd, url, wait_seconds
        self.log_file = log_file
        self.proc: subprocess.Popen | None = None
        self.started = False
        self.already_running = False

    def start(self) -> None:
        if is_listening(self.url):
            self.already_running = True  # the user's own app: use it, never stop it
            return
        argv = split_command(self.command, self.cwd)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        out = self.log_file.open("w", encoding="utf-8", errors="replace")
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        kwargs: dict = {"cwd": str(self.cwd), "stdin": subprocess.DEVNULL, "stdout": out, "stderr": subprocess.STDOUT,
                        "env": env}
        if sys.platform == "win32":
            kwargs["creationflags"] = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        try:
            self.proc = subprocess.Popen(argv, **kwargs)  # noqa: S603 - user's own configured command, no shell
        except OSError as exc:
            out.close()
            raise LaunchError(f"Could not start the app: {exc}") from exc
        finally:
            if self.proc is not None:
                out.close()  # the child keeps its own handle
        self.started = True
        log.info("Started app for web scan", extra={"url": self.url, "pid": self.proc.pid})
        deadline = time.monotonic() + self.wait
        while time.monotonic() < deadline:
            if CANCEL_EVENT.is_set():
                self.stop()
                raise LaunchError("Scan cancelled while waiting for the app to start")
            if self.proc.poll() is not None:
                code = self.proc.returncode
                self.stop()
                raise LaunchError(f"The app exited right after starting (exit code {code}). Its output is in "
                                  f"{self.log_file}.")
            if is_listening(self.url):
                time.sleep(0.5)  # let the first request handler come up
                return
            time.sleep(0.5)
        self.stop()
        raise LaunchError(f"The app did not answer at {self.url} within {self.wait}s after starting. Check the start "
                          f"command and port; its output is in {self.log_file}.")

    def stop(self) -> None:
        if not self.started or self.proc is None:
            return
        pid = self.proc.pid
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True,
                               creationflags=CREATE_NO_WINDOW, timeout=30)
            else:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        for _ in range(20):  # child processes (e.g. Flask reloader) may hold the port a moment longer
            if not is_listening(self.url, 0.3):
                break
            time.sleep(0.25)
        else:
            log.warning("Port still answering after stopping the app", extra={"url": self.url, "pid": pid})
        self.started = False
        log.info("Stopped app after web scan", extra={"url": self.url, "pid": pid})

    def __enter__(self) -> "AppLauncher":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
