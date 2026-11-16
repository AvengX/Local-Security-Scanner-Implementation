"""Process-level job lock (prevents overlapping scan-all jobs, e.g. scheduled + manual)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType

from utils.security import pid_alive


class JobLockError(RuntimeError):
    pass


class JobLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.acquired = False

    def holder(self) -> dict | None:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                info = self.holder()
                if info and pid_alive(int(info.get("pid", 0))):
                    raise JobLockError(f"Another scan job is running (pid {info.get('pid')}, "
                                       f"since {info.get('started_at')})") from None
                try:
                    self.path.unlink()  # stale lock from a dead process
                except FileNotFoundError:
                    pass
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"pid": os.getpid(), "started_at": datetime.now(timezone.utc).isoformat()}, fh)
            self.acquired = True
            return
        raise JobLockError("Could not acquire job lock")

    def release(self) -> None:
        if self.acquired:
            try:
                info = self.holder()
                if info and int(info.get("pid", 0)) == os.getpid():
                    self.path.unlink()
            except OSError:
                pass
            self.acquired = False

    def __enter__(self) -> "JobLock":
        self.acquire()
        return self

    def __exit__(self, et: type[BaseException] | None, ev: BaseException | None, tb: TracebackType | None) -> None:
        self.release()
