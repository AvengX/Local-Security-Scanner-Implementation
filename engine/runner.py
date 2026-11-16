"""Shared subprocess execution for scanners: argument lists, timeouts, cancellation, timing."""

from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from engine.finding_normalizer import Coverage, NormalizedFinding
from engine.scanner_health import CREATE_NO_WINDOW, describe_os_error
from utils.logger import get_logger
from utils.security import redact

log = get_logger(__name__)

_ACTIVE: set[subprocess.Popen[str]] = set()
_ACTIVE_LOCK = threading.Lock()
CANCEL_EVENT = threading.Event()


@dataclass
class ProcessOutcome:
    exit_code: int | None
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    duration: float
    timed_out: bool = False
    cancelled: bool = False
    launch_error: str | None = None


@dataclass
class ScanExecution:
    """Result of one scanner invocation, before persistence."""

    scanner: str
    scan_type: str
    scan_target: str
    status: str  # COMPLETED | COMPLETED_WITH_FINDINGS | FAILED | TIMED_OUT | CANCELLED | SKIPPED
    coverage: Coverage | None
    started_at: str | None = None
    finished_at: str | None = None
    duration: float | None = None
    exit_code: int | None = None
    tool_version: str | None = None
    database_updated_at: str | None = None
    offline: bool = False
    report_path: str | None = None
    error_message: str | None = None
    findings: list[NormalizedFinding] = field(default_factory=list)
    command: list[str] = field(default_factory=list)

    @property
    def successful(self) -> bool:
        return self.status in ("COMPLETED", "COMPLETED_WITH_FINDINGS")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def run_process(args: list[str], timeout: int, tool: str, cwd: Path | None = None) -> ProcessOutcome:
    started, t0 = _now(), time.monotonic()
    log.info("Launching scanner", extra={"tool": tool, "command": redact(" ".join(args))})
    try:
        proc = subprocess.Popen(  # noqa: S603 - argument list, shell=False
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True,
            encoding="utf-8", errors="replace", shell=False, cwd=str(cwd) if cwd else None,
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError as exc:
        return ProcessOutcome(None, "", "", started, _now(), time.monotonic() - t0,
                              launch_error=describe_os_error(exc, tool))
    with _ACTIVE_LOCK:
        _ACTIVE.add(proc)
    timed_out = cancelled = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out, err = proc.communicate()
    except KeyboardInterrupt:
        cancelled = True
        CANCEL_EVENT.set()
        proc.kill()
        out, err = proc.communicate()
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE.discard(proc)
    if not timed_out and (CANCEL_EVENT.is_set() or (proc.returncode is not None and proc.returncode < 0)):
        cancelled = True
    return ProcessOutcome(proc.returncode, out or "", err or "", started, _now(),
                          round(time.monotonic() - t0, 2), timed_out, cancelled)


def cancel_all() -> int:
    """Kill every running scanner process (used on Ctrl+C)."""
    CANCEL_EVENT.set()
    with _ACTIVE_LOCK:
        procs = list(_ACTIVE)
    for p in procs:
        try:
            p.kill()
        except OSError:
            pass
    return len(procs)


def stderr_excerpt(text: str, limit: int = 800) -> str:
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    tail = "\n".join(lines[-12:])
    return redact(tail[-limit:])
