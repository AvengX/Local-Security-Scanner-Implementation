"""Security helpers: secret redaction, safe path resolution, process liveness."""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import sys
from pathlib import Path

from utils.paths import is_within

# Patterns for values that must never reach logs. Deliberately broad: false positives only cost readability.
_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-SLACK-TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED-API-KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED-GOOGLE-KEY]"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "[REDACTED-JWT]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
     "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"
                r"(\s*[:=]\s*)(['\"]?)[^\s'\"]{4,}\3"), r"\1\2\3[REDACTED]\3"),
]


def redact(text: str | None) -> str:
    """Remove likely secret values from free text (logs, stderr excerpts)."""
    if not text:
        return ""
    out = text
    for pattern, repl in _REDACTION_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def sha256_hex(*parts: object) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(str(part if part is not None else "").encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()


def safe_report_path(candidate: str | Path, reports_dir: Path) -> Path:
    """Resolve ``candidate`` and ensure it is a regular file inside ``reports_dir``.

    Raises ``PermissionError`` for anything outside the reports directory (path traversal, absolute
    paths elsewhere, symlinks escaping the directory) and ``FileNotFoundError`` if missing.
    """
    raw = Path(candidate)
    if not raw.is_absolute():
        raw = reports_dir / raw
    resolved = raw.resolve()
    if not is_within(resolved, reports_dir):
        raise PermissionError("Requested report is outside the configured reports directory")
    if not resolved.is_file():
        raise FileNotFoundError(f"Report file not found: {resolved.name}")
    return resolved


# Docker/OCI image reference: [registry[:port]/]name[:tag][@digest]
_IMAGE_REF = re.compile(
    r"^(?:[a-zA-Z0-9.\-]+(?::[0-9]+)?/)?[a-z0-9]+(?:[._\-/][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127})?"
    r"(?:@sha256:[a-f0-9]{64})?$"
)


def is_safe_image_ref(ref: str) -> bool:
    return bool(ref) and not ref.startswith("-") and len(ref) <= 512 and bool(_IMAGE_REF.match(ref))


def is_safe_cli_value(value: str) -> bool:
    """Reject values that could be interpreted as flags or contain control characters."""
    return bool(value) and not value.startswith("-") and not any(ord(c) < 32 for c in value)


def process_start_time(pid: int) -> float | None:
    """Creation time of a running process (seconds, platform clock), or None if it can't be read.

    Used together with the PID to tell "the same process" from "a new process that reused the PID"."""
    if pid <= 0:
        return None
    if sys.platform == "win32":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            ft = [ctypes.c_ulonglong() for _ in range(4)]  # creation, exit, kernel, user (FILETIME, 100 ns)
            if kernel32.GetProcessTimes(handle, *(ctypes.byref(x) for x in ft)):
                return ft[0].value / 1e7
            return None
        finally:
            kernel32.CloseHandle(handle)
    try:  # Linux: start time in clock ticks since boot (field 22 of /proc/<pid>/stat)
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[19]) / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        return None


def same_process_alive(pid: int, start: float | None) -> bool:
    """True if ``pid`` is running *and* (when ``start`` is known) is the same process that recorded it."""
    if not pid_alive(pid):
        return False
    if start is None:
        return True
    now = process_start_time(pid)
    return now is None or abs(now - start) < 1.0


def pid_alive(pid: int) -> bool:
    """Return True if a process with ``pid`` is running. Never sends signals."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            # Access denied means the process exists but belongs to someone else.
            return ctypes.GetLastError() == 5  # type: ignore[attr-defined]
        try:
            code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return code.value == STILL_ACTIVE
            return False
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
