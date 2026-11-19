"""Windows Task Scheduler integration (Register-ScheduledTask to create; explicit user confirmation required)."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass

from engine.scanner_health import CREATE_NO_WINDOW
from utils.paths import PROJECT_ROOT
from utils.validators import validate_schedule_time

TASK_FOLDER = "LocalSecurityScanner"
TASK_NAMES = {"daily": f"\\{TASK_FOLDER}\\DailyScan", "weekly": f"\\{TASK_FOLDER}\\WeeklyScan"}
WEEK_DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")


@dataclass
class ScheduleResult:
    ok: bool
    message: str
    command: list[str]


def venv_python() -> str:
    candidate = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    return str(candidate) if candidate.is_file() else os.path.realpath(sys.executable)


def _ps_quote(value: str) -> str:
    """Single-quote a value for PowerShell (single quotes are doubled; no expansion happens)."""
    return "'" + value.replace("'", "''") + "'"


_DAY_NAMES = {"MON": "Monday", "TUE": "Tuesday", "WED": "Wednesday", "THU": "Thursday", "FRI": "Friday",
              "SAT": "Saturday", "SUN": "Sunday"}


def task_action(frequency: str) -> tuple[str, str]:
    """(executable, arguments) run by the task: venv Python + run_scan.py scan-all. No shell, no policy change."""
    script = PROJECT_ROOT / "run_scan.py"
    return venv_python(), f'"{script}" scan-all --scheduled --frequency {frequency}'


def build_create_script(frequency: str, time: str = "02:00", day: str = "SUN") -> str:
    """PowerShell Register-ScheduledTask script (no 261-character /TR limit, native overlap protection)."""
    if frequency not in TASK_NAMES:
        raise ValueError("frequency must be 'daily' or 'weekly'")
    validate_schedule_time(time)
    if day not in WEEK_DAYS:
        raise ValueError(f"day must be one of {WEEK_DAYS}")
    exe, args = task_action(frequency)
    trigger = (f"New-ScheduledTaskTrigger -Daily -At {_ps_quote(time)}" if frequency == "daily" else
               f"New-ScheduledTaskTrigger -Weekly -DaysOfWeek {_DAY_NAMES[day]} -At {_ps_quote(time)}")
    name = TASK_NAMES[frequency].rsplit("\\", 1)[1]
    return "; ".join([
        "$ErrorActionPreference = 'Stop'",
        f"$a = New-ScheduledTaskAction -Execute {_ps_quote(exe)} -Argument {_ps_quote(args)} "
        f"-WorkingDirectory {_ps_quote(str(PROJECT_ROOT))}",
        f"$t = {trigger}",
        "$s = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable "
        "-ExecutionTimeLimit (New-TimeSpan -Hours 12)",
        "$p = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) "
        "-LogonType Interactive -RunLevel Limited",
        f"Register-ScheduledTask -TaskPath {_ps_quote(chr(92) + TASK_FOLDER + chr(92))} -TaskName {_ps_quote(name)} "
        "-Action $a -Trigger $t -Settings $s -Principal $p "
        "-Description 'Local Security Scanner scheduled scan' -Force | Out-Null",
        f"'Registered {TASK_NAMES[frequency]}'",
    ])


def build_create_command(frequency: str, time: str = "02:00", day: str = "SUN") -> list[str]:
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            build_create_script(frequency, time, day)]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",  # noqa: S603
                          timeout=60, shell=False, creationflags=CREATE_NO_WINDOW)


def create_task(frequency: str, time: str = "02:00", day: str = "SUN") -> ScheduleResult:
    cmd = build_create_command(frequency, time, day)
    if os.name != "nt":
        return ScheduleResult(False, "Windows Task Scheduler is only available on Windows", cmd)
    proc = _run(cmd)
    ok = proc.returncode == 0
    return ScheduleResult(ok, (proc.stdout or proc.stderr).strip(), cmd)


def delete_task(frequency: str) -> ScheduleResult:
    cmd = ["schtasks", "/Delete", "/TN", TASK_NAMES[frequency], "/F"]
    if os.name != "nt":
        return ScheduleResult(False, "Not on Windows", cmd)
    proc = _run(cmd)
    msg = (proc.stdout or proc.stderr).strip()
    if proc.returncode != 0 and "cannot find" in msg.lower():
        return ScheduleResult(True, f"No {frequency} task was registered", cmd)
    return ScheduleResult(proc.returncode == 0, msg, cmd)


_QUERY_PS = (
    "$ErrorActionPreference = 'SilentlyContinue'; "
    f"$tasks = @(Get-ScheduledTask -TaskPath '\\{TASK_FOLDER}\\'); "
    "$out = foreach ($t in $tasks) { $i = $t | Get-ScheduledTaskInfo; $tr = $t.Triggers | Select-Object -First 1; "
    "[pscustomobject]@{ name = $t.TaskName; state = [string]$t.State; "
    "next = if ($i.NextRunTime) { $i.NextRunTime.ToString('s') } else { '' }; "
    "last = if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) { $i.LastRunTime.ToString('s') } else { '' }; "
    "result = [int64]$i.LastTaskResult; trigger = [string]$tr.CimClass.CimClassName; "
    "start = [string]$tr.StartBoundary; days = [int]$tr.DaysOfWeek } }; "
    "ConvertTo-Json -InputObject @($out) -Compress"
)
_BITS = {1: "SUN", 2: "MON", 4: "TUE", 8: "WED", 16: "THU", 32: "FRI", 64: "SAT"}
RESULT_TEXT = {0: "Finished OK", 1: "Finished - some scanner runs failed", 2: "Could not start (configuration)",
               3: "Skipped - another scan was already running", 267008: "Ready", 267009: "Running now",
               267011: "Not run yet", 2147750687: "Already running (overlap prevented)"}


def _describe(item: dict) -> str:
    when = (item.get("start") or "")[11:16]
    if "Weekly" in (item.get("trigger") or ""):
        days = [d for bit, d in _BITS.items() if int(item.get("days") or 0) & bit]
        return f"Weekly on {', '.join(_DAY_NAMES[d] for d in days) or '?'} at {when}"
    if "Daily" in (item.get("trigger") or ""):
        return f"Daily at {when}"
    return item.get("trigger") or "?"


def query_tasks() -> list[dict[str, str]]:
    """Registered Local Security Scanner tasks: frequency, task, schedule, state, next/last run, last result.

    Uses PowerShell's ScheduledTasks module (JSON) so the result does not depend on the Windows display language."""
    if os.name != "nt":
        return []
    proc = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _QUERY_PS])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    import json

    try:
        items = json.loads(proc.stdout)
    except ValueError:
        return []
    out: list[dict[str, str]] = []
    for it in items if isinstance(items, list) else [items]:
        name = str(it.get("name") or "")
        freq = next((f for f, full in TASK_NAMES.items() if full.endswith("\\" + name)), "")
        if not freq:
            continue
        code = int(it.get("result") or 0)
        out.append({"frequency": freq, "task": TASK_NAMES[freq], "schedule": _describe(it),
                    "state": str(it.get("state") or ""), "next_run": str(it.get("next") or ""),
                    "last_run": str(it.get("last") or ""), "last_result": str(code),
                    "last_result_text": RESULT_TEXT.get(code, f"Exit code {code}")})
    return out


def run_now(frequency: str) -> ScheduleResult:
    """Start a registered task immediately (to test it). It runs in the background like a scheduled run."""
    cmd = ["schtasks", "/Run", "/TN", TASK_NAMES[frequency]]
    if os.name != "nt":
        return ScheduleResult(False, "Not on Windows", cmd)
    proc = _run(cmd)
    return ScheduleResult(proc.returncode == 0, (proc.stdout or proc.stderr).strip(), cmd)


def schedule_health(tasks: list[dict[str, str]], now: "datetime | None" = None) -> tuple[str, str, str]:
    """(state ok|warn|err, short label, explanation) for the sidebar and Overview."""
    from datetime import datetime, timedelta

    if not tasks:
        return "warn", "Not set up", ("No scheduled scan is registered, so scans only run when you start them. Set one "
                                      "up in Settings -> Scheduling.")
    now = now or datetime.now()
    worst = ("ok", "", "")
    for t in tasks:
        code = int(t.get("last_result") or 0)
        period = timedelta(days=1 if t["frequency"] == "daily" else 7)
        nxt = t.get("next_run", "").replace("T", " ")[:16]
        state, label, detail = "ok", f"{t['frequency'].title()} - next {nxt or '?'}", t.get("schedule", "")
        if t.get("state") == "Disabled":
            state, label, detail = "warn", "Disabled", f"The {t['frequency']} task is disabled in Task Scheduler."
        elif code not in (0, 267008, 267009, 267011, 2147750687):
            state, label = "err", f"Last run failed ({RESULT_TEXT.get(code, f'exit {code}')})"
            detail = "See logs/scheduled_runs.log and Scan History for the failed runs."
        elif t.get("last_run"):
            try:
                last = datetime.fromisoformat(t["last_run"])
            except ValueError:
                last = None
            if last and now - last > period + timedelta(days=1):
                state, label = "warn", "Missed runs"
                detail = (f"The last scheduled scan was on {t['last_run'][:10]}. The computer may have been off; "
                          "missed runs start as soon as it is on again.")
        if ("ok", "warn", "err").index(state) >= ("ok", "warn", "err").index(worst[0]) and (state != "ok" or not worst[1]):
            worst = (state, label, detail)
    return worst


def instructions() -> str:
    return (
        "Create (asks for confirmation):  python run_scan.py schedule --frequency daily --time 02:00\n"
        "                                 python run_scan.py schedule --frequency weekly --day SUN --time 03:00\n"
        "Inspect:                         schtasks /Query /TN \\LocalSecurityScanner\\DailyScan /V /FO LIST\n"
        "                                 (or Task Scheduler > Task Scheduler Library > LocalSecurityScanner)\n"
        "Remove:                          python run_scan.py unschedule   (or: schtasks /Delete /TN "
        "\\LocalSecurityScanner\\DailyScan /F)\n"
        "Logs of scheduled runs:          logs/scanner.log and logs/scheduled_runs.log"
    )
