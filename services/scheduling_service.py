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


def query_tasks() -> list[dict[str, str]]:
    """Return registered Local Security Scanner tasks (name, next run, status)."""
    if os.name != "nt":
        return []
    out: list[dict[str, str]] = []
    for freq, name in TASK_NAMES.items():
        proc = _run(["schtasks", "/Query", "/TN", name, "/FO", "LIST", "/V"])
        if proc.returncode != 0:
            continue
        info: dict[str, str] = {"frequency": freq, "task": name}
        for line in proc.stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                if k in ("Next Run Time", "Status", "Last Run Time", "Last Result", "Schedule Type"):
                    info[k] = v.strip()
        out.append(info)
    return out


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
