"""Scheduled scans managed from the dashboard: task query (language-independent), health, run-now."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime

import pytest

from services import scheduling_service as sch


def _fake_run(stdout: str, code: int = 0):  # noqa: ANN202
    calls: list[list[str]] = []

    def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, code, stdout, "")
    return run, calls


def test_query_tasks_parses_powershell_json(monkeypatch) -> None:  # noqa: ANN001
    data = [{"name": "WeeklyScan", "state": "Ready", "next": "2026-11-22T02:00:00", "last": "2026-11-15T02:00:04",
             "result": 0, "trigger": "MSFT_TaskWeeklyTrigger", "start": "2026-11-15T02:00:00", "days": 1},
            {"name": "DailyScan", "state": "Ready", "next": "2026-11-20T03:30:00", "last": "", "result": 267011,
             "trigger": "MSFT_TaskDailyTrigger", "start": "2026-11-19T03:30:00", "days": 0},
            {"name": "SomethingElse", "state": "Ready", "result": 0}]
    run, calls = _fake_run(json.dumps(data))
    monkeypatch.setattr(sch, "_run", run)
    monkeypatch.setattr(sch.os, "name", "nt")
    tasks = {t["frequency"]: t for t in sch.query_tasks()}
    assert set(tasks) == {"weekly", "daily"}
    assert tasks["weekly"]["schedule"] == "Weekly on Sunday at 02:00"
    assert tasks["daily"]["schedule"] == "Daily at 03:30" and tasks["daily"]["last_result_text"] == "Not run yet"
    assert calls[0][0] == "powershell.exe" and "Get-ScheduledTask -TaskPath '\\LocalSecurityScanner\\'" in calls[0][-1]


def test_query_tasks_handles_nothing_registered(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(sch.os, "name", "nt")
    for out in ("[]", "", "not json"):
        monkeypatch.setattr(sch, "_run", _fake_run(out)[0])
        assert sch.query_tasks() == []


@pytest.mark.parametrize("tasks,state,label", [
    ([], "warn", "Not set up"),
    ([{"frequency": "weekly", "state": "Ready", "next_run": "2026-11-22T02:00:00", "last_run": "2026-11-15T02:00:04",
       "last_result": "0", "schedule": "Weekly on Sunday at 02:00"}], "ok", "Weekly - next 2026-11-22 02:00"),
    ([{"frequency": "weekly", "state": "Ready", "next_run": "", "last_run": "2026-11-15T02:00:04",
       "last_result": "1", "schedule": ""}], "err", "Last run failed"),
    ([{"frequency": "daily", "state": "Ready", "next_run": "", "last_run": "2026-11-10T02:00:04",
       "last_result": "0", "schedule": ""}], "warn", "Missed runs"),
    ([{"frequency": "daily", "state": "Disabled", "next_run": "", "last_run": "", "last_result": "0",
       "schedule": ""}], "warn", "Disabled"),
])
def test_schedule_health(tasks: list, state: str, label: str) -> None:
    got = sch.schedule_health(tasks, now=datetime(2026, 11, 19, 12, 0))
    assert got[0] == state and got[1].startswith(label)


def test_run_now_and_delete_commands(monkeypatch) -> None:  # noqa: ANN001
    run, calls = _fake_run("SUCCESS")
    monkeypatch.setattr(sch, "_run", run)
    monkeypatch.setattr(sch.os, "name", "nt")
    assert sch.run_now("weekly").ok
    assert sch.delete_task("daily").ok
    assert calls == [["schtasks", "/Run", "/TN", "\\LocalSecurityScanner\\WeeklyScan"],
                     ["schtasks", "/Delete", "/TN", "\\LocalSecurityScanner\\DailyScan", "/F"]]


def test_create_script_is_limited_and_overlap_safe() -> None:
    script = sch.build_create_script("weekly", "02:30", "SAT")
    assert "-Weekly -DaysOfWeek Saturday -At '02:30'" in script
    assert "-RunLevel Limited" in script and "-MultipleInstances IgnoreNew" in script
    assert "scan-all --scheduled --frequency weekly" in script
    with pytest.raises(ValueError):
        sch.build_create_script("hourly")
    with pytest.raises(ValueError):
        sch.build_create_script("daily", "25:00")
