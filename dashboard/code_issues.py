"""Page — Code issues (SAST: security bugs in the project's own Python code, found by Bandit)."""

from __future__ import annotations

from dashboard.findings_view import render_findings


def render() -> None:
    render_findings("code")
