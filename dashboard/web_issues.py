"""Page — Web app issues (DAST: problems found by testing the user's running web apps through their address)."""

from __future__ import annotations

from dashboard.findings_view import render_findings


def render() -> None:
    render_findings("web")
