"""Page — Security Findings (all categories)."""

from __future__ import annotations

from dashboard.findings_view import render_findings


def render() -> None:
    render_findings("all")
