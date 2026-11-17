"""Page — Secrets (values are never stored or shown)."""

from __future__ import annotations

from dashboard.findings_view import render_findings


def render() -> None:
    render_findings("secret")
