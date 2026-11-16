"""Shared dashboard helpers: config/DB access, styling, cards, banners and background jobs."""

from __future__ import annotations

import html
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import streamlit as st

from database.db import init_db
from engine.scanner_health import CREATE_NO_WINDOW, DbFreshness, trivy_db_freshness
from utils.config import AppConfig, load_config
from utils.paths import PROJECT_ROOT

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#EF4444", "HIGH": "#F97316", "MEDIUM": "#EAB308", "LOW": "#3B82F6", "UNKNOWN": "#6B7280",
}
CATEGORY_COLORS: dict[str, str] = {
    "VULNERABILITY": "#8B5CF6", "SECRET": "#EF4444", "MISCONFIGURATION": "#F59E0B", "LICENSE": "#14B8A6",
    "OTHER": "#6B7280",
}
STATUS_COLORS: dict[str, str] = {
    "COMPLETED": "#22C55E", "COMPLETED_WITH_FINDINGS": "#F59E0B", "FAILED": "#EF4444", "TIMED_OUT": "#EF4444",
    "CANCELLED": "#9CA3AF", "SKIPPED": "#9CA3AF", "RUNNING": "#3B82F6", "PENDING": "#3B82F6",
}
PLOTLY_LAYOUT: dict[str, Any] = dict(
    template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    margin=dict(l=10, r=10, t=40, b=10), height=340, font=dict(family="Segoe UI, Inter, sans-serif", size=12),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
)
PAGES: dict[str, Any] = {}

CSS = """
<style>
.block-container {padding-top: 1.6rem; padding-bottom: 2rem; max-width: 1500px;}
section[data-testid="stSidebar"] {border-right: 1px solid #1F2A44;}
.lss-card {background: linear-gradient(180deg,#131D33 0%,#0F172A 100%); border:1px solid #1F2A44;
  border-radius: 12px; padding: 14px 16px; height: 100%;}
.lss-card .label {color:#94A3B8; font-size:.74rem; text-transform:uppercase; letter-spacing:.06em;
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
.lss-card .value {font-size:clamp(1.05rem, 1.7vw, 1.75rem); font-weight:700; color:#F1F5F9; line-height:1.25;
  margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
.lss-card .sub {color:#64748B; font-size:.75rem; margin-top:2px; white-space:nowrap; overflow:hidden;
  text-overflow:ellipsis;}
.lss-accent {border-left: 4px solid var(--accent);}
.lss-title {font-size:1.55rem; font-weight:700; color:#F8FAFC; margin-bottom:0;}
.lss-subtitle {color:#94A3B8; font-size:.9rem; margin-top:0; margin-bottom:1rem;}
.lss-pill {display:inline-block; padding:2px 10px; border-radius:999px; font-size:.72rem; font-weight:600;
  color:#0B1220;}
.lss-banner {border-radius:10px; padding:10px 14px; margin-bottom:12px; font-size:.88rem;}
.lss-ok {background:#052E1B; border:1px solid #14532D; color:#BBF7D0;}
.lss-warn {background:#2A1B04; border:1px solid #78350F; color:#FDE68A;}
.lss-err {background:#2B0B0B; border:1px solid #7F1D1D; color:#FECACA;}
</style>
"""


@st.cache_resource(show_spinner=False)
def _conn_for(db_path: str) -> sqlite3.Connection:
    return init_db(Path(db_path))


def get_config() -> AppConfig:
    return load_config()


def get_conn(cfg: AppConfig | None = None) -> sqlite3.Connection:
    cfg = cfg or get_config()
    cfg.ensure_dirs()
    return _conn_for(str(cfg.db_path))


def get_freshness(cfg: AppConfig) -> DbFreshness:
    return trivy_db_freshness(cfg.trivy.cache_dir, cfg.scan.db_freshness_hours)


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str) -> None:
    st.markdown(f"<p class='lss-title'>{html.escape(title)}</p><p class='lss-subtitle'>{html.escape(subtitle)}</p>",
                unsafe_allow_html=True)


def card(label: str, value: Any, sub: str = "", accent: str | None = None) -> str:
    style = f" lss-accent' style='--accent:{accent}" if accent else ""
    return (f"<div class='lss-card{style}'><div class='label'>{html.escape(label)}</div>"
            f"<div class='value'>{html.escape(str(value))}</div><div class='sub'>{html.escape(sub)}</div></div>")


def card_row(cards: list[str]) -> None:
    cols = st.columns(len(cards))
    for col, c in zip(cols, cards):
        col.markdown(c, unsafe_allow_html=True)


def banner(text: str, kind: str = "ok") -> None:
    st.markdown(f"<div class='lss-banner lss-{kind}'>{html.escape(text)}</div>", unsafe_allow_html=True)


def freshness_banner(cfg: AppConfig) -> DbFreshness:
    f = get_freshness(cfg)
    mode = "OFFLINE mode" if cfg.scan.offline else "Online mode"
    if not f.present:
        banner(f"{mode} · Vulnerability DB missing — {f.message}", "err")
    elif f.stale:
        banner(f"{mode} · {f.message}", "warn")
    else:
        banner(f"{mode} · {f.message} (threshold {cfg.scan.db_freshness_hours}h)", "ok")
    return f


def fmt_ts(value: Any, short: bool = False) -> str:
    if not value or (isinstance(value, float) and value != value):
        return "—"
    return str(value).replace("T", " ")[: 16 if short else 19]


def empty_state(message: str) -> None:
    st.info(message, icon=":material/inbox:")


def launch_background(args: list[str], cfg: AppConfig) -> int:
    """Start a CLI job (scan/discover) detached from the Streamlit process; output goes to logs/."""
    py = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    exe = str(py) if py.is_file() else sys.executable
    log_path = cfg.logs_dir / "dashboard_jobs.log"
    cfg.logs_dir.mkdir(parents=True, exist_ok=True)
    flags = CREATE_NO_WINDOW | (0x00000200 if os.name == "nt" else 0)  # CREATE_NEW_PROCESS_GROUP
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(f"\n=== {' '.join(args)}\n")
        fh.flush()
        proc = subprocess.Popen(  # noqa: S603 - fixed script + validated arguments
            [exe, str(PROJECT_ROOT / "run_scan.py"), *args], cwd=str(PROJECT_ROOT), stdout=fh,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, shell=False, creationflags=flags,
        )
    return proc.pid


def severity_pill(sev: str) -> str:
    return f"<span class='lss-pill' style='background:{SEVERITY_COLORS.get(sev, '#6B7280')}'>{sev}</span>"
