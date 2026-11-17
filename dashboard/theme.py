"""Design system: palette, global CSS, inline SVG icons, HTML components and Plotly styling.

All scanner-derived text passed to these helpers is HTML-escaped. Nothing here loads remote assets
(fonts, icons and images are local), so the dashboard stays fully offline.
"""

from __future__ import annotations

import html
from typing import Any, Iterable

# ----------------------------------------------------------------------------------------------- palette
BG = "#080D18"
BG_2 = "#101827"
CARD = "#141F30"
ELEVATED = "#19263A"
BORDER = "#22314A"
ACCENT = "#38BDF8"
ACCENT_2 = "#8B5CF6"
SUCCESS = "#22C55E"
WARNING = "#F59E0B"
DANGER = "#EF4444"
TEXT = "#F8FAFC"
MUTED = "#94A3B8"
FAINT = "#64748B"

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#EF4444", "HIGH": "#F97316", "MEDIUM": "#EAB308", "LOW": "#60A5FA", "UNKNOWN": "#64748B",
}
# Shape glyphs make severity readable without relying on colour alone.
SEVERITY_GLYPH: dict[str, str] = {"CRITICAL": "◆", "HIGH": "▲", "MEDIUM": "●", "LOW": "▼", "UNKNOWN": "○"}
CATEGORY_COLORS: dict[str, str] = {
    "VULNERABILITY": "#8B5CF6", "SECRET": "#EF4444", "MISCONFIGURATION": "#F59E0B", "LICENSE": "#14B8A6",
    "OTHER": "#64748B",
}
STATUS_COLORS: dict[str, str] = {
    "COMPLETED": "#22C55E", "COMPLETED_WITH_FINDINGS": "#F59E0B", "FAILED": "#EF4444", "TIMED_OUT": "#EF4444",
    "CANCELLED": "#94A3B8", "SKIPPED": "#94A3B8", "RUNNING": "#38BDF8", "PENDING": "#8B5CF6",
    "QUEUED": "#8B5CF6", "OPEN": "#F97316", "UNVERIFIED": "#EAB308", "RESOLVED": "#22C55E",
}
STATUS_LABELS: dict[str, str] = {
    "COMPLETED": "Clean", "COMPLETED_WITH_FINDINGS": "Findings", "FAILED": "Failed", "TIMED_OUT": "Timed out",
    "CANCELLED": "Cancelled", "SKIPPED": "Skipped", "RUNNING": "Running", "PENDING": "Queued", "QUEUED": "Queued",
    "OPEN": "Open", "UNVERIFIED": "Unverified", "RESOLVED": "Resolved",
}
TONES: dict[str, str] = {"ok": SUCCESS, "warn": WARNING, "err": DANGER, "info": ACCENT, "neutral": MUTED,
                         "violet": ACCENT_2}

# ------------------------------------------------------------------------------------------------- icons
# Simple 24x24 stroke icons drawn for this project.
_ICON_PATHS: dict[str, str] = {
    "shield": "M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z",
    "shield_check": "M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z M8.5 12l2.5 2.5 4.5-5",
    "folder": "M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z",
    "scan": "M4 8V5a1 1 0 011-1h3 M16 4h3a1 1 0 011 1v3 M20 16v3a1 1 0 01-1 1h-3 M8 20H5a1 1 0 01-1-1v-3 M4 12h16",
    "alert": "M12 4l9 16H3z M12 10v4 M12 17.5v.01",
    "flame": "M12 3c1 4 5 5.5 5 10a5 5 0 01-10 0c0-2.5 1.5-4 2.5-5 .3 2 1.2 3 2.5 3-1-3 0-6 0-8z",
    "key": "M14.5 9.5a4 4 0 11-1.2-2.8 M13.3 6.7L20 13.4V17h-3v-2h-2v-2l-1.7-1.7",
    "sliders": "M5 6h9 M18 6h1 M5 12h3 M12 12h7 M5 18h11 M20 18h-0 M14 4v4 M8 10v4 M16 16v4",
    "x_circle": "M12 21a9 9 0 100-18 9 9 0 000 18z M9 9l6 6 M15 9l-6 6",
    "check_circle": "M12 21a9 9 0 100-18 9 9 0 000 18z M8 12l3 3 5-6",
    "clock": "M12 21a9 9 0 100-18 9 9 0 000 18z M12 7v5l3 2",
    "database": "M12 3c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3z M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6 M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
    "bug": "M9 7a3 3 0 016 0v1H9z M7 10h10v4a5 5 0 01-10 0z M12 10v9 M4 12h3 M17 12h3 M5 18l2.5-2 M19 18l-2.5-2 M5 6l2.5 2 M19 6l-2.5 2",
    "package": "M12 3l8 4.5v9L12 21l-8-4.5v-9z M4 7.5l8 4.5 8-4.5 M12 12v9",
    "activity": "M3 12h4l3-8 4 16 3-8h4",
    "info": "M12 21a9 9 0 100-18 9 9 0 000 18z M12 11v6 M12 7.5v.01",
    "arrow_right": "M5 12h14 M13 6l6 6-6 6",
    "lab": "M9 3h6 M10 3v6L5 18a2 2 0 001.8 3h10.4a2 2 0 001.8-3L14 9V3 M7.5 14h9",
    "wifi_off": "M3 3l18 18 M8.5 16.5a5 5 0 017 0 M5 13a10 10 0 015.5-2.8 M19 13a10 10 0 00-3-2 M12 20h.01",
}


def icon(name: str, size: int = 18, color: str = "currentColor", stroke: float = 1.8) -> str:
    segs = _ICON_PATHS.get(name, _ICON_PATHS["info"]).split(" M")
    paths = "".join(f"<path d='{s if i == 0 else 'M' + s}'/>" for i, s in enumerate(segs))
    return (f"<svg aria-hidden='true' width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' "
            f"stroke='{color}' stroke-width='{stroke}' stroke-linecap='round' stroke-linejoin='round'>{paths}</svg>")


def esc(value: Any) -> str:
    if value is None or (isinstance(value, float) and value != value):
        return ""
    return html.escape(str(value), quote=True)


# --------------------------------------------------------------------------------------------- components
def sev_badge(sev: str) -> str:
    sev = (sev or "UNKNOWN").upper()
    c = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["UNKNOWN"])
    return (f"<span class='lss-badge' style='--c:{c}'><span aria-hidden='true'>{SEVERITY_GLYPH.get(sev, '○')}"
            f"</span>{esc(sev.title())}</span>")


def status_badge(status: str, label: str | None = None) -> str:
    s = (status or "").upper()
    c = STATUS_COLORS.get(s, MUTED)
    pulse = " lss-pulse" if s in ("RUNNING", "PENDING", "QUEUED") else ""
    return (f"<span class='lss-badge lss-status{pulse}' style='--c:{c}'><span class='dot' aria-hidden='true'>"
            f"</span>{esc(label or STATUS_LABELS.get(s, s.title()))}</span>")


def metric_card(label: str, value: Any, sub: str = "", tone: str = "neutral", icon_name: str = "info",
                aria: str | None = None) -> str:
    c = TONES.get(tone, tone)
    return (f"<div class='lss-metric' style='--c:{c}' role='group' aria-label='{esc(aria or f'{label}: {value}')}'>"
            f"<div class='lss-metric-top'><span class='lss-metric-label'>{esc(label)}</span>"
            f"<span class='lss-metric-icon'>{icon(icon_name, 16, c)}</span></div>"
            f"<div class='lss-metric-value'>{esc(value)}</div><div class='lss-metric-sub'>{esc(sub)}</div></div>")


def metric_grid(cards: Iterable[str], min_width: int = 150) -> str:
    return f"<div class='lss-grid' style='--min:{min_width}px'>{''.join(cards)}</div>"


def notice(kind: str, title: str, body: str = "", icon_name: str | None = None, body_html: str | None = None) -> str:
    """Consistent design for empty, info, warning, error and success states."""
    c = TONES.get(kind, ACCENT)
    ic = icon_name or {"ok": "check_circle", "warn": "alert", "err": "x_circle", "info": "info",
                       "neutral": "info"}.get(kind, "info")
    role = "alert" if kind in ("err", "warn") else "status"
    content = body_html if body_html is not None else esc(body)
    return (f"<div class='lss-notice' role='{role}' style='--c:{c}'><div class='lss-notice-icon'>{icon(ic, 20, c)}"
            f"</div><div><div class='lss-notice-title'>{esc(title)}</div>"
            f"<div class='lss-notice-body'>{content}</div></div></div>")


def chip(text: str, tone: str = "neutral", icon_name: str | None = None, title: str = "") -> str:
    c = TONES.get(tone, tone)
    ic = icon(icon_name, 14, c) if icon_name else f"<span class='dot' style='background:{c}'></span>"
    return f"<span class='lss-chip' title='{esc(title)}' style='--c:{c}'>{ic}{esc(text)}</span>"


def section_title(title: str, caption: str = "") -> str:
    cap = f"<span class='lss-section-cap'>{esc(caption)}</span>" if caption else ""
    return f"<div class='lss-section'><span class='lss-section-title'>{esc(title)}</span>{cap}</div>"


def kv_table(rows: list[tuple[str, str]]) -> str:
    """Two-column definition list; values must already be escaped/HTML."""
    body = "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in rows)
    return f"<dl class='lss-kv'>{body}</dl>"


def safe_url(url: Any) -> str | None:
    """Only http(s) links are rendered (blocks javascript:, data:, file: and similar schemes)."""
    if not isinstance(url, str):
        return None
    u = url.strip()
    return u if u.lower().startswith(("https://", "http://")) and " " not in u else None


# ----------------------------------------------------------------------------------------------- plotly
def style_fig(fig: Any, height: int = 300, title: str | None = None, legend: bool = True) -> Any:
    custom_legend = fig.layout.legend.y is not None and fig.layout.legend.y < 0
    fig.update_layout(
        template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=height,
        margin=dict(l=8, r=8, t=44 if title else 12, b=8),
        title=dict(text=title, font=dict(size=14, color="#E2E8F0"), x=0, xanchor="left", y=0.98) if title else None,
        font=dict(family="Segoe UI Variable Text, Segoe UI, system-ui, sans-serif", size=12, color=MUTED),
        showlegend=legend,
        legend=dict(font=dict(size=11), bgcolor="rgba(0,0,0,0)", title=None) if custom_legend else
        dict(orientation="h", yanchor="bottom", y=1.0, xanchor="right", x=1, font=dict(size=11),
             bgcolor="rgba(0,0,0,0)", title=None),
        hoverlabel=dict(bgcolor=ELEVATED, bordercolor=BORDER, font=dict(color=TEXT, size=12)),
        bargap=0.35,
    )
    fig.update_xaxes(gridcolor="#1A2740", zerolinecolor="#1A2740", linecolor="#22314A", title=None)
    fig.update_yaxes(gridcolor="#1A2740", zerolinecolor="#1A2740", linecolor="#22314A", title=None)
    return fig


PLOTLY_CONFIG: dict[str, Any] = {"displayModeBar": False, "responsive": True}


# --------------------------------------------------------------------------------------------------- CSS
CSS = """
<style>
:root {
  --lss-bg:#080D18; --lss-bg2:#101827; --lss-card:#141F30; --lss-elev:#19263A; --lss-border:#22314A;
  --lss-accent:#38BDF8; --lss-accent2:#8B5CF6; --lss-text:#F8FAFC; --lss-muted:#94A3B8; --lss-faint:#64748B;
  --lss-radius:14px; --lss-ease:cubic-bezier(.2,.7,.2,1);
}
.stApp { background:
  radial-gradient(1100px 500px at 85% -10%, rgba(56,189,248,.07), transparent 60%),
  radial-gradient(900px 480px at -10% 110%, rgba(139,92,246,.06), transparent 60%), var(--lss-bg); }
header[data-testid="stHeader"] { background: transparent; }
/* When the sidebar is collapsed its logo sits in the header: leave room so it never overlaps the title. */
.stApp:has([data-testid="stSidebar"][data-collapsed="true"]) [data-testid="stMainBlockContainer"] { padding-top: 3.6rem; }
.block-container, [data-testid="stMainBlockContainer"] { padding-top: 1.1rem; padding-bottom: 2.5rem;
  max-width: 1560px; padding-left: clamp(.8rem, 2.4vw, 2.6rem); padding-right: clamp(.8rem, 2.4vw, 2.6rem); }
[data-testid="stSidebar"] { background: linear-gradient(180deg,#0B1220 0%, #090F1C 100%); }
[data-testid="stSidebarNav"] a { border-radius: 10px; transition: background .18s var(--lss-ease), color .18s; }
[data-testid="stSidebarNav"] a:hover { background: rgba(56,189,248,.08); }
[data-testid="stSidebarNav"] a[aria-current="page"] { background: linear-gradient(90deg, rgba(56,189,248,.16), rgba(139,92,246,.06));
  box-shadow: inset 2px 0 0 var(--lss-accent); }
[data-testid="stSidebarNavSeparator"] { border-color: #1A2740; }
[data-testid="stSidebarHeader"] img { max-width: 100%; }
h1, h2, h3 { letter-spacing: -.01em; }
p, li, label, .stMarkdown { font-size: .93rem; }
:focus-visible { outline: 2px solid var(--lss-accent) !important; outline-offset: 2px; border-radius: 6px; }

/* Buttons */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button, [data-testid="stPageLink"] a {
  border-radius: 10px; border: 1px solid var(--lss-border); transition: transform .12s var(--lss-ease),
  border-color .18s, background .18s, box-shadow .18s; font-weight: 600; }
.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {
  border-color: rgba(56,189,248,.55); box-shadow: 0 0 0 3px rgba(56,189,248,.08); }
.stButton > button:active, .stDownloadButton > button:active { transform: translateY(1px) scale(.99); }
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primaryFormSubmit"] {
  background: linear-gradient(135deg, #38BDF8 0%, #6D7CF6 100%); color: #051221; border: 0; }
.stButton > button[kind="primary"]:hover { box-shadow: 0 6px 22px -8px rgba(56,189,248,.65); }
.stButton > button:disabled { opacity: .45; }

/* Bordered containers become cards */
[data-testid="stVerticalBlockBorderWrapper"], div[data-testid="stVerticalBlock"][class*="st-key-panel"] {
  border-radius: var(--lss-radius); }
div[class*="st-key-panel"] { background: linear-gradient(180deg, rgba(25,38,58,.55), rgba(20,31,48,.55));
  border: 1px solid var(--lss-border); border-radius: var(--lss-radius); padding: 14px 16px 10px;
  box-shadow: 0 10px 30px -18px rgba(0,0,0,.7); }

/* Inputs, tables, tabs, expanders */
[data-baseweb="input"], [data-baseweb="select"] > div, [data-baseweb="textarea"] { border-radius: 10px !important; }
[data-testid="stDataFrame"] { border: 1px solid var(--lss-border); border-radius: 12px; overflow: hidden; }
[data-testid="stTabs"] [role="tablist"] { gap: .25rem; border-bottom: 1px solid var(--lss-border); }
[data-testid="stTabs"] button[role="tab"] { border-radius: 10px 10px 0 0; padding: .45rem .9rem; }
[data-testid="stExpander"] details { border-radius: 12px; border-color: var(--lss-border); background: rgba(20,31,48,.5); }
[data-testid="stPlotlyChart"] { border-radius: 12px; }
[data-testid="stAlert"] { border-radius: 12px; }

/* Top bar */
div[class*="st-key-topbar"] { border-bottom: 1px solid var(--lss-border); padding-bottom: .55rem; margin-bottom: .35rem; }
div[class*="st-key-topbar"] [data-testid="stHorizontalBlock"] { flex-wrap: wrap; row-gap: .4rem; }
div[class*="st-key-topbar"] [data-testid="stColumn"]:nth-child(1) { flex: 3 1 260px !important; min-width: 240px; }
div[class*="st-key-topbar"] [data-testid="stColumn"]:nth-child(2) { flex: 3 1 260px !important; min-width: 240px; }
div[class*="st-key-topbar"] [data-testid="stColumn"]:nth-child(3) { flex: 0 0 118px !important; min-width: 118px; }
[data-testid="stForm"] [data-testid="stColumn"]:last-child:has(button) { min-width: 110px; }
.lss-title { font-size: clamp(1.25rem, 1.6vw, 1.6rem); font-weight: 700; color: var(--lss-text); margin: 0; line-height: 1.2; }
.lss-head { display: flow-root; padding-bottom: .1rem; }
div[class*="st-key-topbar"] [data-testid="stMarkdownContainer"] { margin-bottom: 0 !important; }
.lss-subtitle { color: var(--lss-muted); font-size: .86rem; margin: .15rem 0 0; line-height: 1.4; }
.lss-chips { display: flex; flex-wrap: wrap; gap: .4rem; justify-content: flex-end; align-items: center; min-height: 2.4rem; }
.lss-chip { display: inline-flex; align-items: center; gap: .38rem; padding: .28rem .6rem; border-radius: 999px;
  background: rgba(20,31,48,.85); border: 1px solid var(--lss-border); color: #CBD5E1; font-size: .76rem;
  white-space: nowrap; }
.lss-chip .dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; box-shadow: 0 0 0 3px rgba(255,255,255,.04); }

/* Metric cards */
.lss-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(var(--min,150px), 1fr)); gap: .75rem; margin: .35rem 0 .9rem; }
.lss-metric { position: relative; background: linear-gradient(180deg, #172338 0%, #121C2D 100%); border: 1px solid var(--lss-border);
  border-radius: var(--lss-radius); padding: .8rem .95rem .75rem; overflow: hidden; min-width: 0;
  transition: transform .18s var(--lss-ease), border-color .18s, box-shadow .18s; }
.lss-metric::before { content: ""; position: absolute; inset: 0 0 auto 0; height: 2px; background: linear-gradient(90deg, var(--c), transparent 85%); opacity: .9; }
.lss-metric:hover { transform: translateY(-2px); border-color: color-mix(in srgb, var(--c) 45%, #22314A); box-shadow: 0 12px 28px -18px var(--c); }
.lss-metric-top { display: flex; justify-content: space-between; align-items: flex-start; gap: .5rem; min-height: 1.9rem; }
.lss-metric-label { color: var(--lss-muted); font-size: .7rem; font-weight: 600; text-transform: uppercase; letter-spacing: .05em;
  line-height: 1.25; overflow-wrap: anywhere; min-width: 0; }
.lss-metric-icon { display: inline-flex; padding: .3rem; border-radius: 9px; background: color-mix(in srgb, var(--c) 14%, transparent); }
.lss-metric-value { font-size: clamp(1.35rem, 2vw, 1.9rem); font-weight: 700; color: var(--lss-text); margin-top: .25rem; line-height: 1.15;
  font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.lss-metric-sub { color: var(--lss-faint); font-size: .74rem; margin-top: .15rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* Badges */
.lss-badge { display: inline-flex; align-items: center; gap: .32rem; padding: .12rem .55rem; border-radius: 999px; font-size: .74rem;
  font-weight: 600; color: var(--c); background: color-mix(in srgb, var(--c) 13%, transparent);
  border: 1px solid color-mix(in srgb, var(--c) 35%, transparent); white-space: nowrap; }
.lss-status .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--c); }
.lss-pulse .dot { animation: lss-pulse 1.4s ease-in-out infinite; }
@keyframes lss-pulse { 0%,100% { opacity: 1; } 50% { opacity: .25; } }

/* Notices (empty / info / warning / error / success) */
.lss-notice { display: flex; gap: .8rem; align-items: flex-start; padding: .85rem 1rem; border-radius: 12px; margin: .3rem 0 .8rem;
  background: linear-gradient(90deg, color-mix(in srgb, var(--c) 10%, #121C2D), #121C2D 70%);
  border: 1px solid color-mix(in srgb, var(--c) 30%, #22314A); }
.lss-notice-icon { padding-top: .05rem; }
.lss-notice-title { font-weight: 650; color: var(--lss-text); font-size: .93rem; }
.lss-notice-body { color: #B6C2D3; font-size: .85rem; margin-top: .15rem; line-height: 1.5; }
.lss-notice-body code { font-size: .8rem; }

/* Sections, posture hero, lists */
.lss-section { display: flex; align-items: baseline; gap: .6rem; margin: .9rem 0 .4rem; flex-wrap: wrap; }
.lss-section-title { font-size: .98rem; font-weight: 650; color: #E2E8F0; }
.lss-section-cap { font-size: .78rem; color: var(--lss-faint); }
.lss-hero { position: relative; display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: 1.2rem; align-items: center;
  padding: 1.1rem 1.25rem; border-radius: 16px; border: 1px solid var(--lss-border); overflow: hidden;
  background: linear-gradient(120deg, color-mix(in srgb, var(--c) 14%, #131D2E) 0%, #131D2E 55%, #111a2b 100%); margin: .3rem 0 .9rem; }
.lss-hero::after { content: ""; position: absolute; right: -60px; top: -60px; width: 220px; height: 220px; border-radius: 50%;
  background: radial-gradient(circle, color-mix(in srgb, var(--c) 22%, transparent), transparent 70%); pointer-events: none; }
.lss-hero-kicker { font-size: .72rem; letter-spacing: .12em; text-transform: uppercase; color: var(--lss-muted); font-weight: 600; }
.lss-hero-level { font-size: clamp(1.3rem, 2.2vw, 1.85rem); font-weight: 750; color: var(--c); margin: .15rem 0 .25rem; display: flex; align-items: center; gap: .5rem; }
.lss-hero-text { color: #CBD5E1; font-size: .9rem; line-height: 1.5; }
.lss-hero-stats { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: .55rem; position: relative; z-index: 1; }
.lss-hero-stat { background: rgba(8,13,24,.45); border: 1px solid rgba(148,163,184,.12); border-radius: 12px; padding: .55rem .7rem; min-width: 0; }
.lss-hero-stat b { display: block; font-size: 1.15rem; color: var(--lss-text); font-variant-numeric: tabular-nums; }
.lss-hero-stat span { font-size: .72rem; color: var(--lss-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: block; }
@media (max-width: 1100px) { .lss-hero { grid-template-columns: 1fr; } }

.lss-list { list-style: none; margin: 0; padding: 0; }
.lss-list li { display: flex; gap: .7rem; align-items: flex-start; padding: .6rem .2rem; border-bottom: 1px solid rgba(34,49,74,.7); font-size: .86rem; color: #CBD5E1; }
.lss-list li:last-child { border-bottom: 0; }
.lss-list .t { color: var(--lss-text); font-weight: 600; }
.lss-list .s { color: var(--lss-faint); font-size: .78rem; }
.lss-list .grow { flex: 1; min-width: 0; overflow-wrap: anywhere; }
.lss-step { flex: none; width: 1.55rem; height: 1.55rem; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center;
  font-size: .75rem; font-weight: 700; color: var(--c); background: color-mix(in srgb, var(--c) 15%, transparent); }

.lss-table { width: 100%; border-collapse: collapse; font-size: .84rem; }
.lss-table th { text-align: left; color: var(--lss-faint); font-weight: 600; font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
  padding: .35rem .45rem; border-bottom: 1px solid var(--lss-border); }
.lss-table td { padding: .5rem .45rem; border-bottom: 1px solid rgba(34,49,74,.6); color: #CBD5E1; overflow-wrap: anywhere; vertical-align: top; }
.lss-table tr:last-child td { border-bottom: 0; }
.lss-table-wrap { overflow-x: auto; }

.lss-kv { display: grid; grid-template-columns: minmax(110px, max-content) 1fr; gap: .35rem 1rem; margin: .2rem 0 .6rem; font-size: .86rem; }
.lss-kv dt { color: var(--lss-faint); }
.lss-kv dd { margin: 0; color: #E2E8F0; overflow-wrap: anywhere; }
.lss-desc { white-space: pre-wrap; color: #CBD5E1; font-size: .86rem; line-height: 1.55; background: rgba(8,13,24,.4);
  border: 1px solid var(--lss-border); border-radius: 10px; padding: .7rem .85rem; max-height: 260px; overflow: auto; }
.lss-remed { border-left: 3px solid var(--c); background: rgba(8,13,24,.45); border-radius: 0 10px 10px 0; padding: .6rem .85rem;
  color: #E2E8F0; font-size: .86rem; line-height: 1.5; white-space: pre-wrap; }

/* Sidebar health panel */
.lss-health { margin-top: .4rem; padding: .7rem .75rem; border: 1px solid #1A2740; border-radius: 12px; background: rgba(20,31,48,.55); }
.lss-health-title { font-size: .68rem; letter-spacing: .12em; text-transform: uppercase; color: var(--lss-faint); font-weight: 700; margin-bottom: .35rem; }
.lss-health-row { display: flex; justify-content: space-between; align-items: center; gap: .5rem; padding: .28rem 0; font-size: .8rem; color: #CBD5E1; }
.lss-health-row .state { display: inline-flex; align-items: center; gap: .35rem; font-weight: 600; color: var(--c); font-size: .76rem; white-space: nowrap; }
.lss-health-row .state i { width: 7px; height: 7px; border-radius: 50%; background: var(--c); display: inline-block; }
.lss-health-foot { font-size: .7rem; color: var(--lss-faint); margin-top: .35rem; }
.lss-running { margin-top: .5rem; padding: .55rem .7rem; border-radius: 10px; border: 1px solid rgba(56,189,248,.35);
  background: rgba(56,189,248,.07); font-size: .78rem; color: #BAE6FD; }

/* Responsive helpers for column groups that should wrap on narrow screens */
div[class*="st-key-wrap"] [data-testid="stHorizontalBlock"] { flex-wrap: wrap; gap: 1rem; }
div[class*="st-key-wrap"] [data-testid="stColumn"] { min-width: min(100%, 360px); flex: 1 1 360px !important; }
div[class*="st-key-actions"] [data-testid="stHorizontalBlock"] { flex-wrap: wrap; gap: .5rem; }
div[class*="st-key-actions"] [data-testid="stColumn"] { min-width: 170px; flex: 1 1 170px !important; }
div[class*="st-key-panel_filters"] [data-testid="stHorizontalBlock"] { flex-wrap: wrap; row-gap: .25rem; }
div[class*="st-key-panel_filters"] [data-testid="stColumn"] { min-width: 180px; flex: 1 1 180px !important; }
@media (max-width: 900px) { .lss-chips { justify-content: flex-start; } }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
}
</style>
"""
