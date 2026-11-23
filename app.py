"""Local Security Scanner — one page: paste a folder, scan everything in it, get a VAPT report as PDF.

Start with:  scripts\\start.ps1   (or)   streamlit run app.py --server.address 127.0.0.1
Everything runs on this computer; nothing is uploaded.
"""

from __future__ import annotations

import html
import secrets
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

st.set_page_config(page_title="Local Security Scanner", page_icon=str(ROOT / "dashboard" / "assets" / "emblem.svg"),
                   layout="wide", initial_sidebar_state="collapsed")

from dashboard import scan_job  # noqa: E402
from dashboard.common import get_config, inject_css, notice  # noqa: E402
from utils.logger import setup_logging  # noqa: E402
from utils.version import __version__  # noqa: E402

ASSETS = ROOT / "dashboard" / "assets"
# Files here are served by Streamlit at /app/static/... (server.enableStaticServing) so the browser's own PDF viewer
# can show the report inside the page. Copies use random names and are cleared after a day.
VIEW_DIR = ROOT / "static" / "reports"
SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEV_NAME = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Info"}


def _view_url(pdf: Path) -> str:
    """Copy the PDF to the static folder under a random name and return its URL."""
    VIEW_DIR.mkdir(parents=True, exist_ok=True)
    cutoff = time.time() - 86400
    for old in VIEW_DIR.glob("*.pdf"):
        try:
            if old.stat().st_mtime < cutoff:
                old.unlink()
        except OSError:
            pass
    cache = st.session_state.setdefault("view_copies", {})
    name = cache.get(str(pdf))
    if not name or not (VIEW_DIR / name).is_file():
        name = f"{secrets.token_hex(8)}.pdf"
        shutil.copyfile(pdf, VIEW_DIR / name)
        cache[str(pdf)] = name
    return f"app/static/reports/{name}"


def _show_pdf(pdf: Path, key: str) -> None:
    data = pdf.read_bytes()
    c1, c2, _ = st.columns([1, 1, 3])
    c1.download_button("Download PDF", data, file_name=pdf.name, mime="application/pdf", icon=":material/download:",
                       type="primary", key=f"dl_{key}", width="stretch")
    url = _view_url(pdf)
    c2.link_button("Open in new tab", url, icon=":material/open_in_new:", width="stretch")
    # Chrome / Edge block their PDF viewer inside the page's sandboxed frames, so the PDF pages are shown as images
    # (rendered by Windows' own PDF engine). "Open in new tab" still uses the browser's real PDF viewer.
    from services.pdf_preview import PreviewError, page_images

    try:
        with st.spinner("Preparing the preview…"):
            pages = page_images(pdf)
    except PreviewError as exc:
        notice("warn", "Preview not available", f"{exc} Use Download PDF or Open in new tab.")
        return
    with st.container(height=900, border=True):
        for n, img in enumerate(pages, 1):
            st.image(str(img), width="stretch", caption=f"Page {n} of {len(pages)}")


@st.fragment(run_every=2)
def _progress() -> None:
    """Live progress of the background scan; reloads the page once it has finished."""
    job = scan_job.current()
    if job is None:
        return
    state, label, lines = job.snapshot()
    if state != "running":
        st.rerun()
    mins, secs = divmod(int(time.time() - job.started), 60)
    with st.status(f"{label}  ({mins}:{secs:02d})", expanded=True):
        st.markdown("\n\n".join(lines[-16:]) or "Starting…")
        st.caption("You can leave this page open; the scan keeps running even if you click around or refresh.")


def _finished_panel() -> None:
    job = scan_job.current()
    if job is None or job.state == "running":
        return
    if job.state == "error":
        notice("err", "The scan could not finish", job.error or "")
        return
    with st.status(job.label, state="complete", expanded=False):
        st.markdown("\n\n".join(job.lines))


def _summary_line(counts: dict[str, int]) -> str:
    parts = [f"{counts[s]} {SEV_NAME[s]}" for s in SEV_ORDER if counts.get(s)]
    return " · ".join(parts) if parts else "No open issues"


def main() -> None:
    inject_css()
    try:
        cfg = get_config()
    except Exception as exc:  # noqa: BLE001
        notice("err", "Could not load configuration", str(exc))
        st.stop()
    setup_logging(cfg.logs_dir, cfg.log_level, console=False)

    st.title("Security assessment (VAPT)")
    st.caption("Paste the path of a project folder. Everything in it is scanned on this computer — libraries, "
               "passwords and keys, source code, Docker / cloud settings and (if set up) the running web app — and "
               "you get a PDF report. Nothing is changed or uploaded. You can also paste a website address "
               "(https://…) to test a live site you are authorised to test; its host must be listed under "
               "dast.allowed_hosts in config.yaml.")

    if "folder" not in st.session_state:
        last = scan_job.current()
        st.session_state["folder"] = last.folder if last else ""
    c1, c2, c3 = st.columns([6, 1, 1.3], vertical_alignment="bottom")
    if c2.button("Browse…", icon=":material/folder_open:", width="stretch"):
        from utils.folder_picker import FolderPickerError, pick_folder

        try:
            chosen = pick_folder("Select the project folder to scan", st.session_state["folder"] or None)
        except FolderPickerError as exc:
            st.toast(str(exc), icon=":material/error:")
            chosen = None
        if chosen:
            st.session_state["folder"] = chosen
    folder = c1.text_input("Project folder or website address", key="folder",
                           placeholder=r"for example  D:\Projects\my-app   or   https://app.example.com/")
    running = scan_job.is_running()
    start = c3.button("Scan", type="primary", icon=":material/shield:", width="stretch",
                      disabled=running or not folder.strip())
    if start:
        scan_job.start(folder.strip().strip('"'))  # a folder, or website address(es)
        st.rerun()
    if scan_job.is_running():
        _progress()
        return
    _finished_panel()
    job = scan_job.current()
    results = job.results if job is not None and job.state == "done" else None
    if results:
        if len(results) > 1:
            names = [f"{r['project']} — {_summary_line(r['counts'])}" for r in results]
            pick = st.radio("Reports (one per project found in the folder)", range(len(results)),
                            format_func=lambda i: names[i])
        else:
            pick = 0
        r = results[pick]
        st.subheader(r["project"])
        st.write(f"{r['issues']} issue(s): {_summary_line(r['counts'])}")
        if r["pdf"] and Path(r["pdf"]).is_file():
            _show_pdf(Path(r["pdf"]), f"r{pick}")
        else:
            notice("warn", "The PDF could not be created", r["error"] or "Unknown error")
            html_path = Path(r["html"])
            if html_path.is_file():
                st.download_button("Download the report as HTML", html_path.read_bytes(), file_name=html_path.name,
                                   mime="text/html")
    else:
        from services.vapt_report import list_vapt_reports

        old = list_vapt_reports(cfg)
        if old:
            with st.expander("Earlier reports", icon=":material/history:"):
                choice = st.selectbox("Report", old, format_func=lambda p: p.stem.replace("_VAPT_", " — "),
                                      label_visibility="collapsed")
                if choice:
                    _show_pdf(choice, "old")
    st.caption(f"Local Security Scanner {__version__} · reports are kept in {cfg.reports_dir / 'vapt'}")


main()
