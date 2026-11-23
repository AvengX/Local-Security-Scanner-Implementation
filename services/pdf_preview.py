"""Page images of a PDF report, so the dashboard can show the PDF in any browser.

Chrome and Edge refuse to run their PDF viewer inside a sandboxed frame (which is what a Streamlit page can offer),
so the report pages are rendered to PNG with the PDF engine built into Windows and shown as images. The images are
cached next to the PDF (``<report>_pages``) and rebuilt only when the PDF changes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).with_name("pdf_pages.ps1")
CREATE_NO_WINDOW = 0x08000000


class PreviewError(RuntimeError):
    """The PDF pages could not be turned into images (not Windows, or the renderer failed)."""


def pages_dir(pdf: Path) -> Path:
    return pdf.with_name(pdf.stem + "_pages")


def page_images(pdf: Path, width: int = 1400, timeout: int = 120) -> list[Path]:
    """PNG files for every page of ``pdf`` (cached; rebuilt when the PDF is newer than the images)."""
    pdf = Path(pdf).resolve()
    if not pdf.is_file():
        raise PreviewError(f"Report not found: {pdf}")
    out = pages_dir(pdf)
    done = out / "done.txt"
    if done.is_file() and done.stat().st_mtime >= pdf.stat().st_mtime:
        cached = sorted(out.glob("page*.png"))
        if cached and len(cached) == _count(done):
            return cached
    if os.name != "nt":
        raise PreviewError("Page preview needs Windows. Use Download PDF or Open in new tab.")
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        raise PreviewError("PowerShell was not found, so the PDF pages cannot be previewed.")
    if out.is_dir():
        shutil.rmtree(out, ignore_errors=True)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed shell and bundled script, paths passed as arguments
            [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT),
             str(pdf), str(out), str(width)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise PreviewError("Rendering the PDF pages took too long.") from exc
    except OSError as exc:
        raise PreviewError(f"Could not start PowerShell to render the PDF pages: {exc}") from exc
    pages = sorted(out.glob("page*.png"))
    if proc.returncode != 0 or not pages or len(pages) != _count(done):
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise PreviewError("The PDF pages could not be rendered" + (f": {detail[-1][:200]}" if detail else "."))
    return pages


def _count(done: Path) -> int:
    try:
        return int(done.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return -1
