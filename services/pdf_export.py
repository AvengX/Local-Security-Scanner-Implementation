"""Turn the HTML reports into real PDF files with the browser that is already on the computer.

Microsoft Edge ships with Windows 10/11 (Google Chrome and Chromium work too). Its headless mode prints an HTML
file to PDF exactly as the "Print -> Save as PDF" dialog would - same layout, page numbers and footers from the
report's print CSS - without installing anything. The report is a local file with no external resources, a
throw-away browser profile is used, and nothing is sent anywhere.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

CREATE_NO_WINDOW = 0x08000000
CANDIDATES = [
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
]


class PdfError(RuntimeError):
    pass


def find_browser() -> str | None:
    for c in CANDIDATES:
        p = Path(os.path.expandvars(c))
        if p.is_file():
            return str(p)
    for name in ("msedge", "chrome", "chromium", "google-chrome"):
        found = shutil.which(name)
        if found:
            return found
    return None


def html_to_pdf(html_path: Path, pdf_path: Path | None = None, timeout: int = 120) -> Path:
    """Print a local HTML file to PDF. Returns the PDF path (next to the HTML file by default)."""
    html_path = Path(html_path).resolve()
    if not html_path.is_file():
        raise PdfError(f"Report not found: {html_path}")
    browser = find_browser()
    if not browser:
        raise PdfError("No Microsoft Edge or Google Chrome was found to create the PDF. Open the HTML report in a "
                       "browser and choose Print -> Save as PDF instead.")
    pdf_path = Path(pdf_path or html_path.with_suffix(".pdf")).resolve()
    pdf_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="lss-pdf-", ignore_cleanup_errors=True) as profile:
        args = [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
                "--disable-background-networking", "--disable-sync", "--no-default-browser-check",
                "--no-pdf-header-footer", f"--user-data-dir={profile}", f"--print-to-pdf={pdf_path}",
                html_path.as_uri()]
        deadline = time.monotonic() + timeout
        try:
            subprocess.run(args, capture_output=True, timeout=timeout,  # noqa: S603 - fixed browser, local file
                           creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0)
        except subprocess.TimeoutExpired as exc:
            raise PdfError(f"Creating the PDF took longer than {timeout}s") from exc
        except OSError as exc:
            raise PdfError(f"Could not start the browser to create the PDF: {exc}") from exc
        # Edge's launcher can return before the headless browser has written the file: wait until it exists and
        # its size stops changing (the temporary profile must stay until then).
        last = -1
        while time.monotonic() < deadline:
            size = pdf_path.stat().st_size if pdf_path.is_file() else -1
            if size > 0 and size == last:
                break
            last = size
            time.sleep(0.5)
    if not pdf_path.is_file() or pdf_path.stat().st_size < 1000 or pdf_path.read_bytes()[:5] != b"%PDF-":
        raise PdfError("The browser did not produce a PDF. Open the HTML report and use Print -> Save as PDF.")
    return pdf_path
