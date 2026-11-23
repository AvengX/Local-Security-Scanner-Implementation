"""Folder scan running in a background thread, so clicks and page refreshes never interrupt it.

The page only reads the shared progress record and refreshes itself while the scan runs. One scan at a time.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

JOB_LABEL = {
    ("trivy", "fs"): "Libraries with known flaws", ("trivy", "config"): "Docker / cloud settings",
    ("trivy", "installed"): "Installed library versions", ("trivy", "image"): "Container image",
    ("trivy", "sbom"): "Software bill of materials", ("gitleaks", "dir"): "Passwords and keys in files",
    ("gitleaks", "git"): "Passwords and keys in Git history", ("bandit", "python"): "Python code",
    ("codescan", "multi"): "Code in other languages", ("dast", "web"): "Running web app",
}


@dataclass
class ScanJob:
    folder: str
    state: str = "running"  # running | done | error
    label: str = "Looking for projects in the folder…"
    lines: list[str] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    started: float = field(default_factory=time.time)
    finished: float | None = None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, line: str, replace_last: bool = False) -> None:
        with self.lock:
            if replace_last and self.lines:
                self.lines[-1] = line
            else:
                self.lines.append(line)

    def snapshot(self) -> tuple[str, str, list[str]]:
        with self.lock:
            return self.state, self.label, list(self.lines)


_current: ScanJob | None = None
_guard = threading.Lock()


def current() -> ScanJob | None:
    return _current


def is_running() -> bool:
    return _current is not None and _current.state == "running"


def start(folder: str) -> ScanJob:
    """Start scanning ``folder`` in the background (returns the running job if one is already going)."""
    global _current
    with _guard:
        if is_running():
            return _current  # type: ignore[return-value]
        job = ScanJob(folder)
        _current = job
    threading.Thread(target=_run, args=(job,), name="folder-scan", daemon=True).start()
    return job


def _run(job: ScanJob) -> None:
    from database.db import init_db
    from engine.scan_orchestrator import FolderScanError, ScanOrchestrator
    from services.vapt_report import generate_vapt
    from utils.config import load_config

    try:
        cfg = load_config()
        orch = ScanOrchestrator(cfg)

        def on_project(i: int, n: int, repo: dict) -> None:
            job.label = f"Scanning {repo['name']} ({i} of {n})…"
            job.add(f"**{repo['name']}** · `{repo['path']}`")

        def on_job(j: Any, summary: Any) -> None:
            label = JOB_LABEL.get((j.scanner, j.scan_type), f"{j.scanner} {j.scan_type}")
            if j.scan_type in ("installed", "web", "image"):
                label += f" ({j.target.split(':', 1)[-1]})"
            if summary is None:
                job.add(f"- {label}: checking…")
                return
            ok = summary.status in ("COMPLETED", "COMPLETED_WITH_FINDINGS")
            text = f"{summary.findings} finding(s)" if ok else f"did not finish: {summary.error or summary.status}"
            job.add(f"- {label}: {':green[done]' if ok else ':red[problem]'} · {text}", replace_last=True)

        scan = orch.scan_folder(job.folder, on_project=on_project, on_job=on_job)
        job.label = "Writing the PDF report(s)…"
        conn = init_db(cfg.db_path)
        try:
            for repo in scan.projects:
                job.add(f"- Report for {repo['name']}: writing…")
                f = generate_vapt(conn, cfg, repo["id"])
                if f.pdf_path:  # prepare the in-page preview now, so the report shows at once
                    from services.pdf_preview import PreviewError, page_images

                    try:
                        page_images(f.pdf_path)
                    except PreviewError:
                        pass  # the page explains it and still offers Download / Open in new tab
                job.results.append({"project": f.project, "pdf": str(f.pdf_path) if f.pdf_path else None,
                                    "html": str(f.html_path), "counts": f.counts, "issues": f.issues,
                                    "error": f.error})
                job.add(f"- Report for {repo['name']}: {':green[done]' if f.pdf_path else ':red[HTML only]'}",
                        replace_last=True)
        finally:
            conn.close()
        n = len(job.results)
        job.label = f"Done: {n} project{'s' if n != 1 else ''} scanned."
        job.state = "done"
    except FolderScanError as exc:
        job.error, job.label, job.state = str(exc), str(exc), "error"
    except Exception as exc:  # noqa: BLE001 - shown to the user instead of a silent dead thread
        job.error, job.label, job.state = f"{type(exc).__name__}: {exc}", "The scan stopped with an error.", "error"
    finally:
        job.finished = time.time()
