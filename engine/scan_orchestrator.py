"""Central scan orchestration: discovery, planning, bounded concurrency, persistence and summaries."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from database import repositories as dao
from database.db import connect, get_setting, init_db, set_setting, utcnow
from engine.comparison_engine import apply_scan_results, mark_unverified_after_failure
from engine.dast_scanner import DastScanner
from engine.gitleaks_scanner import GitleaksScanner
from engine.locks import JobLock, JobLockError
from engine.repository_discovery import DiscoveryResult, discover_repositories
from engine.runner import CANCEL_EVENT, ScanExecution, cancel_all
from engine.sast_scanner import BanditScanner, exclude_patterns
from engine.scanner_health import ToolStatus, check_bandit, check_gitleaks, check_trivy
from engine.trivy_scanner import TrivyOptions, TrivyScanner
from utils.config import AppConfig
from utils.logger import get_logger
from utils.paths import is_within, normalize_key

DISCOVERY_ROOTS_KEY = "last_discovery_roots"


def roots_signature(roots: list[str]) -> str:
    """Order- and case-insensitive fingerprint of the configured repository roots."""
    return "\n".join(sorted({normalize_key(r) for r in roots}))


def roots_changed(conn: sqlite3.Connection, roots: list[str]) -> bool:
    """True when the configured roots differ from those of the last discovery (e.g. config.yaml edited by hand).

    Unknown (no discovery recorded yet) counts as unchanged, so nothing runs before the first explicit discovery."""
    stored = get_setting(conn, DISCOVERY_ROOTS_KEY)
    return stored is not None and stored != roots_signature(roots)


log = get_logger(__name__)


@dataclass
class Job:
    scanner: str
    scan_type: str
    target: str = "."


@dataclass
class RunSummary:
    run_id: int
    repository: str
    scanner: str
    scan_type: str
    scan_target: str
    status: str
    findings: int = 0
    new: int = 0
    resolved: int = 0
    unverified: int = 0
    duration: float | None = None
    error: str | None = None


@dataclass
class BatchSummary:
    batch_id: str
    started_at: str
    finished_at: str | None = None
    repositories: int = 0
    runs: list[RunSummary] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def status_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.runs:
            out[r.status] = out.get(r.status, 0) + 1
        return out

    @property
    def failed(self) -> int:
        return sum(1 for r in self.runs if r.status in ("FAILED", "TIMED_OUT", "CANCELLED"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id, "started_at": self.started_at, "finished_at": self.finished_at,
            "repositories": self.repositories, "status_counts": self.status_counts(),
            "findings": sum(r.findings for r in self.runs), "new": sum(r.new for r in self.runs),
            "resolved": sum(r.resolved for r in self.runs), "errors": self.errors,
            "runs": [vars(r) for r in self.runs],
        }


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:60] or "repo"


class ScanOrchestrator:
    def __init__(self, cfg: AppConfig, trivy_tool: ToolStatus | None = None,
                 gitleaks_tool: ToolStatus | None = None, bandit_tool: ToolStatus | None = None) -> None:
        self.cfg = cfg
        cfg.ensure_dirs()
        self.db_path = cfg.db_path
        conn = init_db(self.db_path)
        recovered = dao.recover_orphaned_runs(conn)
        if recovered:
            log.warning("Recovered orphaned scan runs", extra={"count": recovered})
        conn.close()
        self._trivy_tool = trivy_tool
        self._gitleaks_tool = gitleaks_tool
        self._bandit_tool = bandit_tool

    # Tools are resolved lazily so 'discover' does not need scanners installed.
    @property
    def trivy(self) -> TrivyScanner:
        if self._trivy_tool is None:
            self._trivy_tool = check_trivy(self.cfg.trivy.executable)
        return TrivyScanner(self._trivy_tool, self.cfg.scan.db_freshness_hours)

    @property
    def gitleaks(self) -> GitleaksScanner:
        if self._gitleaks_tool is None:
            self._gitleaks_tool = check_gitleaks(self.cfg.gitleaks.executable)
        return GitleaksScanner(self._gitleaks_tool)

    @property
    def bandit(self) -> BanditScanner:
        if self._bandit_tool is None:
            self._bandit_tool = check_bandit()
        return BanditScanner(self._bandit_tool, self.cfg.data_dir / "tmp")

    def connect(self) -> sqlite3.Connection:
        return connect(self.db_path)

    # ------------------------------------------------------------------ discovery
    def discover(self) -> tuple[DiscoveryResult, dict[str, int]]:
        result = discover_repositories(
            self.cfg.repository_roots, self.cfg.excluded_dirs, max_depth=self.cfg.max_depth,
            follow_symlinks=self.cfg.follow_symlinks, protected_dirs=self.cfg.app_dirs(),
            capture_metadata=self.cfg.capture_git_metadata,
        )
        conn = self.connect()
        try:
            # Missing roots must not deactivate repositories (could be an unplugged drive).
            present_roots = [r for r in self.cfg.repository_roots if r not in result.missing_roots]
            # Repositories outside every configured root (a root removed in Settings) are deactivated.
            stats = dao.sync_discovered(conn, result.repositories, present_roots,
                                        configured_roots=self.cfg.repository_roots)
            set_setting(conn, "last_discovery_at", utcnow())
            set_setting(conn, DISCOVERY_ROOTS_KEY, roots_signature(self.cfg.repository_roots))
        finally:
            conn.close()
        return result, stats

    # ------------------------------------------------------------------ planning
    def plan_jobs(self, repo: dict[str, Any]) -> list[Job]:
        jobs: list[Job] = []
        if self.cfg.trivy.enabled:
            jobs += [Job("trivy", t) for t in self.cfg.trivy.scan_types]
            jobs += [Job("trivy", "image", img) for img in self.cfg.trivy.images.get(repo["name"], [])]
            if self.cfg.trivy.generate_sbom:
                jobs.append(Job("trivy", "sbom"))
        if self.cfg.gitleaks.enabled:
            jobs += [Job("gitleaks", m) for m in self.cfg.gitleaks.modes]
        if self.cfg.sast.enabled:
            jobs.append(Job("bandit", "python"))
        if self.cfg.dast.enabled:
            jobs += [Job("dast", "web", url) for url in self.cfg.dast.targets_for(repo["name"])]
        return jobs

    def _report_path(self, repo: dict[str, Any], job: Job, run_id: int) -> Path:
        folder = self.cfg.reports_dir / f"{_safe_name(repo['name'])}_{repo['id']}"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        ext = "cdx.json" if job.scan_type == "sbom" else "json"
        tgt = "" if job.target == "." else "_" + _safe_name(job.target)
        return folder / f"{stamp}_{job.scanner}_{job.scan_type}{tgt}_run{run_id}.{ext}"

    def _run_job(self, job: Job, repo_path: Path, report: Path, offline: bool,
                 repo_id: int | None = None) -> ScanExecution:
        cfg = self.cfg
        if job.scanner == "trivy":
            opts = TrivyOptions.from_config(cfg, offline=offline)
            # Skip installed-dependency/cache folders at any depth, and never let Trivy walk into our own
            # data/report/log folders if they sit inside a repository.
            # Trivy needs both forms: "name" matches at the repo root, "**/name" matches nested folders.
            for name in cfg.scan.skip_dirs:
                opts.skip_dirs += [name, f"**/{name}"]
            opts.skip_dirs += self._app_dirs_inside(repo_path)
            scanner = self.trivy
            if job.scan_type == "fs":
                return scanner.scan_fs(repo_path, report, opts)
            if job.scan_type == "config":
                return scanner.scan_config(repo_path, report, opts)
            if job.scan_type == "image":
                return scanner.scan_image(job.target, report, opts)
            if job.scan_type == "sbom":
                return scanner.generate_sbom(repo_path, report, opts)
        if job.scanner == "gitleaks":
            g = cfg.gitleaks
            gl_config = self._gitleaks_config(repo_path, report)
            try:
                return self.gitleaks.scan(job.scan_type, repo_path, report, cfg.scan.timeout_seconds,
                                          gl_config, g.log_opts, g.max_target_megabytes)
            finally:
                if gl_config and gl_config != g.config_path:
                    Path(gl_config).unlink(missing_ok=True)
        if job.scanner == "bandit":
            excludes = exclude_patterns(cfg.scan.skip_dirs, self._app_dirs_inside(repo_path))
            return self.bandit.scan(repo_path, report, cfg.scan.timeout_seconds, excludes, cfg.sast.skip_tests)
        if job.scanner == "dast":
            d = cfg.dast
            return DastScanner(d.request_timeout, d.max_pages, d.max_requests).scan(
                job.target, report, cfg.scan.timeout_seconds, self._dast_seeds(repo_id, job.target))
        raise ValueError(f"Unknown job {job}")

    def _dast_seeds(self, repo_id: int | None, target: str) -> list[tuple[str, list[str]]]:
        """Pages of earlier, still-open web findings. They are always re-tested first, so a finding is only
        marked resolved after its own page was checked again (not because the crawl happened to miss it)."""
        if repo_id is None:
            return []
        conn = self.connect()
        try:
            rows = conn.execute("SELECT file_path, metadata_json FROM findings WHERE repository_id=? AND "
                                "scanner='dast' AND scan_target=? AND status IN ('OPEN','UNVERIFIED')",
                                (repo_id, target)).fetchall()
        finally:
            conn.close()
        seeds: dict[tuple[str, tuple[str, ...]], tuple[str, list[str]]] = {}
        for r in rows:
            try:
                params = [str(p) for p in (json.loads(r["metadata_json"] or "{}").get("params") or [])]
            except ValueError:
                params = []
            path = r["file_path"] or "/"
            seeds[(path, tuple(sorted(params)))] = (path, params)
        return list(seeds.values())

    def _app_dirs_inside(self, repo_path: Path) -> list[str]:
        return [str(d.relative_to(repo_path)).replace("\\", "/") for d in self.cfg.app_dirs()
                if is_within(d, repo_path) and d != repo_path]

    def _gitleaks_config(self, repo_path: Path, report: Path) -> str | None:
        """Gitleaks config adding the scan skip list on top of the effective base config.

        Base config precedence is preserved: user-configured file > the repository's own .gitleaks.toml >
        Gitleaks defaults. Returns the user's config unchanged when there is nothing to skip.
        """
        user_cfg = self.cfg.gitleaks.config_path
        names = [re.escape(n) for n in self.cfg.scan.skip_dirs]
        rel_dirs = [re.escape(p).replace("/", r"[\\/]") for p in self._app_dirs_inside(repo_path)]
        if not names and not rel_dirs:
            return user_cfg
        base = Path(user_cfg) if user_cfg else repo_path / ".gitleaks.toml"
        extend = (f"path = '''{base.as_posix()}'''" if base.is_file() else "useDefault = true")
        patterns = []
        if names:
            patterns.append(rf"(^|[\\/])({'|'.join(names)})([\\/]|$)")
        patterns += [rf"^{p}([\\/]|$)" for p in rel_dirs]
        body = ("# Generated by Local Security Scanner for one scan; safe to delete.\n"
                f"[extend]\n{extend}\n\n[allowlist]\n"
                "description = \"Installed dependencies, caches and scanner output folders (scan.skip_dirs)\"\n"
                "paths = [" + ", ".join(f"'''{p}'''" for p in patterns) + "]\n")
        folder = self.cfg.data_dir / "tmp"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{report.stem}.gitleaks.toml"
        path.write_text(body, encoding="utf-8")
        return str(path)

    # ------------------------------------------------------------------ execution
    def _skip_all(self, conn: sqlite3.Connection, repo: dict[str, Any], batch_id: str, reason: str
                  ) -> list[RunSummary]:
        out = []
        for job in self.plan_jobs(repo) or [Job("orchestrator", "none")]:
            rid = dao.create_scan_run(conn, repo["id"], job.scanner, job.scan_type, job.target, batch_id,
                                      os.getpid(), status="SKIPPED")
            dao.finish_scan_run(conn, rid, finished_at=utcnow(), duration=0, error_message=reason)
            out.append(RunSummary(rid, repo["name"], job.scanner, job.scan_type, job.target, "SKIPPED", error=reason))
        return out

    def is_path_allowed(self, path: str) -> bool:
        return any(is_within(path, root) for root in self.cfg.repository_roots)

    def scan_repository(self, repo: dict[str, Any], batch_id: str | None = None,
                        offline: bool | None = None) -> list[RunSummary]:
        batch_id = batch_id or uuid.uuid4().hex[:12]
        offline = self.cfg.scan.offline if offline is None else offline
        conn = self.connect()
        summaries: list[RunSummary] = []
        pid = os.getpid()
        try:
            repo_path = Path(repo["path"])
            if not self.is_path_allowed(repo["path"]):
                return self._skip_all(conn, repo, batch_id, "Repository is outside the configured roots")
            if not repo_path.is_dir():
                return self._skip_all(conn, repo, batch_id, "Repository path no longer exists")
            stale_after = self.cfg.scan.timeout_seconds * 4 + 600
            if not dao.acquire_repo_lock(conn, repo["id"], pid, stale_after):
                return self._skip_all(conn, repo, batch_id, "Another scan of this repository is in progress")
            try:
                for job in self.plan_jobs(repo):
                    if CANCEL_EVENT.is_set():
                        summaries += self._skip_cancelled(conn, repo, batch_id, job)
                        continue
                    summaries.append(self._execute_job(conn, repo, job, repo_path, batch_id, offline))
            finally:
                dao.release_repo_lock(conn, repo["id"], pid)
        finally:
            conn.close()
        return summaries

    def _skip_cancelled(self, conn: sqlite3.Connection, repo: dict[str, Any], batch_id: str, job: Job
                        ) -> list[RunSummary]:
        rid = dao.create_scan_run(conn, repo["id"], job.scanner, job.scan_type, job.target, batch_id,
                                  os.getpid(), status="CANCELLED")
        dao.finish_scan_run(conn, rid, finished_at=utcnow(), error_message="Batch cancelled before start")
        return [RunSummary(rid, repo["name"], job.scanner, job.scan_type, job.target, "CANCELLED",
                           error="Batch cancelled before start")]

    def _execute_job(self, conn: sqlite3.Connection, repo: dict[str, Any], job: Job, repo_path: Path,
                     batch_id: str, offline: bool) -> RunSummary:
        run_id = dao.create_scan_run(conn, repo["id"], job.scanner, job.scan_type, job.target, batch_id,
                                     os.getpid())
        report = self._report_path(repo, job, run_id)
        try:
            ex = self._run_job(job, repo_path, report, offline, repo["id"])
        except Exception as exc:  # noqa: BLE001 - one job must not break the batch
            log.exception("Scanner job crashed", extra={"repo": repo["name"], "job": vars(job)})
            ex = ScanExecution(job.scanner, job.scan_type, job.target, "FAILED", None,
                               error_message=f"Internal error: {type(exc).__name__}: {exc}")
        if ex.coverage is not None and job.scan_type not in ("image", "web") and self.cfg.scan.skip_dirs:
            # Record what the scan did NOT look inside, so findings there are never marked resolved.
            ex.coverage = dataclasses.replace(ex.coverage, skip_dirs=frozenset(self.cfg.scan.skip_dirs))
        summary = RunSummary(run_id, repo["name"], job.scanner, job.scan_type, job.target, ex.status,
                             duration=ex.duration, error=ex.error_message)
        fields: dict[str, Any] = dict(
            status=ex.status, started_at=ex.started_at, finished_at=ex.finished_at or utcnow(),
            duration=ex.duration, exit_code=ex.exit_code, tool_version=ex.tool_version,
            database_updated_at=ex.database_updated_at, offline=int(ex.offline),
            report_path=ex.report_path if ex.report_path and Path(ex.report_path).is_file() else None,
            error_message=ex.error_message, coverage=ex.coverage.key() if ex.coverage else None,
        )
        if fields["started_at"] is None:  # preflight failures never launched: keep the creation timestamp
            fields.pop("started_at")
        try:
            if ex.successful and ex.coverage is not None:
                cmp = apply_scan_results(conn, repo["id"], run_id, ex.coverage, ex.findings)
                summary.findings, summary.new = len(ex.findings), len(cmp.new)
                summary.resolved, summary.unverified = len(cmp.resolved), len(cmp.unverified)
                fields.update(findings_count=len(ex.findings), new_count=len(cmp.new),
                              resolved_count=len(cmp.resolved))
            elif not ex.successful and ex.coverage is not None:
                summary.unverified = len(mark_unverified_after_failure(
                    conn, repo["id"], run_id, job.scanner, job.scan_type, ex.scan_target))
        except Exception as exc:  # noqa: BLE001 - persistence failure must surface as FAILED, never clean
            log.exception("Persisting scan results failed", extra={"run_id": run_id})
            fields.update(status="FAILED", error_message=f"Result persistence failed: {exc}")
            summary.status, summary.error = "FAILED", fields["error_message"]
        dao.finish_scan_run(conn, run_id, **fields)
        log.info("Scan job finished", extra={"repo": repo["name"], "scanner": job.scanner,
                                             "scan_type": job.scan_type, "status": summary.status,
                                             "findings": summary.findings})
        return summary

    def scan_many(self, repos: list[dict[str, Any]], offline: bool | None = None,
                  batch_id: str | None = None) -> BatchSummary:
        batch = BatchSummary(batch_id or uuid.uuid4().hex[:12], utcnow(), repositories=len(repos))
        CANCEL_EVENT.clear()
        workers = max(1, self.cfg.scan.concurrency)
        try:
            if workers == 1:
                for repo in repos:
                    batch.runs += self.scan_repository(repo, batch.batch_id, offline)
            else:
                with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as pool:
                    futures = {pool.submit(self.scan_repository, r, batch.batch_id, offline): r for r in repos}
                    try:
                        for fut in as_completed(futures):
                            try:
                                batch.runs += fut.result()
                            except Exception as exc:  # noqa: BLE001
                                batch.errors.append(f"{futures[fut]['name']}: {exc}")
                    except KeyboardInterrupt:
                        cancel_all()
                        raise
        except KeyboardInterrupt:
            cancel_all()
            batch.errors.append("Batch cancelled by user")
        batch.finished_at = utcnow()
        self._post_batch(batch)
        return batch

    def scan_all(self, offline: bool | None = None, discover_first: bool = True) -> BatchSummary:
        lock = JobLock(self.cfg.data_dir / "scan_all.lock")
        try:
            lock.acquire()
        except JobLockError as exc:
            b = BatchSummary(uuid.uuid4().hex[:12], utcnow(), finished_at=utcnow())
            b.errors.append(str(exc))
            return b
        try:
            if discover_first:
                result, _ = self.discover()
                errors = result.errors
            else:
                errors = []
            conn = self.connect()
            repos = dao.list_repositories(conn)
            conn.close()
            batch = self.scan_many(repos, offline)
            batch.errors = errors + batch.errors
            return batch
        finally:
            lock.release()

    def _post_batch(self, batch: BatchSummary) -> None:
        conn = self.connect()
        try:
            set_setting(conn, "last_batch_at", batch.finished_at or utcnow())
            if self.cfg.scan.retention_days > 0:
                pruned = dao.prune_history(conn, self.cfg.scan.retention_days)
                for p in pruned["report_paths"]:
                    if is_within(p, self.cfg.reports_dir):
                        try:
                            Path(p).unlink(missing_ok=True)
                        except OSError:
                            pass
        finally:
            conn.close()
        log.info("Batch finished", extra={"batch": batch.batch_id, "statuses": batch.status_counts()})

