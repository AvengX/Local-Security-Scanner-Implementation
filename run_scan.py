"""Local Security Scanner — command-line interface.

Examples:
    python run_scan.py discover
    python run_scan.py scan-all [--offline]
    python run_scan.py scan-repo --name Phoenix
    python run_scan.py status
    python run_scan.py report --repository Phoenix
    python run_scan.py update-databases
    python run_scan.py health
    python run_scan.py schedule --frequency daily
    python run_scan.py unschedule
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from utils.config import AppConfig, load_config
from utils.logger import get_logger, setup_logging
from utils.paths import EXAMPLE_CONFIG_PATH, config_path

EXIT_OK, EXIT_SCAN_FAILURES, EXIT_USAGE, EXIT_BUSY = 0, 1, 2, 3
log = get_logger("cli")


def _print_table(rows: list[dict], cols: list[str]) -> None:
    if not rows:
        print("  (none)")
        return
    widths = {c: min(60, max(len(c), *(len(str(r.get(c, "") or "")) for r in rows))) for c in cols}
    print("  " + "  ".join(c.upper().ljust(widths[c]) for c in cols))
    for r in rows:
        print("  " + "  ".join(str(r.get(c, "") or "")[: widths[c]].ljust(widths[c]) for c in cols))


def _orchestrator(cfg: AppConfig):
    from engine.scan_orchestrator import ScanOrchestrator

    return ScanOrchestrator(cfg)


def _print_batch(batch, as_json: bool) -> int:
    if as_json:
        print(json.dumps(batch.to_dict(), indent=2, default=str))
    else:
        d = batch.to_dict()
        print(f"\nScan batch {d['batch_id']}  ({d['started_at']} -> {d['finished_at']})")
        print(f"Repositories: {d['repositories']}   Status counts: {d['status_counts']}")
        print(f"Findings observed: {d['findings']}   New: {d['new']}   Resolved: {d['resolved']}")
        _print_table([{**r, "error": (r["error"] or "")[:70]} for r in d["runs"]],
                     ["run_id", "repository", "scanner", "scan_type", "status", "findings", "new", "resolved", "error"])
        for e in d["errors"]:
            print(f"  ! {e}")
        if getattr(batch, "alert_id", None):
            print(f"  ALERT #{batch.alert_id}: new serious problems found - see the Overview page.")
    if any("Another scan job is running" in e for e in batch.errors):
        return EXIT_BUSY
    return EXIT_SCAN_FAILURES if batch.failed else EXIT_OK


# --------------------------------------------------------------------------------------- commands
def cmd_init(cfg: AppConfig, args: argparse.Namespace) -> int:
    from database.db import init_db

    target = config_path()
    if not target.exists():
        shutil.copyfile(EXAMPLE_CONFIG_PATH, target)
        print(f"Created configuration: {target}")
    else:
        print(f"Configuration already exists (left unchanged): {target}")
    cfg = load_config()
    cfg.ensure_dirs()
    init_db(cfg.db_path).close()
    print(f"Database ready: {cfg.db_path}")
    return EXIT_OK


def cmd_discover(cfg: AppConfig, args: argparse.Namespace) -> int:
    if not cfg.repository_roots:
        print("No repository_roots configured. Edit config.yaml or the dashboard Settings page.")
        return EXIT_USAGE
    result, stats = _orchestrator(cfg).discover()
    print(f"Discovered {len(result.repositories)} repositories under {len(cfg.repository_roots)} root(s). "
          f"new={stats['new']} updated={stats['updated']} moved={stats['moved']} deactivated={stats['deactivated']}")
    _print_table([vars(r) for r in result.repositories], ["name", "path", "kind", "current_branch"])
    for e in result.errors:
        print(f"  ! {e}")
    if result.skipped_links:
        print(f"  (skipped {result.skipped_links} symlinks/junctions)")
    return EXIT_OK


def cmd_scan_all(cfg: AppConfig, args: argparse.Namespace) -> int:
    offline = True if args.offline else (False if args.online else None)
    if not cfg.repository_roots:
        print("No repository_roots configured.")
        return EXIT_USAGE
    batch = _orchestrator(cfg).scan_all(offline=offline, discover_first=not args.no_discover)
    code = _print_batch(batch, args.json)
    if args.scheduled:
        line = (f"{datetime.now(timezone.utc).isoformat()} frequency={args.frequency or 'manual'} "
                f"batch={batch.batch_id} statuses={batch.status_counts()} exit={code} errors={len(batch.errors)}\n")
        with open(cfg.logs_dir / "scheduled_runs.log", "a", encoding="utf-8") as fh:
            fh.write(line)
    return code


def cmd_scan_repo(cfg: AppConfig, args: argparse.Namespace) -> int:
    from database import repositories as dao

    orch = _orchestrator(cfg)
    conn = orch.connect()
    matches = dao.find_repositories(conn, name=args.name, path=args.path)
    if not matches and cfg.repository_roots:
        orch.discover()
        matches = dao.find_repositories(conn, name=args.name, path=args.path)
    conn.close()
    if not matches:
        print(f"Repository not found: {args.name or args.path}. Run 'discover' and check repository_roots.")
        return EXIT_USAGE
    if len(matches) > 1:
        print("Multiple repositories share that name; use --path:")
        _print_table(matches, ["id", "name", "path"])
        return EXIT_USAGE
    offline = True if args.offline else (False if args.online else None)
    batch = orch.scan_many(matches, offline=offline)
    return _print_batch(batch, args.json)


def cmd_status(cfg: AppConfig, args: argparse.Namespace) -> int:
    from database.db import init_db
    from engine.scanner_health import trivy_db_freshness
    from services import analytics_service as an

    conn = init_db(cfg.db_path)
    m = an.overview_metrics(conn)
    fresh = trivy_db_freshness(cfg.trivy.cache_dir, cfg.scan.db_freshness_hours)
    print(f"Repositories: {m['repositories']} (scanned: {m['repositories_scanned']})")
    print("Open findings: " + ", ".join(f"{k}={v}" for k, v in m["severity"].items()))
    print(f"Secrets: {m['category']['SECRET']}  Code issues: {m['category']['CODE']}  "
          f"Web app issues: {m['category']['WEB']}  "
          f"Misconfigurations: {m['category']['MISCONFIGURATION']}  "
          f"Unverified: {m['unverified']}")
    print(f"Failed scans (latest per scanner): {m['failed_scans_latest']}  Total scans: {m['total_scans']}")
    print(f"Last successful scan: {m['last_successful_scan'] or 'never'}")
    print(f"Vulnerability DB: {fresh.message}")
    rows = an.repository_table(conn).to_dict("records")
    _print_table(rows, ["name", "branch", "last_scan", "critical", "high", "open_findings", "scan_status"])
    conn.close()
    return EXIT_OK


def cmd_report(cfg: AppConfig, args: argparse.Namespace) -> int:
    from database import repositories as dao
    from database.db import init_db
    from engine.scanner_health import trivy_db_freshness
    from services.export_service import export_bundle

    conn = init_db(cfg.db_path)
    repo_id = repo_name = None
    if args.repository:
        matches = dao.find_repositories(conn, name=args.repository)
        if len(matches) != 1:
            print(f"Repository '{args.repository}' not found or ambiguous ({len(matches)} matches)")
            return EXIT_USAGE
        repo_id, repo_name = matches[0]["id"], matches[0]["name"]
    formats = tuple(f.strip() for f in args.format.split(",") if f.strip())
    bad = [f for f in formats if f not in ("md", "html", "json", "csv")]
    if bad:
        print(f"Unknown formats: {bad}")
        return EXIT_USAGE
    fresh = trivy_db_freshness(cfg.trivy.cache_dir, cfg.scan.db_freshness_hours)
    for p in export_bundle(conn, cfg.reports_dir, repo_id, repo_name, formats, fresh):
        print(f"Wrote {p}")
    conn.close()
    return EXIT_OK


def cmd_audit(cfg: AppConfig, args: argparse.Namespace) -> int:
    from database import repositories as dao
    from database.db import init_db
    from services.audit_report import save_audit

    conn = init_db(cfg.db_path)
    matches = dao.find_repositories(conn, name=args.name, path=args.path)
    if len(matches) != 1:
        print(f"Repository not found or ambiguous ({len(matches)} matches). Use --name or --path; run 'discover' first.")
        conn.close()
        return EXIT_USAGE
    path = save_audit(conn, cfg, matches[0]["id"])
    conn.close()
    print(f"Wrote {path}")
    return _maybe_pdf(path, args.pdf)


def cmd_summary(cfg: AppConfig, args: argparse.Namespace) -> int:
    from database import repositories as dao
    from database.db import init_db
    from services.export_service import write_export
    from services.summary_report import generate_summary

    conn = init_db(cfg.db_path)
    repo_id = None
    if args.name or args.path:
        matches = dao.find_repositories(conn, name=args.name, path=args.path)
        if len(matches) != 1:
            print(f"Repository not found or ambiguous ({len(matches)} matches).")
            conn.close()
            return EXIT_USAGE
        repo_id = matches[0]["id"]
    name, doc, data = generate_summary(conn, cfg, repo_id)
    conn.close()
    path = write_export(cfg.reports_dir, name, doc)
    print(f"{data['risk'][0]}: {data['risk'][2]}")
    print(f"Wrote {path}")
    return _maybe_pdf(path, args.pdf)


def _maybe_pdf(path: Path, wanted: bool) -> int:
    if not wanted:
        print("Add --pdf to also create a PDF (uses Microsoft Edge / Chrome already on this computer).")
        return EXIT_OK
    from services.pdf_export import PdfError, html_to_pdf

    try:
        print(f"Wrote {html_to_pdf(path)}")
    except PdfError as exc:
        print(f"PDF not created: {exc}")
        return EXIT_SCAN_FAILURES
    return EXIT_OK


def cmd_sarif(cfg: AppConfig, args: argparse.Namespace) -> int:
    """Write a SARIF 2.1.0 file (GitHub code scanning / VS Code) with the open findings of one repository."""
    from database import repositories as dao
    from database.db import init_db
    from services.sarif_export import sarif_bytes

    conn = init_db(cfg.db_path)
    matches = dao.find_repositories(conn, name=args.name, path=args.path)
    if len(matches) != 1:
        print(f"Repository not found or ambiguous ({len(matches)} matches). Use --name or --path.")
        conn.close()
        return EXIT_USAGE
    data = sarif_bytes(conn, matches[0]["id"])
    conn.close()
    out = Path(args.out) if args.out else cfg.reports_dir / "exports" / f"{matches[0]['name']}.sarif"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    runs = json.loads(data)["runs"]
    print(f"Wrote {out} ({sum(len(r['results']) for r in runs)} result(s) from {len(runs)} tool(s))")
    return EXIT_OK


def cmd_guard(cfg: AppConfig, args: argparse.Namespace) -> int:
    """Install, remove or show the pre-commit secret guard of one project (or the status of all)."""
    from database import repositories as dao
    from database.db import init_db
    from engine.scanner_health import check_gitleaks
    from services import secret_guard as sg

    conn = init_db(cfg.db_path)
    if args.name or args.path:
        repos = dao.find_repositories(conn, name=args.name, path=args.path)
        if len(repos) != 1:
            print(f"Repository not found or ambiguous ({len(repos)} matches).")
            conn.close()
            return EXIT_USAGE
    elif args.action == "status":
        repos = dao.list_repositories(conn)
    else:
        print("Name the project with --name or --path.")
        conn.close()
        return EXIT_USAGE
    conn.close()
    code = EXIT_OK
    for r in repos:
        path = Path(r["path"])
        try:
            if args.action == "install":
                st = sg.install(path, check_gitleaks().path)
            elif args.action == "remove":
                st = sg.remove(path)
            else:
                st = sg.status(path)
        except sg.GuardError as exc:
            print(f"  {r['name']}: not installed - {exc}")
            code = EXIT_SCAN_FAILURES
            continue
        print(f"  {r['name']}: secret guard {st.label} - {st.detail}")
    return code


def cmd_test_alert(cfg: AppConfig, args: argparse.Namespace) -> int:
    """Send a test alert through the configured channels (Windows notification / webhook)."""
    from services.alert_service import alert_text, notify_windows, post_webhook

    sample = {"severity": "HIGH", "new_count": 1, "projects": {"example": {"severity": {"HIGH": 1},
                                                                          "category": {"CODE": 1}}},
              "top": [{"severity": "HIGH", "item": "test alert - nothing is wrong", "repository": "example",
                       "category": "CODE"}]}
    title, body = alert_text(sample)
    title = "TEST - " + title
    ok = True
    if cfg.alerts.windows_notification:
        err = notify_windows(title, body)
        print(f"Windows notification: {err or 'sent'}")
        ok &= not err
    if cfg.alerts.webhook_url:
        err = post_webhook(cfg.alerts.webhook_url, title, body, sample)
        print(f"Webhook: {err or 'sent'}")
        ok &= not err
    if not cfg.alerts.windows_notification and not cfg.alerts.webhook_url:
        print("No alert channel is enabled (alerts are shown on the Overview page only).")
    return EXIT_OK if ok else EXIT_SCAN_FAILURES


def cmd_update_databases(cfg: AppConfig, args: argparse.Namespace) -> int:
    from engine.scanner_health import check_trivy, trivy_db_freshness
    from engine.trivy_scanner import TrivyScanner

    if cfg.scan.offline and not args.force:
        print("Offline mode is enabled; refusing to download. Use --force to update anyway.")
        return EXIT_USAGE
    tool = check_trivy(cfg.trivy.executable)
    results = TrivyScanner(tool).update_databases(cfg.trivy.cache_dir)
    for name, ok, msg in results:
        print(f"  {name}: {'OK' if ok else 'FAILED'} - {msg}")
    print(trivy_db_freshness(cfg.trivy.cache_dir, cfg.scan.db_freshness_hours).message)
    return EXIT_OK if all(ok for _, ok, _ in results) else EXIT_SCAN_FAILURES


def cmd_health(cfg: AppConfig, args: argparse.Namespace) -> int:
    from engine.scanner_health import (check_bandit, check_codescan, check_dast, check_git, check_gitleaks,
                                       check_trivy, trivy_db_freshness)

    tools = [check_git(), check_trivy(cfg.trivy.executable), check_gitleaks(cfg.gitleaks.executable), check_bandit(),
             check_codescan(), check_dast()]
    print(f"Python {sys.version.split()[0]}   config: {config_path()}")
    ok = True
    for t in tools:
        state = "OK" if t.usable else ("BLOCKED/ERROR" if t.installed else "MISSING")
        print(f"  {t.name:9} {state:14} {t.version or '':12} {t.path or ''}")
        if t.error:
            print(f"            -> {t.error}")
        needed = ((t.name == "trivy" and cfg.trivy.enabled) or (t.name == "gitleaks" and cfg.gitleaks.enabled)
                  or (t.name == "bandit" and cfg.sast.enabled))
        ok &= t.usable or not needed
    fresh = trivy_db_freshness(cfg.trivy.cache_dir, cfg.scan.db_freshness_hours)
    print(f"  Vulnerability DB: {fresh.message}")
    print(f"  Offline mode: {cfg.scan.offline}   Roots: {cfg.repository_roots or '(none configured)'}")
    if cfg.dast.enabled:
        print(f"  Web scan (DAST) addresses: {', '.join(f'{t.repository} -> {t.url}' for t in cfg.dast.targets) or '(none added)'}")
    for d in cfg.app_dirs():
        print(f"  dir {d}  {'exists' if d.exists() else 'missing'}")
    return EXIT_OK if ok else EXIT_SCAN_FAILURES


def cmd_schedule(cfg: AppConfig, args: argparse.Namespace) -> int:
    from services import scheduling_service as sch

    time = args.time or cfg.schedule.time
    day = args.day or cfg.schedule.weekly_day
    try:
        cmd = sch.build_create_command(args.frequency, time, day)
    except ValueError as exc:
        print(f"Invalid schedule: {exc}")
        return EXIT_USAGE
    exe, task_args = sch.task_action(args.frequency)
    when = f"daily at {time}" if args.frequency == "daily" else f"weekly on {day} at {time}"
    print("This will register a Windows scheduled task (current user, limited privileges, no overlapping runs):")
    print(f"  Task:    {sch.TASK_NAMES[args.frequency]}  ({when})")
    print(f"  Runs:    \"{exe}\" {task_args}")
    print(f"  Command: {' '.join(cmd[:4])} \"{cmd[4]}\"")
    if args.dry_run:
        print("(dry run - nothing created)")
        return EXIT_OK
    if not args.yes:
        answer = input("Create this scheduled task? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cancelled; no task created.")
            return EXIT_OK
    res = sch.create_task(args.frequency, time, day)
    print(("Created: " if res.ok else "FAILED: ") + res.message)
    print(sch.instructions())
    return EXIT_OK if res.ok else EXIT_SCAN_FAILURES


def cmd_unschedule(cfg: AppConfig, args: argparse.Namespace) -> int:
    from services import scheduling_service as sch

    freqs = ["daily", "weekly"] if args.frequency == "all" else [args.frequency]
    if not args.yes:
        answer = input(f"Delete scheduled task(s) {freqs}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cancelled.")
            return EXIT_OK
    ok = True
    for f in freqs:
        res = sch.delete_task(f)
        ok &= res.ok
        print(f"  {f}: {'OK' if res.ok else 'FAILED'} - {res.message}")
    return EXIT_OK if ok else EXIT_SCAN_FAILURES


def cmd_prune(cfg: AppConfig, args: argparse.Namespace) -> int:
    from database import repositories as dao
    from database.db import init_db
    from utils.paths import is_within

    days = args.days if args.days is not None else cfg.scan.retention_days
    if days <= 0:
        print("Retention is disabled (retention_days = 0); nothing pruned. Pass --days N to prune.")
        return EXIT_OK
    conn = init_db(cfg.db_path)
    res = dao.prune_history(conn, days)
    removed = 0
    for p in res["report_paths"]:
        if is_within(p, cfg.reports_dir) and Path(p).is_file():
            Path(p).unlink()
            removed += 1
    print(f"Deleted {res['runs_deleted']} scan runs older than {days} days and {removed} report files.")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run_scan.py", description="Local Security Scanner CLI - libraries, secrets, code, settings and running web apps (all local)")
    p.add_argument("--config", help="Path to config.yaml (default: project config.yaml or LSS_CONFIG)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create config.yaml (if missing) and initialise the database")
    sub.add_parser("discover", help="Discover Git repositories under the configured roots")

    sa = sub.add_parser("scan-all", help="Discover and scan all active repositories")
    sb = sub.add_parser("scan-repo", help="Scan a single repository")
    for s in (sa, sb):
        g = s.add_mutually_exclusive_group()
        g.add_argument("--offline", action="store_true", help="Use cached vulnerability DBs only")
        g.add_argument("--online", action="store_true", help="Override offline mode from config")
        s.add_argument("--json", action="store_true", help="Print the batch summary as JSON")
    sa.add_argument("--no-discover", action="store_true", help="Skip discovery before scanning")
    sa.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    sa.add_argument("--frequency", choices=["daily", "weekly"], help=argparse.SUPPRESS)
    tgt = sb.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--name", help="Repository name (as discovered)")
    tgt.add_argument("--path", help="Absolute repository path (must be under a configured root)")

    sub.add_parser("status", help="Show current security posture")
    r = sub.add_parser("report", help="Export summary/CSV/JSON reports to reports/exports")
    r.add_argument("--repository", help="Limit to one repository")
    r.add_argument("--format", default="md,html,json,csv", help="Comma list of md,html,json,csv")

    au = sub.add_parser("audit", help="Write the detailed security audit report (HTML) for one repository")
    ag = au.add_mutually_exclusive_group(required=True)
    ag.add_argument("--name", help="Repository name (as discovered)")
    ag.add_argument("--path", help="Absolute repository path")
    au.add_argument("--pdf", action="store_true", help="Also create a PDF (Edge / Chrome, nothing to install)")
    sf = sub.add_parser("sarif", help="Write a SARIF file (GitHub code scanning / VS Code) for one repository")
    sg = sf.add_mutually_exclusive_group(required=True)
    sg.add_argument("--name")
    sg.add_argument("--path")
    sf.add_argument("--out", help="Output file (default reports/exports/<name>.sarif)")

    gd = sub.add_parser("guard", help="Pre-commit secret guard: install / remove / status")
    gd.add_argument("action", choices=["install", "remove", "status"])
    gd.add_argument("--name")
    gd.add_argument("--path")
    sub.add_parser("test-alert", help="Send a test alert (Windows notification / webhook)")
    sm = sub.add_parser("summary", help="Write the plain-language management summary (HTML) for all or one project")
    sm.add_argument("--name")
    sm.add_argument("--path")
    sm.add_argument("--pdf", action="store_true", help="Also create a PDF (Edge / Chrome, nothing to install)")
    u = sub.add_parser("update-databases", help="Download/refresh Trivy vulnerability databases (online)")
    u.add_argument("--force", action="store_true", help="Update even if offline mode is enabled")
    sub.add_parser("health", help="Check tools, versions and DB freshness")

    sc = sub.add_parser("schedule", help="Register a Windows scheduled scan (asks for confirmation)")
    sc.add_argument("--frequency", choices=["daily", "weekly"], required=True)
    sc.add_argument("--time", help="HH:MM (24h), default from config")
    sc.add_argument("--day", choices=["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"], help="Weekly day")
    sc.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    sc.add_argument("--dry-run", action="store_true", help="Show the schtasks command without running it")
    us = sub.add_parser("unschedule", help="Remove scheduled scan task(s)")
    us.add_argument("--frequency", choices=["daily", "weekly", "all"], default="all")
    us.add_argument("--yes", action="store_true")

    pr = sub.add_parser("prune", help="Delete scan history older than the retention period")
    pr.add_argument("--days", type=int, help="Override retention_days")
    return p


COMMANDS = {
    "init": cmd_init, "discover": cmd_discover, "scan-all": cmd_scan_all, "scan-repo": cmd_scan_repo,
    "status": cmd_status, "report": cmd_report, "audit": cmd_audit, "summary": cmd_summary, "sarif": cmd_sarif, "test-alert": cmd_test_alert, "guard": cmd_guard, "update-databases": cmd_update_databases,
    "health": cmd_health, "schedule": cmd_schedule, "unschedule": cmd_unschedule, "prune": cmd_prune,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.config:
        import os

        os.environ["LSS_CONFIG"] = str(Path(args.config).resolve())
    try:
        cfg = load_config()
    except ValidationError as exc:
        print(f"Configuration error in {config_path()}:\n{exc}")
        return EXIT_USAGE
    except Exception as exc:  # noqa: BLE001 - e.g. YAML syntax error
        print(f"Could not load configuration {config_path()}: {exc}")
        return EXIT_USAGE
    cfg.ensure_dirs()
    setup_logging(cfg.logs_dir, cfg.log_level)
    log.info("CLI command", extra={"command": args.command})
    try:
        return COMMANDS[args.command](cfg, args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return EXIT_SCAN_FAILURES


if __name__ == "__main__":
    sys.exit(main())
