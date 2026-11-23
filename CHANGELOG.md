# Changelog

## 1.3.0 — 2026-11-23
**One simple flow:** paste a folder path, click Scan, get a VAPT report as a PDF.
- The dashboard is now a single page: folder box (with Browse…), Scan button with live progress, the PDF shown in the
  page, **Download PDF** and **Open in new tab**, and earlier reports. The scan runs in the background, so clicks and
  refreshes do not interrupt it.
- New VAPT report laid out like a professional security assessment: executive summary and overall posture, scope &
  methodology, findings table (severity, CVSS 3.1, OWASP Top 10), finding details (location, confidence, effort,
  roadmap, description, evidence, impact, fix), what's done well, remediation roadmap, not tested in this pass.
- One report per project when the folder holds several projects; a folder without Git is scanned as one project.
- CVSS 3.1 scores and CWE ids are now kept from Trivy results.
- CLI: `run_scan.py vapt <folder>`.
- Removed the multi-page dashboard (Overview, Findings, Trends, Settings and the rest). The engine, database and CLI
  commands are unchanged; settings are edited in `config.yaml`.

## 1.2.0 — 2026-11-19
**Coverage**
- **Code scan (SAST)** with Bandit for Python, plus a built-in check for JavaScript/TypeScript, HTML/Jinja
  templates, PHP, Java, Go and C#.
- **Web scan (DAST)**, built in and safe: headers, cookies, exposed files, debug pages, error leaks, CORS, XSS,
  SQL errors, open redirect, path traversal; loopback-only, GET-only.
  - Optional **test-account login** to reach pages behind sign-in.
  - **Auto-start** of the app when it is not running.
  - **API testing from OpenAPI / Swagger files** (POST only to endpoints you allow).
- **Installed versions**: unpinned libraries are checked against the exact versions installed in each project's
  `.venv` / `venv` / `node_modules`.

**Understanding and managing results**
- **In plain words** on every finding: what, why, how it is abused, fix steps, how soon.
- Help & glossary page, first-run tour.
- **Triage**: false positive, accepted risk (with review date), archive — always with a reason; listed separately
  in every report.
- **Alerts** after scans that find new serious problems: Overview, Windows notification, optional webhook.
- **Scheduled scans** created, tested and removed from the dashboard, with a health row.
- **Trends**: open issues over time, new vs fixed, time to fix, by type, projects vs 30 days ago.
- **Pre-commit secret guard** per project.

**Reports and sharing**
- **Management summary** in plain language for managers.
- **PDF export** of the summary and the audit report, using Microsoft Edge / Chrome already on the computer
  (nothing to install).
- **SARIF 2.1.0 export** for GitHub code scanning and the VS Code SARIF Viewer.

**Quality**
- VAPT acceptance test: 106 checks (up from 55).
- Test suite: 250+ tests.
- Database schema v5: migrations add the CODE/WEB categories, triage and alerts tables, all automatic.

## 1.1.0 — 2026-11-17
- Audit fixes and dashboard redesign.
- Detailed audit report.
- VAPT Lab page.
- Windows folder picker.
- Cached-DB fallback.

## 1.0.0 — 2026-11-16
- First release: Trivy + Gitleaks scanning of discovered repositories, SQLite history, Streamlit dashboard, exports.
