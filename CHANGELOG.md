# Changelog

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
