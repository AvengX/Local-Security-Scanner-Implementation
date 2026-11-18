# VAPT acceptance test

A one-command, fully local test that proves the scanner finds what it should, stays quiet where it should,
and never leaks secrets. It drives the **real application** (CLI, Trivy, Gitleaks, Bandit, the built-in web scan, SQLite, exports) against
a lab of intentionally vulnerable repositories created on the fly, plus two small web apps it starts on
127.0.0.1 (`vapt/lab_web_app.py`) for the web scan.

```powershell
.\scripts\run_vapt_test.ps1               # run the test (about 1.5 minutes)
.\scripts\run_vapt_test.ps1 -UpdateDb     # refresh the Trivy DB first (internet)
.\scripts\run_vapt_test.ps1 -Dashboard    # then open the dashboard on the lab results (http://127.0.0.1:8502)
```
Results: `vapt_lab\VAPT_TEST_RESULTS.md` and `.json`; one line per run is appended to `vapt_lab\history.jsonl`.
Exit code 0 means all checks passed. The dashboard's **VAPT Lab** page runs the same test in the background and
shows expected-versus-actual results and run history. It only ever touches the generated lab.

## Scope (read this)
"VAPT" is Vulnerability Assessment **and** Penetration Testing. This application and this test cover the
**vulnerability assessment** part: static analysis of source repositories plus a safe, automated web scan of
running local apps:

| Covered | Not covered (needs separate, authorised tooling and scope) |
|---|---|
| Known CVEs in dependencies (lockfiles/manifests) | Pages behind a login; POST/PUT/DELETE requests; APIs without links |
| Hard-coded secrets in code **and Git history** | Network/port scanning, service exploitation |
| IaC misconfiguration (Dockerfile, Kubernetes, Terraform, etc.) | Authentication/authorisation, business-logic flaws |
| Risky patterns in Python code (SAST, Bandit) | Apps on other machines (the web scan is loopback-only) |
| Running local web apps (DAST): headers, cookies, exposed files, debug pages, error leaks, CORS, XSS, SQL errors, open redirect, path traversal | Manual penetration testing and exploitation |
| SBOM inventory | |

Treat results as one input to a VAPT engagement, not a replacement for a penetration test.

## The lab (`vapt_lab\targets`, recreated on every run)
| Repository | Planted weaknesses (all harmless fixtures) |
|---|---|
| `vuln-python-app` | `requests 2.25.0`, `urllib3 1.26.4`, `PyYAML 5.3`, `Jinja2 2.10`; fake AWS key + GitHub token in code; a second fake token committed then removed (history only) |
| `vuln-node-app` | `lodash 4.17.15`, `minimist 1.2.0` in `package-lock.json` |
| `insecure-infra` | Dockerfile (`:latest`, root user, `ADD` from URL), privileged Kubernetes Deployment with hostNetwork, Terraform S3 without public-access block and SSH open to `0.0.0.0/0` |
| `clean-app` | Nothing — the false-positive control |
| Web app (unsafe), linked to `vuln-python-app` | Reflected XSS, SQL error from string-built SQL (in-memory SQLite), open redirect, simulated path traversal (fake passwd line, no real file read), `.env` served, fake Werkzeug console, stack-trace page, directory listing, CORS echoing any origin with credentials, cookie without flags, version in Server header; `/logout` and `/delete-account` links that must never be visited; a POST form that must never be submitted |
| Web app (clean), linked to `clean-app` | Same shape done right — must produce zero findings |

Fake credentials are generated randomly on each run, belong to no account, and are recorded in
`vapt_lab\lab_secrets.json` only so the leak audit can search for them. Dependencies are never installed
or executed; IaC is never deployed.

## Checks (73)
1. **Health**: Trivy, Gitleaks and Bandit runnable, web scan built in, Trivy DB cached and fresh.
2. **Discovery**: all 4 repositories found.
3. **Scan**: `scan-all` exits 0; 26 runs (4 repos × Trivy fs/config/SBOM + Gitleaks git/dir + Bandit, plus 2 web
   addresses) all succeed;
   tool version and DB timestamp on every run.
4. **Detection**: specific CVEs (e.g. CVE-2023-32681 in requests, lodash CVEs), CRITICAL/HIGH present,
   misconfigurations in each IaC file (privileged pod, open security group/public S3), secrets via both
   Gitleaks and Trivy, history-only secret found by `git` mode but not `dir` mode, revoke-and-rotate
   remediation, zero findings in the clean repo, SBOMs generated, no duplicate findings, a secret planted
   inside an untracked `.venv` is skipped by both scanners, working-tree paths are repository-relative.
   **SAST**: SQL injection (B608), `shell=True` (B602), `pickle.loads` (B301), `yaml.load` (B506) and a
   hardcoded password (B105) planted in `app/db.py` are found with file, line and remediation; repositories
   without Python report no code issues; unsafe code inside `.venv` is skipped.
   **DAST**: XSS, SQL injection, open redirect, path traversal, exposed `.env`, debugger console, stack trace,
   directory listing, CORS, cookie without HttpOnly and missing CSP are found on the unsafe app with page,
   evidence and remediation; the scan never visits log-out/delete links or sends POST; a non-local address is
   refused by the configuration; the clean app produces no findings.
5. **Remediation**: upgrade `requests`, rescan one repo → the CVE becomes RESOLVED, the history secret stays
   OPEN, unfixed CVEs stay OPEN. Then switch `find_user` to a parameterised query and rescan → B608 becomes
   RESOLVED while the unfixed `shell=True` issue stays OPEN. Then make the web app escape its search term and
   rescan → DAST-XSS becomes RESOLVED while SQL injection stays OPEN. Finally stop the app and rescan → the web
   scan is SKIPPED and its issues become UNVERIFIED (not resolved).
6. **Offline**: `scan-all --offline` succeeds with the cached DB, runs flagged offline, still detects CVEs.
7. **Reports**: md/html/json/csv exports, `status`, raw JSON reports kept locally.
8. **Leak audit**: no planted secret value (including the SAST fixture password and the password inside the
   web app's exposed `.env`) anywhere in the database, raw reports, exports or logs.

## Reference run (2026-11-18, Trivy 0.76.2, Gitleaks 8.30.1, Bandit 1.9.4, DAST 1.0, Windows 11)
73/73 PASS, including 9 code issues in 3 files and 15 web app issues on the unsafe lab app; 0 on the clean app.

Earlier reference run (2026-11-18, before DAST): 55/55 PASS.

Earlier reference run (2026-11-16, before SAST): 45/45 PASS. Highlights: 4 vulnerable Python packages (11 CRITICAL/HIGH), 6 lodash advisories,
66 IaC misconfigurations (Dockerfile 10, Kubernetes 40, Terraform 16), secrets detected by both scanners,
0 findings in the clean repository, 0 secret leaks.

## Running against your own repositories
After the test passes, point `repository_roots` in `config.yaml` at your project folders and run
`python run_scan.py scan-all`, or use the dashboard. Only scan repositories you own or are authorised to assess.
