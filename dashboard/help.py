"""Page — Help: how to use the scanner in five steps, what every page and status means, and a glossary of the
security words used across the app. Written for people who are not security specialists."""

from __future__ import annotations

import streamlit as st

from dashboard import theme as t
from dashboard.common import get_conn, html, page_header, section
from services.explain import URGENCY

GLOSSARY: dict[str, str] = {
    "VAPT": "Vulnerability Assessment and Penetration Testing. Vulnerability assessment = finding weaknesses "
            "(what this app does automatically). Penetration testing = a person actively trying to break in.",
    "SAST": "Static Application Security Testing: reading the source code, without running it, to spot risky "
            "patterns. Shown on the Code issues page.",
    "DAST": "Dynamic Application Security Testing: testing a running app from the outside through its web address, "
            "the way a browser or attacker would. Shown on the Web app issues page.",
    "CVE": "Common Vulnerabilities and Exposures: a public ID (like CVE-2024-12345) for a known security flaw in a "
           "piece of software.",
    "CVSS": "Common Vulnerability Scoring System: a 0-10 score of how dangerous a flaw is. 9-10 critical, 7-8.9 "
            "high, 4-6.9 medium, below 4 low.",
    "CWE": "Common Weakness Enumeration: a catalogue of kinds of mistakes (CWE-79 = cross-site scripting, CWE-89 = "
           "SQL injection). Useful to look up background and examples.",
    "Severity": "How serious a finding is: Critical, High, Medium, Low (or Unknown). See 'How soon to fix' above.",
    "Dependency": "A library your project uses (for example Flask or numpy). Its flaws become your flaws.",
    "Transitive dependency": "A library that one of your libraries uses. You did not choose it directly, but it "
                             "still runs in your app.",
    "Lockfile": "A file listing the exact version of every library (package-lock.json, poetry.lock). Needed so "
                "known flaws can be matched to versions.",
    "SBOM": "Software Bill of Materials: a list of every component in your software, like an ingredients label.",
    "Secret": "A password, API key, token or private key. Anyone who has it can act as you on that service.",
    "Environment variable": "A setting stored by the operating system rather than in the code, e.g. "
                            "DATABASE_PASSWORD. The usual safe place for secrets.",
    "Git history": "Every version of every file ever committed. Deleting a secret from today's file does not "
                   "remove it from the history.",
    "Working tree": "The files in the project folder right now, including changes not yet committed.",
    "Misconfiguration": "An unsafe setting in a configuration file, for example a Docker container that runs as "
                        "the administrator (root).",
    "IaC": "Infrastructure as Code: files that describe servers and containers (Dockerfile, Kubernetes, Terraform).",
    "XSS": "Cross-site scripting: an attacker gets their script to run inside your web page, in other users' "
           "browsers. It can steal logins or change the page.",
    "Escaping": "Turning special characters such as < and > into harmless text before putting them in a page, so "
                "they are shown instead of run.",
    "DOM": "The live structure of a web page in the browser that JavaScript reads and changes.",
    "CSP": "Content-Security-Policy: a header that tells the browser which scripts may run. A strong safety net "
           "against XSS.",
    "SQL injection": "Gluing user input into a database command so the input can change the command - letting an "
                     "attacker read or change all data.",
    "Parameterised query": "A database query where values are passed separately from the SQL text (placeholders "
                           "like ?), so they can never change the command. The fix for SQL injection.",
    "Command injection": "User input ends up in an operating-system command and adds extra commands.",
    "Code injection": "User input is run as program code (eval/exec).",
    "Path traversal": "Using ../ in a file name to read files outside the folder the app meant to allow.",
    "Open redirect": "A link on your site that forwards visitors to any address given in the URL - abused in "
                     "phishing.",
    "Phishing": "Tricking people into giving away passwords, usually with a fake e-mail or login page.",
    "Deserialisation": "Turning stored data back into program objects. Some formats (pickle) can run code while "
                       "doing it.",
    "Hash": "A one-way fingerprint of data. MD5 and SHA-1 are broken; passwords need slow hashes like bcrypt.",
    "Random": "Normal random generators are predictable. Security tokens need a cryptographic generator "
              "(secrets module, crypto.getRandomValues).",
    "TLS": "The encryption behind HTTPS. Certificate checks prove you are talking to the real server.",
    "HTTPS": "Encrypted web traffic. Plain http:// can be read and changed by anyone on the network.",
    "Man-in-the-middle": "An attacker secretly sitting between you and a server (e.g. on public Wi-Fi), reading or "
                         "changing traffic.",
    "SRI": "Subresource Integrity: a hash on a script tag so the browser refuses the file if someone changed it.",
    "CDN": "Content Delivery Network: another company's servers that host scripts and images for many sites.",
    "Clickjacking": "Showing your page invisibly inside another site to trick users into clicking your buttons.",
    "HSTS": "Strict-Transport-Security: a header that tells browsers to always use HTTPS for your site.",
    "Cookie": "A small value the browser stores and sends back to the site, often used to keep you logged in.",
    "Session": "The period you are logged in. The session cookie is as valuable as your password during it.",
    "CSRF": "Cross-site request forgery: another website makes your browser perform actions on a site you are "
            "logged in to.",
    "CORS": "Cross-Origin Resource Sharing: rules that decide which other websites may read your app's responses.",
    "Debug mode": "A developer mode that shows internal details and sometimes allows running code. Never for "
                  "anything others can reach.",
    "Licence": "The legal terms under which a library may be used. Some require you to publish your own code.",
    "False positive": "A finding that looks like a problem but is not one in your situation. Check the line; the "
                      "explanation says when the scanner is unsure.",
    "Remediation": "The fix: what to change so the problem goes away.",
    "API": "Application Programming Interface: addresses (endpoints) that other programs call to get or send data, "
           "usually JSON. They have no links, so the web scan only tests them when it is given an OpenAPI file.",
    "OpenAPI / Swagger": "A standard file (openapi.json / .yaml) that describes an API: every endpoint, method and "
                         "parameter. Settings -> Web scan -> OpenAPI file lets the scanner test the API from it.",
    "Authentication": "Proving who you are (logging in, or sending a token). Endpoints that change or reveal "
                      "private data should require it.",
    "Pre-commit hook": "A small script Git runs before every commit. The secret guard uses one to stop commits that "
                       "contain passwords or keys (Repositories → project → Secret guard).",
    "Webhook": "An internet address that receives a short message, used to post alerts to Teams, Slack or a phone "
               "app. Optional - alerts otherwise stay on this computer.",
    "Alert": "A message after a scan that found new serious problems: shown on the Overview and optionally as a "
             "Windows notification or webhook message.",
    "Triage": "Deciding what to do with a finding: fix it, mark it as a false positive, accept the risk for a while, "
              "or archive it. Done in each finding's details under 'Your decision'.",
    "Accepted risk": "A real problem you knowingly decide to live with for now, with a reason and a review date. "
                     "On that date it counts again until someone decides anew.",
    "Loopback / localhost": "The address 127.0.0.1 - this computer only. The web scan is limited to it.",
    "Trivy": "Open-source scanner used here for vulnerable libraries and unsafe configuration files.",
    "Gitleaks": "Open-source scanner used here for secrets in files and Git history.",
    "Bandit": "Open-source scanner used here for risky patterns in Python code.",
}

STEPS = [
    ("Add your project folders", "Settings → Repository roots. Pick the folder that holds your projects; each Git "
                                 "project inside is found automatically and listed on the Repositories page."),
    ("Scan", "Repositories → Scan all (or one project). Libraries, secrets, code, configuration files - and running "
             "web apps if you added their address - are checked. Nothing is uploaded."),
    ("Add your web apps (optional)", "Settings → Web scan (DAST): the project and the local address where its app "
                                     "runs, e.g. http://127.0.0.1:5000/. Add a test-account login to also test pages "
                                     "behind sign-in. Start the app before scanning."),
    ("Read the Overview", "Overview → 'Recommended next steps' lists what to do first. Red and orange numbers matter "
                          "most."),
    ("Fix and re-scan", "Open any issue: 'In plain words' says what it is, why it matters, how it is abused, the fix "
                        "step by step and how soon. Fix it, scan again - it moves to Resolved by itself."),
]

PAGES_HELP = [
    ("Overview", "One-screen summary: totals, problems by project, recommended next steps and system health."),
    ("Security Findings", "Every finding of every kind in one searchable table."),
    ("Vulnerabilities", "Libraries your projects use that have publicly known flaws (CVEs), with the version that "
                        "fixes them."),
    ("Secrets", "Passwords, keys and tokens written in files or Git history. Only the location is shown, never "
                "the value."),
    ("Code issues", "Risky ways of writing code: Python (Bandit) plus JavaScript/TypeScript, HTML templates, PHP, "
                    "Java, Go and C# (built-in check)."),
    ("Web app issues", "Problems found by testing your running local apps through their address (DAST)."),
    ("Misconfigurations", "Unsafe settings in Dockerfiles, Kubernetes, Terraform and similar files (only shown when "
                          "you have such files)."),
    ("Repositories", "Your projects: scan them, see when they were last scanned and their status, and switch on the "
                     "secret guard that blocks commits containing passwords or keys."),
    ("Scan History", "Every scan run with its result, duration and any error."),
    ("Reports", "Management summary (plain language, for managers), detailed audit report per project, CSV/JSON "
                "exports and the scanners' raw output."),
    ("VAPT Lab", "A self-test: builds practice projects and web apps with planted problems and checks that every "
                 "one is found."),
    ("Settings", "Project folders, scanners, alerts, web app addresses (start commands, logins), schedule."),
]

STATUSES = [
    ("OPEN", "Found in the latest scan and not fixed yet."),
    ("UNVERIFIED", "Found earlier, but the latest scan could not check it (the scanner failed, or the web app was "
                   "not running). It is NOT counted as fixed."),
    ("RESOLVED", "A later scan checked the same place and the problem was gone."),
    ("DECIDED", "A person marked it as a false positive, an accepted risk (comes back on its review date) or "
                "archived, with a reason. It is left out of the counts but still listed (Status → Decided) and in "
                "every report."),
]


def _tour_reset() -> None:
    from database.db import set_setting

    set_setting(get_conn(), "tour_done", "")
    st.session_state["tour_step"] = 0
    st.session_state["tour_force"] = True
    st.session_state["tour_hidden"] = False


def render() -> None:
    page_header("Help", "How to use the scanner, what everything means, and a glossary of security words")
    c1, c2 = st.columns([3, 1], vertical_alignment="center")
    c1.markdown("New here? The five steps below are all you need. Every issue in the app also has an **In plain "
                "words** box that explains it without jargon.")
    c2.button("Show the welcome tour", icon=":material/tour:", on_click=_tour_reset, width="stretch")

    section("Start here: five steps")
    li = "".join(f"<li><span class='lss-step' style='--c:{t.ACCENT}'>{i}</span><div class='grow'>"
                 f"<div class='t'>{t.esc(a)}</div><div class='s'>{t.esc(b)}</div></div></li>"
                 for i, (a, b) in enumerate(STEPS, 1))
    html(f"<ul class='lss-list'>{li}</ul>")

    section("How soon to fix: severity")
    rows = "".join(f"<tr><td>{t.sev_badge(s)}</td><td>{t.esc(URGENCY[s])}</td></tr>"
                   for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"))
    html(f"<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Severity</th><th>What to do</th></tr>"
         f"</thead><tbody>{rows}</tbody></table></div>")

    section("What the statuses mean")
    rows = "".join(f"<tr><td>{t.status_badge(s)}</td><td>{t.esc(d)}</td></tr>" for s, d in STATUSES)
    html(f"<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Status</th><th>Meaning</th></tr>"
         f"</thead><tbody>{rows}</tbody></table></div>")

    section("What each page shows")
    rows = "".join(f"<tr><td><b>{t.esc(p)}</b></td><td>{t.esc(d)}</td></tr>" for p, d in PAGES_HELP)
    html(f"<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Page</th><th>Shows</th></tr></thead>"
         f"<tbody>{rows}</tbody></table></div>")

    section("What is checked - and what is not")
    a, b = st.columns(2)
    a.markdown("**Checked automatically**\n"
               "- Libraries with known flaws (CVEs), from requirements.txt, lockfiles, etc.\n"
               "- Passwords, keys and tokens in files **and** Git history\n"
               "- Risky code: Python, JavaScript/TypeScript, HTML templates, PHP, Java, Go, C#\n"
               "- Unsafe Docker / Kubernetes / Terraform settings\n"
               "- Running local web apps: headers, cookies, exposed files, debug pages, error leaks, CORS, XSS, SQL "
               "injection, open redirect, path traversal - also behind a login when a test account is set")
    b.markdown("**Not checked (needs a person or other tools)**\n"
               "- Business logic (e.g. can a user see another user's order?)\n"
               "- Apps on other computers or the internet (web scan is this-computer only)\n"
               "- Forms that change data (never submitted, so nothing is altered)\n"
               "- Libraries listed without exact versions (pin them to be checked)\n"
               "- A manual penetration test - this app is the automated first line")

    section("Glossary", f"{len(GLOSSARY)} terms")
    q = st.text_input("Find a word", placeholder="e.g. XSS, CVE, cookie", key="help_q")
    hits = {k: v for k, v in GLOSSARY.items() if not q or q.lower() in (k + " " + v).lower()}
    if not hits:
        st.caption("No matching word.")
    rows = "".join(f"<tr><td style='white-space:nowrap'><b>{t.esc(k)}</b></td><td>{t.esc(v)}</td></tr>"
                   for k, v in sorted(hits.items(), key=lambda kv: kv[0].lower()))
    if rows:
        html(f"<div class='lss-table-wrap'><table class='lss-table'><thead><tr><th>Word</th><th>Meaning</th></tr>"
             f"</thead><tbody>{rows}</tbody></table></div>")
