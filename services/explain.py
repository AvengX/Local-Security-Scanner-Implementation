"""Plain-language explanations for every finding: what it is, why it matters, how an attacker would use it, the
fix step by step, and how soon to fix it.

Written for people who are not security specialists. Used by the dashboard detail panel, the audit report and
the management summary. Every scanner rule maps to a topic; anything unknown still gets a sensible generic text,
so no finding is ever shown without an explanation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass
class Explanation:
    what: str
    why: str
    attack: str
    fix: list[str]
    urgency: str
    note: str = ""
    topic: str = "generic"
    terms: list[str] = field(default_factory=list)  # glossary words worth looking up on the Help page


URGENCY = {
    "CRITICAL": "Fix today. This can be abused easily and the damage is serious.",
    "HIGH": "Fix this week. A real attack is possible with moderate effort.",
    "MEDIUM": "Plan a fix within the next month. It needs other conditions to be abused, or the damage is limited.",
    "LOW": "Fix when convenient. On its own it is a small risk, but it makes other attacks easier.",
    "UNKNOWN": "Review it to decide how serious it is for your app.",
}
RESCAN = "Scan the project again. When the problem is gone the finding is marked Resolved automatically."


@dataclass(frozen=True)
class Topic:
    what: str
    why: str
    attack: str
    fix: tuple[str, ...]
    terms: tuple[str, ...] = ()


T = Topic
TOPICS: dict[str, Topic] = {
    # ---------------------------------------------------------------- injection
    "xss": T("The app puts text typed by a visitor straight into a web page without making it harmless first "
             "(cross-site scripting, XSS).",
             "A visitor's browser cannot tell your real code from code that came in through the page, so injected "
             "code runs with your site's full trust.",
             "An attacker sends a victim a link containing a small script. When the victim opens it, the script runs "
             "as if it were your site: it can steal the login session, change what the page shows, or act as the user.",
             ("Escape every value before it goes into HTML. Template engines such as Jinja2 do this automatically - "
              "do not switch it off.",
              "Add a Content-Security-Policy header so injected scripts are blocked even if one slips through.",
              "Test the page again with the same input and check it shows as plain text."),
             ("XSS", "Escaping", "CSP")),
    "xss_dom": T("JavaScript in the page builds HTML from a variable (for example with innerHTML). If that variable "
                 "can contain user input, it becomes cross-site scripting (XSS) inside the browser.",
                 "Text inserted as HTML is treated as code by the browser, so any script inside it runs.",
                 "If the value comes from the URL, a form, or the server's data, an attacker can place a script "
                 "there and it runs for every visitor who sees it.",
                 ("Use textContent or innerText to show text; build elements with document.createElement.",
                  "If you really need to insert HTML, clean it first with a sanitiser such as DOMPurify.",
                  "If the value can never contain user input, note that in a comment so reviewers know it is safe."),
                 ("XSS", "DOM")),
    "xss_template": T("A template switches off the automatic HTML escaping (for example with |safe or "
                      "autoescape false). Anything a user can influence in that value becomes cross-site scripting.",
                      "Escaping is the protection that turns <script> into harmless text. Switching it off removes "
                      "the protection for that value.",
                      "If a user can put text into that value (a name, a comment, a profile field), they can store "
                      "a script that runs for everyone who opens the page.",
                      ("Remove |safe / autoescape false for any value that can contain user input.",
                       "If you need to allow some formatting, clean the HTML with a sanitiser (for example bleach) "
                       "before marking it safe.",
                       "Keep |safe only for HTML you wrote yourself."),
                      ("XSS", "Escaping")),
    "sqli": T("A database query is built by gluing text from the request into the SQL command (SQL injection).",
              "The database cannot tell your SQL from SQL that an attacker typed, so it runs both.",
              "An attacker types a crafted value such as  ' OR '1'='1  into a form field or URL. They can then read "
              "every row (passwords, personal data), change or delete data, and sometimes take over the server.",
              ("Use parameterised queries: put ? or %s placeholders in the SQL and pass the values separately, "
               "for example cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)).",
               "Or use your framework's ORM / query builder, which does this for you.",
               "Never build SQL with +, f-strings or .format() from request values."),
              ("SQL injection", "Parameterised query")),
    "cmd": T("The program runs an operating-system command that is built from a variable (command injection).",
             "The shell treats characters such as ; | & as 'run another command', so extra text becomes extra "
             "commands.",
             "If any part of that variable comes from a user, they can add  ; del /q *  or download and start "
             "malware - with the same rights as your app.",
             ("Do not use a shell: pass the program and its arguments as a list (subprocess.run(['prog', arg]) / "
              "execFile in Node).",
              "Check user values against an allow-list (for example only letters and digits).",
              "Better still, use a library function instead of an external command."),
             ("Command injection",)),
    "code_exec": T("The program runs text as code (for example eval, exec or new Function).",
                   "Whoever controls that text controls what your program does.",
                   "If the text can come from a user, a file, or the network, an attacker can run any code they "
                   "like inside your app: read files, steal keys, or take over the machine.",
                   ("Remove eval/exec. Parse data with a real parser (json.loads, ast.literal_eval, JSON.parse).",
                    "Call the function you need directly instead of building code as text."),
                   ("Code injection",)),
    "traversal": T("A file path is built from a value in the request, so ../ sequences can reach files outside "
                   "the intended folder (path traversal).",
                   "The server reads whatever path it is given; ../ climbs up the folder tree.",
                   "An attacker asks for ../../.env or ../../etc/passwd and downloads passwords, keys, or source code.",
                   ("Never use request values as file paths. Map allowed names to files (for example a dict).",
                    "If you must, resolve the full path and check it is still inside the allowed folder "
                    "(Path(base / name).resolve().is_relative_to(base)).",
                    "Use your framework's safe helper (Flask: send_from_directory)."),
                   ("Path traversal",)),
    "redirect": T("The app sends visitors to any address given in the URL (open redirect).",
                  "Links that start with your trusted domain are believed by users and by spam filters.",
                  "An attacker sends  yoursite/go?next=evil.example  in a phishing e-mail. The victim sees your "
                  "name, clicks, and lands on a fake login page that steals their password.",
                  ("Only redirect to paths inside your own app (values that start with a single /).",
                   "Or keep an allow-list of external sites you trust."),
                  ("Open redirect", "Phishing")),
    "deserialization": T("The program loads data with pickle (or a similar format) that can contain code.",
                         "Loading a pickle can run arbitrary Python code that was hidden in the data.",
                         "If an attacker can supply or replace the file or message being loaded, they can run "
                         "their own code on your server.",
                         ("Use JSON (or another data-only format) for anything that comes from outside.",
                          "Only unpickle files your own program created and that nobody else can change."),
                         ("Deserialisation",)),
    "yaml": T("YAML is loaded with yaml.load, which can create any Python object.",
              "A crafted YAML file can run code while it is being read.",
              "If a user can upload or edit the YAML, they can run code on your server.",
              ("Use yaml.safe_load instead of yaml.load.",), ()),
    # ---------------------------------------------------------------- secrets and crypto
    "hardcoded_password": T("A password or key appears to be written directly in the source code.",
                            "Everyone who can read the code - teammates, a stolen laptop, a public GitHub copy - "
                            "can read the password too, and it is hard to change without a new release.",
                            "Someone with the code logs in with that password, to your database or service, as you.",
                            ("Move the value to an environment variable or a .env file that is listed in .gitignore.",
                             "If it is a real password, change it at the service - assume it is already known.",
                             "If this is only a test value, rename it so it is obviously fake (for example "
                             "'test-only-password')."),
                            ("Secret", "Environment variable")),
    "weak_hash": T("The code uses MD5 or SHA-1, hash methods that are broken for security purposes.",
                   "Computers can now find collisions for these quickly, and MD5 password hashes are cracked in "
                   "seconds.",
                   "If this protects passwords or signatures, an attacker can recover the passwords or forge data "
                   "that passes the check.",
                   ("For passwords use bcrypt, scrypt or Argon2 (for example the bcrypt or passlib package).",
                    "For other security uses use SHA-256 or better.",
                    "If it is not used for security (for example a cache key), pass usedforsecurity=False so it is "
                    "clear."),
                   ("Hash",)),
    "weak_random": T("Random values come from a predictable generator (random / Math.random).",
                     "These generators are made for games and simulations; their next value can be predicted.",
                     "If they create tokens, password-reset links, or IDs, an attacker can guess valid ones and "
                     "take over accounts.",
                     ("Use the secrets module in Python (secrets.token_urlsafe()) or crypto.getRandomValues / "
                      "crypto.randomUUID in JavaScript.",),
                     ("Random",)),
    "tls_off": T("Certificate checking for HTTPS connections is switched off.",
                 "The certificate check is what proves you are talking to the real server.",
                 "Anyone on the same network (public Wi-Fi, a compromised router) can pretend to be the server and "
                 "read or change everything sent - including passwords and API keys.",
                 ("Remove verify=False / rejectUnauthorized: false / InsecureSkipVerify.",
                  "If the server uses its own certificate, point the client at that certificate (verify='ca.pem') "
                  "instead of switching checks off."),
                 ("TLS", "Man-in-the-middle")),
    "cleartext": T("Something is sent or loaded over plain http:// instead of https://.",
                   "Plain HTTP is not encrypted, so anyone on the network path can read or replace it.",
                   "On shared Wi-Fi an attacker can read submitted data or swap a script for a malicious one that "
                   "runs on your page.",
                   ("Change the address to https://.",
                    "For scripts and stylesheets, host the file yourself if the other site has no HTTPS."),
                   ("HTTPS",)),
    "sri": T("A script is loaded from another website without an integrity check (Subresource Integrity).",
             "You are trusting that site to never be hacked or change the file.",
             "If the other site (a CDN) is compromised, the attacker's version of the script runs on your pages "
             "with full access.",
             ("Add integrity=\"sha384-…\" and crossorigin=\"anonymous\" to the script tag (the CDN usually shows "
              "the value), or host the file yourself.",),
             ("SRI", "CDN")),
    # ---------------------------------------------------------------- web configuration
    "csp": T("The page is sent without a Content-Security-Policy header.",
             "A CSP tells the browser which scripts are allowed. Without it, any injected script runs.",
             "If any XSS bug exists anywhere on the site, nothing in the browser stops the attacker's script.",
             ("Send the header Content-Security-Policy: default-src 'self' (Flask: set it in an after_request "
              "function or use Flask-Talisman).",
              "Load the page and check the browser console for anything the policy blocks; allow only what you "
              "need."),
             ("CSP",)),
    "clickjack": T("Other websites can show your page inside an invisible frame (clickjacking).",
                   "Users can be tricked into clicking buttons on your page while they think they are clicking "
                   "something else.",
                   "An attacker places your page invisibly over a fake 'Win a prize' button; the victim's click "
                   "actually presses 'Delete account' or 'Send money' on your site.",
                   ("Send X-Frame-Options: DENY, or Content-Security-Policy: frame-ancestors 'self'.",),
                   ("Clickjacking",)),
    "nosniff": T("The X-Content-Type-Options: nosniff header is missing.",
                 "Without it, browsers may guess a file's type and run an uploaded text file as a script.",
                 "If users can upload files, an attacker uploads a file that the browser later treats as script.",
                 ("Send X-Content-Type-Options: nosniff on every response.",), ()),
    "hsts": T("The HTTPS site does not tell browsers to always use HTTPS (HSTS).",
              "The first visit, or a typed address, can still start on plain HTTP.",
              "On public Wi-Fi an attacker can catch that first HTTP request and keep the victim on an unencrypted, "
              "fake copy of the site.",
              ("Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses.",),
              ("HSTS", "HTTPS")),
    "version": T("The server tells every visitor which software and version it runs.",
                 "Version numbers let attackers look up known bugs for exactly that version.",
                 "Automated tools scan the internet for these headers and attack versions with known flaws first.",
                 ("Hide or shorten the Server / X-Powered-By headers in the web server or framework settings.",
                  "More importantly, keep that software updated."),
                 ()),
    "cookie_httponly": T("A cookie can be read by JavaScript because it is missing the HttpOnly flag.",
                         "Session cookies are as good as a password while the user is logged in.",
                         "If any XSS bug exists, the attacker's script reads the cookie and logs in as the victim.",
                         ("Set HttpOnly on the cookie (Flask: SESSION_COOKIE_HTTPONLY = True, the default; for your "
                          "own cookies pass httponly=True to set_cookie).",),
                         ("Cookie", "Session")),
    "cookie_samesite": T("A cookie has no SameSite setting.",
                         "Without it, other websites can make the browser send your cookie along with their requests.",
                         "A malicious site can trigger actions on your site in the background while the user is "
                         "logged in (cross-site request forgery).",
                         ("Set SameSite=Lax (or Strict) on cookies (Flask: SESSION_COOKIE_SAMESITE = 'Lax').",),
                         ("CSRF", "Cookie")),
    "cookie_secure": T("A cookie on an HTTPS site is missing the Secure flag.",
                       "The browser may also send it over plain HTTP, where it can be read.",
                       "On shared Wi-Fi an attacker can capture the session cookie and log in as the user.",
                       ("Set the Secure flag (Flask: SESSION_COOKIE_SECURE = True).",), ("Cookie",)),
    "cors": T("The app allows any website to read its responses (CORS is too open).",
              "Normally browsers stop other websites from reading your app's data. This setting turns that off.",
              "A malicious website the user visits can quietly call your app with the user's cookies and read their "
              "personal data.",
              ("Allow only the exact sites that need access in Access-Control-Allow-Origin.",
               "Never echo back the request's Origin, especially together with Access-Control-Allow-Credentials: true."),
              ("CORS",)),
    "exposed_file": T("A sensitive file (for example .env, a database file or the .git folder) can be downloaded "
                      "from the web app.",
                      "These files usually contain passwords, keys, personal data or the full source code.",
                      "Attackers' tools try these file names on every site. Whoever downloads it gets your "
                      "passwords and data directly.",
                      ("Stop serving it: move the file out of the web/static folder or block it in the web server.",
                       "Change every password and key that was in the file - assume it has been copied.",
                       "Check the server logs for earlier downloads of that path."),
                      ("Secret",)),
    "dir_listing": T("A folder on the web server lists all its files (directory listing).",
                     "It shows attackers file names that were never meant to be found, such as backups.",
                     "An attacker browses the list and downloads old backups, configs or uploaded documents.",
                     ("Turn off directory listing in the web server, or put an index page in the folder.",), ()),
    "debug": T("Debug mode or an interactive debugger is switched on and reachable.",
               "Debug tools are built to give a developer full control of the running program.",
               "Anyone who reaches the page can read secrets from memory or, with the Werkzeug debugger console, "
               "run any command on the server.",
               ("Turn debug off: Flask app.run(debug=False) or FLASK_DEBUG=0; Django DEBUG = False.",
                "Use debug only on your own computer, and never on an address others can reach."),
               ("Debug mode",)),
    "error_leak": T("An error page shows internal details such as a stack trace.",
                    "Stack traces reveal file paths, library versions, and sometimes queries or secrets.",
                    "Attackers deliberately trigger errors to learn how the app is built and where it is weak.",
                    ("Show a short, friendly error page to users.",
                     "Write the full details to the server log instead (Flask: register an errorhandler; turn off "
                     "debug)."),
                    ()),
    "trace": T("The web server answers HTTP TRACE requests.",
               "TRACE echoes the request back, which old attacks used to read protected cookies.",
               "Combined with other bugs, an attacker could read headers that should be hidden from scripts.",
               ("Disable the TRACE method in the web server.",), ()),
    "postmessage": T("Data is sent to other windows with postMessage(…, '*'), meaning any website may receive it.",
                     "If the other window has been navigated to a malicious site, that site receives the data.",
                     "An attacker opens your page from their site and collects whatever you post (tokens, user data).",
                     ("Pass the exact origin of the receiving window instead of '*'.",), ()),
    "storage_token": T("A login token or password is saved in localStorage / sessionStorage.",
                       "Every script on the page can read browser storage - including injected or third-party ones.",
                       "If any XSS bug exists, the attacker's script copies the token and uses the account.",
                       ("Keep session tokens in an HttpOnly, Secure, SameSite cookie set by the server.",),
                       ("Session",)),
    "noopener": T("A link opens a new tab (target=\"_blank\") without rel=\"noopener\".",
                  "The opened page gets a handle back to your tab.",
                  "A malicious linked page can silently replace your tab with a fake login page (tab-nabbing).",
                  ("Add rel=\"noopener noreferrer\" to links with target=\"_blank\".",), ()),
    "api_auth": T("An API endpoint that the API description says needs a login answered a request without one.",
                  "Whoever can reach the app can call it directly - no account, no password.",
                  "An attacker calls the endpoint from a script and reads or changes data meant only for logged-in "
                  "users (or admins), without ever seeing the web pages.",
                  ("Add the authentication check to this endpoint in the code (e.g. @login_required, a FastAPI "
                   "Depends(get_current_user), or middleware that covers the whole /api path).",
                   "Return 401 when no valid session or token is sent.",
                   "If the endpoint is really meant to be public, remove the security requirement from the API "
                   "description so it is honest."), ("Authentication", "API")),
    "api_docs": T("The interactive API documentation (Swagger UI) or the API description file can be opened by "
                  "anyone.",
                  "It lists every endpoint, parameter and data format - a ready-made map for an attacker.",
                  "Attackers read it to find hidden or admin endpoints and craft exact requests, instead of guessing.",
                  ("Turn the docs off outside development (FastAPI: docs_url=None, openapi_url=None; flask-smorest / "
                   "flasgger: disable in production config).",
                   "Or put them behind a login."), ("API",)),
    # ---------------------------------------------------------------- Python-specific hygiene
    "bind_all": T("A server is set to listen on every network interface (0.0.0.0).",
                  "Anyone on the same network - office, café Wi-Fi - can reach it, not just you.",
                  "Others on the network can open the app, including debug pages or unprotected admin functions.",
                  ("Use host='127.0.0.1' for local development.",
                   "Only use 0.0.0.0 behind a firewall or reverse proxy in production."), ()),
    "assert": T("An assert statement is used where it may be acting as a security check.",
                "Python removes all assert statements when run with the -O option, so the check silently disappears.",
                "If assert checks permissions or input, running optimised turns the protection off.",
                ("Replace security checks with if … : raise …",
                 "Asserts in tests are fine; this only matters in application code."), ()),
    "swallowed_error": T("An error is caught and silently ignored (try/except: pass).",
                         "Failures - including security failures - become invisible.",
                         "An attack or a broken safety check goes unnoticed because nothing is logged.",
                         ("Log the exception, or handle the specific error you expect (except ValueError:).",), ()),
    "timeout": T("A network request has no timeout.",
                 "If the other side never answers, your program waits forever.",
                 "A slow or malicious server can hang your app (denial of service).",
                 ("Pass timeout=10 (seconds) to requests.get/post and similar calls.",), ()),
    "tmpfile": T("A fixed file name in a temporary folder is used.",
                 "Other users or programs on the machine can create or replace that file first.",
                 "An attacker places a file or link at that name to read or overwrite data.",
                 ("Use the tempfile module (tempfile.NamedTemporaryFile / mkstemp).",), ()),
    "permissions": T("A file is given permissions that let everyone write to it.",
                     "Any user on the machine can change it.",
                     "Another user or program modifies the file to change your program's behaviour.",
                     ("Use the narrowest permissions that work, for example 0o600 or 0o644.",), ()),
    "subprocess": T("An external program is started from Python.",
                    "Starting programs is safe only when the program and its arguments cannot be changed by users.",
                    "If a user can influence the program name or arguments, they can run their own commands.",
                    ("Check that every part of the command is fixed or validated.",
                     "Pass a list of arguments, never a single string with shell=True.",
                     "Use a full path to the program."), ("Command injection",)),
    "partial_path": T("A program is started by its short name (for example 'git' instead of a full path).",
                      "Windows/Linux look the name up on the PATH, which can be changed.",
                      "A malicious program with the same name placed earlier on the PATH would run instead.",
                      ("Use the full path to the program, or look it up once with shutil.which and check it.",), ()),
}

RULE_TOPIC: dict[str, str] = {
    # DAST
    "DAST-XSS": "xss", "DAST-SQLI": "sqli", "DAST-REDIRECT": "redirect", "DAST-TRAVERSAL": "traversal",
    "DAST-CSP": "csp", "DAST-CLICKJACK": "clickjack", "DAST-NOSNIFF": "nosniff", "DAST-HSTS": "hsts",
    "DAST-VERSION": "version", "DAST-COOKIE-HTTPONLY": "cookie_httponly", "DAST-COOKIE-SAMESITE": "cookie_samesite",
    "DAST-COOKIE-SECURE": "cookie_secure", "DAST-CORS": "cors", "DAST-EXPOSED-FILE": "exposed_file",
    "DAST-DIR-LISTING": "dir_listing", "DAST-DEBUG": "debug", "DAST-ERROR-LEAK": "error_leak",
    "DAST-TRACE": "trace", "DAST-API-AUTH": "api_auth", "DAST-API-DOCS": "api_docs",
    # Built-in code scan (other languages)
    "JS-EVAL": "code_exec", "JS-INNERHTML": "xss_dom", "JS-DANGEROUS-HTML": "xss_dom", "JS-CMD-INJECTION": "cmd",
    "JS-STRING-TIMER": "code_exec", "JS-WEAK-RANDOM": "weak_random", "JS-STORAGE-TOKEN": "storage_token",
    "JS-TLS-OFF": "tls_off", "JS-SQL-CONCAT": "sqli", "JS-POSTMESSAGE-ANY": "postmessage", "JS-CORS-ANY": "cors",
    "JS-OPEN-REDIRECT": "redirect", "TPL-SAFE-FILTER": "xss_template", "TPL-HTTP-SCRIPT": "cleartext",
    "TPL-NO-SRI": "sri", "TPL-BLANK-NOOPENER": "noopener", "TPL-HTTP-FORM": "cleartext", "PHP-EVAL": "code_exec",
    "PHP-CMD-INJECTION": "cmd", "PHP-SQL-CONCAT": "sqli", "PHP-XSS-ECHO": "xss", "PHP-FILE-INCLUDE": "traversal",
    "JAVA-SQL-CONCAT": "sqli", "JAVA-CMD": "cmd", "JAVA-WEAK-HASH": "weak_hash", "GO-TLS-OFF": "tls_off",
    "GO-SQL-SPRINTF": "sqli", "GO-SHELL": "cmd", "CS-SQL-CONCAT": "sqli", "CS-TLS-OFF": "tls_off",
    # Bandit (Python)
    "B101": "assert", "B102": "code_exec", "B103": "permissions", "B104": "bind_all", "B105": "hardcoded_password",
    "B106": "hardcoded_password", "B107": "hardcoded_password", "B108": "tmpfile", "B110": "swallowed_error",
    "B112": "swallowed_error", "B113": "timeout", "B201": "debug", "B301": "deserialization", "B302":
    "deserialization", "B303": "weak_hash", "B304": "weak_hash", "B305": "weak_hash", "B306": "tmpfile",
    "B307": "code_exec", "B311": "weak_random", "B321": "cleartext", "B324": "weak_hash", "B401": "cleartext",
    "B402": "cleartext", "B403": "deserialization", "B404": "subprocess", "B501": "tls_off", "B502": "tls_off",
    "B503": "tls_off", "B504": "tls_off", "B506": "yaml", "B601": "cmd", "B602": "cmd", "B603": "subprocess",
    "B604": "cmd", "B605": "cmd", "B606": "subprocess", "B607": "partial_path", "B608": "sqli", "B609": "cmd",
    "B610": "sqli", "B611": "sqli", "B701": "xss_template", "B702": "xss_template", "B703": "xss_template",
}
CWE_TOPIC = {79: "xss", 89: "sqli", 78: "cmd", 94: "code_exec", 95: "code_exec", 22: "traversal", 601: "redirect",
             502: "deserialization", 259: "hardcoded_password", 798: "hardcoded_password", 327: "weak_hash",
             328: "weak_hash", 330: "weak_random", 338: "weak_random", 295: "tls_off", 319: "cleartext",
             942: "cors", 489: "debug", 209: "error_leak", 548: "dir_listing", 538: "exposed_file", 605: "bind_all",
             703: "swallowed_error", 400: "timeout", 377: "tmpfile", 732: "permissions", 1004: "cookie_httponly"}

SECRET_KINDS = [
    (r"aws", "Amazon Web Services (AWS) key"), (r"gcp|google", "Google Cloud key"), (r"azure", "Microsoft Azure key"),
    (r"github", "GitHub token"), (r"gitlab", "GitLab token"), (r"slack", "Slack token"), (r"stripe", "Stripe key"),
    (r"twilio", "Twilio key"), (r"sendgrid", "SendGrid key"), (r"openai", "OpenAI API key"),
    (r"anthropic", "Anthropic API key"), (r"supabase", "Supabase key"), (r"jwt", "login token (JWT)"),
    (r"private-key|private_key", "private key"), (r"password|passwd", "password"), (r"npm", "npm token"),
    (r"pypi", "PyPI token"), (r"generic-api-key|api-key|apikey", "API key"),
]

LOCAL_SECRET_FILE = re.compile(r"(?i)(^|/)(\.env(\.[\w-]+)?|secrets\.toml|\.secrets?|[\w-]*\.local)$")

MISCONF_ATTACK = {
    "DS002": "If someone breaks into the app, they get administrator (root) rights inside the container, which "
             "makes escaping to the host much easier.",
    "DS001": "Using the 'latest' tag means a different, untested image can be pulled at any time - including a "
             "compromised one.",
    "DS026": "Without a health check, a broken or hijacked container keeps running and receiving traffic unnoticed.",
    "DS004": "Exposing SSH (port 22) in a container gives attackers another way in to try passwords.",
    "DS005": "ADD can fetch remote files and unpack archives automatically, which can pull in unexpected content.",
}


def _meta(f: Mapping[str, Any]) -> dict[str, Any]:
    m = f.get("metadata") if isinstance(f.get("metadata"), dict) else None
    if m is not None:
        return m
    raw = f.get("metadata_json")
    try:
        return json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}


def _s(x: Any) -> str:
    return "" if x is None or (isinstance(x, float) and x != x) else str(x)


def _where(f: Mapping[str, Any], meta: dict[str, Any]) -> str:
    path = _s(f.get("file_path"))
    line = f.get("line")
    try:
        line = int(line) if line and line == line else None
    except (TypeError, ValueError):
        line = None
    if f.get("category") == "WEB":
        p = meta.get("parameter")
        return f" Found on page {path or '/'}" + (f", in the URL parameter '{p}'" if p else "") + "."
    if path:
        return f" Found in {path}" + (f" at line {line}" if line else "") + "."
    return ""


def _topic_for(f: Mapping[str, Any], meta: dict[str, Any]) -> str | None:
    rule = _s(f.get("rule_id")).upper()
    if rule in RULE_TOPIC:
        return RULE_TOPIC[rule]
    try:
        cwe = int(meta.get("cwe")) if meta.get("cwe") else None
    except (TypeError, ValueError):
        cwe = None
    return CWE_TOPIC.get(cwe) if cwe else None


def _confidence_note(meta: dict[str, Any]) -> str:
    conf = _s(meta.get("confidence")).upper()
    if conf == "LOW":
        return ("The scanner is not very sure about this one. Look at the line: if you can see that no outside "
                "input can reach it, it is a false alarm and can be left.")
    if conf == "MEDIUM":
        return "The scanner is fairly sure, but check the line to confirm user input can actually reach it."
    return ""


def explain(f: Mapping[str, Any]) -> Explanation:
    """Explanation for one finding (a DB row, a pandas row converted with dict(), or a NormalizedFinding-like map)."""
    meta = _meta(f)
    cat = _s(f.get("category")).upper()
    sev = _s(f.get("severity")).upper() or "UNKNOWN"
    urgency = URGENCY.get(sev, URGENCY["UNKNOWN"])
    where = _where(f, meta)
    remediation = _s(f.get("remediation")).strip()

    if cat == "VULNERABILITY":
        pkg, inst = _s(f.get("package_name")) or "a library", _s(f.get("installed_version"))
        fixed, vid = _s(f.get("fixed_version")), _s(f.get("vulnerability_id")) or _s(f.get("identifier"))
        title = _s(f.get("title"))
        what = (f"Your project uses {pkg}" + (f" version {inst}" if inst else "") +
                f", which has a publicly known security flaw ({vid or 'advisory'}).")
        if title:
            what += f" The advisory describes it as: “{title[:160]}”."
        installed = meta.get("version_source") == "installed"
        if installed:
            what += (f" The version was read from what is installed in {meta.get('environment')}, because the "
                     "project does not pin it.")
        steps = ([f"Update {pkg} to version {fixed.split(',')[0].strip()} or newer in "
                  + (f"the project's installed environment ({meta.get('environment')}), and write that exact "
                     "version into requirements.txt / package-lock.json so it stays pinned."
                     if installed else f"{_s(f.get('file_path')) or 'your dependency file'}."),
                  "Re-install the dependencies (for example pip install -r requirements.txt) and run your tests.",
                  RESCAN] if fixed else
                 [f"No fixed version of {pkg} has been published yet.",
                  "Check the advisory: does your app use the affected feature? If not, the risk is low.",
                  "If it does, look for a workaround in the advisory or consider a different library.",
                  "Re-check regularly - the scanner will show the fixed version as soon as one exists."])
        return Explanation(
            what + where,
            "Lists of known flaws are public. Attackers use them to find software that has not been updated, and "
            "for many flaws ready-made attack code is available.",
            f"If your app uses the vulnerable part of {pkg}, an attacker can use the published technique against it. "
            "What they can do depends on the flaw - from crashing the app to reading data or running code.",
            steps, urgency, topic="vulnerable_library", terms=["CVE", "CVSS", "Dependency"])

    if cat == "SECRET":
        rule = _s(f.get("rule_id")).lower()
        kind = next((name for pat, name in SECRET_KINDS if re.search(pat, rule)), "secret (password, key or token)")
        in_history = _s(f.get("scan_type")) == "git"
        commit = _s(meta.get("commit"))[:10]
        article = "An" if kind[0].lower() in "aeiou" else "A"
        what = (f"{article} {kind} appears to be written in the project's files." + where +
                (f" It is in the Git history (commit {commit}), so deleting it from today's file is not enough."
                 if in_history and commit else ""))
        return Explanation(
            what,
            "Anyone who can see the code - teammates, a lost laptop, a public GitHub copy, a backup - can copy the "
            "value and use it as if they were you.",
            "They sign in to the service with it: read or delete data, send messages in your name, or run up bills "
            "(cloud and AI keys are a common target).",
            ["Revoke (cancel) the key or change the password at the provider first - assume it is already known.",
             "Put the new value in an environment variable or a .env file that is listed in .gitignore.",
             "Remove it from the code. If it was committed, it stays in Git history: rewrite history "
             "(git filter-repo) or simply rely on step 1 having made it useless.",
             RESCAN],
            urgency if sev != "UNKNOWN" else URGENCY["HIGH"],
            note=("The scanner never stores or shows the secret itself - only where it is."
                  + (" This file is a normal place to keep secrets on your own computer. If it is listed in "
                     ".gitignore and was never committed (the Git-history scan would then report it too), it has "
                     "not leaked: keep it out of Git, shared folders and screenshots - rotating is only needed if "
                     "it was shared." if not in_history and LOCAL_SECRET_FILE.search(_s(f.get("file_path")))
                     else "")),
            topic="secret", terms=["Secret", "Git history", "Working tree"])

    if cat in ("MISCONFIGURATION", "LICENSE"):
        rule = _s(f.get("rule_id")) or _s(f.get("vulnerability_id"))
        title = _s(f.get("title")) or "unsafe setting"
        if cat == "LICENSE":
            return Explanation(
                f"A dependency uses a licence that may restrict how you can use or share your software: {title}."
                + where,
                "Some licences require you to publish your own source code or forbid commercial use.",
                "This is a legal rather than a hacking risk: using it wrongly can lead to licence disputes.",
                ["Check the licence with whoever approves software licences in your organisation.",
                 "Replace the library if the licence does not fit how you distribute your software."],
                URGENCY.get(sev, URGENCY["LOW"]), topic="license", terms=["Licence"])
        return Explanation(
            f"A setting in a configuration file is unsafe: {title}." + where,
            "Files such as Dockerfiles, Kubernetes and Terraform decide how your app runs on servers. One unsafe "
            "line is copied to every server built from it.",
            MISCONF_ATTACK.get(rule, "It makes a successful break-in more damaging, or gives an attacker an easier "
                                     "way in."),
            [x for x in (remediation or "Follow the check's reference link for the safe setting.", RESCAN) if x],
            urgency, topic="misconfiguration", terms=["Misconfiguration", "IaC"])

    topic_key = _topic_for(f, meta)
    topic = TOPICS.get(topic_key or "")
    if topic is None:
        title = _s(f.get("title")) or "a security problem"
        return Explanation(
            f"The scanner reported: {title}." + where,
            "It is a known pattern that weakens the security of the app.",
            "How it can be abused depends on how this part of the app is used; the reference link explains the "
            "risk in detail.",
            [remediation or "Review the code at this location and follow the reference link.", RESCAN],
            urgency, note=_confidence_note(meta), topic="generic")
    steps = [*topic.fix, RESCAN]
    what = topic.what + where
    if cat == "WEB" and meta.get("evidence"):
        what += f" What the scan saw: {meta['evidence']}"
    return Explanation(what, topic.why, topic.attack, steps, urgency, note=_confidence_note(meta),
                       topic=topic_key or "generic", terms=list(topic.terms))


def risk_level(counts: Mapping[str, int]) -> tuple[str, str, str]:
    """(label, colour, sentence) for a set of open findings by severity - used in the management summary."""
    c, h, m = counts.get("CRITICAL", 0), counts.get("HIGH", 0), counts.get("MEDIUM", 0)
    if c:
        return ("High risk", "#EF4444", f"{c} critical issue(s) can be abused easily and should be fixed today.")
    if h:
        return ("Elevated risk", "#F97316", f"{h} high-severity issue(s) should be fixed this week.")
    if m:
        return ("Moderate risk", "#EAB308", f"No critical or high issues; {m} medium issue(s) to plan in.")
    if sum(counts.values()):
        return ("Low risk", "#22C55E", "Only low-severity issues remain.")
    return ("No open issues", "#22C55E", "No open issues were found by the checks that ran.")
