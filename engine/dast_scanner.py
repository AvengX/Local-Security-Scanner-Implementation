"""DAST (dynamic application security testing): a built-in, safe scanner for the user's own running web apps.

DAST tests an application from the outside, through its web address, the way a browser or attacker would. It
finds problems that only show up while the app runs: missing security headers, unsafe cookies, exposed files,
debug pages, error pages that leak internals, and simple injection flaws.

Safety rules (enforced here, not only in the configuration):
* Only loopback addresses (localhost, 127.0.0.0/8, ::1) are contacted; every request re-checks the host.
* Only GET requests (plus one TRACE probe) are sent. Forms are filled in only when they use GET; POST, PUT and
  DELETE are never sent, so stored data is not changed. The one exception is an optional, configured login:
  exactly one POST to the app's own sign-in form with a test account, whose password is read from an
  environment variable at scan time and never written anywhere.
* Links that look destructive (logout, delete, reset, …) are not followed.
* Redirects are never followed automatically and never leave the target; no proxy is used.
* Response bodies are never stored. Exposed files are recognised by a signature and only their size is kept.
* Hard limits on pages, requests, time per response and total time; cancellation is honoured between requests.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import ssl
import time
import http.cookiejar
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from engine.finding_normalizer import Coverage, NormalizedFinding, deduplicate
from engine.runner import CANCEL_EVENT, ScanExecution
from utils.logger import get_logger
from utils.security import sha256_hex
from utils.validators import SEVERITIES, is_loopback_host

log = get_logger(__name__)

SCANNER = "dast"
SCAN_TYPE = "web"
CATEGORY = "WEB"
ENGINE_VERSION = "1.2"
MAX_BODY = 1_000_000
USER_AGENT = "LocalSecurityScanner-DAST/1.0 (local test)"
OWASP = "https://owasp.org/www-project-top-ten/"


@dataclass(frozen=True)
class Check:
    title: str
    severity: str
    cwe: int
    remediation: str
    reference: str = OWASP


CHECKS: dict[str, Check] = {
    "DAST-CSP": Check(
        "Content-Security-Policy header missing", "MEDIUM", 693,
        "Send a Content-Security-Policy header (start with \"default-src 'self'\") so injected scripts cannot run.",
        "https://developer.mozilla.org/docs/Web/HTTP/CSP"),
    "DAST-CLICKJACK": Check(
        "Page can be shown inside other websites (clickjacking)", "MEDIUM", 1021,
        "Send X-Frame-Options: DENY (or CSP frame-ancestors 'self') so other sites cannot frame the page.",
        "https://owasp.org/www-community/attacks/Clickjacking"),
    "DAST-NOSNIFF": Check(
        "X-Content-Type-Options: nosniff header missing", "LOW", 693,
        "Send X-Content-Type-Options: nosniff so browsers do not guess file types (prevents some XSS tricks).",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    "DAST-HSTS": Check(
        "HTTPS site does not force HTTPS (Strict-Transport-Security missing)", "MEDIUM", 319,
        "Send Strict-Transport-Security: max-age=31536000 on HTTPS responses.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"),
    "DAST-VERSION": Check(
        "Server software and version are disclosed", "LOW", 200,
        "Hide version numbers in the Server / X-Powered-By headers so attackers cannot look up known bugs.",
        "https://owasp.org/www-project-web-security-testing-guide/"),
    "DAST-COOKIE-HTTPONLY": Check(
        "Cookie readable by JavaScript (HttpOnly missing)", "MEDIUM", 1004,
        "Set the HttpOnly flag on session cookies so an XSS bug cannot steal them.",
        "https://owasp.org/www-community/HttpOnly"),
    "DAST-COOKIE-SAMESITE": Check(
        "Cookie without SameSite attribute", "LOW", 1275,
        "Set SameSite=Lax (or Strict) on cookies to reduce cross-site request forgery.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value"),
    "DAST-COOKIE-SECURE": Check(
        "Cookie on HTTPS site without Secure flag", "MEDIUM", 614,
        "Set the Secure flag so the cookie is never sent over plain HTTP.",
        "https://owasp.org/www-community/controls/SecureCookieAttribute"),
    "DAST-CORS": Check(
        "Any website can read this app's responses (CORS allows every origin)", "MEDIUM", 942,
        "Only allow the exact origins that need access in Access-Control-Allow-Origin; never echo the request's "
        "Origin back, especially together with Access-Control-Allow-Credentials: true.",
        "https://portswigger.net/web-security/cors"),
    "DAST-EXPOSED-FILE": Check(
        "Sensitive file can be downloaded", "HIGH", 538,
        "Stop serving this file: move it out of the web folder or block it in the web server. If it held "
        "passwords or keys, rotate them.",
        "https://owasp.org/www-project-web-security-testing-guide/"),
    "DAST-DIR-LISTING": Check(
        "Folder contents are listed (directory listing)", "MEDIUM", 548,
        "Turn off directory listing in the web server so file names are not exposed.",
        "https://cwe.mitre.org/data/definitions/548.html"),
    "DAST-DEBUG": Check(
        "Debug mode / interactive debugger is exposed", "CRITICAL", 489,
        "Turn debug mode off (Flask: debug=False, Django: DEBUG=False). The debugger lets anyone who reaches "
        "the app run commands on the server.",
        "https://flask.palletsprojects.com/en/stable/debugging/"),
    "DAST-ERROR-LEAK": Check(
        "Error page shows internal details (stack trace)", "MEDIUM", 209,
        "Show a generic error page to users and log the details on the server instead.",
        "https://owasp.org/www-community/Improper_Error_Handling"),
    "DAST-TRACE": Check(
        "HTTP TRACE method is enabled", "LOW", 693,
        "Disable the TRACE method in the web server.",
        "https://owasp.org/www-community/attacks/Cross_Site_Tracing"),
    "DAST-XSS": Check(
        "Reflected cross-site scripting (XSS)", "HIGH", 79,
        "Escape user input before putting it in a page (use the template engine's auto-escaping) and add a "
        "Content-Security-Policy.",
        "https://owasp.org/www-community/attacks/xss/"),
    "DAST-SQLI": Check(
        "SQL injection (a quote character breaks the database query)", "HIGH", 89,
        "Use parameterised queries (cursor.execute(sql, params)) or the ORM; never build SQL from request values.",
        "https://owasp.org/www-community/attacks/SQL_Injection"),
    "DAST-REDIRECT": Check(
        "Open redirect (app sends users to any website)", "MEDIUM", 601,
        "Only redirect to paths inside the app or to an allow-list of known sites.",
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
    "DAST-API-AUTH": Check(
        "API endpoint documented as needing a login answers without one", "HIGH", 306,
        "Require authentication on this endpoint in the code (for example a login-required decorator or "
        "dependency). The API description says it is protected, but it answered a request without credentials.",
        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"),
    "DAST-API-DOCS": Check(
        "API documentation is publicly reachable", "LOW", 200,
        "Turn off the interactive API docs (Swagger UI, /openapi.json) outside development, or put them behind a "
        "login, so attackers do not get a map of every endpoint.",
        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"),
    "DAST-TRAVERSAL": Check(
        "Path traversal (server files can be read through a parameter)", "HIGH", 22,
        "Never build file paths from request values; map allowed names to files, or resolve the path and check "
        "it stays inside the intended folder.",
        "https://owasp.org/www-community/attacks/Path_Traversal"),
}


def _is_html(resp: "Response") -> bool:
    return "html" in (resp.headers.get("Content-Type") or "").lower() or resp.body[:200].lstrip().lower().startswith(
        (b"<!doctype html", b"<html"))


def _env_sig(b: bytes) -> bool:
    return not b.lstrip().startswith(b"<") and re.search(rb"(?m)^[A-Z][A-Z0-9_]{1,63}=", b) is not None


def _sql_sig(b: bytes) -> bool:
    return not b.lstrip().startswith(b"<") and re.search(rb"(?i)\b(create table|insert into)\b", b) is not None


# (path, what it is, severity, signature). Signatures avoid false positives from pages that answer 200 for
# every address. Contents are never stored.
EXPOSED_FILES: list[tuple[str, str, str, Callable[[bytes], bool]]] = [
    ("/.env", "environment file (.env) with settings and usually passwords or keys", "CRITICAL", _env_sig),
    ("/.git/HEAD", "Git repository (.git) — the full source code and history can be downloaded", "HIGH",
     lambda b: b.startswith(b"ref: refs/") or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None),
    ("/.git/config", "Git repository configuration (.git/config)", "HIGH",
     lambda b: b"[core]" in b and not b.lstrip().startswith(b"<")),
    ("/db.sqlite3", "SQLite database file", "CRITICAL", lambda b: b.startswith(b"SQLite format 3\x00")),
    ("/app.db", "SQLite database file", "CRITICAL", lambda b: b.startswith(b"SQLite format 3\x00")),
    ("/backup.sql", "database backup (SQL dump)", "CRITICAL", _sql_sig),
    ("/dump.sql", "database backup (SQL dump)", "CRITICAL", _sql_sig),
    ("/.htpasswd", "password file (.htpasswd)", "HIGH",
     lambda b: re.match(rb"^[\w.-]+:\$?[\w./$]{8,}", b) is not None),
    ("/.DS_Store", "macOS folder index (.DS_Store) listing file names", "LOW",
     lambda b: b.startswith(b"\x00\x00\x00\x01Bud1")),
    ("/server-status", "Apache server status page", "MEDIUM", lambda b: b"Apache Server Status" in b),
    ("/phpinfo.php", "PHP configuration page (phpinfo)", "MEDIUM", lambda b: b"PHP Version" in b and b"phpinfo" in b),
]

SQL_ERRORS = [
    "sqlite3.OperationalError", "unrecognized token:", "SQLITE_ERROR", "You have an error in your SQL syntax",
    "Warning: mysql_", "MySQLSyntaxErrorException", "unterminated quoted string", "psycopg2.errors",
    "PG::SyntaxError", "syntax error at or near", "quoted string not properly terminated", "ORA-01756",
    "Microsoft OLE DB Provider for SQL Server", "Unclosed quotation mark after the character string",
    "SQLSTATE[", "SQLiteException", "near \"'\": syntax error",
]
STACK_TRACES = [
    ("Traceback (most recent call last)", "Python stack trace"),
    ("at java.", "Java stack trace"),
    ("System.Web.HttpException", ".NET error details"),
    ("Fatal error: Uncaught", "PHP error details"),
    ("node_modules/express/", "Node.js stack trace"),
]
REDIRECT_PARAMS = {"next", "url", "redirect", "redirect_url", "redirect_uri", "return", "return_to", "returnurl",
                   "goto", "dest", "destination", "continue", "target", "to", "r", "u", "link"}
FILE_PARAMS = {"file", "filename", "path", "page", "template", "doc", "document", "folder", "dir", "include",
               "name", "download", "view", "img", "image"}
TRAVERSAL_PAYLOADS = [("../" * 8 + "etc/passwd", rb"root:[x*]?:0:0:"),
                      ("..\\" * 8 + "windows\\win.ini", rb"(?i)\[fonts\]|for 16-bit app support")]
REDIRECT_PROBE = "https://lss-redirect-check.invalid/"
CORS_PROBE = "https://lss-cors-check.invalid"
NOT_FOUND_PATH = "/lss-page-that-does-not-exist"
DESTRUCTIVE = re.compile(r"(?i)(log-?out|sign-?out|log-?off|delete|remove|destroy|drop|reset|shutdown|"
                         r"unsubscribe|disable|revoke|purge|wipe)")
STATIC_EXT = (".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
              ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz", ".tar", ".mp3", ".mp4", ".webm",
              ".avi", ".mov", ".exe", ".msi", ".dmg", ".iso", ".wasm")


class _Stop(Exception):
    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


class Unreachable(Exception):
    pass


@dataclass
class Response:
    status: int
    headers: Message
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None  # 3xx is returned as a response; we decide ourselves whether to follow it


class Client:
    """Loopback-only HTTP client with a request budget, a deadline and cancellation."""

    def __init__(self, timeout: int, max_requests: int, deadline: float) -> None:
        ctx = ssl.create_default_context()
        # Local development servers usually use self-signed certificates; only loopback hosts are ever contacted.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.cookies = http.cookiejar.CookieJar()  # in memory only; keeps a login session during one scan
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                                  urllib.request.HTTPSHandler(context=ctx),
                                                  urllib.request.HTTPCookieProcessor(self.cookies))
        self.timeout = timeout
        self.max_requests = max_requests
        self.deadline = deadline
        self.count = 0
        self.errors = 0

    def request(self, url: str, method: str = "GET", headers: dict[str, str] | None = None,
                raise_unreachable: bool = False, data: bytes | None = None) -> Response | None:
        if CANCEL_EVENT.is_set():
            raise _Stop("CANCELLED", "Scan cancelled")
        if time.monotonic() > self.deadline:
            raise _Stop("TIMED_OUT", "Web scan exceeded the scan time limit")
        if self.count >= self.max_requests:
            raise _Stop("BUDGET", "Request limit reached")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not is_loopback_host(parts.hostname):
            raise ValueError(f"Refusing to contact a non-local address: {parts.hostname}")
        self.count += 1
        if method not in ("GET", "TRACE") and not (method == "POST" and (getattr(self, "_login_post", False)
                                                                            or getattr(self, "_api_post", False))):
            raise ValueError(f"The web scan never sends {method} requests")
        req = urllib.request.Request(url, method=method, data=data,
                                     headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:  # noqa: S310 - loopback http(s) only
                return Response(r.status, r.headers, r.read(MAX_BODY), url)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(MAX_BODY)
            except Exception:  # noqa: BLE001
                body = b""
            return Response(e.code, e.headers, body, url)
        except (urllib.error.URLError, OSError, ValueError) as e:
            if raise_unreachable:
                raise Unreachable(str(getattr(e, "reason", e))) from e
            self.errors += 1
            return None


class _LoginForm(HTMLParser):
    """The first form on a page that has a password input: its action, method and every input (name, type, value)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._cur: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea") and self._cur is not None and a.get("name"):
            self._cur["inputs"].append((a["name"], (a.get("type") or "text").lower(), a.get("value", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._cur = None

    def login_form(self) -> dict[str, Any] | None:
        return next((f for f in self.forms if any(t == "password" for _, t, _ in f["inputs"])), None)


def _has_password_input(text: str) -> bool:
    return re.search(r"(?i)<input\b[^>]*type\s*=\s*['\"]?password", text) is not None


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[tuple[str, str, list[str]]] = []
        self._form: tuple[str, str, list[str]] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = (a.get("action", ""), (a.get("method") or "get").lower(), [])
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None and a.get("name"):
            if a.get("type", "").lower() not in ("submit", "button", "image", "file", "password", "hidden"):
                self._form[2].append(a["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


@dataclass
class _Page:
    path: str
    params: list[str]

    def url(self, origin: str) -> str:
        q = urlencode([(p, "1") for p in self.params])
        return origin + self.path + (f"?{q}" if q else "")

    @property
    def key(self) -> tuple[str, tuple[str, ...]]:
        return self.path, tuple(sorted(self.params))


@dataclass
class _State:
    origin: str
    https: bool
    findings: list[NormalizedFinding] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    cookies_seen: set[str] = field(default_factory=set)
    target: str = ""
    logged_in: bool = False
    api_tested: list[str] = field(default_factory=list)
    api_skipped_post: list[str] = field(default_factory=list)
    api_source: str = ""
    landing: "_Page | None" = None   # page shown after signing in: crawled too, so the members area is reached


def _clean_path(path: str) -> str:
    return path or "/"


class DastScanner:
    def __init__(self, timeout: int = 10, max_pages: int = 30, max_requests: int = 400) -> None:
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_requests = max_requests

    # ------------------------------------------------------------------ findings
    def _add(self, st: _State, check_id: str, path: str, *, param: str | None = None, key: str = "",
             severity: str | None = None, evidence: str = "", params: list[str] | None = None,
             title: str | None = None, confidence: str = "HIGH", method: str = "GET", api: bool = False) -> None:
        c = CHECKS[check_id]
        path = _clean_path(path)
        where = path + (f" (parameter '{param}')" if param else "")
        st.findings.append(NormalizedFinding(
            scanner=SCANNER, scan_type=SCAN_TYPE, scan_target=st.target, category=CATEGORY,
            severity=severity or c.severity, rule_id=check_id, file_path=path,
            title=title or c.title,
            description=f"{title or c.title} at {where}. {evidence}".strip(),
            remediation=c.remediation, reference_url=c.reference,
            metadata={"url": st.origin + path, "parameter": param, "params": params or [], "evidence": evidence,
                      "confidence": confidence, "cwe": c.cwe,
                      "cwe_link": f"https://cwe.mitre.org/data/definitions/{c.cwe}.html", "method": method,
                      **({"api": True} if api else {})},
            identity=(check_id, path, param or "", key),
            dedup_key=sha256_hex("WEB", st.target, check_id, path, param or "", key),
        ))

    # ------------------------------------------------------------------ passive checks
    def _site_checks(self, st: _State, resp: Response, path: str) -> None:
        h = resp.headers
        html = _is_html(resp)
        csp = (h.get("Content-Security-Policy") or "").lower()
        if html and not csp:
            self._add(st, "DAST-CSP", path, evidence="No Content-Security-Policy header on the page.")
        if html and not h.get("X-Frame-Options") and "frame-ancestors" not in csp:
            self._add(st, "DAST-CLICKJACK", path, evidence="No X-Frame-Options header and no CSP frame-ancestors.")
        if (h.get("X-Content-Type-Options") or "").strip().lower() != "nosniff":
            self._add(st, "DAST-NOSNIFF", path, evidence="X-Content-Type-Options is not 'nosniff'.")
        if st.https and not h.get("Strict-Transport-Security"):
            self._add(st, "DAST-HSTS", path, evidence="No Strict-Transport-Security header.")
        shown = [f"{n}: {h.get(n)}" for n in ("Server", "X-Powered-By", "X-AspNet-Version")
                 if h.get(n) and re.search(r"\d", h.get(n) or "")]
        if shown:
            self._add(st, "DAST-VERSION", path, evidence="; ".join(shown)[:200])

    def _cookie_checks(self, st: _State, resp: Response, path: str) -> None:
        for raw in resp.headers.get_all("Set-Cookie") or []:
            name, _, rest = raw.partition("=")
            name = name.strip()
            if not name or name in st.cookies_seen:
                continue
            st.cookies_seen.add(name)
            attrs = {a.strip().split("=", 1)[0].lower() for a in rest.split(";")[1:]}
            label = f"Cookie '{name}'"
            if "httponly" not in attrs and not re.search(r"(?i)csrf|xsrf", name):
                self._add(st, "DAST-COOKIE-HTTPONLY", path, key=name, evidence=f"{label} is set without HttpOnly.",
                          title=f"{CHECKS['DAST-COOKIE-HTTPONLY'].title}: {name}")
            if "samesite" not in attrs:
                self._add(st, "DAST-COOKIE-SAMESITE", path, key=name, evidence=f"{label} has no SameSite.",
                          title=f"{CHECKS['DAST-COOKIE-SAMESITE'].title}: {name}")
            if st.https and "secure" not in attrs:
                self._add(st, "DAST-COOKIE-SECURE", path, key=name, evidence=f"{label} has no Secure flag.",
                          title=f"{CHECKS['DAST-COOKIE-SECURE'].title}: {name}")

    def _body_checks(self, st: _State, resp: Response, path: str) -> None:
        text = resp.text
        if "Werkzeug Debugger" in text or ("__debugger__" in text and "werkzeug" in text.lower()):
            self._add(st, "DAST-DEBUG", path, key="werkzeug",
                      evidence="The Werkzeug (Flask) interactive debugger is shown to visitors.")
            return
        if "You're seeing this error because you have <code>DEBUG = True</code>" in text:
            self._add(st, "DAST-DEBUG", path, key="django", severity="HIGH",
                      evidence="Django debug pages are shown to visitors (DEBUG = True).")
            return
        for marker, what in STACK_TRACES:
            if marker in text:
                self._add(st, "DAST-ERROR-LEAK", path, evidence=f"{what} in the response (HTTP {resp.status}).",
                          confidence="MEDIUM" if marker.startswith("at ") else "HIGH")
                break
        if _is_html(resp) and re.search(r"<title>\s*(Index of /|Directory listing for /)", text, re.I):
            self._add(st, "DAST-DIR-LISTING", path, evidence="The page lists the files in a folder.")

    # ------------------------------------------------------------------ active (safe) checks
    def _probe_files(self, st: _State, client: Client) -> None:
        git_found = False
        for path, what, severity, sig in EXPOSED_FILES:
            if path == "/.git/config" and git_found:
                continue
            resp = client.request(st.origin + path)
            if resp is not None and resp.status == 200 and resp.body and sig(resp.body):
                git_found = git_found or path.startswith("/.git/")
                self._add(st, "DAST-EXPOSED-FILE", path, severity=severity,
                          title=f"Sensitive file can be downloaded: {path}",
                          evidence=f"{what[0].upper() + what[1:]} is served ({len(resp.body)} bytes; contents not "
                                   "stored).")
        from engine.api_scanner import DOC_PATHS

        for path, sig in DOC_PATHS:  # interactive API docs / descriptions left open
            resp = client.request(st.origin + path)
            if resp is not None and resp.status == 200 and resp.body and sig(resp.body[:200_000]):
                self._add(st, "DAST-API-DOCS", path, evidence=f"The API documentation is served at {path}.")
                break
        console = client.request(st.origin + "/console")
        if console is not None and console.status == 200 and "werkzeug" in console.text.lower() \
                and "console" in console.text.lower():
            self._add(st, "DAST-DEBUG", "/console", key="werkzeug",
                      evidence="The Werkzeug debugger console page is reachable at /console.")
        trace = client.request(st.target, method="TRACE", headers={"X-LSS-Trace": "probe"})
        if trace is not None and trace.status == 200 and b"X-LSS-Trace" in trace.body:
            self._add(st, "DAST-TRACE", urlsplit(st.target).path, evidence="TRACE echoes the request back.")
        cors = client.request(st.target, headers={"Origin": CORS_PROBE})
        if cors is not None and (cors.headers.get("Access-Control-Allow-Origin") or "").strip() == CORS_PROBE:
            creds = (cors.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
            self._add(st, "DAST-CORS", urlsplit(st.target).path, severity="HIGH" if creds else "MEDIUM",
                      evidence="The app echoed an unknown website's Origin in Access-Control-Allow-Origin"
                               + (" and allows credentials (cookies)." if creds else "."))

    def _probe_params(self, st: _State, client: Client, page: _Page, baseline: Response) -> None:
        for param in page.params:
            def url_with(value: str) -> str:
                q = urlencode([(p, value if p == param else "1") for p in page.params])
                return f"{st.origin}{page.path}?{q}"

            marker = "lss" + secrets.token_hex(4)
            resp = client.request(url_with(f"\"'><{marker}>"))
            if resp is not None:
                if _is_html(resp) and f"<{marker}>" in resp.text:
                    self._add(st, "DAST-XSS", page.path, param=param, params=page.params,
                              evidence="A test value containing an HTML tag was returned in the page unescaped.")
                self._body_checks(st, resp, page.path)
            resp = client.request(url_with("1'"))
            if resp is not None:
                hit = next((s for s in SQL_ERRORS if s in resp.text and s not in baseline.text), None)
                if hit:
                    self._add(st, "DAST-SQLI", page.path, param=param, params=page.params,
                              evidence=f"Adding a quote character produced a database error ({hit}).")
                self._body_checks(st, resp, page.path)
            if param.lower() in REDIRECT_PARAMS:
                resp = client.request(url_with(REDIRECT_PROBE))
                loc = (resp.headers.get("Location") or "") if resp is not None else ""
                if resp is not None and 300 <= resp.status < 400 and loc.startswith(
                        (REDIRECT_PROBE, "//lss-redirect-check.invalid")):
                    self._add(st, "DAST-REDIRECT", page.path, param=param, params=page.params,
                              evidence="The app redirected to an outside test address taken from the parameter.")
            if param.lower() in FILE_PARAMS:
                for payload, sig in TRAVERSAL_PAYLOADS:
                    resp = client.request(url_with(payload))
                    if resp is not None and re.search(sig, resp.body) and not re.search(sig, baseline.body):
                        self._add(st, "DAST-TRAVERSAL", page.path, param=param, params=page.params,
                                  evidence="A ../ path in the parameter returned the contents of a system file "
                                           "(not stored).")
                        break

    # ------------------------------------------------------------------ crawl
    def _in_scope(self, st: _State, url: str) -> bool:
        p = urlsplit(url)
        if f"{p.scheme}://{p.netloc}" != st.origin:
            return False
        if p.path.lower().endswith(STATIC_EXT):
            return False
        return not DESTRUCTIVE.search(p.path + "?" + p.query)

    def _extract(self, st: _State, resp: Response) -> list[_Page]:
        parser = _Links()
        try:
            parser.feed(resp.text)
        except Exception:  # noqa: BLE001 - malformed HTML must not stop the scan
            pass
        out: list[_Page] = []
        for href in parser.links:
            if href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                continue
            full = urljoin(resp.url, href)
            if self._in_scope(st, full):
                p = urlsplit(full)
                out.append(_Page(_clean_path(p.path), list(dict.fromkeys(k for k, _ in parse_qsl(p.query, True)))))
        for action, method, names in parser.forms:
            if method != "get":
                continue  # POST forms can change data; never submitted
            full = urljoin(resp.url, action or resp.url)
            if self._in_scope(st, full) and names:
                out.append(_Page(_clean_path(urlsplit(full).path), list(dict.fromkeys(names))))
        return out

    def _fetch_start(self, st: _State, client: Client) -> Response:
        url = st.target
        for _ in range(5):
            resp = client.request(url, raise_unreachable=True)
            assert resp is not None
            loc = resp.headers.get("Location")
            if not (300 <= resp.status < 400 and loc):
                return resp
            nxt = urljoin(url, loc)
            if not self._in_scope(st, nxt):
                return resp
            url = nxt
        return resp

    # ------------------------------------------------------------------ entry point
    def _login(self, st: _State, client: Client, login: Any) -> None:
        """Sign in with the configured test account (one POST to the app's own login form).

        Raises _Stop("FAILED", reason) when the login cannot be done; reasons never contain the password."""
        password = os.environ.get(login.password_env)
        if not password:
            raise _Stop("FAILED", f"Login not possible: the environment variable {login.password_env} is not set. "
                                  "Set it to the test account's password, then scan again.")
        page = client.request(login.url, raise_unreachable=True)
        assert page is not None
        parser = _LoginForm()
        try:
            parser.feed(page.text)
        except Exception:  # noqa: BLE001
            pass
        form = parser.login_form()
        if form is None:
            raise _Stop("FAILED", f"Login not possible: no form with a password box was found at {login.url}.")
        action = urljoin(page.url, form["action"] or page.url)
        a = urlsplit(action)
        if f"{a.scheme}://{a.netloc}" != st.origin:
            raise _Stop("FAILED", "Login not possible: the login form sends the password to a different site.")
        user_field = login.username_field or next(
            (n for n, t, _ in form["inputs"] if t in ("text", "email") or n.lower() in ("username", "user", "email",
                                                                                     "login")), "")
        pass_field = login.password_field or next((n for n, t, _ in form["inputs"] if t == "password"), "")
        if not user_field or not pass_field:
            raise _Stop("FAILED", "Login not possible: the user-name or password box could not be identified; set "
                                  "username_field / password_field in the web scan settings.")
        fields: list[tuple[str, str]] = []
        for name, kind, value in form["inputs"]:
            if name == user_field:
                fields.append((name, login.username))
            elif name == pass_field:
                fields.append((name, password))
            elif kind in ("hidden", "checkbox") or (kind == "submit" and value):
                fields.append((name, value))  # CSRF tokens and similar
        client._login_post = True  # noqa: SLF001 - the only POST the scan may send
        try:
            resp = client.request(action, method=form["method"].upper() if form["method"] == "post" else "POST",
                                  headers={"Content-Type": "application/x-www-form-urlencoded",
                                           "Referer": page.url},
                                  data=urlencode(fields).encode("utf-8"))
        finally:
            client._login_post = False  # noqa: SLF001
        del password, fields
        for _ in range(5):  # follow the post-login redirect with GET, inside the app only
            if resp is None or not (300 <= resp.status < 400 and resp.headers.get("Location")):
                break
            nxt = urljoin(resp.url, resp.headers["Location"])
            if not self._in_scope(st, nxt):
                break
            resp = client.request(nxt)
        if resp is None or resp.status >= 400:
            raise _Stop("FAILED", "Login failed: the app rejected the sign-in"
                                  + (f" (HTTP {resp.status})." if resp is not None else " (no answer)."))
        if login.logged_in_text:
            ok = login.logged_in_text in resp.text
        else:
            ok = not _has_password_input(resp.text)
        if not ok:
            raise _Stop("FAILED", "Login failed: after signing in the app still showed the login form (or the "
                                  "'logged-in text' was not found). Check the user name and password.")
        st.logged_in = True
        landing = urlsplit(resp.url)
        st.landing = _Page(_clean_path(landing.path), list(dict.fromkeys(k for k, _ in parse_qsl(landing.query, True))))

    # ------------------------------------------------------------------ API (OpenAPI / Swagger)
    def _send(self, client: Client, op: Any, origin: str, query: dict | None = None, body: Any = None,
              ) -> Response | None:
        url = op.url(origin, query)
        if op.method == "get":
            return client.request(url, headers={"Accept": "application/json"})
        client._api_post = True  # noqa: SLF001 - allowed only for paths the user listed
        try:
            return client.request(url, method="POST", data=json.dumps(op.body if body is None else body).encode(),
                                  headers={"Content-Type": "application/json", "Accept": "application/json"})
        finally:
            client._api_post = False  # noqa: SLF001

    def _api_probe(self, st: _State, resp: Response | None, baseline: Response, op: Any, param: str, kind: str,
                   mark: str = "") -> None:
        if resp is None:
            return
        m = op.method.upper()
        if kind == "xss" and _is_html(resp) and f"<{mark}>" in resp.text:
            self._add(st, "DAST-XSS", op.path, param=param, key=m, method=m, api=True,
                      evidence=f"{m} {op.path}: a test value with an HTML tag came back unescaped in an HTML answer.")
        if kind in ("sql", "type"):
            hit = next((s for s in SQL_ERRORS if s in resp.text and s not in baseline.text), None)
            if hit:
                self._add(st, "DAST-SQLI", op.path, param=param, key=m, method=m, api=True,
                          evidence=f"{m} {op.path}: a quote character in '{param}' produced a database error ({hit}).")
        if kind == "traversal":
            for _, sig in TRAVERSAL_PAYLOADS:
                if re.search(sig, resp.body) and not re.search(sig, baseline.body):
                    self._add(st, "DAST-TRAVERSAL", op.path, param=param, key=m, method=m, api=True,
                              evidence=f"{m} {op.path}: a ../ path in '{param}' returned a system file (not stored).")
                    break
        for marker_text, what in STACK_TRACES:
            if marker_text in resp.text and marker_text not in baseline.text:
                self._add(st, "DAST-ERROR-LEAK", op.path, param=param, key=m, method=m, api=True,
                          confidence="MEDIUM" if marker_text.startswith("at ") else "HIGH",
                          evidence=f"{m} {op.path}: unexpected input in '{param}' returned a {what} "
                                   f"(HTTP {resp.status}).")
                break

    def _test_api(self, st: _State, client: Client, api: dict[str, Any]) -> None:
        from engine import api_scanner as A

        source = str(api.get("source") or "")
        st.api_source = source
        try:
            if source.startswith(("/", "http://", "https://")):
                url = source if source.startswith("http") else st.origin + source
                if f"{urlsplit(url).scheme}://{urlsplit(url).netloc}" != st.origin:
                    raise A.SpecError("The API description URL must be on the same app as the web address")
                resp = client.request(url, headers={"Accept": "application/json, application/yaml"})
                if resp is None or resp.status != 200:
                    raise A.SpecError(f"API description not found at {url}"
                                      + (f" (HTTP {resp.status})" if resp is not None else ""))
                spec = A.parse_spec(resp.text)
            else:
                text, _ = A.read_spec_file(source, api.get("project"), list(api.get("roots") or []))
                spec = A.parse_spec(text)
        except A.SpecError as exc:
            raise _Stop("FAILED", f"API testing not possible: {exc}") from exc
        allowed = {p.rstrip("/") or "/" for p in api.get("post_allowed") or []}
        anon: Client | None = None
        for op in A.operations(spec):
            if op.method == "post" and (op.path.rstrip("/") or "/") not in allowed:
                st.api_skipped_post.append(op.key)
                continue
            baseline = self._send(client, op, st.origin)
            if baseline is None:
                continue
            st.api_tested.append(op.key)
            m = op.method.upper()
            self._body_checks(st, baseline, op.path)
            if op.secured:
                check = baseline
                if st.logged_in:  # ask again without the session cookie
                    if anon is None:
                        anon = Client(self.timeout, max(1, client.max_requests - client.count), client.deadline)
                    check = self._send(anon, op, st.origin)
                    client.count += 1
                if check is not None and 200 <= check.status < 300:
                    self._add(st, "DAST-API-AUTH", op.path, key=m, method=m, api=True,
                              evidence=f"{m} {op.path} is documented as requiring authentication but answered "
                                       f"HTTP {check.status} to a request without credentials.")
            query = {p["name"]: p["value"] for p in op.params if p["in"] == "query"}
            for p in [p for p in op.params if p["in"] == "query"]:
                name = p["name"]
                mark = A.marker()
                self._api_probe(st, self._send(client, op, st.origin, {**query, name: f"\"'><{mark}>"}), baseline,
                                op, name, "xss", mark)
                self._api_probe(st, self._send(client, op, st.origin, {**query, name: f"{p['value']}'"}), baseline,
                                op, name, "sql")
                if name.lower() in FILE_PARAMS:
                    self._api_probe(st, self._send(client, op, st.origin, {**query, name: TRAVERSAL_PAYLOADS[0][0]}),
                                    baseline, op, name, "traversal")
            if op.method == "post" and op.body is not None:
                for field_name in A.string_fields(op.body):
                    mark = A.marker()
                    label = f"body.{field_name}"
                    self._api_probe(st, self._send(client, op, st.origin, body=A.with_value(
                        op.body, field_name, f"\"'><{mark}>")), baseline, op, label, "xss", mark)
                    self._api_probe(st, self._send(client, op, st.origin, body=A.with_value(
                        op.body, field_name, "test'")), baseline, op, label, "sql")
                for field_name in A.numeric_fields(op.body):
                    self._api_probe(st, self._send(client, op, st.origin, body=A.with_value(
                        op.body, field_name, "abc'")), baseline, op, f"body.{field_name}", "type")

    def scan(self, target: str, report: Path, time_limit: int, seeds: list[tuple[str, list[str]]] | None = None,
             login: Any = None, api: dict[str, Any] | None = None) -> ScanExecution:
        cov = Coverage(SCANNER, SCAN_TYPE, target, frozenset({CATEGORY}), frozenset(SEVERITIES))
        ex = ScanExecution(SCANNER, SCAN_TYPE, target, "PENDING", cov, tool_version=ENGINE_VERSION,
                           command=["built-in DAST", target])
        parts = urlsplit(target)
        if not is_loopback_host(parts.hostname):
            ex.status, ex.error_message = "FAILED", "Web scan is limited to apps on this computer"
            return ex
        st = _State(origin=f"{parts.scheme}://{parts.netloc}", https=parts.scheme == "https", target=target)
        t0 = time.monotonic()
        ex.started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        client = Client(self.timeout, self.max_requests, t0 + time_limit)
        seeds = seeds or []
        notes: list[str] = []
        seeds_done = 0
        api_done = True
        try:
            try:
                if login is not None:
                    self._login(st, client, login)
                start = self._fetch_start(st, client)
            except Unreachable as exc:
                ex.status = "SKIPPED"
                ex.error_message = (f"Nothing answered at {target} ({exc}). Start the app and scan again; its "
                                    "earlier web findings are kept as unverified.")
                return ex
            start_path = _clean_path(urlsplit(start.url).path)
            self._site_checks(st, start, start_path)
            self._cookie_checks(st, start, start_path)
            self._body_checks(st, start, start_path)
            self._probe_files(st, client)
            missing = client.request(f"{st.origin}{NOT_FOUND_PATH}")
            if missing is not None:  # error pages often leak more than normal pages
                self._body_checks(st, missing, NOT_FOUND_PATH)
                self._cookie_checks(st, missing, NOT_FOUND_PATH)
            api_done = api is None or not api.get("source")
            if not api_done:
                self._test_api(st, client, api)  # before the crawl, so the request budget covers every endpoint
                api_done = True

            first = _Page(start_path, list(dict.fromkeys(k for k, _ in parse_qsl(urlsplit(start.url).query, True))))
            queue: deque[tuple[_Page, bool]] = deque([(first, False)])
            if st.landing is not None:
                queue.append((st.landing, False))
            queue.extend((_Page(_clean_path(p), list(ps)), True) for p, ps in seeds)
            seen: set[tuple[str, tuple[str, ...]]] = set()
            visited = 0
            while queue:
                page, is_seed = queue.popleft()
                if page.key in seen or not self._in_scope(st, st.origin + page.path):
                    seeds_done += is_seed
                    continue
                if not is_seed and visited >= self.max_pages:
                    continue
                seen.add(page.key)
                resp = start if page is first else client.request(page.url(st.origin))
                visited += 1
                if resp is None:
                    seeds_done += is_seed
                    continue
                st.pages.append(page.path)
                if page is not first:
                    self._cookie_checks(st, resp, page.path)
                    self._body_checks(st, resp, page.path)
                if page.params:
                    self._probe_params(st, client, page, resp)
                if _is_html(resp) and resp.status < 400:
                    for nxt in self._extract(st, resp):
                        if nxt.key not in seen:
                            queue.append((nxt, False))
                seeds_done += is_seed
        except _Stop as stop:
            if stop.status == "FAILED":
                ex.status, ex.error_message = "FAILED", str(stop)
                return ex
            if stop.status != "BUDGET":
                ex.status, ex.error_message = stop.status, str(stop)
                return ex
            if not api_done:
                ex.status = "FAILED"
                ex.error_message = (f"Request limit ({self.max_requests}) reached before every API endpoint was "
                                    "tested; raise dast.max_requests.")
                return ex
            if seeds_done < len(seeds):
                ex.status = "FAILED"
                ex.error_message = (f"Request limit ({self.max_requests}) reached before every earlier finding was "
                                    "re-checked; raise dast.max_requests.")
                return ex
            notes.append(f"Request limit ({self.max_requests}) reached; some pages were not tested.")
        finally:
            ex.duration = round(time.monotonic() - t0, 2)
            ex.finished_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        ex.findings = deduplicate(st.findings)
        if client.errors:
            notes.append(f"{client.errors} request(s) got no answer.")
        ex.error_message = " ".join(notes) or None
        self._write_report(report, target, st, client, ex)
        ex.report_path = str(report)
        ex.status = "COMPLETED_WITH_FINDINGS" if ex.findings else "COMPLETED"
        return ex

    @staticmethod
    def _write_report(report: Path, target: str, st: _State, client: Client, ex: ScanExecution) -> None:
        data: dict[str, Any] = {
            "scanner": "Local Security Scanner built-in DAST", "engine_version": ENGINE_VERSION, "target": target,
            "started_at": ex.started_at, "duration_seconds": ex.duration,
            "pages_tested": sorted(set(st.pages)), "requests_sent": client.count, "requests_failed": client.errors,
            "logged_in": st.logged_in,
            "api_description": st.api_source or None, "api_operations_tested": st.api_tested,
            "api_post_not_allowed": st.api_skipped_post,
            "checks": sorted(CHECKS),
            "findings": [{"check": f.rule_id, "severity": f.severity, "path": f.file_path,
                          "parameter": f.metadata.get("parameter"), "title": f.title,
                          "evidence": f.metadata.get("evidence")} for f in deduplicate(st.findings)],
            "note": "Response bodies are never stored.",
        }
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(data, indent=1), encoding="utf-8")


def read_report_summary(path: str | None) -> dict[str, Any] | None:
    """Pages and requests of a saved DAST report (for the dashboard's 'what was checked' panel)."""
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return {"pages": len(data.get("pages_tested") or []), "requests": data.get("requests_sent", 0),
            "logged_in": bool(data.get("logged_in")), "api_tested": len(data.get("api_operations_tested") or []),
            "api_skipped": len(data.get("api_post_not_allowed") or [])}
