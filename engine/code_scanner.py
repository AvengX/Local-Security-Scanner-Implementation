"""Built-in code scan (SAST) for languages other than Python: JavaScript/TypeScript, HTML/Jinja templates, PHP,
Java, Go and C#.

Bandit covers Python in depth. This scanner adds well-known risky patterns in the other languages a typical
project contains (front-end scripts, templates, small services). It reads files as text with regular
expressions — it never runs or imports anything and needs no download.

Rules are deliberately few and high-signal; each one has a plain-language explanation (services/explain.py) and
a fix. Matched source text is never stored (it could contain a secret): only the rule, file and line number.
Minified bundles, installed dependencies (scan.skip_dirs, node_modules, vendor) and very large files are skipped.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.finding_normalizer import Coverage, NormalizedFinding, deduplicate
from engine.runner import CANCEL_EVENT, ScanExecution
from utils.security import sha256_hex
from utils.validators import SEVERITIES

SCANNER = "codescan"
SCAN_TYPE = "multi"
CATEGORY = "CODE"
ENGINE_VERSION = "1.0"
MAX_FILE_BYTES = 1_500_000
MAX_LINE = 2_000          # longer lines are minified/generated code
ALWAYS_SKIP = {"node_modules", "vendor", "bower_components", ".git", ".hg", ".svn", "__pycache__", "dist", "build",
               ".next", ".nuxt", "coverage", "site-packages", "target", "bin", "obj"}

LANGUAGES: dict[str, tuple[str, ...]] = {
    "JavaScript/TypeScript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"),
    "HTML templates": (".html", ".htm", ".jinja", ".jinja2", ".j2", ".njk", ".hbs", ".ejs"),
    "PHP": (".php",),
    "Java": (".java",),
    "Go": (".go",),
    "C#": (".cs",),
}
EXT_LANG = {ext: lang for lang, exts in LANGUAGES.items() for ext in exts}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    language: str
    severity: str
    confidence: str
    cwe: int
    title: str
    remediation: str
    pattern: re.Pattern[str]
    reference: str = "https://owasp.org/www-project-top-ten/"


def _r(p: str) -> re.Pattern[str]:
    return re.compile(p)


JS, TPL, PHP, JAVA, GO, CS = ("JavaScript/TypeScript", "HTML templates", "PHP", "Java", "Go", "C#")
_DYN = r"(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+|\+\s*\w)"  # template literal with ${} or string concatenation

RULES: list[Rule] = [
    # ---- JavaScript / TypeScript
    Rule("JS-EVAL", JS, "HIGH", "MEDIUM", 95, "eval() or new Function() runs text as code",
         "Remove eval/new Function. Parse data with JSON.parse and call functions directly.",
         _r(r"(?<![\w.$])(?:eval\s*\(|new\s+Function\s*\()"),
         "https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!"),
    Rule("JS-INNERHTML", JS, "MEDIUM", "MEDIUM", 79, "HTML is built from a variable (innerHTML / document.write)",
         "Use textContent (or createElement) for text. If HTML is really needed, sanitise it with DOMPurify first.",
         _r(r"(?:\.(?:innerHTML|outerHTML)\s*\+?=\s*(?!\s*['\"`][^'\"`$]*['\"`]\s*;?\s*$)|"
            r"\.insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\()"),
         "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"),
    Rule("JS-DANGEROUS-HTML", JS, "MEDIUM", "MEDIUM", 79, "React dangerouslySetInnerHTML inserts raw HTML",
         "Render the value as normal JSX text. If HTML is really needed, sanitise it with DOMPurify first.",
         _r(r"dangerouslySetInnerHTML\s*=\s*\{"),
         "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html"),
    Rule("JS-CMD-INJECTION", JS, "HIGH", "MEDIUM", 78, "Shell command built from a variable (child_process)",
         "Use execFile/spawn with an argument array (no shell) and never put request values into the command.",
         _r(r"(?<![\w.])(?:exec|execSync)\s*\(\s*" + _DYN),
         "https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback"),
    Rule("JS-STRING-TIMER", JS, "MEDIUM", "LOW", 95, "setTimeout/setInterval given a string (runs it as code)",
         "Pass a function instead of a string: setTimeout(() => doThing(), 1000).",
         _r(r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]")),
    Rule("JS-WEAK-RANDOM", JS, "LOW", "LOW", 338, "Math.random() used for a token, password or ID",
         "Use crypto.getRandomValues() in the browser or crypto.randomBytes()/randomUUID() in Node.",
         _r(r"(?i)(?:token|secret|password|passwd|otp|nonce|session|apikey|api_key)\w*\s*[:=][^;\n]*Math\.random\(")),
    Rule("JS-STORAGE-TOKEN", JS, "MEDIUM", "LOW", 922, "Token or password saved in localStorage/sessionStorage",
         "Keep session tokens in an HttpOnly cookie set by the server; any script on the page can read localStorage.",
         _r(r"(?i)(?:local|session)Storage\.setItem\s*\(\s*['\"`][^'\"`]*(?:token|jwt|auth|password|secret)")),
    Rule("JS-TLS-OFF", JS, "HIGH", "HIGH", 295, "TLS certificate checking is turned off",
         "Remove rejectUnauthorized: false / NODE_TLS_REJECT_UNAUTHORIZED=0; fix the certificate instead.",
         _r(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=\s*['\"]?0")),
    Rule("JS-SQL-CONCAT", JS, "HIGH", "MEDIUM", 89, "SQL query built from a variable (SQL injection)",
         "Use placeholders: db.query('SELECT … WHERE id = ?', [id]) or the ORM's query builder.",
         _r(r"(?i)\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\b(?:select|insert|update|delete)\b[^`]*\$\{|"
            r"['\"][^'\"]*\b(?:select|insert|update|delete)\b[^'\"]*['\"]\s*\+)"),
         "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"),
    Rule("JS-POSTMESSAGE-ANY", JS, "LOW", "MEDIUM", 345, "postMessage sends data to any website ('*')",
         "Pass the exact origin of the receiving window instead of '*'.",
         _r(r"\.postMessage\s*\([^;]*,\s*['\"]\*['\"]")),
    Rule("JS-CORS-ANY", JS, "MEDIUM", "MEDIUM", 942, "CORS allows every website",
         "List the exact origins that may call the API, e.g. cors({ origin: ['https://app.example.com'] }).",
         _r(r"cors\s*\(\s*\{[^}]*origin\s*:\s*(?:['\"]\*['\"]|true)|Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*")),
    Rule("JS-OPEN-REDIRECT", JS, "MEDIUM", "LOW", 601, "Page redirects to an address taken from the URL",
         "Only redirect to paths inside the site or to an allow-list; never to location.search/hash values as-is.",
         _r(r"(?:window\.)?location(?:\.href)?\s*=\s*[^;\n]*(?:location\.(?:search|hash)|URLSearchParams|getParameter)")),
    # ---- HTML / Jinja / other templates
    Rule("TPL-SAFE-FILTER", TPL, "MEDIUM", "MEDIUM", 79, "Template turns off HTML escaping (|safe / autoescape off)",
         "Remove |safe (or {% autoescape false %}) for anything a user can influence; let the template escape it.",
         _r(r"\|\s*safe\b|\{%-?\s*autoescape\s+(?:false|off)|\{\{\{[^}]+\}\}\}|<%-\s"),
         "https://jinja.palletsprojects.com/en/stable/templates/#html-escaping"),
    Rule("TPL-HTTP-SCRIPT", TPL, "MEDIUM", "HIGH", 319, "Script or stylesheet loaded over plain http://",
         "Load it over https:// (or host it yourself). Over http anyone on the network can replace it.",
         _r(r"(?i)<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*['\"]http://(?!localhost|127\.0\.0\.1)")),
    Rule("TPL-NO-SRI", TPL, "LOW", "MEDIUM", 353, "Script from another website loaded without an integrity check",
         "Add integrity=\"sha384-…\" crossorigin=\"anonymous\" (Subresource Integrity), or host the file yourself.",
         _r(r"(?i)<script\b(?![^>]*\bintegrity\s*=)[^>]*\bsrc\s*=\s*['\"](?:https?:)?//"),
         "https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity"),
    Rule("TPL-BLANK-NOOPENER", TPL, "LOW", "MEDIUM", 1022, "Link opens a new tab without rel=\"noopener\"",
         "Add rel=\"noopener noreferrer\" to links with target=\"_blank\".",
         _r(r"(?i)<a\b(?![^>]*\brel\s*=\s*['\"][^'\"]*noopener)[^>]*\btarget\s*=\s*['\"]_blank['\"]"),
         "https://developer.mozilla.org/docs/Web/HTML/Attributes/rel/noopener"),
    Rule("TPL-HTTP-FORM", TPL, "MEDIUM", "HIGH", 319, "Form sends data over plain http://",
         "Use an https:// form action (or a relative path) so the data is encrypted.",
         _r(r"(?i)<form\b[^>]*\baction\s*=\s*['\"]http://(?!localhost|127\.0\.0\.1)")),
    # ---- PHP
    Rule("PHP-EVAL", PHP, "HIGH", "MEDIUM", 95, "eval()/assert() runs text as code",
         "Remove eval; use explicit logic or a safe parser.", _r(r"(?<![\w>])(?:eval|assert)\s*\(\s*\$")),
    Rule("PHP-CMD-INJECTION", PHP, "HIGH", "MEDIUM", 78, "Shell command built from user input",
         "Avoid shell functions; if unavoidable, escape every argument with escapeshellarg().",
         _r(r"(?<![\w>])(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)")),
    Rule("PHP-SQL-CONCAT", PHP, "HIGH", "MEDIUM", 89, "SQL query built from user input (SQL injection)",
         "Use prepared statements (PDO::prepare with placeholders).",
         _r(r"(?i)(?:mysqli?_query|->query)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)")),
    Rule("PHP-XSS-ECHO", PHP, "HIGH", "MEDIUM", 79, "User input printed into the page without escaping",
         "Wrap output in htmlspecialchars($value, ENT_QUOTES, 'UTF-8').",
         _r(r"(?<![\w>])(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)")),
    Rule("PHP-FILE-INCLUDE", PHP, "HIGH", "MEDIUM", 98, "File included from user input",
         "Map allowed names to files; never pass request values to include/require.",
         _r(r"(?<![\w>])(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)")),
    # ---- Java
    Rule("JAVA-SQL-CONCAT", JAVA, "HIGH", "MEDIUM", 89, "SQL query built by string concatenation",
         "Use PreparedStatement with ? placeholders.",
         _r(r"(?i)\.(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*\"[^\"]*\b(?:select|insert|update|delete)\b[^\"]*\"\s*\+")),
    Rule("JAVA-CMD", JAVA, "HIGH", "LOW", 78, "Command started with Runtime.exec",
         "Use ProcessBuilder with a fixed program and a list of arguments; never pass user input to a shell.",
         _r(r"Runtime\.getRuntime\(\)\.exec\s*\(")),
    Rule("JAVA-WEAK-HASH", JAVA, "MEDIUM", "MEDIUM", 328, "MD5 or SHA-1 used",
         "Use SHA-256 or better; for passwords use bcrypt/scrypt/Argon2.",
         _r(r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"")),
    # ---- Go
    Rule("GO-TLS-OFF", GO, "HIGH", "HIGH", 295, "TLS certificate checking is turned off",
         "Remove InsecureSkipVerify: true; fix or trust the certificate properly.",
         _r(r"InsecureSkipVerify\s*:\s*true")),
    Rule("GO-SQL-SPRINTF", GO, "HIGH", "MEDIUM", 89, "SQL query built with fmt.Sprintf (SQL injection)",
         "Use placeholders: db.Query(\"SELECT … WHERE id = $1\", id).",
         _r(r"\.(?:Query|QueryRow|Exec)(?:Context)?\s*\([^;\n]*fmt\.Sprintf\s*\(")),
    Rule("GO-SHELL", GO, "HIGH", "LOW", 78, "Command run through a shell (sh -c)",
         "Run the program directly with exec.Command(program, args...) and validate every argument.",
         _r(r"exec\.Command(?:Context)?\s*\([^)]*\"(?:/bin/)?(?:ba)?sh\"\s*,\s*\"-c\"")),
    # ---- C#
    Rule("CS-SQL-CONCAT", CS, "HIGH", "MEDIUM", 89, "SQL command built by string concatenation",
         "Use SqlCommand parameters (@id) or an ORM.",
         _r(r"(?i)new\s+SqlCommand\s*\(\s*(?:\$\"[^\"]*\b(?:select|insert|update|delete)\b[^\"]*\{|\"[^\"]*\b(?:select|insert|update|delete)\b[^\"]*\"\s*\+)")),
    Rule("CS-TLS-OFF", CS, "HIGH", "HIGH", 295, "TLS certificate checking is turned off",
         "Do not return true from ServerCertificateValidationCallback; fix the certificate instead.",
         _r(r"ServerCertificate(?:Custom)?ValidationCallback\s*=\s*(?:\([^)]*\)|\w+)\s*=>\s*true")),
]
RULES_BY_ID = {r.rule_id: r for r in RULES}
_COMMENT = re.compile(r"^\s*(?://|#|\*|/\*|<!--)")


def _iter_files(root: Path, skip: set[str], skip_rel: list[str]):  # noqa: ANN202
    for cur, dirs, files in os.walk(root):
        rel_dir = Path(cur).relative_to(root).as_posix()
        dirs[:] = [d for d in dirs if d.lower() not in skip and not d.startswith(".")
                   and not any((f"{rel_dir}/{d}" if rel_dir != "." else d) == s for s in skip_rel)]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in EXT_LANG and ".min." not in name.lower():
                yield Path(cur) / name, EXT_LANG[ext]


def count_files(root: Path, skip_dirs: list[str]) -> dict[str, int]:
    """Files per language the built-in code scan reads (for the 'what was checked' panel)."""
    skip = {d.lower() for d in skip_dirs} | ALWAYS_SKIP
    out: dict[str, int] = {}
    if root.is_dir():
        for _, lang in _iter_files(root, skip, []):
            out[lang] = out.get(lang, 0) + 1
    return out


def scan_text(text: str, rel: str, language: str) -> list[tuple[Rule, int, str]]:
    """(rule, line number, normalised line text) for every match; line text is only used for identity hashing."""
    hits: list[tuple[Rule, int, str]] = []
    rules = [r for r in RULES if r.language == language]
    if language == JS and rel.lower().endswith((".vue", ".svelte")):
        rules += [r for r in RULES if r.language == TPL]
    if language == TPL:
        rules += [r for r in RULES if r.rule_id in ("JS-EVAL", "JS-INNERHTML", "JS-STRING-TIMER", "JS-STORAGE-TOKEN")]
    for num, line in enumerate(text.splitlines(), 1):
        if len(line) > MAX_LINE or _COMMENT.match(line):
            continue
        for rule in rules:
            if rule.pattern.search(line):
                hits.append((rule, num, re.sub(r"\s+", " ", line).strip()))
    return hits


class CodeScanner:
    def scan(self, target: Path, report: Path, time_limit: int, skip_dirs: list[str] | None = None,
             skip_rel: list[str] | None = None) -> ScanExecution:
        cov = Coverage(SCANNER, SCAN_TYPE, ".", frozenset({CATEGORY}), frozenset(SEVERITIES))
        ex = ScanExecution(SCANNER, SCAN_TYPE, ".", "PENDING", cov, tool_version=ENGINE_VERSION,
                           command=["built-in code scan", "."])
        t0 = time.monotonic()
        ex.started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        skip = {d.lower() for d in (skip_dirs or [])} | ALWAYS_SKIP
        findings: list[NormalizedFinding] = []
        per_lang: dict[str, int] = {}
        unreadable: list[str] = []
        seen: dict[tuple[str, str, str], int] = {}
        for path, lang in _iter_files(target, skip, skip_rel or []):
            if CANCEL_EVENT.is_set():
                ex.status, ex.error_message = "CANCELLED", "Scan cancelled"
                return ex
            if time.monotonic() - t0 > time_limit:
                ex.status, ex.error_message = "TIMED_OUT", f"Code scan exceeded the {time_limit}s timeout"
                return ex
            rel = path.relative_to(target).as_posix()
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    unreadable.append(rel)
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                unreadable.append(rel)
                continue
            per_lang[lang] = per_lang.get(lang, 0) + 1
            for rule, line, line_text in scan_text(text, rel, lang):
                line_hash = sha256_hex(line_text)[:16]
                key = (rule.rule_id, rel, line_hash)
                seen[key] = seen.get(key, 0) + 1
                findings.append(NormalizedFinding(
                    scanner=SCANNER, scan_type=SCAN_TYPE, category=CATEGORY, severity=rule.severity,
                    rule_id=rule.rule_id, file_path=rel, line=line, title=rule.title,
                    description=f"Built-in check {rule.rule_id} ({rule.language}) flagged {rel} line {line}. "
                                f"Confidence: {rule.confidence.title()}.",
                    remediation=rule.remediation, reference_url=rule.reference,
                    metadata={"confidence": rule.confidence, "test_name": rule.title, "language": rule.language,
                              "cwe": rule.cwe, "cwe_link": f"https://cwe.mitre.org/data/definitions/{rule.cwe}.html",
                              "occurrence": seen[key]},
                    identity=(rule.rule_id, rel, line_hash, seen[key]),
                    dedup_key=sha256_hex("CODE", ".", rule.rule_id, rel, line_hash, seen[key]),
                ))
        ex.findings = deduplicate(findings)
        ex.duration = round(time.monotonic() - t0, 2)
        ex.finished_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        data: dict[str, Any] = {
            "scanner": "Local Security Scanner built-in code scan", "engine_version": ENGINE_VERSION,
            "files_checked": per_lang, "files_skipped": unreadable[:50], "rules": sorted(RULES_BY_ID),
            "findings": [{"rule": f.rule_id, "severity": f.severity, "file": f.file_path, "line": f.line,
                          "title": f.title} for f in ex.findings],
            "note": "Source code is never copied into this report.",
        }
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(data, indent=1), encoding="utf-8")
        ex.report_path = str(report)
        if unreadable:
            ex.error_message = (f"{len(unreadable)} file(s) were too large or unreadable and were not checked: "
                                + ", ".join(unreadable[:5]) + (" …" if len(unreadable) > 5 else ""))
        ex.status = "COMPLETED_WITH_FINDINGS" if ex.findings else "COMPLETED"
        return ex


def read_report_summary(path: str | None) -> dict[str, int] | None:
    if not path:
        return None
    try:
        return dict(json.loads(Path(path).read_text(encoding="utf-8")).get("files_checked") or {})
    except (OSError, ValueError):
        return None
