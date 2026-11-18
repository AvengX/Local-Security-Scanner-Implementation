"""Two tiny web apps for the DAST part of the VAPT test, served on 127.0.0.1 only.

* ``vulnerable``: deliberately unsafe — reflected XSS, SQL error from string-built SQL (in-memory SQLite), open
  redirect, simulated path traversal (returns a fake passwd line, never reads real files), exposed .env, directory
  listing, a fake Werkzeug debugger console, a stack-trace page, an over-permissive CORS policy, a cookie without
  flags and a version-revealing Server header. It also has /logout and /delete-account links that a safe scanner
  must never follow (hits are counted).
* ``clean``: the same shape done right, so the scan must report nothing (false-positive control).

Standard library only; nothing here is reachable from other machines.
"""

from __future__ import annotations

import html
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

VULN_HOME = """<!doctype html><html><head><title>Lab shop</title></head><body>
<h1>Lab shop</h1>
<a href="/search?q=shoes">Search</a> <a href="/item?id=1">Item</a> <a href="/go?next=/">Home</a>
<a href="/view?file=readme.txt">Readme</a> <a href="/static/">Files</a> <a href="/crash">Report</a>
<a href="/logout">Log out</a> <a href="/delete-account">Delete my account</a>
<form action="/search" method="get"><input name="q"><input type="submit"></form>
<form action="/order" method="post"><input name="qty"></form>
</body></html>"""

CLEAN_HOME = """<!doctype html><html><head><title>Clean app</title></head><body>
<h1>Clean app</h1><a href="/about">About</a> <a href="/search?q=shoes">Search</a>
<form action="/search" method="get"><input name="q"></form></body></html>"""


class LabState:
    def __init__(self, env_secret: str) -> None:
        self.env_secret = env_secret
        self.xss_fixed = False
        self.destructive_hits = 0
        self.post_hits = 0


def _handler(kind: str, state: LabState) -> type[BaseHTTPRequestHandler]:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE items(id INTEGER, name TEXT)")
    db.execute("INSERT INTO items VALUES (1, 'shoe')")
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        if kind == "clean":
            server_version = "Server"
            sys_version = ""

        def log_message(self, *args: object) -> None:  # keep the test output quiet
            pass

        def _send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8",
                  extra: dict[str, str] | None = None) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if kind == "clean":
                self.send_header("Content-Security-Policy", "default-src 'self'")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("X-Content-Type-Options", "nosniff")
            else:
                origin = self.headers.get("Origin")
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:  # noqa: N802
            state.post_hits += 1
            self._send(405, "no")

        def do_GET(self) -> None:  # noqa: N802
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            if kind == "clean":
                return self._clean(u.path, q)
            return self._vuln(u.path, q)

        def _clean(self, path: str, q: dict[str, str]) -> None:
            if path == "/":
                return self._send(200, CLEAN_HOME, extra={"Set-Cookie": "sid=x1; HttpOnly; SameSite=Lax; Path=/"})
            if path == "/about":
                return self._send(200, "<html><body>About</body></html>")
            if path == "/search":
                return self._send(200, f"<html><body>Results for {html.escape(q.get('q', ''))}</body></html>")
            return self._send(404, "<html><body>Not found</body></html>")

        def _vuln(self, path: str, q: dict[str, str]) -> None:
            if path in ("/logout", "/delete-account"):
                state.destructive_hits += 1
                return self._send(200, "<html><body>done</body></html>")
            if path == "/":
                return self._send(200, VULN_HOME, extra={"Set-Cookie": "session=lab123; Path=/"})
            if path == "/search":
                term = q.get("q", "")
                shown = html.escape(term) if state.xss_fixed else term
                return self._send(200, f"<html><body>Results for {shown}</body></html>")
            if path == "/item":
                try:
                    with lock:  # deliberately string-built SQL (in-memory database, lab only)
                        rows = db.execute("SELECT name FROM items WHERE id = '" + q.get("id", "") + "'").fetchall()
                except sqlite3.Error as exc:
                    return self._send(500, f"<html><body>sqlite3.OperationalError: {html.escape(str(exc))}"
                                           "</body></html>")
                return self._send(200, f"<html><body>{len(rows)} item(s)</body></html>")
            if path == "/go":
                return self._send(302, "", extra={"Location": q.get("next", "/")})
            if path == "/view":
                if ".." in q.get("file", ""):  # simulated traversal: never reads a real file
                    return self._send(200, "root:x:0:0:root:/root:/bin/bash\n", "text/plain")
                return self._send(200, "<html><body>readme</body></html>")
            if path == "/static/":
                return self._send(200, "<html><head><title>Directory listing for /static/</title></head>"
                                       "<body><a href='app.css'>app.css</a></body></html>")
            if path == "/crash":
                return self._send(500, "<html><body><pre>Traceback (most recent call last):\n  File \"app.py\", "
                                       "line 3\nZeroDivisionError: division by zero</pre></body></html>")
            if path == "/console":
                return self._send(200, "<html><head><title>Console // Werkzeug Debugger</title></head>"
                                       "<body>console</body></html>")
            if path == "/.env":
                return self._send(200, f"DEBUG=1\nDB_PASSWORD={state.env_secret}\n", "text/plain")
            return self._send(404, "<html><body>Not found</body></html>")

    return H


class LabWebApp:
    """Start/stop one lab app on a free 127.0.0.1 port in a background thread."""

    def __init__(self, kind: str, env_secret: str = "unused") -> None:
        self.state = LabState(env_secret)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(kind, self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/"

    def start(self) -> "LabWebApp":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
