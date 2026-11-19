"""SQLite connection management, schema initialisation and migrations."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from utils.logger import get_logger
from utils.paths import SCHEMA_PATH

log = get_logger(__name__)

SCHEMA_VERSION = 5


def _rebuild_findings_with_category(conn: sqlite3.Connection, category: str, after: str) -> None:
    """Allow a new findings category. SQLite cannot alter a CHECK constraint, so the findings table is rebuilt
    (official 12-step procedure; foreign keys are switched off around it by init_db). Rows and history are kept."""
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'").fetchone()
    if row is None or f"'{category}'" in row[0]:
        return
    new_sql = re.sub(r"CREATE TABLE\s+(IF NOT EXISTS\s+)?\"?findings\"?", "CREATE TABLE findings_new", row[0],
                     count=1)
    new_sql = new_sql.replace(f"'{after}',", f"'{after}','{category}',", 1)
    if f"'{category}'" not in new_sql:
        raise RuntimeError("Could not update the findings category constraint")
    cols = ", ".join(r[1] for r in conn.execute("PRAGMA table_info(findings)"))
    conn.execute(new_sql)
    conn.execute(f"INSERT INTO findings_new ({cols}) SELECT {cols} FROM findings")
    conn.execute("DROP TABLE findings")
    conn.execute("ALTER TABLE findings_new RENAME TO findings")
    bad = conn.execute("PRAGMA foreign_key_check").fetchall()
    if bad:
        raise RuntimeError(f"Foreign key check failed after migration: {len(bad)} row(s)")


def _allow_code_category(conn: sqlite3.Connection) -> None:
    """v2: allow category 'CODE' (SAST findings from Bandit)."""
    _rebuild_findings_with_category(conn, "CODE", "MISCONFIGURATION")


def _allow_web_category(conn: sqlite3.Connection) -> None:
    """v3: allow category 'WEB' (DAST findings from the built-in web scan)."""
    _rebuild_findings_with_category(conn, "WEB", "CODE")


def _add_triage(conn: sqlite3.Connection) -> None:
    """v4: triage tables (finding_triage, triage_log). They are created by schema.sql (applied before
    migrations); this step only checks they exist and records the version."""
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"finding_triage", "triage_log"} <= names:
        raise RuntimeError("Triage tables are missing after applying the schema")


def _add_alerts(conn: sqlite3.Connection) -> None:
    """v5: alerts table (created by schema.sql, applied before migrations); only checks it exists."""
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alerts'").fetchone():
        raise RuntimeError("Alerts table is missing after applying the schema")


# Ordered migrations: (target_version, callable). Each runs inside a transaction.
# Future schema changes append here; never edit a released migration.
MIGRATIONS: list[tuple[int, Callable[[sqlite3.Connection], None]]] = [(2, _allow_code_category),
                                                                      (3, _allow_web_category),
                                                                      (4, _add_triage),
                                                                      (5, _add_alerts)]


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    """Open a connection with foreign keys, WAL journaling and a busy timeout."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        conn.execute("PRAGMA journal_mode = WAL")
    except sqlite3.OperationalError:
        pass  # e.g. network share; default journal mode still works
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Explicit IMMEDIATE transaction (autocommit connection) with rollback on error."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def init_db(db_path: Path) -> sqlite3.Connection:
    """Create schema if needed, apply pending migrations and return an open connection."""
    conn = connect(db_path)
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    current = int(get_setting(conn, "schema_version", "0") or 0)
    if current == 0:
        set_setting(conn, "schema_version", str(SCHEMA_VERSION))
        set_setting(conn, "created_at", utcnow())
        current = SCHEMA_VERSION
    pending = [(v, m) for v, m in MIGRATIONS if v > current]
    if pending:
        conn.execute("PRAGMA foreign_keys = OFF")  # table rebuilds must not cascade; checked inside each migration
        try:
            for version, migrate in pending:
                log.info("Applying database migration", extra={"version": version})
                with transaction(conn):
                    migrate(conn)
                    set_setting(conn, "schema_version", str(version))
                current = version
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))  # re-create indexes dropped by a rebuild
    if current > SCHEMA_VERSION and not MIGRATIONS:
        log.warning("Database schema is newer than this application", extra={"db_version": current})
    return conn
