"""SQLite connection management, schema initialisation and migrations."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from utils.logger import get_logger
from utils.paths import SCHEMA_PATH

log = get_logger(__name__)

SCHEMA_VERSION = 1

# Ordered migrations: (target_version, callable). Each runs inside a transaction.
# Future schema changes append here; never edit a released migration.
MIGRATIONS: list[tuple[int, Callable[[sqlite3.Connection], None]]] = []


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
    for version, migrate in MIGRATIONS:
        if version > current:
            log.info("Applying database migration", extra={"version": version})
            with transaction(conn):
                migrate(conn)
                set_setting(conn, "schema_version", str(version))
            current = version
    if current > SCHEMA_VERSION and not MIGRATIONS:
        log.warning("Database schema is newer than this application", extra={"db_version": current})
    return conn
