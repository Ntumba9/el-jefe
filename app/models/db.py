import sqlite3
from contextlib import contextmanager

from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,
    authentication_method TEXT NOT NULL,
    user_role TEXT NOT NULL,
    location TEXT NOT NULL,
    source TEXT NOT NULL,
    received_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS intel_cache (
    cache_key TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    result_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    intel_json TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_band TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_by TEXT,
    approved INTEGER,
    response_action TEXT,
    notes TEXT,
    outcome TEXT,
    decided_at TEXT,
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);

-- Lets a caller (e.g. Activepieces retrying a failed HTTP call) replay the
-- exact same POST /events request safely: the second delivery returns the
-- first response verbatim instead of being scored and stored again.
CREATE TABLE IF NOT EXISTS idempotency_keys (
    idempotency_key TEXT PRIMARY KEY,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def get_raw_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL lets a reader (GET /incidents) proceed without blocking on a
    # writer, and the busy_timeout avoids an immediate "database is locked"
    # error under brief write contention from concurrent webhook deliveries.
    # Note: WAL needs real file-locking support — skip it for a DB path on
    # a network or cloud-sync filesystem, where it can misbehave.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db() -> None:
    conn = get_raw_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def get_connection():
    conn = get_raw_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
