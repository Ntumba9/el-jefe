import sqlite3
from datetime import datetime, timedelta, timezone

from app.intelligence.cache import get_cached, set_cached
from app.models.db import SCHEMA


def make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def test_set_then_get_returns_the_same_result():
    conn = make_conn()
    set_cached(conn, "key1", "abuseipdb", {"score": 42})
    assert get_cached(conn, "key1", ttl_minutes=60) == {"score": 42}


def test_get_returns_none_for_missing_key():
    conn = make_conn()
    assert get_cached(conn, "does-not-exist", ttl_minutes=60) is None


def test_get_returns_none_once_entry_is_older_than_ttl():
    conn = make_conn()
    stale_time = (datetime.now(timezone.utc) - timedelta(minutes=120)).isoformat()
    conn.execute(
        "INSERT INTO intel_cache (cache_key, source, result_json, fetched_at) VALUES (?, ?, ?, ?)",
        ("key2", "abuseipdb", '{"score": 10}', stale_time),
    )
    assert get_cached(conn, "key2", ttl_minutes=60) is None


def test_set_cached_overwrites_existing_entry():
    conn = make_conn()
    set_cached(conn, "key3", "abuseipdb", {"score": 1})
    set_cached(conn, "key3", "abuseipdb", {"score": 2})
    assert get_cached(conn, "key3", ttl_minutes=60) == {"score": 2}
