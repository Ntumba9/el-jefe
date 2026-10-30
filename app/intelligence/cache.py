import json
import sqlite3
from datetime import datetime, timedelta, timezone


def get_cached(conn: sqlite3.Connection, cache_key: str, ttl_minutes: int) -> dict | None:
    row = conn.execute(
        "SELECT result_json, fetched_at FROM intel_cache WHERE cache_key = ?", (cache_key,)
    ).fetchone()
    if row is None:
        return None
    fetched_at = datetime.fromisoformat(row["fetched_at"])
    if datetime.now(timezone.utc) - fetched_at > timedelta(minutes=ttl_minutes):
        return None
    return json.loads(row["result_json"])


def set_cached(conn: sqlite3.Connection, cache_key: str, source: str, result: dict) -> None:
    conn.execute(
        "INSERT INTO intel_cache (cache_key, source, result_json, fetched_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(cache_key) DO UPDATE SET result_json = excluded.result_json, "
        "fetched_at = excluded.fetched_at",
        (cache_key, source, json.dumps(result), datetime.now(timezone.utc).isoformat()),
    )
