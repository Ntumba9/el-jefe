import json
import sqlite3
from datetime import datetime, timezone


def get_cached_response(conn: sqlite3.Connection, idempotency_key: str) -> dict | None:
    row = conn.execute(
        "SELECT response_json FROM idempotency_keys WHERE idempotency_key = ?",
        (idempotency_key,),
    ).fetchone()
    return json.loads(row["response_json"]) if row else None


def store_response(conn: sqlite3.Connection, idempotency_key: str, response: dict) -> None:
    conn.execute(
        "INSERT INTO idempotency_keys (idempotency_key, response_json, created_at) VALUES (?, ?, ?) "
        "ON CONFLICT(idempotency_key) DO NOTHING",
        (idempotency_key, json.dumps(response), datetime.now(timezone.utc).isoformat()),
    )
