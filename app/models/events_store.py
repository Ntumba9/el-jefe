import sqlite3
from datetime import datetime, timezone

from app.models.schemas import AuthEvent


class DuplicateEventError(Exception):
    pass


def insert_event(conn: sqlite3.Connection, event: AuthEvent) -> None:
    try:
        conn.execute(
            "INSERT INTO events "
            "(event_id, username, source_ip, timestamp, status, authentication_method, "
            "user_role, location, source, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.username,
                event.source_ip,
                event.timestamp.isoformat(),
                event.status.value,
                event.authentication_method,
                event.user_role,
                event.location,
                event.source,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise DuplicateEventError(f"event_id '{event.event_id}' was already ingested") from exc
