import sqlite3
from datetime import timedelta

from app.detection import rules
from app.models.schemas import AuthEvent, Finding


def _window_start(event: AuthEvent, window_minutes: int):
    return event.timestamp - timedelta(minutes=window_minutes)


def fetch_user_window(conn: sqlite3.Connection, event: AuthEvent, window_minutes: int) -> list[dict]:
    start = _window_start(event, window_minutes)
    rows = conn.execute(
        "SELECT * FROM events WHERE username = ? AND timestamp >= ? AND timestamp <= ? "
        "ORDER BY timestamp ASC",
        (event.username, start.isoformat(), event.timestamp.isoformat()),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_ip_window(conn: sqlite3.Connection, event: AuthEvent, window_minutes: int) -> list[dict]:
    start = _window_start(event, window_minutes)
    rows = conn.execute(
        "SELECT * FROM events WHERE source_ip = ? AND timestamp >= ? AND timestamp <= ? "
        "ORDER BY timestamp ASC",
        (event.source_ip, start.isoformat(), event.timestamp.isoformat()),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_last_known_location(conn: sqlite3.Connection, event: AuthEvent) -> str | None:
    row = conn.execute(
        "SELECT location FROM events WHERE username = ? AND event_id != ? AND location != 'Unknown' "
        "ORDER BY timestamp DESC LIMIT 1",
        (event.username, event.event_id),
    ).fetchone()
    return row["location"] if row else None


def run_detection(
    conn: sqlite3.Connection,
    event: AuthEvent,
    abuse_confidence_score: int,
    failed_login_threshold: int,
    spray_threshold: int,
    abuseipdb_threshold: int,
    window_minutes: int,
) -> list[Finding]:
    """Runs all detection rules against one event and returns the findings.

    The event must already be inserted into the `events` table before this
    runs, so correlation-window queries include it.
    """
    user_window = fetch_user_window(conn, event, window_minutes)
    ip_window = fetch_ip_window(conn, event, window_minutes)
    last_known_location = fetch_last_known_location(conn, event)

    findings: list[Finding] = []

    for finding in (
        rules.repeated_failed_logins(event, user_window, failed_login_threshold),
        rules.password_spray(event, ip_window, spray_threshold),
        rules.success_after_failures(event, user_window),
        rules.malicious_ip_reputation(event, abuse_confidence_score, abuseipdb_threshold),
        rules.geographic_anomaly(event, last_known_location),
    ):
        if finding is not None:
            findings.append(finding)

    privileged_finding = rules.privileged_account_anomaly(event, other_findings_present=bool(findings))
    if privileged_finding is not None:
        findings.append(privileged_finding)

    return findings
