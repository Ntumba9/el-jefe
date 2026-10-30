"""Cross-incident correlation context.

This is deliberately *not* a detection rule and does not touch the risk
score. It answers a different question than the detection engine does:
not "is this event anomalous on its own", but "has this account or IP
already been through this before". That's valuable context for whoever
reviews the incident (a third HIGH incident from the same IP this month
is a materially different situation than the first), but folding it into
the score automatically would double-count signal that's already present
in each of those prior incidents' own scores — so for now it's surfaced
as read-only context on the response, for a human or a future rule to
act on, not as an automatic score adjustment.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

from app.models.schemas import AuthEvent, RiskBand


def correlate(conn: sqlite3.Connection, event: AuthEvent, lookback_days: int) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
    bands = (RiskBand.HIGH.value, RiskBand.CRITICAL.value)

    prior_for_user = conn.execute(
        "SELECT COUNT(*) AS n FROM incidents i JOIN events e ON e.event_id = i.event_id "
        "WHERE e.username = ? AND i.risk_band IN (?, ?) AND i.created_at >= ? "
        "AND e.event_id != ?",
        (event.username, *bands, since, event.event_id),
    ).fetchone()["n"]

    prior_for_ip = conn.execute(
        "SELECT COUNT(*) AS n FROM incidents i JOIN events e ON e.event_id = i.event_id "
        "WHERE e.source_ip = ? AND i.risk_band IN (?, ?) AND i.created_at >= ? "
        "AND e.event_id != ?",
        (event.source_ip, *bands, since, event.event_id),
    ).fetchone()["n"]

    return {
        "lookback_days": lookback_days,
        "prior_high_critical_incidents_same_user": prior_for_user,
        "prior_high_critical_incidents_same_ip": prior_for_ip,
    }
