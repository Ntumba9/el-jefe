import json
import sqlite3
import uuid
from datetime import datetime, timezone

from app.models.schemas import DecisionRequest, Finding, IntelResult, RiskBand

# Only incidents at HIGH or CRITICAL risk get a persisted incident record
# and go through the approval workflow; LOW/MEDIUM events are still
# detected, scored and returned in the API response, but recording an
# incident (and asking an administrator to approve a response) for every
# low-severity failed login would bury real signal in noise.
INCIDENT_BANDS = {RiskBand.HIGH, RiskBand.CRITICAL}


def create_incident(
    conn: sqlite3.Connection,
    event_id: str,
    findings: list[Finding],
    intel: list[IntelResult],
    risk_score: int,
    risk_band: RiskBand,
) -> str:
    incident_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO incidents "
        "(incident_id, event_id, findings_json, intel_json, risk_score, risk_band, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            incident_id,
            event_id,
            json.dumps([f.model_dump() for f in findings]),
            json.dumps([i.model_dump() for i in intel]),
            risk_score,
            risk_band.value,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    return incident_id


def get_incident(conn: sqlite3.Connection, incident_id: str) -> dict | None:
    row = conn.execute(
        "SELECT i.*, e.username, e.source_ip, e.timestamp AS event_timestamp, "
        "e.status AS event_status, e.user_role, e.location, e.source "
        "FROM incidents i JOIN events e ON e.event_id = i.event_id "
        "WHERE i.incident_id = ?",
        (incident_id,),
    ).fetchone()
    if row is None:
        return None
    incident = dict(row)
    incident["findings"] = json.loads(incident.pop("findings_json"))
    incident["intel"] = json.loads(incident.pop("intel_json"))
    incident["approved"] = bool(incident["approved"]) if incident["approved"] is not None else None
    return incident


def record_decision(conn: sqlite3.Connection, incident_id: str, decision: DecisionRequest, outcome: str) -> bool:
    cursor = conn.execute(
        "UPDATE incidents SET decided_by = ?, approved = ?, response_action = ?, "
        "notes = ?, outcome = ?, decided_at = ? WHERE incident_id = ?",
        (
            decision.decided_by,
            1 if decision.approved else 0,
            decision.response_action,
            decision.notes,
            outcome,
            datetime.now(timezone.utc).isoformat(),
            incident_id,
        ),
    )
    return cursor.rowcount > 0
