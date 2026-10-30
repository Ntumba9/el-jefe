"""Formats incident data into the plain-text summary Activepieces sends to
Telegram. Kept separate from the Activepieces flow so the exact wording of
a notification is unit-testable here, rather than only visible by reading
a flow definition.
"""

from app.models.schemas import Finding, IntelResult, RiskBand


def format_incident_summary(
    incident_id: str,
    username: str,
    source_ip: str,
    risk_score: int,
    risk_band: RiskBand,
    findings: list[Finding],
    intel: list[IntelResult],
) -> str:
    lines = [
        f"SENTINEL ALERT — {risk_band.value} ({risk_score}/100)",
        f"Incident: {incident_id}",
        f"Account: {username}  |  Source IP: {source_ip}",
        "",
        "Findings:",
    ]
    for f in findings:
        lines.append(f"  - [{f.mitre_technique_id}] {f.description}")
    if intel:
        lines.append("")
        lines.append("Threat intel:")
        for i in intel:
            lines.append(f"  - {i.source}: {i.summary}")
    return "\n".join(lines)
