from app.models.schemas import Finding, IntelResult, RiskBand
from app.notifications.formatter import format_incident_summary


def test_format_incident_summary_includes_core_fields():
    findings = [
        Finding(
            rule="password_spray",
            severity_weight=30,
            description="4 distinct accounts received failed authentication attempts.",
            mitre_technique_id="T1110.003",
            mitre_technique_name="Brute Force: Password Spraying",
        )
    ]
    summary = format_incident_summary(
        incident_id="abc-123",
        username="victim3",
        source_ip="203.0.113.50",
        risk_score=75,
        risk_band=RiskBand.HIGH,
        findings=findings,
        intel=[],
    )
    assert "HIGH (75/100)" in summary
    assert "abc-123" in summary
    assert "victim3" in summary
    assert "203.0.113.50" in summary
    assert "[T1110.003]" in summary
    assert "4 distinct accounts" in summary
    assert "Threat intel:" not in summary


def test_format_incident_summary_includes_intel_section_when_present():
    intel = [IntelResult(source="abuseipdb", summary="Confidence score 90.", raw={})]
    summary = format_incident_summary(
        incident_id="abc-456",
        username="jane.doe",
        source_ip="198.51.100.1",
        risk_score=90,
        risk_band=RiskBand.CRITICAL,
        findings=[],
        intel=intel,
    )
    assert "Threat intel:" in summary
    assert "abuseipdb: Confidence score 90." in summary
