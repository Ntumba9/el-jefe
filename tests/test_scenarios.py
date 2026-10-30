import httpx
import respx
from httpx import Response

from tests.conftest import auth_event


def test_success_after_repeated_failures_flags_but_does_not_block(client):
    username = "flaky.typer"
    ip = "203.0.113.77"
    for i in range(3):
        response = client.post(
            "/events",
            json=auth_event(event_id=f"EVT-f{i}", username=username, source_ip=ip, status="failed"),
        )
        assert response.status_code == 200

    response = client.post(
        "/events",
        json=auth_event(event_id="EVT-success", username=username, source_ip=ip, status="success"),
    )
    assert response.status_code == 200
    body = response.json()
    rules_fired = {f["rule"] for f in body["findings"]}
    assert "success_after_failures" in rules_fired


def test_false_positive_two_mistyped_passwords_then_success_is_low_risk(client):
    """Two failed attempts (below the 3-failure threshold) followed by a
    success is the textbook benign case: a user mistyping their own
    password. It must not be flagged."""
    username = "regular.employee"
    ip = "203.0.113.90"
    for i in range(2):
        response = client.post(
            "/events",
            json=auth_event(event_id=f"EVT-fp{i}", username=username, source_ip=ip, status="failed"),
        )
        assert response.status_code == 200

    response = client.post(
        "/events",
        json=auth_event(event_id="EVT-fp-success", username=username, source_ip=ip, status="success"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["risk_band"] == "LOW"
    assert body["incident_id"] is None


def test_geographic_anomaly_fires_after_establishing_history(client):
    username = "traveler"
    response = client.post(
        "/events",
        json=auth_event(
            event_id="EVT-geo-1", username=username, status="success", location="Berlin, DE"
        ),
    )
    assert response.status_code == 200
    assert "geographic_anomaly" not in {f["rule"] for f in response.json()["findings"]}

    response = client.post(
        "/events",
        json=auth_event(
            event_id="EVT-geo-2", username=username, status="success", location="Lagos, NG"
        ),
    )
    assert response.status_code == 200
    assert "geographic_anomaly" in {f["rule"] for f in response.json()["findings"]}


def test_suspicious_ip_reputation_flagged_via_abuseipdb(make_client):
    with make_client(ABUSEIPDB_API_KEY="dummy-key") as client:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=Response(
                    200,
                    json={
                        "data": {
                            "abuseConfidenceScore": 90,
                            "totalReports": 42,
                            "countryCode": "RU",
                        }
                    },
                )
            )
            response = client.post(
                "/events",
                json=auth_event(event_id="EVT-malip", source_ip="198.51.100.200", status="failed"),
            )
    assert response.status_code == 200
    body = response.json()
    assert "malicious_ip_reputation" in {f["rule"] for f in body["findings"]}
    assert any(i["source"] == "abuseipdb" for i in body["intel"])


def test_abuseipdb_outage_degrades_gracefully_instead_of_failing_ingestion(make_client):
    with make_client(ABUSEIPDB_API_KEY="dummy-key") as client:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://api.abuseipdb.com/api/v2/check").mock(
                side_effect=httpx.ConnectError("simulated network failure")
            )
            response = client.post("/events", json=auth_event(event_id="EVT-outage"))
    assert response.status_code == 200
    body = response.json()
    assert "malicious_ip_reputation" not in {f["rule"] for f in body["findings"]}


def test_missing_required_field_rejected(client):
    event = auth_event()
    del event["username"]
    response = client.post("/events", json=event)
    assert response.status_code == 422


def test_wrong_type_for_status_field_rejected(client):
    response = client.post("/events", json=auth_event(status="definitely-not-a-status"))
    assert response.status_code == 422
