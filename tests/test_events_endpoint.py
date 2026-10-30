from tests.conftest import auth_event


def test_missing_api_key_is_rejected(client):
    client.headers.pop("X-API-Key")
    response = client.post("/events", json=auth_event())
    assert response.status_code == 401


def test_wrong_api_key_is_rejected(client):
    client.headers["X-API-Key"] = "wrong-key"
    response = client.post("/events", json=auth_event())
    assert response.status_code == 401


def test_malformed_payload_missing_field_is_rejected(client):
    event = auth_event()
    del event["source_ip"]
    response = client.post("/events", json=event)
    assert response.status_code == 422


def test_malformed_payload_invalid_ip_is_rejected(client):
    response = client.post("/events", json=auth_event(source_ip="not-an-ip"))
    assert response.status_code == 422


def test_malformed_payload_unknown_field_is_rejected(client):
    event = auth_event()
    event["unexpected_field"] = "should not be accepted"
    response = client.post("/events", json=event)
    assert response.status_code == 422


def test_duplicate_event_id_is_rejected(client):
    event = auth_event(event_id="EVT-DUP")
    first = client.post("/events", json=event)
    assert first.status_code == 200
    second = client.post("/events", json=event)
    assert second.status_code == 409


def test_normal_employee_login_is_low_risk_with_no_incident(client):
    response = client.post("/events", json=auth_event(status="success", username="normal.user"))
    assert response.status_code == 200
    body = response.json()
    assert body["risk_band"] == "LOW"
    assert body["incident_id"] is None
    assert body["findings"] == []


def test_incident_is_created_for_high_or_critical_band_and_readable(client):
    """Stacks three independent signals (spray + repeated failures on one
    account + a privileged role) to deterministically cross into HIGH/
    CRITICAL, exercising the full pipeline end to end."""
    ip = "203.0.113.50"
    target = "victim3"
    for i, username in enumerate(["victim0", "victim1", "victim2", target]):
        response = client.post(
            "/events",
            json=auth_event(
                event_id=f"EVT-spray-{i}", username=username, source_ip=ip, status="failed"
            ),
        )
        assert response.status_code == 200

    for i in range(3):
        response = client.post(
            "/events",
            json=auth_event(
                event_id=f"EVT-repeat-{i}", username=target, source_ip=ip, status="failed"
            ),
        )
        assert response.status_code == 200

    final = client.post(
        "/events",
        json=auth_event(
            event_id="EVT-final",
            username=target,
            source_ip=ip,
            status="failed",
            user_role="admin",
        ),
    )
    assert final.status_code == 200
    body = final.json()
    assert body["risk_band"] in {"HIGH", "CRITICAL"}
    assert body["incident_id"] is not None
    fired_rules = {f["rule"] for f in body["findings"]}
    assert "repeated_failed_logins" in fired_rules
    assert "password_spray" in fired_rules
    assert "privileged_account_anomaly" in fired_rules

    read = client.get(f"/incidents/{body['incident_id']}")
    assert read.status_code == 200
    incident = read.json()
    assert incident["username"] == target
    assert incident["risk_score"] == body["risk_score"]


def test_unknown_incident_returns_404(client):
    response = client.get("/incidents/does-not-exist")
    assert response.status_code == 404
