from tests.conftest import DECISION_KEY, auth_event


def _create_high_risk_incident(client) -> str:
    """Stacks spray + repeated failures + a privileged role so the combined
    score deterministically reaches the HIGH/CRITICAL incident threshold."""
    ip = "198.51.100.20"
    target = "privileged.user"
    for i, username in enumerate(["dec.v0", "dec.v1", "dec.v2", target]):
        response = client.post(
            "/events",
            json=auth_event(event_id=f"EVT-dec-spray-{i}", username=username, source_ip=ip, status="failed"),
        )
        assert response.status_code == 200

    for i in range(3):
        response = client.post(
            "/events",
            json=auth_event(event_id=f"EVT-dec-repeat-{i}", username=target, source_ip=ip, status="failed"),
        )
        assert response.status_code == 200

    response = client.post(
        "/events",
        json=auth_event(
            event_id="EVT-dec-final", username=target, source_ip=ip, status="failed", user_role="admin"
        ),
    )
    assert response.status_code == 200
    incident_id = response.json()["incident_id"]
    assert incident_id is not None
    return incident_id


def test_decision_requires_api_key(client):
    incident_id = _create_high_risk_incident(client)
    response = client.post(
        f"/incidents/{incident_id}/decision",
        json={"approved": True, "decided_by": "soc-analyst", "response_action": "disable_account"},
    )
    assert response.status_code == 401


def test_ingest_key_alone_cannot_approve_a_decision(client):
    """The whole point of scoped keys: a pipeline that can submit events
    must not also be able to approve containment actions."""
    incident_id = _create_high_risk_incident(client)
    response = client.post(
        f"/incidents/{incident_id}/decision",
        json={"approved": True, "decided_by": "soc-analyst", "response_action": "disable_account"},
        headers={"X-API-Key": client.headers["X-API-Key"]},
    )
    assert response.status_code == 401


def test_approved_decision_produces_simulated_outcome(client):
    incident_id = _create_high_risk_incident(client)
    response = client.post(
        f"/incidents/{incident_id}/decision",
        json={"approved": True, "decided_by": "soc-analyst", "response_action": "disable_account"},
        headers={"X-API-Key": DECISION_KEY},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["simulated"] is True
    assert "[SIMULATED]" in body["outcome"]

    incident = client.get(f"/incidents/{incident_id}").json()
    assert incident["decided_by"] == "soc-analyst"
    assert incident["approved"] is True
    assert incident["outcome"] == body["outcome"]


def test_disapproved_decision_takes_no_action(client):
    incident_id = _create_high_risk_incident(client)
    response = client.post(
        f"/incidents/{incident_id}/decision",
        json={"approved": False, "decided_by": "soc-analyst", "response_action": "block_ip"},
        headers={"X-API-Key": DECISION_KEY},
    )
    assert response.status_code == 200
    body = response.json()
    assert "No action taken" in body["outcome"]


def test_decision_on_unknown_incident_returns_404(client):
    response = client.post(
        "/incidents/does-not-exist/decision",
        json={"approved": True, "decided_by": "soc-analyst", "response_action": "block_ip"},
        headers={"X-API-Key": DECISION_KEY},
    )
    assert response.status_code == 404
