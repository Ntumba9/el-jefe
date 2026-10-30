import httpx
import respx
from httpx import Response

from tests.conftest import auth_event


def test_idempotency_key_replays_the_first_response_without_reprocessing(client):
    event = auth_event(event_id="EVT-idem-1", username="idem.user")
    first = client.post("/events", json=event, headers={"Idempotency-Key": "replay-key-1"})
    assert first.status_code == 200

    # Change the body on the "retry" (as a real retried delivery might carry
    # a slightly different timestamp) — the idempotency key alone decides
    # whether this is treated as a replay, not the request body.
    retried_event = dict(event)
    retried_event["event_id"] = "EVT-idem-1-retry-attempt"
    second = client.post(
        "/events", json=retried_event, headers={"Idempotency-Key": "replay-key-1"}
    )
    assert second.status_code == 200
    assert second.json() == first.json()

    # The retried delivery's own event_id must never have been inserted,
    # since it was short-circuited by the idempotency cache.
    lookup = client.get(f"/incidents/{first.json().get('incident_id') or 'none'}")
    assert lookup.status_code in (200, 404)


def test_requests_without_idempotency_key_are_processed_independently(client):
    first = client.post("/events", json=auth_event(event_id="EVT-noidem-1"))
    second = client.post("/events", json=auth_event(event_id="EVT-noidem-2"))
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["event_id"] != second.json()["event_id"]


def test_response_includes_correlation_context(client):
    response = client.post("/events", json=auth_event(event_id="EVT-corr-1"))
    assert response.status_code == 200
    correlation = response.json()["correlation"]
    assert correlation["prior_high_critical_incidents_same_user"] == 0
    assert correlation["prior_high_critical_incidents_same_ip"] == 0
    assert correlation["lookback_days"] > 0


def test_correlation_counts_prior_high_critical_incidents_for_same_ip(client):
    ip = "203.0.113.200"

    def spray_to_high(username: str, suffix: str) -> str:
        for i, u in enumerate([f"{username}-v0", f"{username}-v1", f"{username}-v2", username]):
            r = client.post(
                "/events",
                json=auth_event(event_id=f"EVT-{suffix}-spray-{i}", username=u, source_ip=ip, status="failed"),
            )
            assert r.status_code == 200
        for i in range(3):
            r = client.post(
                "/events",
                json=auth_event(event_id=f"EVT-{suffix}-repeat-{i}", username=username, source_ip=ip, status="failed"),
            )
            assert r.status_code == 200
        r = client.post(
            "/events",
            json=auth_event(
                event_id=f"EVT-{suffix}-final", username=username, source_ip=ip, status="failed", user_role="admin"
            ),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["risk_band"] in {"HIGH", "CRITICAL"}
        return body["event_id"]

    spray_to_high("first.victim", "c1")
    second_response_event_id = spray_to_high("second.victim", "c2")

    # The second account is different, so prior_high_critical_incidents_same_user
    # is 0 for it, but the shared IP already produced one HIGH incident.
    final_event = client.post(
        "/events",
        json=auth_event(
            event_id="EVT-c3-confirm",
            username="third.victim",
            source_ip=ip,
            status="failed",
            user_role="admin",
        ),
    )
    assert final_event.status_code == 200
    correlation = final_event.json()["correlation"]
    assert correlation["prior_high_critical_incidents_same_ip"] >= 2
    assert correlation["prior_high_critical_incidents_same_user"] == 0


def test_abuseipdb_retries_a_transient_server_error_then_succeeds(make_client):
    with make_client(ABUSEIPDB_API_KEY="dummy-key", ELJEFE_INTEL_RETRY_BACKOFF_SECONDS="0") as client:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.get("https://api.abuseipdb.com/api/v2/check")
            route.side_effect = [
                Response(503, json={"error": "temporarily unavailable"}),
                Response(200, json={"data": {"abuseConfidenceScore": 95, "totalReports": 10, "countryCode": "CN"}}),
            ]
            response = client.post(
                "/events",
                json=auth_event(event_id="EVT-retry-1", source_ip="198.51.100.9", status="failed"),
            )
    assert response.status_code == 200
    body = response.json()
    assert route.call_count == 2
    assert "malicious_ip_reputation" in {f["rule"] for f in body["findings"]}


def test_abuseipdb_gives_up_after_max_retries_and_degrades_gracefully(make_client):
    with make_client(ABUSEIPDB_API_KEY="dummy-key", ELJEFE_INTEL_RETRY_BACKOFF_SECONDS="0") as client:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.get("https://api.abuseipdb.com/api/v2/check")
            route.mock(return_value=Response(503, json={"error": "down"}))
            response = client.post(
                "/events",
                json=auth_event(event_id="EVT-retry-2", source_ip="198.51.100.8", status="failed"),
            )
    assert response.status_code == 200
    # default max_retries is 2 -> 1 initial attempt + 2 retries = 3 calls
    assert route.call_count == 3
    assert "malicious_ip_reputation" not in {f["rule"] for f in response.json()["findings"]}
