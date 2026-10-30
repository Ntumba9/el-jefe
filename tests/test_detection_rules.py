from app.detection import rules
from app.models.schemas import AuthEvent


def make_event(**overrides) -> AuthEvent:
    base = dict(
        event_id="EVT-1",
        username="alice",
        source_ip="203.0.113.10",
        timestamp="2026-10-30T09:30:00Z",
        status="failed",
        authentication_method="password",
        user_role="employee",
        location="Unknown",
        source="identity_provider",
    )
    base.update(overrides)
    return AuthEvent(**base)


def window_row(event: AuthEvent) -> dict:
    return {
        "event_id": event.event_id,
        "username": event.username,
        "status": event.status.value,
    }


def test_repeated_failed_logins_fires_at_threshold():
    event = make_event(event_id="EVT-5")
    window = [window_row(make_event(event_id=f"EVT-{i}")) for i in range(5)]
    finding = rules.repeated_failed_logins(event, window, threshold=5)
    assert finding is not None
    assert finding.rule == "repeated_failed_logins"


def test_repeated_failed_logins_silent_below_threshold():
    event = make_event(event_id="EVT-2")
    window = [window_row(make_event(event_id=f"EVT-{i}")) for i in range(2)]
    assert rules.repeated_failed_logins(event, window, threshold=5) is None


def test_repeated_failed_logins_ignores_successful_event():
    event = make_event(status="success")
    assert rules.repeated_failed_logins(event, [], threshold=5) is None


def test_password_spray_fires_for_distinct_accounts_from_one_ip():
    event = make_event(username="victim4")
    window = [
        window_row(make_event(username=f"victim{i}", event_id=f"EVT-{i}"))
        for i in range(4)
    ]
    finding = rules.password_spray(event, window, threshold=4)
    assert finding is not None
    assert finding.rule == "password_spray"


def test_password_spray_silent_for_single_account_many_attempts():
    event = make_event(username="alice")
    window = [window_row(make_event(username="alice", event_id=f"EVT-{i}")) for i in range(10)]
    assert rules.password_spray(event, window, threshold=4) is None


def test_success_after_failures_fires():
    event = make_event(status="success", event_id="EVT-success")
    window = [
        window_row(make_event(event_id=f"EVT-{i}")) for i in range(3)
    ]
    finding = rules.success_after_failures(event, window, min_prior_failures=3)
    assert finding is not None
    assert finding.rule == "success_after_failures"


def test_success_after_failures_silent_on_clean_login():
    event = make_event(status="success", event_id="EVT-success")
    assert rules.success_after_failures(event, [], min_prior_failures=3) is None


def test_malicious_ip_reputation_respects_threshold():
    event = make_event()
    assert rules.malicious_ip_reputation(event, abuse_confidence_score=10, threshold=50) is None
    finding = rules.malicious_ip_reputation(event, abuse_confidence_score=80, threshold=50)
    assert finding is not None
    assert finding.severity_weight <= 40


def test_geographic_anomaly_requires_prior_known_location():
    event = make_event(location="Berlin, DE")
    assert rules.geographic_anomaly(event, last_known_location=None) is None
    assert rules.geographic_anomaly(event, last_known_location="Unknown") is None


def test_geographic_anomaly_fires_on_location_change():
    event = make_event(location="Berlin, DE")
    finding = rules.geographic_anomaly(event, last_known_location="Lagos, NG")
    assert finding is not None


def test_geographic_anomaly_silent_on_same_location():
    event = make_event(location="Berlin, DE")
    assert rules.geographic_anomaly(event, last_known_location="Berlin, DE") is None


def test_privileged_account_anomaly_fires_on_failed_privileged_login():
    event = make_event(user_role="admin", status="failed")
    finding = rules.privileged_account_anomaly(event, other_findings_present=False)
    assert finding is not None


def test_privileged_account_anomaly_silent_for_non_privileged_role():
    event = make_event(user_role="employee", status="failed")
    assert rules.privileged_account_anomaly(event, other_findings_present=True) is None


def test_privileged_account_anomaly_silent_on_clean_privileged_login():
    event = make_event(user_role="admin", status="success")
    assert rules.privileged_account_anomaly(event, other_findings_present=False) is None
