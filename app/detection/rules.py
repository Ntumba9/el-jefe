"""Deterministic detection rules.

Each rule is a plain function: (event, window_events_for_user,
window_events_for_ip) -> Finding | None. A rule fires at most once per
incoming event — it looks at the correlation window to decide, but never
emits more than one Finding of its own kind per event, so a single noisy
account can't inflate its own score by repeating the same signal.

Limitations are documented per rule rather than in one place, because each
rule's blind spots are different and matter when reading a specific finding.
"""

from app.models.schemas import AuthEvent, Finding

PRIVILEGED_ROLES = {"admin", "administrator", "root", "superuser", "privileged", "owner"}


def repeated_failed_logins(event: AuthEvent, user_window: list[dict], threshold: int) -> Finding | None:
    """Flags an account receiving >= threshold failed attempts in the window.

    Limitation: a static per-window count can't distinguish a user who
    mistyped their password five times in two minutes from a scripted
    brute-force attempt spread evenly across the same window. It also
    resets every window, so a slow attack spread across many short windows
    will not accumulate.
    """
    if event.status != "failed":
        return None
    failed_count = sum(1 for e in user_window if e["status"] == "failed")
    if failed_count < threshold:
        return None
    return Finding(
        rule="repeated_failed_logins",
        severity_weight=25,
        description=(
            f"{failed_count} failed authentication attempts for "
            f"'{event.username}' within the correlation window."
        ),
        mitre_technique_id="T1110.001",
        mitre_technique_name="Brute Force: Password Guessing",
    )


def password_spray(event: AuthEvent, ip_window: list[dict], threshold: int) -> Finding | None:
    """Flags one source IP attempting authentication against many accounts.

    Limitation: shared egress points (corporate NAT, VPN exit nodes, campus
    Wi-Fi) legitimately produce many distinct usernames from one IP. This
    rule has no way to distinguish that from an actual spray without
    additional context such as a known-good IP allowlist, which is out of
    scope for this project.
    """
    if event.status != "failed":
        return None
    distinct_users = {e["username"] for e in ip_window if e["status"] == "failed"}
    if len(distinct_users) < threshold:
        return None
    return Finding(
        rule="password_spray",
        severity_weight=30,
        description=(
            f"{len(distinct_users)} distinct accounts received failed "
            f"authentication attempts from {event.source_ip} within the "
            "correlation window."
        ),
        mitre_technique_id="T1110.003",
        mitre_technique_name="Brute Force: Password Spraying",
    )


def success_after_failures(
    event: AuthEvent, user_window: list[dict], min_prior_failures: int = 3
) -> Finding | None:
    """Flags a successful login immediately preceded by repeated failures.

    Limitation: this is also the single most common benign pattern —
    a legitimate user who mistyped their password a few times before
    getting it right. It is deliberately sensitive because, from the
    event stream alone, there is no reliable way to tell that case apart
    from a credential-stuffing attempt that finally guessed correctly;
    downstream risk scoring and human review exist precisely to absorb
    that ambiguity.
    """
    if event.status != "success":
        return None
    prior_failures = sum(
        1 for e in user_window if e["status"] == "failed" and e["event_id"] != event.event_id
    )
    if prior_failures < min_prior_failures:
        return None
    return Finding(
        rule="success_after_failures",
        severity_weight=40,
        description=(
            f"Successful login for '{event.username}' followed "
            f"{prior_failures} failed attempts within the correlation window."
        ),
        mitre_technique_id="T1078",
        mitre_technique_name="Valid Accounts",
    )


def malicious_ip_reputation(event: AuthEvent, abuse_confidence_score: int, threshold: int) -> Finding | None:
    """Flags authentication from an IP with a poor AbuseIPDB reputation.

    Limitation: AbuseIPDB reputation reflects the IP's history, not proof
    that *this* login is malicious — shared/dynamic IPs (mobile carriers,
    CGNAT) can carry a bad reputation from unrelated abuse while also
    serving a legitimate employee. The technique mapping below is a
    judgment call: a login from already-flagged infrastructure is most
    consistent with an adversary using credentials they already hold, so
    it is mapped to Valid Accounts rather than to an initial-access
    technique.
    """
    if abuse_confidence_score < threshold:
        return None
    return Finding(
        rule="malicious_ip_reputation",
        severity_weight=min(40, abuse_confidence_score // 2),
        description=(
            f"Source IP {event.source_ip} has an AbuseIPDB confidence "
            f"score of {abuse_confidence_score} (threshold {threshold})."
        ),
        mitre_technique_id="T1078",
        mitre_technique_name="Valid Accounts",
    )


def geographic_anomaly(event: AuthEvent, last_known_location: str | None) -> Finding | None:
    """Flags authentication from a location that differs from the last one seen.

    Limitation: 'location' is whatever label the identity provider sends —
    there is no distance/time feasibility check (true "impossible travel"
    would need coordinates and a travel-time model), and this rule only
    runs when there is at least one prior non-'Unknown' location to compare
    against ("sufficient historical context"), per the project brief. A new
    user, or a user whose provider never reports a location, will never
    trigger it.
    """
    if event.location == "Unknown" or not last_known_location or last_known_location == "Unknown":
        return None
    if event.location == last_known_location:
        return None
    return Finding(
        rule="geographic_anomaly",
        severity_weight=20,
        description=(
            f"'{event.username}' authenticated from '{event.location}', "
            f"previously seen from '{last_known_location}'."
        ),
        mitre_technique_id="T1078",
        mitre_technique_name="Valid Accounts",
    )


def privileged_account_anomaly(event: AuthEvent, other_findings_present: bool) -> Finding | None:
    """Flags any anomalous activity (above) occurring on a privileged account.

    Limitation: privilege is matched against a fixed keyword list
    (admin/root/superuser/...) because there is no canonical privilege
    taxonomy across identity providers; a provider using a custom role
    name (e.g. "tier-1-support") would not be recognized without adding
    it to the list.
    """
    if event.user_role.lower() not in PRIVILEGED_ROLES:
        return None
    if event.status == "failed" or other_findings_present:
        return Finding(
            rule="privileged_account_anomaly",
            severity_weight=20,
            description=(
                f"Anomalous activity involves privileged account "
                f"'{event.username}' (role: {event.user_role})."
            ),
            mitre_technique_id="T1078.003",
            mitre_technique_name="Valid Accounts: Local Accounts",
        )
    return None
