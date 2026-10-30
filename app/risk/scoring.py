"""Risk-scoring engine.

Score = sum of each *distinct* finding rule's severity weight, capped at
100. Findings are deduplicated by rule name before summing — a defensive
measure in case a future rule change ever causes the same rule to fire
twice for one event, so repeats of the same signal cannot inflate the
score beyond what one occurrence would contribute.

Weights already encode the five factors the project brief asks the score
to consider: authentication frequency (repeated_failed_logins), source IP
reputation (malicious_ip_reputation), account privilege level
(privileged_account_anomaly), geographic anomalies (geographic_anomaly),
and successful authentication following repeated failures
(success_after_failures). There is no separate multiplier for any of
these — the detection rule's severity_weight *is* that factor's
contribution, so there is exactly one place (rules.py) that defines how
much each signal is worth.
"""

from app.models.schemas import Finding, RiskBand

BAND_THRESHOLDS: list[tuple[int, int, RiskBand]] = [
    (0, 29, RiskBand.LOW),
    (30, 59, RiskBand.MEDIUM),
    (60, 79, RiskBand.HIGH),
    (80, 100, RiskBand.CRITICAL),
]


def deduplicate(findings: list[Finding]) -> list[Finding]:
    best_by_rule: dict[str, Finding] = {}
    for finding in findings:
        existing = best_by_rule.get(finding.rule)
        if existing is None or finding.severity_weight > existing.severity_weight:
            best_by_rule[finding.rule] = finding
    return list(best_by_rule.values())


def score(findings: list[Finding]) -> int:
    deduped = deduplicate(findings)
    total = sum(f.severity_weight for f in deduped)
    return min(100, total)


def band_for(score_value: int) -> RiskBand:
    for low, high, band in BAND_THRESHOLDS:
        if low <= score_value <= high:
            return band
    return RiskBand.CRITICAL
