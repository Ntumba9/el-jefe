from app.models.schemas import RiskBand
from app.risk.scoring import band_for, deduplicate, score
from app.models.schemas import Finding


def finding(rule="rule_a", weight=25):
    return Finding(
        rule=rule,
        severity_weight=weight,
        description="test",
        mitre_technique_id="T0000",
        mitre_technique_name="Test",
    )


def test_score_sums_distinct_findings():
    assert score([finding("a", 25), finding("b", 30)]) == 55


def test_score_caps_at_100():
    assert score([finding("a", 60), finding("b", 60)]) == 100


def test_deduplicate_keeps_highest_weight_per_rule():
    deduped = deduplicate([finding("a", 10), finding("a", 25)])
    assert len(deduped) == 1
    assert deduped[0].severity_weight == 25


def test_band_boundaries():
    assert band_for(0) == RiskBand.LOW
    assert band_for(29) == RiskBand.LOW
    assert band_for(30) == RiskBand.MEDIUM
    assert band_for(59) == RiskBand.MEDIUM
    assert band_for(60) == RiskBand.HIGH
    assert band_for(79) == RiskBand.HIGH
    assert band_for(80) == RiskBand.CRITICAL
    assert band_for(100) == RiskBand.CRITICAL
