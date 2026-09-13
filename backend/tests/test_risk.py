"""Risk scoring tests — severity weights, cap at 100, CVSS thresholds."""

from app.services.nvd import severity_from_cvss
from app.services.risk import SEVERITY_WEIGHTS, MAX_RISK_SCORE, compute_risk_score


def test_severity_weights_match_spec():
    assert SEVERITY_WEIGHTS == {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}
    assert MAX_RISK_SCORE == 100


def test_known_severities_sum():
    # 15 + 8 + 3 + 1 + 0 = 27
    assert compute_risk_score(["critical", "high", "medium", "low", "info"]) == 27.0


def test_mixed_findings_score():
    # 2 critical (30) + 1 high (8) + 2 medium (6) = 44
    severities = ["critical", "critical", "high", "medium", "medium", "info", "info"]
    assert compute_risk_score(severities) == 44.0


def test_score_capped_at_100():
    assert compute_risk_score(["critical"] * 7) == 100.0  # 7 * 15 = 105
    assert compute_risk_score(["critical"] * 100) == 100.0


def test_empty_and_unknown_severities_score_zero():
    assert compute_risk_score([]) == 0.0
    assert compute_risk_score(["info", "info"]) == 0.0
    assert compute_risk_score(["bogus-severity"]) == 0.0


def test_severity_from_cvss_thresholds():
    assert severity_from_cvss(10.0) == "critical"
    assert severity_from_cvss(9.0) == "critical"
    assert severity_from_cvss(8.9) == "high"
    assert severity_from_cvss(7.0) == "high"
    assert severity_from_cvss(6.9) == "medium"
    assert severity_from_cvss(4.0) == "medium"
    assert severity_from_cvss(3.9) == "low"
    assert severity_from_cvss(0.1) == "low"
    assert severity_from_cvss(0.0) == "info"
