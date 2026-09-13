"""Risk scoring — turns a scan's finding severities into a 0-100 score.

Weights (v0.2): critical 15, high 8, medium 3, low 1, info 0.
The score is the sum over all findings, capped at 100.
"""

from collections.abc import Iterable

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 15,
    "high": 8,
    "medium": 3,
    "low": 1,
    "info": 0,
}

MAX_RISK_SCORE = 100


def compute_risk_score(severities: Iterable[str]) -> float:
    """Sum severity weights, capped at 100. Unknown severities count as 0."""
    total = sum(SEVERITY_WEIGHTS.get(severity, 0) for severity in severities)
    return float(min(MAX_RISK_SCORE, total))
