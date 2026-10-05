"""Findings: the unit of a hackable report."""

from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low", "info")

SEVERITY_WEIGHT = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


@dataclass
class Finding:
    check: str       # check id, e.g. "sqli"
    severity: str    # one of SEVERITIES
    title: str       # short headline
    meaning: str     # plain-English: what this means for a non-expert
    fix: str         # plain-English: how to fix it
    evidence: str = ""
    url: str = ""


def score_findings(findings):
    """Return (score 0-100, grade A-F)."""
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, score)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade
