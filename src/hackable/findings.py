"""Findings: the unit of a hackable report."""

from dataclasses import dataclass, field
from urllib.parse import urlparse

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Every check ends in exactly one of these states. "not_tested" means the
# check could not meaningfully run (unreachable page, login wall, dead
# session): it is reported explicitly instead of silently looking like a pass.
CHECK_STATUSES = ("pass", "fail", "not_tested")


class Inconclusive(Exception):
    """A check raises this when it could not meaningfully test the target.

    The scanner catches it per-check and reports the check as "not tested"
    with the reason, instead of letting it look like a clean pass.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@dataclass
class CheckResult:
    check: str  # check id, e.g. "sqli"
    label: str  # human label, e.g. "SQL injection"
    status: str  # one of CHECK_STATUSES
    reason: str = ""  # why not tested (only for not_tested)
    finding_count: int = 0


_LOGIN_PATH_HINTS = ("login", "signin", "sign-in", "log-in", "authenticate")


def _looks_logged_out(resp):
    if resp is None:
        return False  # can't tell; stay quiet rather than cry wolf
    if resp.status_code in (401, 403):
        return True
    path = urlparse(resp.url).path.lower()
    return any(hint in path for hint in _LOGIN_PATH_HINTS)


def ensure_testable(resp, http, what):
    """Raise Inconclusive if this response means the check could not test.

    - No response at all: the page could not be reached.
    - Logged-out look while scanning with --cookie: the session is dead, so
      the check would only see the public site instead of what was asked for.
    Without --cookie, testing the public pages is the expected behaviour, so
    a login-looking page is only inconclusive for an authenticated scan.
    """
    if resp is None:
        raise Inconclusive("could not reach %s" % what)
    if getattr(http, "has_auth", False) and _looks_logged_out(resp):
        raise Inconclusive(
            "the site answered like you are logged out (login redirect or "
            "401/403) on %s. The --cookie session looks expired; grab a "
            "fresh one from your browser and scan again." % what
        )

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
