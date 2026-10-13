"""CORS misconfiguration."""

from ..findings import Finding, Inconclusive, ensure_testable

EVIL = "https://evil-hackable-test.example.com"


def _check_response(r):
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if acao == EVIL and acac:
        return "critical"
    if acao == EVIL or (acao == "*" and acac):
        return "high"
    if acao == "*":
        return "info"
    return None


def run(base, http):
    # probe both OPTIONS and GET: some servers only answer CORS on one of them
    probed = False
    verdict = None
    for method in ("options", "get"):
        r = getattr(http, method)(base + "/", headers={"Origin": EVIL})
        if r is None:
            continue
        probed = True
        ensure_testable(r, http, "the homepage")
        verdict = _check_response(r)
        if verdict is not None:
            break
    if not probed:
        raise Inconclusive("could not reach the homepage to test CORS")
    if verdict is None:
        return []
    if verdict == "critical":
        return [
            Finding(
                check="cors",
                severity="critical",
                title="Any website can make authenticated requests as your users",
                meaning="Your server tells browsers that evil-hackable-test.example.com "
                "may read responses AND send the victim's cookies along. A malicious "
                "site can silently act as your logged-in users.",
                fix="Never reflect arbitrary origins with Access-Control-Allow-Credentials. "
                "Use an explicit allowlist of your own domains.",
                evidence="Access-Control-Allow-Origin: %s + Allow-Credentials: true" % EVIL,
                url=base + "/",
            )
        ]
    if verdict == "high":
        return [
            Finding(
                check="cors",
                severity="high",
                title="CORS trusts arbitrary websites",
                meaning="Your server accepts cross-origin requests from any site I "
                "named. Depending on your auth model, a malicious page could read "
                "private API responses.",
                fix="Replace the wildcard/reflected origin with an explicit allowlist "
                "of domains you own.",
                url=base + "/",
            )
        ]
    return [
        Finding(
            check="cors",
            severity="info",
            title="CORS allows any origin (no credentials)",
            meaning="Any website can read your public API responses. That is fine for "
            "public data, but double-check nothing private is served this way.",
            fix="If all responses are public, no action needed. Otherwise restrict "
            "Access-Control-Allow-Origin to your own domains.",
            url=base + "/",
        )
    ]
