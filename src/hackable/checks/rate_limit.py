"""Login rate-limiting probe (gentle: 10 attempts, wrong creds)."""

from ..findings import Finding

ENDPOINTS = ["/login", "/signin", "/auth/login", "/api/login", "/admin/login", "/users/sign_in"]


def run(base, http):
    login_url = None
    for path in ENDPOINTS:
        r = http.get(base + path)
        if r is not None and r.status_code in (200, 401, 403, 405):
            login_url = base + path
            break
    if login_url is None:
        return []
    blocked = 0
    attempts = 10
    for _ in range(attempts):
        r = http.post(
            login_url,
            data={"username": "hackable-probe", "password": "wrong-password"},
        )
        if r is None:
            break
        if r.status_code in (429, 403):
            blocked += 1
    if blocked:
        return [
            Finding(
                check="rate_limit",
                severity="info",
                title="Login rate limiting appears active",
                meaning="After a few wrong passwords the server pushed back (%d of %d "
                "attempts blocked). That is what you want." % (blocked, attempts),
                fix="No action needed. Keep it.",
                url=login_url,
            )
        ]
    return [
        Finding(
            check="rate_limit",
            severity="medium",
            title="No rate limiting on the login page",
            meaning="I tried 10 wrong passwords as fast as I could and nobody stopped "
            "me. An attacker can try millions: common passwords, leaked passwords, "
            "until one works.",
            fix="Throttle login attempts (a few tries, then growing delays or a "
            "temporary lockout), add a CAPTCHA after failures, and alert on bursts.",
            evidence="%d rapid attempts, none blocked" % attempts,
            url=login_url,
        )
    ]
