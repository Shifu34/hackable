"""Check that cookies, especially session cookies, carry security flags."""

from ..findings import Finding

FLAG_ADVICE = {
    "secure": ("medium", "Cookie without the Secure flag",
               "This cookie can be sent over plain HTTP, where anyone on the "
               "network can read or steal it.",
               "Fix: set the Secure attribute so the cookie is only ever "
               "sent over HTTPS."),
    "httponly": ("low", "Cookie without the HttpOnly flag",
                 "JavaScript running in the page can read this cookie, which "
                 "makes session theft via XSS much easier.",
                 "Fix: set the HttpOnly attribute so JavaScript cannot read "
                 "the cookie. This blunts XSS-based session theft."),
    "samesite": ("low", "Cookie without the SameSite attribute",
                 "The browser sends this cookie on cross-site requests, which "
                 "enables cross-site request forgery attacks.",
                 "Fix: set SameSite=Lax (or Strict) to block the cookie on "
                 "cross-site requests and reduce CSRF risk."),
}


def _raw_cookies(response):
    try:
        return response.raw.headers.getlist("set-cookie")
    except Exception:
        pass
    single = response.headers.get("set-cookie")
    return [single] if single else []


def run(base, http):
    r = http.get(base + "/")
    if r is None:
        return []
    raw = _raw_cookies(r)
    if not raw:
        return []

    is_https = base.startswith("https://")
    missing = {"secure": [], "httponly": [], "samesite": []}
    for cookie in raw:
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=", 1)[0] or "(unnamed)"
        flags = {p.split("=", 1)[0].lower() for p in parts[1:]}
        for flag in missing:
            if flag == "secure" and not is_https:
                continue  # Secure only makes sense over HTTPS
            if flag not in flags:
                missing[flag].append(name)

    findings = []
    for flag, names in missing.items():
        if not names:
            continue
        severity, title, meaning, fix = FLAG_ADVICE[flag]
        findings.append(Finding(
            check="cookies", severity=severity,
            title=f"{title}: {', '.join(names[:3])}",
            meaning=meaning,
            url=base + "/", evidence=f"Set-Cookie flags seen: {flag} missing",
            fix=fix,
        ))
    return findings
