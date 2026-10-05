"""Missing security headers."""

from ..findings import Finding

WANTED = [
    (
        "strict-transport-security",
        "medium",
        "No HSTS header",
        "Without HSTS, a visitor on public Wi-Fi can be silently downgraded from "
        "HTTPS to plain HTTP, and everything they type can be read.",
        "Send Strict-Transport-Security: max-age=31536000 on every HTTPS response.",
    ),
    (
        "content-security-policy",
        "low",
        "No Content-Security-Policy header",
        "CSP is a seatbelt against cross-site scripting: it tells browsers which "
        "scripts are allowed to run. Without it, one injected script runs anywhere.",
        "Add a Content-Security-Policy header that only allows scripts from your own domain.",
    ),
    (
        "x-frame-options",
        "low",
        "No X-Frame-Options header",
        "Without it, an attacker can embed your site invisibly inside theirs and "
        "trick visitors into clicking things they cannot see (clickjacking).",
        "Send X-Frame-Options: DENY, or use frame-ancestors in your CSP.",
    ),
    (
        "x-content-type-options",
        "low",
        "No X-Content-Type-Options header",
        "Browsers may guess a file's type and execute it. An uploaded 'image' could "
        "be run as a script.",
        "Send X-Content-Type-Options: nosniff on every response.",
    ),
    (
        "referrer-policy",
        "info",
        "No Referrer-Policy header",
        "Browsers may leak full page URLs (sometimes containing tokens or private "
        "IDs) to third-party sites when visitors click links.",
        "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
    ),
]


def run(base, http):
    findings = []
    r = http.get(base + "/")
    if r is None:
        return findings
    present = {k.lower() for k in r.headers}
    is_https = base.startswith("https://")
    for header, severity, title, meaning, fix in WANTED:
        if header == "strict-transport-security" and not is_https:
            continue  # covered by the TLS check instead
        if header not in present:
            findings.append(
                Finding(
                    check="headers",
                    severity=severity,
                    title=title,
                    meaning=meaning,
                    fix=fix,
                    url=base + "/",
                )
            )
    return findings
