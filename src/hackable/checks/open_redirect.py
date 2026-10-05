"""Open redirect probes."""

from ..findings import Finding

EVIL = "https://evil-hackable-test.example.com/"

CANDIDATES = [
    ("/goto", "next"),
    ("/redirect", "next"),
    ("/login", "next"),
    ("", "next"),
    ("/goto", "redirect"),
    ("/go", "url"),
    ("", "redirect"),
    ("/callback", "returnUrl"),
]


def _pairs(base, targets):
    pairs, seen = [], set()
    for url, params in (targets or [])[:8]:
        for param in params[:3]:
            key = (url, param)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    for path, param in CANDIDATES:
        key = (base + path, param)
        if key not in seen:
            seen.add(key)
            pairs.append(key)
    return pairs[:14]


def run(base, http, targets=None):
    for url, param in _pairs(base, targets):
        path = url.replace(base, "") or "/"
        r = http.get(url, params={param: EVIL}, allow_redirects=False)
        if r is None:
            continue
        location = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "evil-hackable-test" in location:
            return [
                Finding(
                    check="open_redirect",
                    severity="high",
                    title="Open redirect in %s" % (path or "/"),
                    meaning="Your site happily redirects visitors to any address I "
                    "name, including an attacker's. Phishing emails love this: the "
                    "link shows YOUR domain, but lands on THEIR fake login page.",
                    fix="Only redirect to relative paths or an allowlist of your "
                    "own domains. Reject anything starting with http or //.",
                    evidence="Location: %s" % location[:120],
                    url=url + "?%s=%s" % (param, EVIL),
                )
            ]
    return []
