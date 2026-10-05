"""Open redirect probes."""

from ..findings import Finding

EVIL = "https://evil-hackable-test.example.com/"
PATHS = None  # replaced by CANDIDATES below
PARAMS = None

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


def run(base, http):
    for path, param in CANDIDATES:
        url = base + path
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
