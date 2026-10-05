"""Reflected cross-site scripting (XSS) probe.

We inject a unique, inert marker tag and check whether it comes back
unescaped. We never execute JavaScript.
"""

import secrets
import string

from ..findings import Finding

PATHS = None  # replaced by CANDIDATES below
PARAMS = None

CANDIDATES = [
    ("/search", "q"),
    ("/hello", "name"),
    ("/greet", "name"),
    ("", "q"),
    ("", "search"),
    ("/user", "name"),
]


def run(base, http):
    findings = []
    token = "hkx" + "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6)
    )
    payload = "<%s>" % token
    for path, param in CANDIDATES:
        url = base + path
        r = http.get(url, params={param: payload})
        if r is None:
            continue
        body = r.text
        if payload in body:
            findings.append(
                Finding(
                    check="xss",
                    severity="high",
                    title="Cross-site scripting in %s" % (path or "/"),
                    meaning="Whatever I typed into '%s' came straight back inside the "
                    "page, unescaped. An attacker can replace my text with a "
                    "script that runs in every visitor's browser: stealing logins, "
                    "defacing the page, or redirecting to malware." % param,
                    fix="Escape all user input before putting it into HTML "
                    "(your template engine usually does this if you let it), and "
                    "add a Content-Security-Policy header as a seatbelt.",
                    evidence="payload reflected unescaped at %s" % url,
                    url=url + "?%s=%s" % (param, payload),
                )
            )
            return findings
        if token in body:
            findings.append(
                Finding(
                    check="xss",
                    severity="low",
                    title="User input reflected in %s (encoded)" % (path or "/"),
                    meaning="Your input appears in the page but is encoded, so it "
                    "cannot run as a script today. Still worth a look: one template "
                    "change could un-encode it.",
                    fix="Keep output encoding on for this field and add automated "
                    "XSS tests.",
                    url=url,
                )
            )
            return findings
    return findings
