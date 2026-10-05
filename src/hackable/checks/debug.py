"""Debug mode / stack traces exposed on error pages."""

import secrets

from ..findings import Finding

MARKERS = [
    "traceback (most recent call last)",
    "django.core.exceptions",
    "werkzeug.debug",
    "raise valueerror",
    'at ".rb:',
    ".java:",
    "system.nullreferenceexception",
    "stack trace:",
    "#0 ",
    "fatal error:",
]


def run(base, http):
    probe = "/hackable-probe-" + secrets.token_hex(4)
    r = http.get(base + probe)
    if r is None:
        return []
    body = r.text.lower()
    hits = [m for m in MARKERS if m in body]
    if not hits:
        return []
    return [
        Finding(
            check="debug",
            severity="high",
            title="Error pages leak stack traces",
            meaning="Your 404 page shows internal error details (matched: %s). Stack "
            "traces reveal file paths, library versions and code structure, which "
            "is exactly what an attacker needs to aim." % ", ".join(hits[:3]),
            fix="Turn off debug mode in production and serve a generic error page "
            "that reveals nothing internal. Log the details server-side instead.",
            evidence=r.text.strip().replace("\n", " ")[:160],
            url=base + probe,
        )
    ]
