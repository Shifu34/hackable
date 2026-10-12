"""A polite HTTP client: slow, identifiable, bounded.

hackable only ever sends harmless probe requests (no destructive payloads,
no DoS-style flooding). This client enforces that politeness in one place:
a small delay between requests, a hard cap on total requests, timeouts,
and an honest User-Agent.

Authenticated scanning: the user hands hackable their own session cookie
(--cookie "name=value; name2=value2"). The pairs are loaded into the
session's cookie jar so requests handles domain scoping and Set-Cookie
responses keep working. hackable never logs in by itself and never prints
the cookie value anywhere.
"""

import time

import requests

from . import __version__

USER_AGENT = (
    "hackable/%s (+https://github.com/Shifu34/hackable; "
    "automated security self-check; scans only with owner permission)"
) % __version__


def parse_cookie_header(raw):
    """Parse a Cookie header string into {name: value}.

    Tolerates stray whitespace and empty segments; values may contain "=".
    Segments without "=" are ignored.
    """
    cookies = {}
    if not raw:
        return cookies
    for segment in raw.split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        name, value = segment.split("=", 1)
        name = name.strip()
        if not name:
            continue
        cookies[name] = value.strip()
    return cookies


class PoliteClient:
    def __init__(self, delay=0.15, timeout=8, max_requests=150,
                 cookies=None, headers=None):
        """cookies: raw "name=value; ..." string (or None).
        headers: dict of extra headers to send on every request (or None)."""
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.delay = delay
        self.timeout = timeout
        self.max_requests = max_requests
        self.count = 0
        # Authenticated session. The values are secrets: they are sent with
        # requests but never printed, logged, or rendered anywhere.
        self.has_auth = bool(cookies)
        for name, value in parse_cookie_header(cookies).items():
            self.session.cookies.set(name, value)
        if headers:
            self.session.headers.update(headers)

    def request(self, method, url, **kwargs):
        if self.count >= self.max_requests:
            raise RuntimeError("request budget exceeded")
        if self.count:
            time.sleep(self.delay)
        kwargs.setdefault("timeout", self.timeout)
        self.count += 1
        try:
            return self.session.request(method, url, **kwargs)
        except requests.RequestException:
            return None

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)
