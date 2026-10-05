"""A polite HTTP client: slow, identifiable, bounded.

hackable only ever sends harmless probe requests (no destructive payloads,
no DoS-style flooding). This client enforces that politeness in one place:
a small delay between requests, a hard cap on total requests, timeouts,
and an honest User-Agent.
"""

import time

import requests

USER_AGENT = (
    "hackable/1.0.0 (+https://github.com/Shifu34/hackable; "
    "automated security self-check; scans only with owner permission)"
)


class PoliteClient:
    def __init__(self, delay=0.15, timeout=8, max_requests=150):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.delay = delay
        self.timeout = timeout
        self.max_requests = max_requests
        self.count = 0

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
