"""Tests for hackable checks, scoring, and reporting."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hackable.checks import cors, debug, disclosure, exposed_files, headers, open_redirect, rate_limit, robots, sqli, tls, xss
from hackable.findings import Finding, score_findings
from hackable.report import render_terminal


class FakeResp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content = text.encode("utf-8", "replace")


class FakeHttp:
    def __init__(self, handler):
        self.handler = handler
        self.count = 0

    def request(self, method, url, **kwargs):
        self.count += 1
        return self.handler(method, url, kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)


BASE = "http://example.test"


def test_score_and_grades():
    fs = [
        Finding(check="t", severity="critical", title="c", meaning="m", fix="f"),
        Finding(check="t", severity="high", title="h", meaning="m", fix="f"),
    ]
    score, grade = score_findings(fs)
    assert score == 60 and grade == "C"
    assert score_findings([]) == (100, "A")
    many = [Finding(check="t", severity="critical", title="x", meaning="m", fix="f")] * 9
    assert score_findings(many)[1] == "F"


def test_headers_missing():
    http = FakeHttp(lambda m, u, k: FakeResp(200, "<html>", {}))
    fs = headers.run(BASE, http)
    titles = [f.title for f in fs]
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert not any("HSTS" in t for t in titles)  # http: covered by TLS check


def test_headers_present():
    h = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    }
    http = FakeHttp(lambda m, u, k: FakeResp(200, "<html>", h))
    assert headers.run(BASE, http) == []


def test_sqli_error_based():
    def handler(m, u, k):
        params = k.get("params", {})
        if any("'" in str(v) for v in params.values()):
            return FakeResp(200, "You have an error in your SQL syntax near '''")
        return FakeResp(200, "results page")

    fs = sqli.run(BASE, FakeHttp(handler))
    assert len(fs) == 1 and fs[0].severity == "critical"


def test_sqli_clean():
    http = FakeHttp(lambda m, u, k: FakeResp(200, "results page"))
    assert sqli.run(BASE, http) == []


def test_xss_reflected():
    def handler(m, u, k):
        params = k.get("params", {})
        v = next(iter(params.values()), "")
        return FakeResp(200, "<p>hello %s</p>" % v)

    fs = xss.run(BASE, FakeHttp(handler))
    assert len(fs) == 1 and fs[0].severity == "high"


def test_open_redirect():
    def handler(m, u, k):
        params = k.get("params", {})
        v = next(iter(params.values()), "")
        if "evil-hackable-test" in v:
            return FakeResp(302, "", {"location": v})
        return FakeResp(200, "home")

    fs = open_redirect.run(BASE, FakeHttp(handler))
    assert len(fs) == 1 and fs[0].severity == "high"


def test_exposed_env():
    def handler(m, u, k):
        if u.endswith("/.env"):
            return FakeResp(200, "STRIPE_SECRET_KEY=sk_test_123\nDEBUG=true\n")
        return FakeResp(404, "not found")

    fs = exposed_files.run(BASE, FakeHttp(handler))
    assert len(fs) == 1 and fs[0].severity == "critical"


def test_exposed_files_spa_fallback_ignored():
    # SPA returns the same HTML shell for every path: must NOT flag /.env
    spa = "<html><body><div id=app></div></body></html>"
    http = FakeHttp(lambda m, u, k: FakeResp(200, spa))
    assert exposed_files.run(BASE, http) == []


def test_debug_trace():
    def handler(m, u, k):
        return FakeResp(404, "<pre>Traceback (most recent call last):\n File x</pre>")

    fs = debug.run(BASE, FakeHttp(handler))
    assert len(fs) == 1 and fs[0].severity == "high"


def test_cors_evil_reflected():
    evil = "https://evil-hackable-test.example.com"

    def handler(m, u, k):
        origin = (k.get("headers") or {}).get("Origin", "")
        return FakeResp(
            200, "", {"Access-Control-Allow-Origin": origin,
                      "Access-Control-Allow-Credentials": "true"})

    fs = cors.run(BASE, FakeHttp(handler))
    assert len(fs) == 1 and fs[0].severity == "critical"


def test_rate_limit_missing():
    posts = []

    def handler(m, u, k):
        if m == "GET":
            return FakeResp(200, "login form") if u.endswith("/login") else FakeResp(404, "")
        posts.append(u)
        return FakeResp(401, "nope")

    fs = rate_limit.run(BASE, FakeHttp(handler))
    assert len(posts) == 10
    assert len(fs) == 1 and fs[0].severity == "medium"


def test_tls_plain_http():
    fs = tls.run("http://example.test", FakeHttp(lambda m, u, k: None))
    assert len(fs) == 1 and fs[0].severity == "medium"


def test_robots():
    http = FakeHttp(
        lambda m, u, k: FakeResp(200, "User-agent: *\nDisallow: /admin/\n"))
    fs = robots.run(BASE, http)
    assert len(fs) == 1 and "/admin/" in fs[0].evidence


def test_disclosure():
    http = FakeHttp(
        lambda m, u, k: FakeResp(200, "", {"server": "Apache/2.4.1",
                                           "x-powered-by": "PHP/8.1.0"}))
    fs = disclosure.run(BASE, http)
    assert len(fs) == 1 and fs[0].severity == "low"


def test_render_terminal_has_score():
    out = render_terminal([], BASE, 1.2, 5, use_color=False)
    assert "SCORE" in out and "100/100" in out and "GRADE  A" in out


def test_crawler_discovers_links_and_forms():
    from hackable.crawler import discover

    pages = {
        "http://example.test/": (
            '<a href="/search?q=lamp">x</a>'
            '<a href="https://other.com/?q=1">ext</a>'
            '<form action="/search" method="get"><input name="q"></form>'
        ),
        "http://example.test/search": "<p>results</p>",
    }

    def handler(m, u, k):
        base = u.split("?")[0]
        if base in pages:
            return FakeResp(200, pages[base], {"content-type": "text/html"})
        return FakeResp(404, "nope", {"content-type": "text/html"})

    found = discover("http://example.test", FakeHttp(handler))
    urls = {u for u, _ in found}
    assert "http://example.test/search" in urls
    assert not any("other.com" in u for u in urls)
    params = {p for _, ps in found for p in ps}
    assert "q" in params


def test_cookies_missing_flags():
    from hackable.checks import cookies

    class RawHeaders:
        def getlist(self, k):
            return ["session=abc; Path=/", "pref=1; Path=/; Secure"] if k == "set-cookie" else []

    class Raw:
        headers = RawHeaders()

    resp = FakeResp(200, "", {})
    resp.raw = Raw()
    fs = cookies.run("https://example.test", FakeHttp(lambda m, u, k: resp))
    titles = " ".join(f.title for f in fs)
    assert "Secure" in titles and "HttpOnly" in titles and "SameSite" in titles
    assert all("session" in f.title for f in fs if "Secure" in f.title)


def test_securitytxt_missing_and_present():
    from hackable.checks import securitytxt

    http = FakeHttp(lambda m, u, k: FakeResp(404, "nope"))
    fs = securitytxt.run(BASE, http)
    assert len(fs) == 1 and fs[0].severity == "info"

    def handler(m, u, k):
        if "security.txt" in u:
            return FakeResp(200, "Contact: mailto:sec@example.test")
        return FakeResp(404, "nope")

    assert securitytxt.run(BASE, FakeHttp(handler)) == []


