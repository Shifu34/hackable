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


def test_sqli_boolean_differential():
    def handler(m, u, k):
        val = (k.get("params") or {}).get("q", "")
        if val == "1 AND 1=2":
            return FakeResp(200, "x" * 50)  # clearly different page
        return FakeResp(200, "y" * 500)

    fs = sqli.run(BASE, FakeHttp(handler), targets=[(BASE + "/search", ["q"])])
    assert any(f.severity == "high" and "blind" in f.title for f in fs)


def test_sqli_boolean_no_false_positive_on_stable():
    def handler(m, u, k):
        return FakeResp(200, "same page " * 40)

    fs = sqli.run(BASE, FakeHttp(handler), targets=[(BASE + "/search", ["q"])])
    assert fs == []


def test_sarif_output_shape():
    import json
    from hackable.report import render_sarif

    fs = [Finding(check="sqli", severity="critical", title="SQLi",
                  meaning="m", fix="use params", url="http://example.test/search")]
    doc = json.loads(render_sarif(fs, BASE, 1.0, 10))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "hackable"
    assert run["tool"]["driver"]["rules"][0]["id"] == "hackable/sqli"
    res = run["results"][0]
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "http://example.test/search"


def test_scanner_only_and_skip():
    from hackable.scanner import scan

    def handler(m, u, k):
        return FakeResp(200, "<html>ok</html>", {})

    http = FakeHttp(handler)
    _base, findings, _cr, _e, _c = scan("example.test", http, include={"headers"})
    assert findings and all(f.check == "headers" for f in findings)

    http2 = FakeHttp(handler)
    _base, findings2, _cr2, _e, _c = scan("example.test", http2, exclude={"headers"})
    assert all(f.check != "headers" for f in findings2)


# --- per-check status: pass / fail / not_tested -----------------------------

from hackable.findings import CheckResult, Inconclusive, ensure_testable
from hackable.report import render_html, render_json


class FakeRespWithUrl(FakeResp):
    def __init__(self, status_code=200, text="", headers=None, url="http://example.test/"):
        super().__init__(status_code, text, headers)
        self.url = url


class FakeAuthHttp(FakeHttp):
    has_auth = True


def test_ensure_testable_none_raises():
    http = FakeHttp(lambda m, u, k: None)
    try:
        ensure_testable(None, http, "the homepage")
        assert False, "should have raised"
    except Inconclusive as e:
        assert "could not reach" in e.reason


def test_ensure_testable_dead_session_raises():
    http = FakeAuthHttp(lambda m, u, k: None)
    resp = FakeRespWithUrl(200, "<html>login</html>", {}, url="http://example.test/login")
    try:
        ensure_testable(resp, http, "the homepage")
        assert False, "should have raised"
    except Inconclusive as e:
        assert "--cookie" in e.reason


def test_ensure_testable_public_scan_ignores_login_look():
    # without --cookie, a login-looking page is the expected public surface
    http = FakeHttp(lambda m, u, k: None)
    resp = FakeRespWithUrl(200, "<html>login</html>", {}, url="http://example.test/login")
    ensure_testable(resp, http, "the homepage")  # must not raise


def test_ensure_testable_healthy_response_ok():
    http = FakeAuthHttp(lambda m, u, k: None)
    resp = FakeRespWithUrl(200, "<html>dashboard</html>", {}, url="http://example.test/app")
    ensure_testable(resp, http, "the homepage")  # must not raise


def test_scan_marks_unreachable_check_not_tested():
    from hackable.scanner import scan
    http = FakeHttp(lambda m, u, k: None)  # every fetch fails
    base, findings, results, _e, _c = scan("example.test", http, include={"headers"})
    assert findings == []
    assert len(results) == 1
    r = results[0]
    assert r.check == "headers" and r.status == "not_tested"
    assert "could not reach" in r.reason


def test_scan_check_results_pass_and_fail():
    from hackable.scanner import scan
    http = FakeHttp(lambda m, u, k: FakeResp(200, "<html>ok</html>", {}))
    base, findings, results, _e, _c = scan("example.test", http, include={"headers"})
    assert findings  # missing headers -> findings
    r = results[0]
    assert r.status == "fail" and r.finding_count == len(findings)


def test_scan_all_checks_reported():
    from hackable.scanner import scan
    from hackable.checks import CHECKS
    http = FakeHttp(lambda m, u, k: FakeResp(200, "<html>ok</html>", {}))
    base, findings, results, _e, _c = scan("example.test", http)
    assert len(results) == len(CHECKS)
    assert {r.status for r in results} <= {"pass", "fail", "not_tested"}


def test_terminal_shows_check_status():
    results = [
        CheckResult(check="headers", label="security headers", status="pass"),
        CheckResult(check="sqli", label="SQL injection", status="fail", finding_count=2),
        CheckResult(check="cors", label="CORS misconfiguration", status="not_tested",
                    reason="could not reach the homepage"),
    ]
    out = render_terminal([], BASE, 1.2, 5, use_color=False, check_results=results)
    assert "CHECK STATUS" in out
    assert "security headers" in out and "passed" in out
    assert "SQL injection" in out and "2 findings" in out
    assert "NOT TESTED" in out.upper() or "not tested" in out
    assert "could not reach the homepage" in out
    assert "may be incomplete" in out


def test_not_tested_does_not_change_score():
    results = [CheckResult(check="x", label="x", status="not_tested", reason="r")]
    out = render_terminal([], BASE, 1.2, 5, use_color=False, check_results=results)
    assert "100/100" in out and "GRADE  A" in out


def test_json_includes_checks():
    import json
    results = [CheckResult(check="headers", label="security headers", status="pass")]
    doc = json.loads(render_json([], BASE, 1.2, 5, check_results=results))
    assert doc["checks"] == [{
        "check": "headers", "label": "security headers", "status": "pass",
        "reason": None, "finding_count": 0,
    }]


def test_html_includes_check_table():
    results = [
        CheckResult(check="cors", label="CORS misconfiguration", status="not_tested",
                    reason="dead session"),
    ]
    out = render_html([], BASE, 1.2, 5, check_results=results)
    assert "Check status" in out
    assert "NOT TESTED" in out
    assert "dead session" in out
    assert "may be incomplete" in out
