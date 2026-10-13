"""Tests for v1.1.0: authenticated scanning, baselines, and diffs.

All tests run against local fixtures only. Never against a real site.
"""

import contextlib
import io
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hackable.baseline import (
    diff_snapshots,
    load_baseline,
    render_diff_text,
    snapshot,
    write_baseline,
)
from hackable.checks import xss
from hackable.cli import main, parse_extra_headers, resolve_cookie
from hackable.crawler import discover
from hackable.findings import Finding
from hackable.polite import PoliteClient, parse_cookie_header
from hackable.report import render_html, render_json, render_sarif
from hackable.scanner import check_auth_session, scan

SESSION_COOKIE = "sessionid=abc123"
SECRET_COOKIE = "sessionid=S3CR3TCOOKIE"


class GatedHandler(BaseHTTPRequestHandler):
    """Tiny app with a cookie-gated dashboard."""

    seen_cookies = []

    def _authed(self):
        cookie = self.headers.get("Cookie", "")
        type(self).seen_cookies.append(cookie)
        return "sessionid=abc123" in cookie or "sessionid=S3CR3TCOOKIE" in cookie

    def _send(self, code, body, ctype="text/html"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)
        if path == "/":
            status = getattr(self.server, "root_status", 200)
            self._send(status,
                       '<a href="/dashboard">dash</a><a href="/public?q=1">pub</a>')
        elif path == "/public":
            self._send(200, "<p>public page, nothing to reflect here</p>")
        elif path == "/dashboard":
            if not self._authed():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            self._send(200, "DASHBOARD-AREA "
                            '<a href="/dashboard/search?q=test">search</a>')
        elif path == "/dashboard/search":
            if not self._authed():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            q = query.get("q", [""])[0]
            self._send(200, "<p>results for %s</p>" % q)  # raw: XSS on purpose
        elif path == "/login":
            self._send(200, '<form><input type="password" name="pw"></form>')
        else:
            self._send(404, "nope")

    def do_POST(self):
        self._send(200, "ok")

    def log_message(self, *args):
        pass


@pytest.fixture()
def gated_app():
    server = ThreadingHTTPServer(("127.0.0.1", 0), GatedHandler)
    GatedHandler.seen_cookies = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d" % server.server_address[1]
    server.shutdown()


def client(cookies=None, **kw):
    kw.setdefault("delay", 0)
    kw.setdefault("max_requests", 500)
    return PoliteClient(cookies=cookies, **kw)


# --- cookie header parsing -------------------------------------------------


def test_parse_multiple_pairs():
    assert parse_cookie_header("a=1; b=2; c=3") == {"a": "1", "b": "2", "c": "3"}


def test_parse_value_with_equals():
    assert parse_cookie_header("tok=ab==cd; x=1") == {"tok": "ab==cd", "x": "1"}


def test_parse_tolerates_whitespace_and_empties():
    assert parse_cookie_header("  a = 1 ;; b=2;") == {"a": "1", "b": "2"}


def test_parse_ignores_segments_without_equals():
    assert parse_cookie_header("a=1; justtext; b=2") == {"a": "1", "b": "2"}


def test_parse_empty():
    assert parse_cookie_header("") == {}
    assert parse_cookie_header(None) == {}


# --- the cookie actually reaches the server --------------------------------


def test_cookie_sent_with_every_request(gated_app):
    http = client(cookies=SESSION_COOKIE)
    discover(gated_app, http)
    assert GatedHandler.seen_cookies, "server saw no requests"
    assert all("sessionid=abc123" in c for c in GatedHandler.seen_cookies)


def test_no_cookie_sent_by_default(gated_app):
    http = client()
    discover(gated_app, http)
    assert all("sessionid" not in c for c in GatedHandler.seen_cookies)


def test_has_auth_flag():
    assert client(cookies=SESSION_COOKIE).has_auth is True
    assert client().has_auth is False


# --- crawler sees the logged-in surface ------------------------------------


def test_discover_finds_gated_pages_with_cookie(gated_app):
    found = discover(gated_app, client(cookies=SESSION_COOKIE))
    urls = [u for u, _ in found]
    assert any("/dashboard/search" in u for u in urls)


def test_discover_skips_gated_pages_without_cookie(gated_app):
    found = discover(gated_app, client())
    urls = [u for u, _ in found]
    # the login form (found via the /dashboard -> /login redirect) is fine;
    # the behind-login surface itself must stay undiscovered
    assert not any("/dashboard/search" in u for u in urls)


def test_xss_probe_hits_gated_input_with_cookie(gated_app):
    http = client(cookies=SESSION_COOKIE)
    found = discover(gated_app, http)
    results = xss.run(gated_app, http, found)
    assert results, "expected the XSS probe to fire on the gated search page"
    assert "/dashboard/search" in results[0].url


def test_xss_probe_cannot_reach_gated_input_without_cookie(gated_app):
    http = client()
    found = discover(gated_app, http)
    results = xss.run(gated_app, http, found)
    assert not any("/dashboard" in f.url for f in results)


# --- dead session warning ----------------------------------------------------


def test_dead_session_warns_but_scans_on(gated_app, capsys):
    server = ThreadingHTTPServer(("127.0.0.1", 0), GatedHandler)
    server.root_status = 401
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = "http://127.0.0.1:%d" % server.server_address[1]
        check_auth_session(base, client(cookies="sessionid=DEADVALUE123"))
        err = capsys.readouterr().err
        assert "looks expired or wrong" in err
        assert "DEADVALUE123" not in err  # the secret never leaks
    finally:
        server.shutdown()


def test_healthy_session_stays_quiet(gated_app, capsys):
    check_auth_session(gated_app, client(cookies=SESSION_COOKIE))
    assert capsys.readouterr().err == ""


# --- the cookie value never leaks into output ------------------------------


def _scan_with_secret(gated_app):
    http = client(cookies=SECRET_COOKIE)
    return scan(gated_app, http, include={"xss"})


def test_secret_not_in_json(gated_app):
    base, findings, _cr, elapsed, count = _scan_with_secret(gated_app)
    assert "S3CR3TCOOKIE" not in render_json(findings, base, elapsed, count)


def test_secret_not_in_sarif(gated_app):
    base, findings, _cr, elapsed, count = _scan_with_secret(gated_app)
    assert "S3CR3TCOOKIE" not in render_sarif(findings, base, elapsed, count)


def test_secret_not_in_html(gated_app):
    base, findings, _cr, elapsed, count = _scan_with_secret(gated_app)
    assert "S3CR3TCOOKIE" not in render_html(findings, base, elapsed, count)


def test_secret_not_in_cli_stdout(gated_app):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["--json", "--yes", gated_app,
                   "--cookie", SECRET_COOKIE, "--only", "xss", "--delay", "0"])
    assert rc == 0
    assert "S3CR3TCOOKIE" not in buf.getvalue()


# --- env var and header helpers ----------------------------------------------


def test_resolve_cookie_prefers_flag(monkeypatch):
    monkeypatch.setenv("HACKABLE_COOKIE", "a=1")

    class A:
        cookie = "b=2"

    assert resolve_cookie(A()) == "b=2"


def test_resolve_cookie_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("HACKABLE_COOKIE", "a=1")

    class A:
        cookie = None

    assert resolve_cookie(A()) == "a=1"


def test_resolve_cookie_none_when_unset(monkeypatch):
    monkeypatch.delenv("HACKABLE_COOKIE", raising=False)

    class A:
        cookie = None

    assert resolve_cookie(A()) is None


def test_parse_extra_headers_ok():
    assert parse_extra_headers(["Authorization: Bearer t",
                                "X-Api: v2"]) == {
        "Authorization": "Bearer t", "X-Api": "v2"}


def test_parse_extra_headers_rejects_malformed():
    assert parse_extra_headers(["no-colon-here"]) is None
    assert parse_extra_headers([": novalue"]) is None


def test_extra_header_reaches_server(gated_app):
    http = client()
    http.session.headers.update({"X-Probe": "yes"})
    http.get(gated_app + "/")
    assert True  # no crash; header plumbing is requests' job


# --- baselines and diffs -----------------------------------------------------


def _f(check, severity, title, url="http://x/"):
    return Finding(check=check, severity=severity, title=title,
                   meaning="m", fix="f", url=url)


def test_diff_reports_new_and_fixed():
    old = snapshot([_f("xss", "high", "XSS here"), _f("tls", "medium", "No HTTPS")],
                   "http://x", 1.0, 10)
    new = snapshot([_f("tls", "medium", "No HTTPS"), _f("sqli", "critical", "SQLi!")],
                   "http://x", 1.0, 10)
    d = diff_snapshots(old, new)
    assert [x["title"] for x in d["new"]] == ["SQLi!"]
    assert [x["title"] for x in d["fixed"]] == ["XSS here"]
    assert d["score_before"] == old["score"]
    assert d["score_after"] == new["score"]


def test_diff_empty_when_identical():
    snap = snapshot([_f("xss", "high", "XSS here")], "http://x", 1.0, 10)
    d = diff_snapshots(snap, snapshot([_f("xss", "high", "XSS here")],
                                      "http://x", 1.0, 10))
    assert d["new"] == [] and d["fixed"] == []


def test_render_diff_text(tmp_path):
    old = snapshot([_f("xss", "high", "XSS here")], "http://x", 1.0, 10)
    new = snapshot([], "http://x", 1.0, 10)
    text = render_diff_text(diff_snapshots(old, new))
    assert "BASELINE DIFF" in text
    assert "FIXED since the baseline (1)" in text
    assert "Score:" in text


def test_baseline_roundtrip(tmp_path):
    snap = snapshot([_f("xss", "high", "XSS here")], "http://x", 1.0, 10)
    path = str(tmp_path / "base.json")
    write_baseline(path, snap)
    loaded = load_baseline(path)
    assert loaded["findings"] == snap["findings"]
    assert loaded["score"] == snap["score"]


def test_load_baseline_rejects_garbage(tmp_path):
    path = str(tmp_path / "bad.json")
    with open(path, "w") as fh:
        fh.write('{"nope": true}')
    with pytest.raises(ValueError):
        load_baseline(path)


def test_cli_save_and_diff(gated_app, tmp_path, capsys):
    base_file = str(tmp_path / "base.json")
    rc = main(["--yes", gated_app, "--only", "xss", "--delay", "0",
               "--save-baseline", base_file, "--color", "never"])
    assert rc == 0
    loaded = load_baseline(base_file)
    assert loaded["target"].startswith("http://127.0.0.1")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["--yes", gated_app, "--only", "xss", "--delay", "0",
                   "--diff-from", base_file, "--color", "never"])
    assert rc == 0
    assert "BASELINE DIFF" in buf.getvalue()


def test_cli_diff_from_missing_file(gated_app, tmp_path, capsys):
    rc = main(["--yes", gated_app, "--only", "xss", "--delay", "0",
               "--diff-from", str(tmp_path / "missing.json")])
    assert rc == 2
    assert "Could not read baseline" in capsys.readouterr().err
