"""DEMO ONLY. The hardened twin of vulnapp.py.

Same routes, every hole fixed the way hackable's report cards suggest:
escaped output, no SQL error leakage, relative-only redirects, no public
/.env, no version disclosure, sane robots.txt, no stack traces, no wildcard
CORS, login rate limiting, and real security headers.

Used to produce the real before/after score pair for the v1.1.0 launch
post: scan vulnapp.py (before), fix the app the way this one is fixed,
scan again (after). Local demo only, never deploy as-is.
"""

import html
import time

from flask import Flask, request, redirect, make_response

app = Flask(__name__)

_attempts = {}


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Server"] = "Acme"
    return resp


@app.route("/")
def index():
    return (
        "<h1>Acme Shop</h1><p>Hand-built with care. Actually secure this time.</p>"
        '<p><a href="/search?q=lamp">Search lamps</a> | '
        '<a href="/hello?name=World">Say hello</a> | '
        '<a href="/goto?next=/">Home</a></p>'
        '<form action="/search" method="get">'
        '<input name="q" placeholder="Search the shop">'
        "<button>Go</button></form>"
    )


@app.route("/search")
def search():
    q = html.escape(request.args.get("q", ""))
    return "<p>Results for %s: nothing found (demo).</p>" % q


@app.route("/hello")
def hello():
    name = html.escape(request.args.get("name", "stranger"))
    return "<h1>Hello %s!</h1>" % name


@app.route("/goto")
def goto():
    nxt = request.args.get("next", "/")
    # relative paths only: no open redirect to attacker domains
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/"
    return redirect(nxt)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "?"
        now = time.time()
        hits = [t for t in _attempts.get(ip, []) if now - t < 60]
        hits.append(now)
        _attempts[ip] = hits
        if len(hits) > 5:
            return "Too many attempts, try again in a minute.", 429
        return "Invalid credentials", 401
    return (
        '<form method="post">'
        '<input name="username" placeholder="username">'
        '<input name="password" type="password" placeholder="password">'
        "</form>"
    )


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow:\n", 200, {"Content-Type": "text/plain"}


@app.route("/.well-known/security.txt")
def security_txt():
    return "Contact: mailto:security@example.com\n", 200, {"Content-Type": "text/plain"}


@app.errorhandler(404)
def not_found(e):
    return "<h1>Not found</h1><p>That page does not exist.</p>", 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
