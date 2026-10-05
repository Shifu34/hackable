"""DEMO ONLY. Intentionally vulnerable app for hackable demos.

NEVER deploy this. Every hole below is deliberate so the scanner has
something dramatic to find.
"""

from flask import Flask, request, redirect, make_response

app = Flask(__name__)

FAKE_ENV = (
    "STRIPE_SECRET_KEY=sk_test_51Hb3n2fakekey000\n"
    "DB_PASSWORD=sup3r-s3cret-hunter2\n"
    "DEBUG=true\n"
)


@app.route("/")
def index():
    resp = make_response(
        "<h1>Acme Shop</h1><p>Hand-built with AI in a weekend. Totally secure. Probably.</p>"
        '<p><a href="/search?q=lamp">Search lamps</a> | '
        '<a href="/hello?name=World">Say hello</a> | '
        '<a href="/goto?next=https://example.com">Partner site</a></p>'
        '<form action="/search" method="get">'
        '<input name="q" placeholder="Search the shop">'
        '<button type="submit">Go</button></form>'
    )
    resp.headers["Server"] = "Werkzeug/2.3.7"
    resp.headers["X-Powered-By"] = "Flask/2.3.3"
    return resp


@app.route("/search")
def search():
    q = request.args.get("q", "")
    if "'" in q:
        return (
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version for the right syntax "
            "near ''' at line 1",
            200,
        )
    return "<p>Results for %s: nothing found (demo).</p>" % q


@app.route("/hello")
def hello():
    name = request.args.get("name", "stranger")
    return "<h1>Hello %s!</h1>" % name


@app.route("/goto")
def goto():
    return redirect(request.args.get("next", "/"))


@app.route("/.env")
def env():
    return FAKE_ENV, 200, {"Content-Type": "text/plain"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return "Invalid credentials", 401
    return (
        '<form method="post">'
        '<input name="username" placeholder="username">'
        '<input name="password" type="password" placeholder="password">'
        "</form>"
    )


@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\nDisallow: /admin/\nDisallow: /backup.zip\n",
        200,
        {"Content-Type": "text/plain"},
    )


@app.errorhandler(404)
def not_found(e):
    return (
        "<h1>Server Error</h1><pre>Traceback (most recent call last):\n"
        '  File "/app/views.py", line 42, in page\n'
        "    return render(template)\n"
        "django.core.exceptions.ViewDoesNotExist: tried 12 URL patterns</pre>",
        404,
    )


@app.after_request
def cors(resp):
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
