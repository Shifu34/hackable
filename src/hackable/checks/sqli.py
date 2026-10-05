"""SQL injection probes (safe: benign payloads, GET only, error-based).

We look for database error messages and for 500s triggered by a quote.
We never send destructive payloads, stacked queries, or time-based probes.
"""

from ..findings import Finding

# (path, param) pairs, most likely first. Used when the crawler found no
# real inputs, so the request budget is spent across endpoints instead of
# being eaten by one page's params.
CANDIDATES = [
    ("/search", "q"),
    ("/search", "search"),
    ("/search", "query"),
    ("", "q"),
    ("", "id"),
    ("", "search"),
    ("/product", "id"),
    ("/user", "id"),
    ("/item", "id"),
    ("/page", "id"),
]

ERROR_SIGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "postgresql",
    "sqlite3",
    "ora-",
    "odbc",
    "sqlstate",
    "jdbc",
    "database error",
]


def _looks_like_sql_error(text):
    t = text.lower()
    return any(sig in t for sig in ERROR_SIGS)


def _pairs(base, targets):
    """Discovered (url, params) first, then guesses. All absolute URLs."""
    pairs, seen = [], set()
    for url, params in (targets or [])[:8]:
        for param in params[:3]:
            key = (url, param)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    for path, param in CANDIDATES[:7]:
        key = (base + path, param)
        if key not in seen:
            seen.add(key)
            pairs.append(key)
    return pairs[:14]


def _error_based(base, http, pairs):
    for url, param in pairs:
        baseline = http.get(url, params={param: "1"})
        if baseline is None:
            continue
        probe = http.get(url, params={param: "1'"})
        if probe is None:
            continue
        full_url = url + "?%s=1'" % param
        if _looks_like_sql_error(probe.text):
            return [Finding(
                check="sqli",
                severity="critical",
                title="SQL injection in %s" % url.replace(base, "") or "/",
                meaning="Your database complained out loud when I typed a single "
                "quote into the '%s' field. That means an attacker can talk "
                "directly to your database: read every table, and often take "
                "over the server." % param,
                fix="Never build database queries by gluing strings together. "
                "Use parameterized queries / prepared statements in your "
                "framework, and validate input.",
                evidence=probe.text.strip().replace("\n", " ")[:160],
                url=full_url,
            )]
        if baseline.status_code < 500 <= probe.status_code:
            return [Finding(
                check="sqli",
                severity="medium",
                title="Possible SQL injection in %s" % url.replace(base, "") or "/",
                meaning="The page works fine normally but crashes with a server "
                "error when I type a quote into '%s'. That pattern often means "
                "user input reaches the database unsanitized." % param,
                fix="Have a developer check how the '%s' parameter is used in "
                "database queries, and switch to parameterized queries." % param,
                evidence="HTTP %s -> HTTP %s on quote payload"
                % (baseline.status_code, probe.status_code),
                url=full_url,
            )]
    return []


def run(base, http, targets=None):
    return _error_based(base, http, _pairs(base, targets))
