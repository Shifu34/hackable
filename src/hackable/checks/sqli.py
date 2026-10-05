"""SQL injection probes (safe: benign payloads, GET only).

Two techniques, both harmless:
- error-based: a single quote that makes the database complain out loud
- boolean differential: AND 1=1 vs AND 1=2 must not change the page; when it
  does, input is very likely reaching the query unsanitized (blind SQLi)

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


def _boolean_based(base, http, pairs):
    """Differential check: the page must not change between AND 1=1 / 1=2.

    Conservative: the two baselines must agree first, the true-condition must
    match the baseline closely, and the false-condition must differ clearly.
    """
    for url, param in pairs[:3]:
        b1 = http.get(url, params={param: "1"})
        b2 = http.get(url, params={param: "1"})
        if b1 is None or b2 is None or len(b1.text) != len(b2.text):
            continue
        n = len(b1.text)
        if n == 0:
            continue
        true = http.get(url, params={param: "1 AND 1=1"})
        false = http.get(url, params={param: "1 AND 1=2"})
        if true is None or false is None:
            continue
        true_diff = abs(len(true.text) - n)
        false_diff = abs(len(false.text) - n)
        if true_diff < 0.05 * n and false_diff > max(100, 0.3 * n):
            return [Finding(
                check="sqli",
                severity="high",
                title="Likely blind SQL injection in %s" % url.replace(base, "") or "/",
                meaning="The page looks identical for a true database condition "
                "but changes clearly for a false one. No error is shown, yet "
                "the '%s' value is very likely reaching your SQL query, which "
                "lets an attacker extract data bit by bit." % param,
                fix="Use parameterized queries / prepared statements for the "
                "'%s' parameter, and validate that it is the expected type." % param,
                evidence="page length %d -> %d on AND 1=2" % (n, len(false.text)),
                url=url + "?%s=1 AND 1=2" % param,
            )]
    return []


def run(base, http, targets=None):
    pairs = _pairs(base, targets)
    findings = _error_based(base, http, pairs)
    if findings:
        return findings  # one confirmed SQLi is enough
    # boolean differential only on real discovered inputs, to limit requests
    discovered = [(u, p) for (u, p) in pairs if targets and u in [t[0] for t in targets]]
    return _boolean_based(base, http, discovered or pairs[:3])
