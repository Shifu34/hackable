"""Scan orchestration."""

import sys
import time
from urllib.parse import urlparse

from .checks import CHECKS
from .crawler import discover
from .polite import PoliteClient

# checks that probe the crawler's discovered inputs
INJECTION_CHECKS = ("sqli", "xss", "open_redirect")

# one cheap heuristic: a root fetch that lands on a login-ish page or gets
# 401/403 means the session cookie is probably expired or wrong
_LOGIN_PATH_HINTS = ("login", "signin", "sign-in", "log-in", "authenticate")


def _looks_logged_out(resp):
    if resp is None:
        return False  # can't tell; stay quiet rather than cry wolf
    if resp.status_code in (401, 403):
        return True
    path = urlparse(resp.url).path.lower()
    return any(hint in path for hint in _LOGIN_PATH_HINTS)


def check_auth_session(base, http):
    """Warn (once, to stderr) if the session cookie looks dead.

    Never raises: the scan continues as the logged-out site either way.
    Never prints the cookie value.
    """
    try:
        resp = http.get(base + "/")
    except Exception:
        return
    if _looks_logged_out(resp):
        print(
            "warning: the session cookie looks expired or wrong "
            "(the site answered like you are logged out). "
            "The scan will only see the public pages. "
            "Grab a fresh cookie from your browser and try again.",
            file=sys.stderr,
        )


def normalize_target(target, http):
    target = target.strip().rstrip("/")
    if "://" not in target:
        for scheme in ("https://", "http://"):
            r = http.get(scheme + target + "/")
            if r is not None and r.status_code < 500:
                return scheme + target
        return "http://" + target
    return target


def scan(target, http=None, on_check=None, include=None, exclude=None):
    """Run checks. Returns (base_url, findings, elapsed_s, requests_made).

    include/exclude are optional sets of check ids (--only / --skip).
    """
    http = http or PoliteClient()
    base = normalize_target(target, http)
    findings = []
    started = time.time()

    if getattr(http, "has_auth", False):
        check_auth_session(base, http)

    wanted = [c for c in CHECKS
              if (include is None or c[0] in include)
              and (exclude is None or c[0] not in exclude)]

    discovered = []
    if any(cid in INJECTION_CHECKS for cid, _l, _f in wanted):
        if on_check:
            on_check("mapping the app")
        try:
            discovered = discover(base, http)
        except Exception:
            discovered = []

    for cid, label, fn in wanted:
        if on_check:
            on_check(label)
        try:
            if cid in INJECTION_CHECKS:
                findings.extend(fn(base, http, discovered) or [])
            else:
                findings.extend(fn(base, http) or [])
        except RuntimeError:
            break  # request budget exceeded: stop gracefully
        except Exception:
            continue  # one broken check must never kill the scan
    elapsed = time.time() - started
    return base, findings, elapsed, http.count
