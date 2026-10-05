"""Scan orchestration."""

import time

from .checks import CHECKS
from .crawler import discover
from .polite import PoliteClient

# checks that probe the crawler's discovered inputs
INJECTION_CHECKS = ("sqli", "xss", "open_redirect")


def normalize_target(target, http):
    target = target.strip().rstrip("/")
    if "://" not in target:
        for scheme in ("https://", "http://"):
            r = http.get(scheme + target + "/")
            if r is not None and r.status_code < 500:
                return scheme + target
        return "http://" + target
    return target


def scan(target, http=None, on_check=None):
    """Run checks. Returns (base_url, findings, elapsed_s, requests_made)."""
    http = http or PoliteClient()
    base = normalize_target(target, http)
    findings = []
    started = time.time()

    wanted = CHECKS

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
