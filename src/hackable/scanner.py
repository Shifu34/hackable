"""Scan orchestration."""

import time

from .checks import CHECKS
from .polite import PoliteClient


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
    """Run all checks. Returns (base_url, findings, elapsed_s, requests_made)."""
    http = http or PoliteClient()
    base = normalize_target(target, http)
    findings = []
    started = time.time()
    for _cid, label, fn in CHECKS:
        if on_check:
            on_check(label)
        try:
            findings.extend(fn(base, http) or [])
        except RuntimeError:
            break  # request budget exceeded: stop gracefully
        except Exception:
            continue  # one broken check must never kill the scan
    elapsed = time.time() - started
    return base, findings, elapsed, http.count
