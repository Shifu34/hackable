"""Scan orchestration."""

import sys
import time

from .checks import CHECKS
from .crawler import discover
from .findings import CheckResult, Inconclusive, _looks_logged_out
from .polite import PoliteClient

# checks that probe the crawler's discovered inputs
INJECTION_CHECKS = ("sqli", "xss", "open_redirect")


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
    """Run checks. Returns (base_url, findings, check_results, elapsed_s,
    requests_made).

    check_results is a list of CheckResult, one per check that was selected
    to run, with status "pass", "fail" or "not_tested".
    include/exclude are optional sets of check ids (--only / --skip).
    """
    http = http or PoliteClient()
    base = normalize_target(target, http)
    findings = []
    check_results = []
    started = time.time()

    if getattr(http, "has_auth", False):
        check_auth_session(base, http)

    wanted = [c for c in CHECKS
              if (include is None or c[0] in include)
              and (exclude is None or c[0] not in exclude)]

    discovered = []
    crawl_ok = True
    if any(cid in INJECTION_CHECKS for cid, _l, _f in wanted):
        if on_check:
            on_check("mapping the app")
        try:
            discovered = discover(base, http)
        except Exception:
            discovered = []
            crawl_ok = False

    for cid, label, fn in wanted:
        if on_check:
            on_check(label)
        try:
            if cid in INJECTION_CHECKS and not crawl_ok and not discovered:
                raise Inconclusive(
                    "could not crawl the site to find forms and inputs to test"
                )
            if cid in INJECTION_CHECKS:
                new_findings = fn(base, http, discovered) or []
            else:
                new_findings = fn(base, http) or []
            findings.extend(new_findings)
            status = "fail" if new_findings else "pass"
            check_results.append(CheckResult(
                check=cid, label=label, status=status,
                finding_count=len(new_findings),
            ))
        except Inconclusive as e:
            # the check could not meaningfully run: report it as not tested
            # instead of letting it look like a clean pass
            check_results.append(CheckResult(
                check=cid, label=label, status="not_tested", reason=e.reason,
            ))
        except RuntimeError:
            # request budget exceeded: stop gracefully, mark the rest untested
            remaining = wanted[wanted.index((cid, label, fn)) + 1:]
            for rcid, rlabel, _rfn in remaining:
                check_results.append(CheckResult(
                    check=rcid, label=rlabel, status="not_tested",
                    reason="request budget exceeded before this check ran",
                ))
            break
        except Exception as e:
            # one broken check must never kill the scan, but it must not
            # look like a pass either
            check_results.append(CheckResult(
                check=cid, label=label, status="not_tested",
                reason="check errored: %s" % e,
            ))
            continue
    elapsed = time.time() - started
    return base, findings, check_results, elapsed, http.count
