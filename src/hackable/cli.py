"""CLI: hackable <target>"""

import argparse
import sys

from . import __version__
from .findings import score_findings
from .polite import PoliteClient
from .checks import CHECKS
from .report import render_html, render_json, render_sarif, render_terminal
from .scanner import scan

CONSENT = """\
hackable will send ~100 harmless test requests to {target}.
It never tries to break anything, delete data, or log in as anyone.

Only scan apps you own or have explicit permission to test.
Scanning without permission may be illegal.
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="hackable",
        description="Hack yourself before they do. One-command website security "
        "check in plain English.",
    )
    p.add_argument("target", help="URL of your app, e.g. https://myapp.com")
    p.add_argument("--yes", "-y", action="store_true",
                   help="skip the permission confirmation")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p.add_argument("--sarif", metavar="FILE",
                   help="write SARIF 2.1.0 output to FILE (GitHub code scanning)")
    p.add_argument("--html", metavar="FILE",
                   help="also write a self-contained HTML report to FILE")
    p.add_argument("--only", metavar="CHECKS",
                   help="run only these checks, comma-separated "
                   "(e.g. sqli,xss). choices: " + ",".join(c[0] for c in CHECKS))
    p.add_argument("--skip", metavar="CHECKS",
                   help="skip these checks, comma-separated")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    p.add_argument("--fail-under", type=int, metavar="SCORE",
                   help="exit 1 if the score is below SCORE (for CI)")
    p.add_argument("--max-requests", type=int, default=150)
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--delay", type=float, default=0.15,
                   help="seconds between requests (be nice)")
    p.add_argument("--version", action="version", version="hackable " + __version__)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not args.yes and sys.stdin.isatty():
        print(CONSENT.format(target=args.target))
        try:
            answer = input("Continue? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return 130
        if answer not in ("y", "yes"):
            print("Aborted. Only ever scan with permission.")
            return 130
    elif not args.yes:
        print("Not a terminal: pass --yes to confirm you have permission to scan.",
              file=sys.stderr)
        return 2

    http = PoliteClient(delay=args.delay, timeout=args.timeout,
                        max_requests=args.max_requests)

    def split(s):
        return {c.strip() for c in s.split(",") if c.strip()} if s else None

    include, exclude = split(args.only), split(args.skip)
    known = {c[0] for c in CHECKS}
    for cid in (include or set()) | (exclude or set()):
        if cid not in known:
            print("Unknown check: %s (choices: %s)" % (cid, ",".join(sorted(known))),
                  file=sys.stderr)
            return 2

    def on_check(label):
        if not args.json:
            print("  checking %-28s" % label, flush=True)

    base, findings, elapsed, req_count = scan(
        args.target, http, on_check=on_check, include=include, exclude=exclude)

    use_color = (
        args.color == "always"
        or (args.color == "auto" and sys.stdout.isatty())
    )
    if args.json:
        print(render_json(findings, base, elapsed, req_count))
    else:
        print(render_terminal(findings, base, elapsed, req_count, use_color=use_color))

    if args.sarif:
        with open(args.sarif, "w") as fh:
            fh.write(render_sarif(findings, base, elapsed, req_count))
        print("SARIF report written to %s" % args.sarif)

    if args.html:
        with open(args.html, "w") as fh:
            fh.write(render_html(findings, base, elapsed, req_count))
        print("HTML report written to %s" % args.html)

    score, _grade = score_findings(findings)
    if args.fail_under is not None and score < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
