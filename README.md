# hackable

**Hack yourself before they do.**

[![PyPI](https://img.shields.io/pypi/v/hackable.svg)](https://pypi.org/project/hackable/)
[![Python](https://img.shields.io/pypi/pyversions/hackable.svg)](https://pypi.org/project/hackable/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Shifu34/hackable)](https://github.com/Shifu34/hackable/releases)

One command that tells you, in plain English, how a hacker would break into your website and exactly how to stop them. Built for people who have never run a security tool.

```
$ pip install hackable
$ hackable https://your-site.com
```

![hackable scanning a deliberately vulnerable demo app](demo/demo.gif)

## What you get

```
CRITICAL (2)
  ✖ Your /.env file is public
    What this means: This file usually holds database passwords, API keys
    and app secrets. Anyone on the internet can now read them and log in as you.
    Fix: Block /.env (and /.env.*) in your web server config immediately,
    then rotate every secret that was inside it. They are all compromised.
    Found at: https://your-site.com/.env

------------------------------------------------------------
SCORE  0/100   GRADE  F
A beginner hacker could break in within minutes. Fix the criticals today.
```

Every finding ships with **what this means** (one sentence, no jargon) and **how to fix it** (one sentence, actionable). You also get a 0-100 score and an A-F grade, so you can watch the number climb as you fix things.

Every report also shows a **check status** table: each of the 14 checks is marked passed, failed, or **not tested** (with the reason). A check that could not run, for example because the page was unreachable or your `--cookie` session had expired and the site answered with a login page, is reported explicitly instead of silently looking like a clean pass. For a non-expert, "not tested" matters as much as "passed".

*Example output from the intentionally vulnerable demo app in `demo/` (`vulnapp.py`).
Its hardened twin, `vulnapp_fixed.py`, shows the same app after fixing every
finding: scan one, fix, scan the other, and watch the score climb.*

## Why this exists

Millions of apps are being vibe-coded right now by people who have never heard of OWASP. The apps work. They also leak database keys, take SQL injection, and let anyone log in as anyone else. The existing scanners (ZAP, Nuclei, Burp) are expert tools with expert UX. They might as well be in another language.

hackable is the Let's Encrypt of pentesting: free, one command, plain English.

## The 14 checks

Before probing anything, hackable crawls your app like a visitor would, collecting real links and forms. Injection tests then hit your actual inputs instead of guessed parameter names. No blind fuzzing of made-up paths.

| Check | What it finds |
|---|---|
| SQL injection | Error-based probes plus boolean differential checks (safe, GET-only) |
| Exposed files | Public `/.env`, `/.git/`, config backups, with content verification (no false alarms from SPA fallbacks) |
| XSS | Your input reflected unescaped into the page |
| Open redirects | Your site redirecting visitors to attacker domains |
| CORS | Arbitrary origins trusted with credentials |
| Debug mode | Stack traces leaking from error pages |
| Login rate limiting | 10 rapid wrong passwords, checking for pushback |
| Security headers | HSTS, CSP, X-Frame-Options, and friends |
| Cookie flags | Session cookies missing Secure, HttpOnly, or SameSite |
| TLS | Missing HTTPS, expired certs, ancient TLS versions |
| Version disclosure | Server headers announcing exact versions |
| HTTP methods | Risky methods like TRACE |
| robots.txt | Hidden paths handed to attackers on a plate |
| security.txt | No standard contact for researchers to report issues |

## Install

```bash
pip install hackable
```

Requires Python 3.9+. Also on [PyPI](https://pypi.org/project/hackable/).

## Usage

```bash
hackable https://your-site.com                 # full scan
hackable https://your-site.com --only sqli,xss  # run a subset of checks
hackable https://your-site.com --skip tls       # skip checks you don't need
hackable https://your-site.com --html report.html   # shareable report card
hackable https://your-site.com --json results.json  # machine-readable output
hackable https://your-site.com --sarif results.sarif # GitHub code scanning
hackable https://your-site.com --fail-under 70  # exit 1 in CI if score < 70
hackable https://your-site.com --cookie "sessionid=abc123"  # scan behind a login
hackable https://your-site.com --diff-from baseline.json    # show NEW/FIXED findings
```

## Scanning behind a login

Most real apps hide their interesting pages behind a login. hackable can scan
as you, using a session cookie you hand it:

```bash
hackable https://your-site.com --cookie "sessionid=abc123; auth_token=xyz"
```

Grab the cookie from your browser's devtools (Application or Storage tab,
then Cookies). The crawler and every probe then run as your logged-in
session, so pages and forms behind the login get crawled and tested too.

A few rules that keep this safe:

- **hackable never logs in for you.** There is no username/password flag and
  never will be. You authenticate in your own browser and lend hackable the
  session. If the cookie looks expired, it warns you and scans the public
  site instead.
- **The cookie value never appears in any output.** Not in the terminal, not
  in `--json`, `--sarif`, or `--html` reports. Reports stay clean of secrets.
- **Keep it out of your shell history.** Prefer reading it from a file:
  `hackable https://your-site.com --cookie "$(cat ~/.config/hackable/cookie)"`.
  You can also set the `HACKABLE_COOKIE` environment variable instead of the
  flag, which is handy in CI.
- Need a bearer token or another header instead? `--header "Authorization:
  Bearer TOKEN"` sends an extra header on every request (repeatable, also
  never printed).

## GitHub Action

Scan on every push. Findings land in your repo's Security tab, no new dashboard to learn:

```yaml
- uses: Shifu34/hackable@v1
  with:
    target: https://your-site.com
    fail-under: 70
```

## Safety

hackable only sends harmless probes: no destructive payloads, no data deletion, no login attempts with real credentials. It never logs in as you: for pages behind a login you hand it your own session cookie with `--cookie`, and the value never appears in any output. About 50-150 requests with delays and an identifying User-Agent. It asks for confirmation before scanning unless you pass `--yes`.

**Only scan apps you own or have explicit permission to test.** Scanning without permission may be illegal. hackable is a first line of defense, not a replacement for a professional penetration test.

## Roadmap

- JavaScript-rendered app support
- Built-in scheduling (for now: pair cron with `--save-baseline` /
  `--diff-from` for scheduled scans with diff alerts)

## License

MIT
