# hackable

**Hack yourself before they do.**

One-command website security check for people who have never run a security tool. Point it at your app, and in about ten seconds it tells you, in plain English, how a hacker would break in and exactly how to stop them.

```
$ pip install hackable
$ hackable https://myapp.com
```

## The problem

Millions of apps are being built with AI right now by people who have never heard of OWASP. The apps work. They also leak database keys, take SQL injection, and let anyone log in as anyone. The existing scanners (ZAP, Nuclei, Burp) are expert tools with expert UX. They might as well be in another language.

hackable is the Let's Encrypt of pentesting: free, one command, plain English.

## What it checks

| Check | What it finds |
|---|---|
| SQL injection | Database error messages and crashes from a single quote (safe, GET-only probes) |
| Exposed files | Public `/.env`, `/.git/`, config backups, with content verification (no false alarms from SPA fallbacks) |
| XSS | Your input reflected unescaped into the page |
| Open redirects | Your site redirecting visitors to attacker domains |
| CORS | Arbitrary origins trusted with credentials |
| Debug mode | Stack traces leaking from error pages |
| Login rate limiting | 10 rapid wrong passwords, checking for pushback |
| Security headers | HSTS, CSP, X-Frame-Options, and friends |
| TLS | Missing HTTPS, expired certs, ancient TLS versions |
| Version disclosure | Server headers announcing exact versions |
| HTTP methods | Risky methods like TRACE |
| robots.txt | Hidden paths handed to attackers on a plate |

Every finding comes with **what this means** (one sentence, no jargon) and **how to fix it** (one sentence, actionable). You get a 0-100 score and an A-F grade.

## Output

Terminal report, machine-readable JSON (`--json`), and a self-contained shareable HTML report card (`--html report.html`).

```bash
hackable https://myapp.com --html report.html
hackable https://myapp.com --fail-under 70   # exit 1 in CI if score < 70
```

## Safety

hackable only sends harmless probes: no destructive payloads, no data deletion, no login attempts with real credentials, ~50-150 requests with delays and an identifying User-Agent. It will ask for confirmation before scanning unless you pass `--yes`.

**Only scan apps you own or have explicit permission to test.** Scanning without permission may be illegal.

## Roadmap

- Boolean-based SQLi differential checks
- Authenticated scans (test behind a login)
- JavaScript-rendered app support
- GitHub Action

## License

MIT
