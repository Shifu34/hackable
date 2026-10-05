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

14 checks. Before probing, hackable crawls your app like a visitor would,
collecting real links and forms, so injection tests hit your actual inputs
instead of guessed parameter names.

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

Every finding comes with **what this means** (one sentence, no jargon) and **how to fix it** (one sentence, actionable). You get a 0-100 score and an A-F grade.

## Output

Terminal report, machine-readable JSON (`--json`), SARIF 2.1.0 for GitHub code
scanning (`--sarif`), and a self-contained shareable HTML report card
(`--html report.html`).

```bash
hackable https://myapp.com --html report.html
hackable https://myapp.com --fail-under 70   # exit 1 in CI if score < 70
hackable https://myapp.com --only sqli,xss   # run a subset of checks
```

## GitHub Action

Drop it into your workflow and every push gets scanned:

```yaml
- uses: Shifu34/hackable@v1
  with:
    target: https://myapp.com
    fail-under: 70
```

Results upload to the Security tab automatically.

## Safety

hackable only sends harmless probes: no destructive payloads, no data deletion, no login attempts with real credentials, ~50-150 requests with delays and an identifying User-Agent. It will ask for confirmation before scanning unless you pass `--yes`.

**Only scan apps you own or have explicit permission to test.** Scanning without permission may be illegal.

## Roadmap

- Authenticated scans (test behind a login)
- JavaScript-rendered app support
- Scheduled scans with diff alerts

## License

MIT
