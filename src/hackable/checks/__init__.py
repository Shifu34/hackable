"""Security checks. Each exposes run(base, http) -> list[Finding]."""

from . import cors, debug, disclosure, exposed_files, headers, methods, open_redirect, rate_limit, robots, sqli, tls, xss

CHECKS = [
    ("headers", "security headers", headers.run),
    ("robots", "robots.txt", robots.run),
    ("disclosure", "version disclosure", disclosure.run),
    ("exposed_files", "exposed sensitive files", exposed_files.run),
    ("debug", "debug mode / stack traces", debug.run),
    ("cors", "CORS misconfiguration", cors.run),
    ("methods", "dangerous HTTP methods", methods.run),
    ("sqli", "SQL injection", sqli.run),
    ("xss", "cross-site scripting", xss.run),
    ("open_redirect", "open redirects", open_redirect.run),
    ("rate_limit", "login rate limiting", rate_limit.run),
    ("tls", "TLS / HTTPS", tls.run),
]
