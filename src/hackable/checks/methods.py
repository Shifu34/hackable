"""Dangerous HTTP methods (TRACE/TRACK)."""

from ..findings import Finding


def run(base, http):
    r = http.options(base + "/")
    if r is None:
        return []
    allow = r.headers.get("allow", "")
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    bad = sorted(m for m in ("TRACE", "TRACK") if m in methods)
    if not bad:
        return []
    return [
        Finding(
            check="methods",
            severity="medium",
            title="Risky HTTP methods enabled (%s)" % ", ".join(bad),
            meaning="The TRACE method lets an attacker bounce requests off your server "
            "to steal cookies and auth headers (cross-site tracing), bypassing the "
            "protections browsers put on JavaScript.",
            fix="Disable TRACE/TRACK in your web server config. You almost certainly "
            "do not use them.",
            evidence="Allow: " + allow,
            url=base + "/",
        )
    ]
