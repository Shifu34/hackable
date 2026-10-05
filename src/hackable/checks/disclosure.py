"""Software version disclosure in response headers."""

import re

from ..findings import Finding

VERSION_RE = re.compile(r"\d+\.\d+")

INTERESTING = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


def run(base, http):
    r = http.get(base + "/")
    if r is None:
        return []
    leaked = []
    for name in INTERESTING:
        value = r.headers.get(name)
        if value and VERSION_RE.search(value):
            leaked.append("%s: %s" % (name, value.strip()))
    if not leaked:
        return []
    return [
        Finding(
            check="disclosure",
            severity="low",
            title="Server software versions are public",
            meaning="Your server announces exactly what it runs (%s). Attackers search "
            "for old versions with known holes, so this tells them where to aim."
            % "; ".join(leaked),
            fix="Hide or genericize the Server and X-Powered-By headers in your web "
            "server config. More importantly, keep the software itself updated.",
            evidence="; ".join(leaked),
            url=base + "/",
        )
    ]
