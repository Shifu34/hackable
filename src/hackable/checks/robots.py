"""Interesting paths leaked via robots.txt."""

from ..findings import Finding


def run(base, http):
    r = http.get(base + "/robots.txt")
    if r is None or r.status_code != 200:
        return []
    lines = [
        line.split(":", 1)[1].strip()
        for line in r.text.splitlines()
        if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
    ]
    if not lines:
        return []
    shown = ", ".join(lines[:5])
    return [
        Finding(
            check="robots",
            severity="low",
            title="robots.txt lists hidden paths",
            meaning="Your robots.txt names %d path(s) you asked search engines to ignore "
            "(%s). Attackers read this file too: it is a map of where you keep the "
            "interesting things." % (len(lines), shown),
            fix="Assume every path in robots.txt is public. If something must stay "
            "hidden, protect it with a login instead of relying on robots.txt.",
            evidence=shown,
            url=base + "/robots.txt",
        )
    ]
