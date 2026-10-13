"""Check for a security.txt file so researchers can report vulnerabilities."""

from ..findings import Finding, Inconclusive


def run(base, http):
    reached = False
    for path in ("/.well-known/security.txt", "/security.txt"):
        r = http.get(base + path)
        if r is not None:
            reached = True
        if r is not None and r.status_code == 200 and "contact" in r.text.lower():
            return []
    if not reached:
        raise Inconclusive("could not reach the site to look for security.txt")
    return [Finding(
        check="securitytxt", severity="info",
        title="No security.txt file",
        meaning="There is no standard way for a security researcher who finds "
                "a vulnerability to contact you, so reports may go public "
                "instead of reaching you first.",
        url=base + "/.well-known/security.txt",
        evidence="no file with a Contact: line found",
        fix="Publish /.well-known/security.txt with a Contact: line so "
            "security researchers can reach you. See securitytxt.org.",
    )]
