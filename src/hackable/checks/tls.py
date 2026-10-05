"""TLS / HTTPS posture."""

import datetime
import socket
import ssl

from ..findings import Finding


def _cert_info(host, port):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            version = ssock.version()
    return cert, version


def run(base, http):
    if not base.startswith("https://"):
        return [
            Finding(
                check="tls",
                severity="medium",
                title="Site does not use HTTPS",
                meaning="Traffic between your visitors and your server travels in plain "
                "text. Anyone on the same network (coffee shop Wi-Fi, compromised "
                "router) can read passwords and cookies.",
                fix="Put the site behind HTTPS with a free certificate (e.g. Let's "
                "Encrypt via your host or certbot), then redirect all HTTP to HTTPS.",
                url=base + "/",
            )
        ]
    host = base.split("://", 1)[1].split("/", 1)[0].split(":")[0]
    try:
        cert, version = _cert_info(host, 443)
    except Exception:
        return [
            Finding(
                check="tls",
                severity="info",
                title="Could not verify TLS certificate",
                meaning="The TLS handshake did not complete from here, so the "
                "certificate could not be checked. This may be a network issue.",
                fix="Check the certificate manually and ensure it is valid.",
                url=base + "/",
            )
        ]
    findings = []
    try:
        not_after = cert.get("notAfter")
        exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days = (exp - datetime.datetime.utcnow()).days
        if days < 0:
            findings.append(
                Finding(
                    check="tls", severity="critical",
                    title="TLS certificate has expired",
                    meaning="Browsers show visitors a full-page security warning, and "
                    "the encryption cannot be trusted.",
                    fix="Renew the certificate immediately and automate renewal.",
                    evidence="expired %d days ago" % abs(days), url=base + "/",
                )
            )
        elif days < 30:
            findings.append(
                Finding(
                    check="tls", severity="medium",
                    title="TLS certificate expires in %d days" % days,
                    meaning="When it lapses, visitors get scary browser warnings and "
                    "may not come back.",
                    fix="Renew soon, and automate renewal so it never lapses.",
                    evidence="expires %s" % not_after, url=base + "/",
                )
            )
    except Exception:
        pass
    if version and version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append(
            Finding(
                check="tls", severity="high",
                title="Outdated TLS version negotiated (%s)" % version,
                meaning="Old TLS versions have known attacks that let eavesdroppers "
                "decrypt traffic.",
                fix="Disable everything below TLS 1.2 on your server.",
                evidence="negotiated %s" % version, url=base + "/",
            )
        )
    return findings
