"""Sensitive files accidentally left public."""

from ..findings import Finding


def _looks_like_env(text):
    t = text.strip()
    if "<html" in t.lower()[:500]:
        return False
    return "=" in t and any(
        k in t for k in ("KEY", "SECRET", "PASSWORD", "TOKEN", "DATABASE_URL")
    )


def _looks_like_git_head(text):
    return text.strip().startswith("ref:")


def _looks_like_git_config(text):
    return "[core]" in text and "repositoryformatversion" in text


def _looks_like_apache_status(text):
    return "Apache Status" in text


def _looks_like_wp_config(text):
    return "DB_PASSWORD" in text


def _looks_like_ds_store(raw):
    return raw[:8].startswith(b"\x00\x01Bud") or raw[:4] == b"Bud1"


TARGETS = [
    (
        "/.env",
        "critical",
        lambda text, raw: _looks_like_env(text),
        "Your /.env file is public",
        "This file usually holds database passwords, API keys and app secrets. "
        "Anyone on the internet can now read them and log in as you.",
        "Block /.env (and /.env.*) in your web server config immediately, then "
        "rotate every secret that was inside it. They are all compromised.",
    ),
    (
        "/.env.bak",
        "critical",
        lambda text, raw: _looks_like_env(text),
        "A backup of your .env file is public",
        "Same as a public /.env: every secret in it is now in attacker hands.",
        "Delete the backup file from the server and rotate every secret in it.",
    ),
    (
        "/.git/HEAD",
        "critical",
        lambda text, raw: _looks_like_git_head(text),
        "Your .git directory is public",
        "Attackers can download your entire source code, including old commits "
        "that may contain secrets you later deleted.",
        "Block /.git/ in your web server config or stop deploying the .git "
        "directory to production.",
    ),
    (
        "/.git/config",
        "high",
        lambda text, raw: _looks_like_git_config(text),
        "Your git config is public",
        "This confirms your repository internals are exposed and often leads to "
        "full source disclosure.",
        "Block /.git/ in your web server config.",
    ),
    (
        "/server-status",
        "high",
        lambda text, raw: _looks_like_apache_status(text),
        "Apache server-status page is public",
        "It shows live requests, client IPs and server internals. Useful for you, "
        "more useful for an attacker mapping your app.",
        "Restrict /server-status to localhost in your Apache config.",
    ),
    (
        "/wp-config.php.bak",
        "critical",
        lambda text, raw: _looks_like_wp_config(text),
        "A WordPress config backup is public",
        "It contains your database username and password in plain text.",
        "Delete the backup file and change the database password.",
    ),
    (
        "/.DS_Store",
        "low",
        lambda text, raw: _looks_like_ds_store(raw),
        ".DS_Store file is public",
        "A macOS metadata file. It can reveal file and folder names on your server.",
        "Stop deploying .DS_Store files; add them to .gitignore.",
    ),
]


def run(base, http):
    findings = []
    for path, severity, signature, title, meaning, fix in TARGETS:
        r = http.get(base + path)
        if r is None or r.status_code != 200:
            continue
        try:
            if signature(r.text, r.content):
                findings.append(
                    Finding(
                        check="exposed_files",
                        severity=severity,
                        title=title,
                        meaning=meaning,
                        fix=fix,
                        evidence=r.text.strip().replace("\n", " ")[:120],
                        url=base + path,
                    )
                )
        except Exception:
            continue
    return findings
