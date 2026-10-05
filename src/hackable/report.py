"""Reports: terminal, JSON, and self-contained HTML."""

import html
import json
from datetime import datetime, timezone

from .findings import SEVERITIES, score_findings

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

SEV_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[34m",
    "info": "\033[90m",
}

SEV_ICON = {
    "critical": "\u2716",  # ✖
    "high": "\u2716",
    "medium": "!",
    "low": "i",
    "info": "\u2139",
}

VERDICTS = {
    "A": "Solid. Scan again after every deploy to stay here.",
    "B": "Good shape. Fix the mediums when you get an afternoon.",
    "C": "Shaky. The highs above are worth fixing this week.",
    "D": "Risky. An attacker would enjoy this site.",
    "F": "A beginner hacker could break in within minutes. Fix the criticals today.",
}

SEV_CSS = {
    "critical": "#ff5555",
    "high": "#ff8c42",
    "medium": "#f1c40f",
    "low": "#5aa9ff",
    "info": "#8a8f98",
}


def _c(text, code, use_color):
    return "%s%s%s" % (code, text, RESET) if use_color else text


def render_terminal(findings, base, elapsed, req_count, use_color=True):
    score, grade = score_findings(findings)
    L = []
    c = lambda t, code: _c(t, code, use_color)  # noqa: E731

    L.append("")
    L.append(c("hackable v0.1.0", BOLD) + c("  -  hack yourself before they do.", DIM))
    L.append("")
    L.append("Target: %s   (%d requests in %.1fs)" % (base, req_count, elapsed))
    L.append("")

    grouped = {s: [f for f in findings if f.severity == s] for s in SEVERITIES}
    if not findings:
        L.append(c("No issues found. Either your site is solid, or it hid well.", BOLD))
    for sev in SEVERITIES:
        items = grouped[sev]
        if not items:
            continue
        L.append(c("%s (%d)" % (sev.upper(), len(items)), SEV_COLOR[sev] + BOLD))
        for f in items:
            L.append(
                "  %s %s"
                % (c(SEV_ICON[sev], SEV_COLOR[sev]), c(f.title, BOLD))
            )
            L.append("    What this means: %s" % f.meaning)
            L.append("    Fix: %s" % f.fix)
            if f.url:
                L.append(c("    Found at: %s" % f.url, DIM))
            if f.evidence:
                ev = f.evidence.replace("\n", " ")
                L.append(c("    Evidence: %s%s" % (ev[:140], "..." if len(ev) > 140 else ""), DIM))
        L.append("")

    L.append(c("-" * 60, DIM))
    L.append(
        "SCORE  %s   GRADE  %s"
        % (c("%d/100" % score, BOLD), c(grade, SEV_COLOR["critical"] if grade in "DF" else BOLD))
    )
    L.append(VERDICTS[grade])
    L.append("")
    return "\n".join(L)


def render_json(findings, base, elapsed, req_count):
    score, grade = score_findings(findings)
    return json.dumps(
        {
            "tool": "hackable 0.1.0",
            "target": base,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "requests": req_count,
            "elapsed_s": round(elapsed, 1),
            "score": score,
            "grade": grade,
            "findings": [
                {
                    "check": f.check,
                    "severity": f.severity,
                    "title": f.title,
                    "meaning": f.meaning,
                    "fix": f.fix,
                    "evidence": f.evidence,
                    "url": f.url,
                }
                for f in findings
            ],
        },
        indent=2,
    )


def render_html(findings, base, elapsed, req_count):
    score, grade = score_findings(findings)
    esc = html.escape
    cards = []
    for f in findings:
        color = SEV_CSS[f.severity]
        cards.append(
            """
        <div class="card">
          <div class="card-head" style="border-left-color: {color}">
            <span class="sev" style="background: {color}">{sev}</span>
            <span class="title">{title}</span>
          </div>
          <p><b>What this means:</b> {meaning}</p>
          <p><b>How to fix it:</b> {fix}</p>
          {url}
          {evidence}
        </div>""".format(
                color=color,
                sev=f.severity.upper(),
                title=esc(f.title),
                meaning=esc(f.meaning),
                fix=esc(f.fix),
                url='<p class="meta">Found at: <code>%s</code></p>' % esc(f.url) if f.url else "",
                evidence='<p class="meta">Evidence: <code>%s</code></p>' % esc(f.evidence[:200])
                if f.evidence
                else "",
            )
        )
    if not cards:
        cards.append('<div class="card"><p><b>No issues found.</b></p></div>')
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>hackable report: {base}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0d1117;
  color: #e6edf3; max-width: 860px; margin: 0 auto; padding: 32px 20px; }}
h1 {{ font-size: 22px; }} .dim {{ color: #8a8f98; }}
.scorebox {{ display: flex; align-items: center; gap: 24px; background: #161b22;
  border: 1px solid #30363d; border-radius: 12px; padding: 20px 24px; margin: 20px 0; }}
.score {{ font-size: 56px; font-weight: 800; }}
.grade {{ font-size: 40px; font-weight: 800; width: 72px; height: 72px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center; border: 3px solid; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px;
  padding: 16px 20px; margin: 14px 0; }}
.card-head {{ border-left: 5px solid; padding-left: 12px; margin-bottom: 8px;
  display: flex; align-items: center; gap: 10px; }}
.sev {{ color: #0d1117; font-weight: 700; font-size: 12px; padding: 3px 8px; border-radius: 6px; }}
.title {{ font-weight: 700; font-size: 16px; }}
.meta {{ color: #8a8f98; font-size: 13px; }} code {{ font-size: 12.5px; }}
.footer {{ margin-top: 28px; color: #8a8f98; font-size: 13px; }}
</style></head><body>
<h1>hackable report</h1>
<p class="dim">Target: {base} &middot; {nreq} requests in {elapsed:.1f}s &middot; {date}</p>
<div class="scorebox">
  <div class="score">{score}<span style="font-size:22px;color:#8a8f98">/100</span></div>
  <div class="grade" style="border-color:{gcolor};color:{gcolor}">{grade}</div>
  <div><b>{verdict}</b></div>
</div>
{cards}
<p class="footer">Generated by hackable 0.1.0 &mdash; hack yourself before they do.
Only scan apps you own or have permission to test.</p>
</body></html>""".format(
        base=esc(base),
        nreq=req_count,
        elapsed=elapsed,
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        score=score,
        grade=grade,
        gcolor="#ff5555" if grade in "DF" else "#f1c40f" if grade == "C" else "#3fb950",
        verdict=esc(VERDICTS[grade]),
        cards="\n".join(cards),
    )
