"""Reports: terminal, JSON, and self-contained HTML."""

import html
import json
from datetime import datetime, timezone

from . import __version__
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


def render_terminal(findings, base, elapsed, req_count, use_color=True, diff=None,
                   check_results=None):
    score, grade = score_findings(findings)
    L = []
    c = lambda t, code: _c(t, code, use_color)  # noqa: E731

    L.append("")
    L.append(c("hackable v" + __version__, BOLD) + c("  -  hack yourself before they do.", DIM))
    L.append("")
    L.append("Target: %s   (%d requests in %.1fs)" % (base, req_count, elapsed))
    L.append("")

    grouped = {s: [f for f in findings if f.severity == s] for s in SEVERITIES}
    n_untested = sum(1 for r in (check_results or []) if r.status == "not_tested")
    if not findings:
        if n_untested:
            L.append(c(
                "No issues found, but %d check%s could not run (see CHECK STATUS "
                "below)." % (n_untested, "s" if n_untested != 1 else ""), BOLD))
        else:
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

    if check_results:
        not_tested = [r for r in check_results if r.status == "not_tested"]
        L.append(c("CHECK STATUS", BOLD))
        for r in check_results:
            if r.status == "fail":
                mark = c("\u2716", SEV_COLOR["high"])
                detail = "%d finding%s" % (r.finding_count,
                                           "s" if r.finding_count != 1 else "")
            elif r.status == "not_tested":
                mark = c("?", "\033[33m")
                detail = c("not tested: %s" % r.reason, DIM)
            else:
                mark = c("\u2713", "\033[32m")
                detail = c("passed", DIM)
            L.append("  %s %-28s %s" % (mark, r.label, detail))
        L.append("")
        if not_tested:
            L.append(c(
                "Note: %d check%s could not run, so this report may be "
                "incomplete. A clean-looking result with untested checks is "
                "not the same as a clean site." % (
                    len(not_tested), "s" if len(not_tested) != 1 else ""),
                "\033[33m"))
            L.append("")

    L.append(c("-" * 60, DIM))
    L.append(
        "SCORE  %s   GRADE  %s"
        % (c("%d/100" % score, BOLD), c(grade, SEV_COLOR["critical"] if grade in "DF" else BOLD))
    )
    L.append(VERDICTS[grade])
    L.append("")
    if diff is not None:
        from .baseline import render_diff_text
        L.append(render_diff_text(diff))
    return "\n".join(L)


def render_json(findings, base, elapsed, req_count, diff=None, check_results=None):
    score, grade = score_findings(findings)
    payload = {
        "tool": "hackable " + __version__,
        "target": base,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "requests": req_count,
        "elapsed_s": round(elapsed, 1),
        "score": score,
        "grade": grade,
        "checks": [
            {
                "check": r.check,
                "label": r.label,
                "status": r.status,  # pass | fail | not_tested
                "reason": r.reason or None,
                "finding_count": r.finding_count,
            }
            for r in (check_results or [])
        ],
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
    }
    if diff is not None:
        payload["diff"] = {
            "new": diff["new"],
            "fixed": diff["fixed"],
            "score_before": diff.get("score_before"),
            "grade_before": diff.get("grade_before"),
            "score_after": diff.get("score_after"),
            "grade_after": diff.get("grade_after"),
        }
    return json.dumps(payload, indent=2)


SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(findings, base, elapsed, req_count):
    """SARIF 2.1.0 output, consumable by GitHub code scanning."""
    rules, seen = [], set()
    for f in findings:
        if f.check not in seen:
            seen.add(f.check)
            rules.append({
                "id": "hackable/" + f.check,
                "name": f.check.replace("_", " ").title(),
                "shortDescription": {"text": f.title},
                "helpUri": "https://github.com/Shifu34/hackable",
            })
    results = []
    for f in findings:
        results.append({
            "ruleId": "hackable/" + f.check,
            "level": SARIF_LEVELS.get(f.severity, "note"),
            "message": {"text": "%s. %s" % (f.title, f.fix or "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url or base},
                }
            }],
        })
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "hackable",
                    "version": __version__,
                    "informationUri": "https://github.com/Shifu34/hackable",
                    "rules": rules,
                }},
                "results": results,
            }],
        },
        indent=2,
    )

def render_html(findings, base, elapsed, req_count, check_results=None):
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
    check_rows = []
    if check_results:
        for r in check_results:
            if r.status == "fail":
                badge = '<span class="sev" style="background:#ff8c42">FAIL</span>'
                detail = "%d finding%s" % (r.finding_count,
                                           "s" if r.finding_count != 1 else "")
            elif r.status == "not_tested":
                badge = '<span class="sev" style="background:#f1c40f">NOT TESTED</span>'
                detail = esc(r.reason)
            else:
                badge = '<span class="sev" style="background:#3fb950">PASS</span>'
                detail = ""
            check_rows.append(
                '<tr><td>%s</td><td>%s</td><td class="meta">%s</td></tr>'
                % (badge, esc(r.label), detail)
            )
    checks_html = ""
    if check_rows:
        not_tested_n = sum(1 for r in check_results if r.status == "not_tested")
        warn = ""
        if not_tested_n:
            warn = ('<p class="warn">%d check%s could not run, so this report '
                    'may be incomplete. A clean-looking result with untested '
                    'checks is not the same as a clean site.</p>'
                    % (not_tested_n, "s" if not_tested_n != 1 else ""))
        checks_html = (
            "<h2>Check status</h2>" + warn +
            '<table class="checks"><tr><th>Status</th><th>Check</th><th>Detail</th></tr>'
            + "".join(check_rows) + "</table>"
        )
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
.checks {{ width: 100%; border-collapse: collapse; margin: 14px 0; }}
.checks th, .checks td {{ text-align: left; padding: 8px 10px;
  border-bottom: 1px solid #30363d; font-size: 14px; }}
.checks th {{ color: #8a8f98; font-weight: 600; }}
.warn {{ background: #3a2f0b; border: 1px solid #f1c40f; border-radius: 8px;
  padding: 10px 14px; font-size: 14px; }}
h2 {{ font-size: 18px; margin-top: 28px; }}
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
{checks_html}
<p class="footer">Generated by hackable " + __version__ + " &mdash; hack yourself before they do.
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
        checks_html=checks_html,
    )
