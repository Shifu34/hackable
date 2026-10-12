"""Baselines and diffs: prove that fixes actually landed.

--save-baseline FILE snapshots the findings of a scan.
--diff-from FILE compares the current scan against a saved baseline and
reports which findings are NEW and which are FIXED, plus the score delta.

Pair with cron for scheduled scans with diff alerts; pair with --fail-under
for CI gates.
"""

import json
from datetime import datetime, timezone

from . import __version__
from .findings import SEVERITIES, score_findings


def _finding_dict(f):
    return {
        "check": f.check,
        "severity": f.severity,
        "title": f.title,
        "url": f.url or "",
    }


def _key(d):
    return (d.get("check", ""), d.get("title", ""), d.get("url", ""))


def snapshot(findings, base, elapsed, req_count):
    """Build a baseline snapshot dict from a finished scan."""
    score, grade = score_findings(findings)
    return {
        "tool": "hackable " + __version__,
        "target": base,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "requests": req_count,
        "elapsed_s": round(elapsed, 1),
        "score": score,
        "grade": grade,
        "findings": [_finding_dict(f) for f in findings],
    }


def write_baseline(path, snap):
    with open(path, "w") as fh:
        json.dump(snap, fh, indent=2)


def load_baseline(path):
    with open(path) as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError("not a hackable baseline file: %s" % path)
    return data


def diff_snapshots(old, new):
    """Return {"new": [...], "fixed": [...], score/grade before/after}."""
    old_map = {_key(d): d for d in old.get("findings", [])}
    new_map = {_key(d): d for d in new.get("findings", [])}
    new_items = [new_map[k] for k in new_map if k not in old_map]
    fixed_items = [old_map[k] for k in old_map if k not in new_map]

    def sev_rank(d):
        try:
            return SEVERITIES.index(d.get("severity", "info"))
        except ValueError:
            return len(SEVERITIES)

    new_items.sort(key=sev_rank)
    fixed_items.sort(key=sev_rank)
    return {
        "new": new_items,
        "fixed": fixed_items,
        "score_before": old.get("score"),
        "grade_before": old.get("grade"),
        "score_after": new.get("score"),
        "grade_after": new.get("grade"),
    }


SEV_MARK = {
    "critical": "x",
    "high": "x",
    "medium": "!",
    "low": "i",
    "info": "i",
}


def render_diff_text(diff):
    """Plain-text diff section for the terminal report."""
    lines = []
    lines.append("")
    lines.append("BASELINE DIFF")
    new, fixed = diff["new"], diff["fixed"]
    if new:
        lines.append("  NEW since the baseline (%d):" % len(new))
        for d in new:
            lines.append("    [%s] %s %s" % (
                SEV_MARK.get(d.get("severity"), "?"),
                d.get("title"),
                ("at " + d["url"]) if d.get("url") else "",
            ))
    else:
        lines.append("  NEW since the baseline: none")
    if fixed:
        lines.append("  FIXED since the baseline (%d):" % len(fixed))
        for d in fixed:
            lines.append("    [ok] %s" % d.get("title"))
    else:
        lines.append("  FIXED since the baseline: none")
    sb, gb = diff.get("score_before"), diff.get("grade_before")
    sa, ga = diff.get("score_after"), diff.get("grade_after")
    if sb is not None and sa is not None:
        delta = sa - sb
        lines.append("  Score: %d (%s) -> %d (%s)  (%+d)" % (sb, gb, sa, ga, delta))
    lines.append("")
    return "\n".join(lines)
