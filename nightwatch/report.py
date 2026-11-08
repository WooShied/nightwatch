"""Reports: turn findings into terminal text, JSON, or an HTML page.

Security note: log lines are written by whoever sent the traffic, so they can
contain things like <script> tags. Every value that goes into the HTML report is
passed through safe(), which turns < into &lt; and so on, so the browser shows
it as text instead of running it. The page also includes a Content-Security-
Policy that blocks all scripts, as a second layer of protection.
"""
import html
import json
import os
from datetime import datetime, timezone

from . import __version__, attack
from .models import SEVERITIES

# Worst first, for display.
SEVERITIES_WORST_FIRST = list(reversed(SEVERITIES))


# =============================================================================
# Small helpers
# =============================================================================

def format_time(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def plural(count, word="event"):
    """plural(1) -> "1 event", plural(3) -> "3 events"."""
    if count == 1:
        return f"{count} {word}"
    return f"{count} {word}s"


def count_by_severity(findings):
    """Returns {"critical": 2, "high": 5, ...} including zeros."""
    counts = {severity: 0 for severity in SEVERITIES_WORST_FIRST}
    for finding in findings:
        counts[finding.rule.severity] += 1
    return counts


def finding_to_dict(finding):
    """Plain dictionary version of a finding, used for JSON output."""
    techniques = []
    for technique_id in finding.rule.attack:
        techniques.append({
            "id": technique_id,
            "name": attack.name(technique_id),
            "tactic": attack.tactic(technique_id),
        })

    evidence = []
    for event in finding.evidence:
        evidence.append({"origin": event.origin, "raw": event.raw})

    return {
        "rule": finding.rule.id,
        "title": finding.rule.title,
        "severity": finding.rule.severity,
        "attack": techniques,
        "group": finding.group,
        "count": finding.count,
        "first_seen": format_time(finding.first_seen),
        "last_seen": format_time(finding.last_seen),
        "detail": finding.detail,
        "entities": finding.entities,
        "description": finding.rule.description,
        "response": finding.rule.response,
        "evidence": evidence,
    }


def summarize(findings, stats):
    """Everything about a scan as plain data (dicts and lists)."""
    span = None
    if stats.get("start"):
        span = [format_time(stats["start"]), format_time(stats["end"])]

    return {
        "tool": "nightwatch",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": stats["files"],
        "events": stats["events"],
        "span": span,
        "counts": count_by_severity(findings),
        "findings": [finding_to_dict(finding) for finding in findings],
    }


# =============================================================================
# JSON
# =============================================================================

def to_json(findings, stats):
    return json.dumps(summarize(findings, stats), indent=2, ensure_ascii=False)


# =============================================================================
# Terminal text
# =============================================================================

# ANSI color codes. Terminals read these as "switch color" instead of printing them.
SEVERITY_COLORS = {
    "critical": "\033[1;97;41m",  # bold white on red
    "high": "\033[91m",           # red
    "medium": "\033[93m",         # yellow
    "low": "\033[96m",            # cyan
    "info": "\033[37m",           # gray
}
DIM = "\033[2m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RESET = "\033[0m"


def use_color(stream):
    """Only use color when printing to a real terminal, and respect NO_COLOR."""
    if os.environ.get("NO_COLOR"):
        return False
    if not stream.isatty():
        return False  # output is going to a file or another program
    if os.name == "nt":
        # A well-known trick: running any shell command turns on color
        # support in the classic Windows console.
        os.system("")
    return True


def to_text(findings, stats, color=False, verbose=False):
    def paint(code, text):
        if color:
            return f"{code}{text}{RESET}"
        return text

    lines = []
    lines.append(paint(GREEN + BOLD, "nightwatch") + paint(DIM, f" v{__version__}"))

    # Which files were read.
    for file in stats["files"]:
        file_format = file["format"] or "unrecognized"
        lines.append(paint(DIM, f"  {file['name']:<28} {file_format:<9} {file['events']:>6} events"))
    if stats.get("start"):
        lines.append(paint(DIM, f"  {stats['events']} events from {format_time(stats['start'])} to {format_time(stats['end'])}"))
    lines.append("")

    if not findings:
        lines.append(paint(GREEN, "No findings. Quiet night."))
        return "\n".join(lines)

    # Summary line, e.g. "4 critical  10 high  4 medium  1 low"
    summary = []
    for severity, count in count_by_severity(findings).items():
        if count:
            summary.append(paint(SEVERITY_COLORS[severity], f"{count} {severity}"))
    lines.append("  ".join(summary))
    lines.append("")

    indent = " " * 11
    for finding in findings:
        rule = finding.rule
        label = paint(SEVERITY_COLORS[rule.severity], f" {rule.severity.upper():<8} ")
        lines.append(f"{label} {paint(BOLD, rule.title)}  {paint(DIM, rule.id)}")

        who = ""
        if finding.group:
            who = f"{rule.group_by}={finding.group}  "
        when = f"{format_time(finding.first_seen)} → {format_time(finding.last_seen)}"
        lines.append(paint(DIM, f"{indent}{who}{plural(finding.count)}  {when}"))

        if finding.detail:
            lines.append(paint(DIM, indent + finding.detail))

        techniques = ", ".join(f"{t} {attack.name(t)}" for t in rule.attack)
        lines.append(paint(DIM, f"{indent}ATT&CK {techniques}"))

        if verbose:
            for event in finding.evidence[:3]:
                lines.append(paint(DIM, f"{indent}│ {event.origin}  {event.raw[:140]}"))
            lines.append(f"{indent}→ {rule.response}")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# =============================================================================
# HTML report
# =============================================================================

def safe(value):
    """Escape text for HTML so it's displayed, never executed."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


CSS = """
:root {
  --bg: #0a0a0a; --bg2: #121212; --fg: #f5f5f5; --fg2: #c7c7c7; --mute: #8f8f8f;
  --line: rgba(255,255,255,.08); --green: #5eea8f;
  --critical: #ff5f56; --high: #ff8a5c; --medium: #f5c04a; --low: #7cc4ff; --info: #8f8f8f;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.55 system-ui, "Segoe UI", sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 40px 20px 80px; }
a { color: var(--green); }
pre, .mono { font-family: ui-monospace, Consolas, Menlo, monospace; }
h1 { font-size: 34px; margin: 10px 0 4px; }
h1 span { color: var(--green); }
h2 { font-size: 18px; margin: 40px 0 14px; }
.small { font: 12px ui-monospace, Consolas, monospace; text-transform: uppercase; letter-spacing: .06em; color: var(--mute); }
.sub { color: var(--fg2); margin: 0; }

/* each severity sets --c, which the elements below use for their color */
.critical { --c: var(--critical); } .high { --c: var(--high); } .medium { --c: var(--medium); }
.low { --c: var(--low); } .info { --c: var(--info); }

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 24px; }
.card { background: var(--bg2); border: 1px solid var(--line); border-radius: 14px; padding: 16px; }
.card b { display: block; font-size: 28px; color: var(--c, var(--fg)); }
.card small { color: var(--mute); }

.stages { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
.stage { border: 1px solid var(--line); border-radius: 12px; padding: 12px; background: var(--bg2); min-height: 92px; }
.stage.seen { border-color: var(--green); }
.stage p { margin: 0 0 6px; font-size: 13px; font-weight: 600; }
.stage.seen p { color: var(--green); }
.stage span { display: block; font: 11px/1.4 ui-monospace, Consolas, monospace; color: var(--fg2); }

.timeline { list-style: none; margin: 0; padding: 0; border-left: 2px solid var(--line); }
.timeline li { position: relative; padding: 0 0 14px 20px; }
.timeline li::before { content: ""; position: absolute; left: -6px; top: 6px; width: 10px; height: 10px; border-radius: 50%; background: var(--c); }
.timeline time { font: 12px ui-monospace, Consolas, monospace; color: var(--mute); }

.finding { background: var(--bg2); border: 1px solid var(--line); border-left: 4px solid var(--c); border-radius: 12px; padding: 18px 20px; margin-bottom: 14px; }
.finding h3 { display: inline; margin: 0 8px; font-size: 17px; }
.badge { font: 11px ui-monospace, Consolas, monospace; text-transform: uppercase; padding: 4px 8px; border-radius: 999px; border: 1px solid var(--c); color: var(--c); }
.meta { color: var(--mute); font-size: 13px; margin: 6px 0 10px; }
.finding p { margin: 8px 0; color: var(--fg2); }
.tags a { display: inline-block; margin: 0 6px 6px 0; padding: 3px 9px; border: 1px solid var(--line); border-radius: 999px; font-size: 12px; text-decoration: none; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; margin: 10px 0; font-size: 13px; }
dt { color: var(--mute); } dd { margin: 0; }
pre { background: var(--bg); border: 1px solid var(--line); border-radius: 10px; padding: 12px; font-size: 12px; color: var(--fg2); white-space: pre-wrap; word-break: break-all; }
.response { border-left: 2px solid var(--green); padding-left: 12px; }
footer { margin-top: 50px; color: var(--mute); font-size: 12px; }
"""


def html_count_cards(findings):
    parts = [f'<div class="card"><b>{len(findings)}</b><small>{"finding" if len(findings) == 1 else "findings"}</small></div>']
    for severity, count in count_by_severity(findings).items():
        parts.append(f'<div class="card {severity}"><b>{count}</b><small>{severity}</small></div>')
    return '<div class="cards">' + "".join(parts) + "</div>"


def html_attack_stages(findings):
    """One box per ATT&CK tactic, lit up green if any finding mapped to it."""
    seen = {}  # tactic -> set of technique ids
    for finding in findings:
        for technique_id in finding.rule.attack:
            tactic = attack.tactic(technique_id)
            seen.setdefault(tactic, set()).add(technique_id)

    boxes = []
    for tactic in attack.TACTICS:
        if tactic in seen:
            items = "".join(f"<span>{safe(t)} {safe(attack.name(t))}</span>" for t in sorted(seen[tactic]))
            boxes.append(f'<div class="stage seen"><p>{safe(tactic)}</p>{items}</div>')
        else:
            boxes.append(f'<div class="stage"><p>{safe(tactic)}</p><span>none seen</span></div>')
    return '<div class="stages">' + "".join(boxes) + "</div>"


def html_timeline(findings):
    """Findings in the order they started, linking down to their cards."""
    numbered = list(enumerate(findings))
    numbered.sort(key=lambda pair: pair[1].first_seen)

    items = []
    for number, finding in numbered:
        who = f" · {safe(finding.group)}" if finding.group else ""
        items.append(
            f'<li class="{safe(finding.rule.severity)}"><time>{safe(format_time(finding.first_seen))}</time><br>'
            f'<a href="#finding-{number}">{safe(finding.rule.title)}</a>{who}</li>'
        )
    if not items:
        items.append("<li>Nothing to show.</li>")
    return '<ol class="timeline">' + "".join(items) + "</ol>"


def html_finding_card(number, finding):
    rule = finding.rule

    tags = ""
    for technique_id in rule.attack:
        tags += f'<a href="{safe(attack.url(technique_id))}" rel="noreferrer">{safe(technique_id)} · {safe(attack.name(technique_id))}</a>'

    entities = ""
    for kind, values in finding.entities.items():
        entities += f'<dt>{safe(kind)}</dt><dd class="mono">{safe(", ".join(values))}</dd>'

    evidence_lines = "\n".join(f"{event.origin}  {event.raw}" for event in finding.evidence)

    meta = f"{plural(finding.count)} · {format_time(finding.first_seen)} → {format_time(finding.last_seen)}"
    if finding.detail:
        meta += f" · {finding.detail}"

    return f"""
<article class="finding {safe(rule.severity)}" id="finding-{number}">
  <span class="badge">{safe(rule.severity)}</span><h3>{safe(rule.title)}</h3><span class="small">{safe(rule.id)}</span>
  <div class="meta mono">{safe(meta)}</div>
  <div class="tags">{tags}</div>
  <p>{safe(rule.description)}</p>
  <dl>{entities}</dl>
  <pre>{safe(evidence_lines)}</pre>
  <p class="response"><strong>Response:</strong> {safe(rule.response)}</p>
</article>"""


def to_html(findings, stats):
    data = summarize(findings, stats)

    sources = []
    for file in data["files"]:
        sources.append(f"{file['name']} ({file['format'] or 'unrecognized'}, {file['events']})")

    if data["span"]:
        span = f"{data['span'][0]} → {data['span'][1]}"
    else:
        span = "no events"

    cards = "".join(html_finding_card(number, finding) for number, finding in enumerate(findings))
    if not cards:
        cards = '<p class="sub">No findings. Quiet night.</p>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- Blocks all scripts and outside requests. Only the inline styles below are allowed. -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>nightwatch report</title>
<style>{CSS}</style>
</head>
<body>
<main>
  <p class="small">nightwatch v{safe(__version__)} · generated {safe(data['generated'])}</p>
  <h1>Incident <span>triage report</span></h1>
  <p class="sub mono">{safe(data['events'])} events · {safe(span)}</p>
  <p class="sub" style="color: var(--mute); font-size: 13px; margin-top: 6px">Sources: {safe(", ".join(sources))}</p>
  {html_count_cards(findings)}

  <h2>Attack stages seen (MITRE ATT&amp;CK)</h2>
  {html_attack_stages(findings)}

  <h2>Timeline</h2>
  {html_timeline(findings)}

  <h2>Findings</h2>
  {cards}

  <footer>Generated by nightwatch. Log content is shown as text and never executed. Technique details: attack.mitre.org.</footer>
</main>
</body>
</html>
"""
