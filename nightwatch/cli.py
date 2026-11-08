"""Command-line interface.

  nightwatch scan PATH [PATH ...]   triage log files or folders
  nightwatch rules                  list detection rules
  nightwatch explain RULE_ID        show what a rule looks for and how to respond
"""
import argparse
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, attack
from .engine import RuleError, load_rules, run
from .models import SEVERITIES, severity_rank
from .parsers import parse_file
from .report import to_html, to_json, to_text, use_color

SKIP_SUFFIXES = {".gz", ".zip", ".exe", ".dll", ".png", ".jpg", ".pdf"}


def collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() not in SKIP_SUFFIXES)
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(p)
    return files


def cmd_scan(args) -> int:
    try:
        rules = load_rules([Path(r) for r in args.rules], include_default=not args.no_default_rules)
        files = collect(args.paths)
    except (RuleError, FileNotFoundError) as exc:
        print(f"nightwatch: {exc}", file=sys.stderr)
        return 2

    events, file_stats = [], []
    for f in files:
        fmt, evts = parse_file(f, args.year)
        events += evts
        file_stats.append({"name": f.name, "format": fmt, "events": len(evts)})
    stats = {
        "files": file_stats,
        "events": len(events),
        "start": min((e.ts for e in events), default=None),
        "end": max((e.ts for e in events), default=None),
    }

    findings = [f for f in run(rules, events) if severity_rank(f.rule.severity) >= severity_rank(args.min_severity)]

    if args.format == "json":
        out = to_json(findings, stats)
    elif args.format == "html":
        out = to_html(findings, stats)
    else:
        color = not args.output and use_color(sys.stdout)
        out = to_text(findings, stats, color=color, verbose=args.verbose)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {args.output} ({len(findings)} findings)", file=sys.stderr)
    else:
        sys.stdout.write(out)

    # Non-zero exit when something at or above --fail-on was found, for scripts and CI.
    if args.fail_on and any(severity_rank(f.rule.severity) >= severity_rank(args.fail_on) for f in findings):
        return 1
    return 0


def cmd_rules(args) -> int:
    rules = load_rules([Path(r) for r in args.rules])
    for r in rules:
        print(f"{r.id}  {r.severity:<8}  {r.type:<9}  {r.title}  [{', '.join(r.attack)}]")
    return 0


def indent_paragraph(text):
    """Wrap long text at 88 characters and indent it two spaces."""
    return textwrap.fill(text, 88, initial_indent="  ", subsequent_indent="  ")


def cmd_explain(args) -> int:
    rules = {r.id.upper(): r for r in load_rules([Path(r) for r in args.rules])}
    r = rules.get(args.rule_id.upper())
    if not r:
        print(f"No rule {args.rule_id}. Run `nightwatch rules` to list them.", file=sys.stderr)
        return 2
    print(f"{r.id}  {r.title}\nseverity {r.severity} · type {r.type}")
    if r.group_by:
        line = f"grouped by {r.group_by}"
        if r.type != "match":
            line += f" · {r.threshold} in {r.window}s"
        print(line)
    print("\nWhat it looks for:\n" + indent_paragraph(r.description))
    print("\nResponse:\n" + indent_paragraph(r.response))
    print("\nMITRE ATT&CK:")
    for t in r.attack:
        print(f"  {t}  {attack.name(t)} ({attack.tactic(t)})  {attack.url(t)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nightwatch", description="Triage logs for attacker behavior and map it to MITRE ATT&CK.")
    p.add_argument("--version", action="version", version=f"nightwatch {__version__}")
    p.add_argument("--rules", action="append", default=[], metavar="FILE", help="extra TOML rule file (repeatable)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan log files or folders")
    s.add_argument("paths", nargs="+")
    s.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    s.add_argument("-o", "--output", help="write the report to a file")
    s.add_argument("-v", "--verbose", action="store_true", help="show evidence and response steps in text output")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at or above this severity")
    s.add_argument("--year", type=int, default=datetime.now(timezone.utc).year,
                   help="year for syslog timestamps, which don't include one (default: this year)")
    s.add_argument("--no-default-rules", action="store_true", help="only use rules from --rules files")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("rules", help="list detection rules")
    s.set_defaults(func=cmd_rules)

    s = sub.add_parser("explain", help="explain one rule")
    s.add_argument("rule_id")
    s.set_defaults(func=cmd_explain)
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RuleError as exc:
        print(f"nightwatch: {exc}", file=sys.stderr)
        return 2
