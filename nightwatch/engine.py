"""Detection engine: loads rules and runs them over events.

A rule describes suspicious behavior. There are four kinds:

    match      any single matching event is suspicious
               (example: the Security log was cleared)

    threshold  too many matching events from one source in a short time
               (example: 8 failed logins from one IP within 5 minutes)

    distinct   too many *different* values from one source in a short time
               (example: one IP trying 5 different usernames = password spray)

    sequence   several "first" events, then a "then" event, from the same source
               (example: 5 failed logins, then a successful one)

Rules live in rules/default.toml. You can add your own with --rules.
"""
import re
import tomllib
from collections import deque
from datetime import timedelta
from importlib import resources

from .models import SEVERITIES, Finding, Rule

MAX_EVIDENCE = 8  # how many example log lines to keep per finding
RULE_TYPES = ["match", "threshold", "distinct", "sequence"]


class RuleError(ValueError):
    """A rule file has a mistake in it."""


# =============================================================================
# Loading rules
# =============================================================================

def compile_patterns(patterns, rule_id):
    """Turn {"field": "regex text"} into {"field": compiled regex}."""
    compiled = {}
    for field, pattern in patterns.items():
        try:
            compiled[field] = re.compile(pattern)
        except re.error as error:
            raise RuleError(f"{rule_id}: bad regex for '{field}': {error}")
    return compiled


def check_rule(raw, file_name):
    """Make sure a rule from the TOML file has everything it needs."""
    rule_id = raw.get("id", "?")

    for required in ["id", "title", "severity", "type"]:
        if required not in raw:
            raise RuleError(f"{file_name}: rule {rule_id} is missing '{required}'")

    if raw["type"] not in RULE_TYPES:
        raise RuleError(f"{rule_id}: unknown type '{raw['type']}'")
    if raw["severity"] not in SEVERITIES:
        raise RuleError(f"{rule_id}: unknown severity '{raw['severity']}'")
    if raw["type"] == "distinct" and not raw.get("distinct"):
        raise RuleError(f"{rule_id}: distinct rules need a 'distinct' field")
    if raw["type"] == "sequence" and not (raw.get("then") or raw.get("then_regex")):
        raise RuleError(f"{rule_id}: sequence rules need a 'then' condition")


def parse_rules(text, file_name="rules"):
    """Read rules from TOML text and return a list of Rule objects."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise RuleError(f"{file_name}: {error}")

    rules = []
    for raw in data.get("rule", []):
        check_rule(raw, file_name)
        rule = Rule(
            id=raw["id"],
            title=raw["title"],
            severity=raw["severity"],
            type=raw["type"],
            description=raw.get("description", ""),
            response=raw.get("response", ""),
            attack=raw.get("attack", []),
            where=raw.get("where", {}),
            where_regex=compile_patterns(raw.get("where_regex", {}), raw["id"]),
            group_by=raw.get("group_by"),
            threshold=raw.get("threshold", 1),
            window=raw.get("window", 300),
            distinct=raw.get("distinct"),
            then=raw.get("then", {}),
            then_regex=compile_patterns(raw.get("then_regex", {}), raw["id"]),
        )
        rules.append(rule)

    check_unique_ids(rules, file_name)
    return rules


def check_unique_ids(rules, where_from):
    seen = set()
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"{where_from}: rule id {rule.id} is used more than once")
        seen.add(rule.id)


def default_rules():
    """Load the rules that ship with nightwatch (rules/default.toml)."""
    text = resources.files("nightwatch").joinpath("rules/default.toml").read_text(encoding="utf-8")
    return parse_rules(text, "default.toml")


def load_rules(extra_files, include_default=True):
    """Load the default rules plus any extra rule files."""
    rules = []
    if include_default:
        rules += default_rules()
    for path in extra_files:
        rules += parse_rules(path.read_text(encoding="utf-8"), path.name)
    check_unique_ids(rules, "rule files")
    return rules


# =============================================================================
# Does an event match a condition?
# =============================================================================

def event_matches(event, exact, patterns):
    """True if the event passes every exact check and every regex check.

    exact:    {"action": "login_failed"}   the field must equal this value
              {"action": ["a", "b"]}        ...or be one of these values
    patterns: {"command": compiled regex}   the field must contain a regex match
    """
    for field, wanted in exact.items():
        value = event.get(field)
        if isinstance(wanted, list):
            if value not in wanted:
                return False
        else:
            if value != wanted:
                return False

    for field, regex in patterns.items():
        value = event.get(field)
        if value is None:
            return False
        if not regex.search(str(value)):
            return False

    return True


# =============================================================================
# Helpers shared by the rule types
# =============================================================================

def group_key(event, rule):
    """Which bucket an event belongs to, e.g. its source IP when group_by = "src_ip"."""
    if not rule.group_by:
        return None
    value = event.get(rule.group_by)
    if value is None:
        return None
    return str(value)


def split_into_groups(events, rule):
    """Put events into buckets by group key. Returns {key: [events]}, keeping time order."""
    groups = {}
    for event in events:
        key = group_key(event, rule)
        if key not in groups:
            groups[key] = []
        groups[key].append(event)
    return groups


def pick_evidence(events):
    """Keep a handful of example events: the first few, plus the last one."""
    if len(events) <= MAX_EVIDENCE:
        return events
    return events[: MAX_EVIDENCE - 1] + [events[-1]]


def make_finding(rule, group, events, count=None, detail=""):
    if count is None:
        count = len(events)
    return Finding(
        rule=rule,
        group=group,
        count=count,
        first_seen=events[0].ts,
        last_seen=events[-1].ts,
        evidence=pick_evidence(events),
        detail=detail,
    )


def busiest_window(events, window_seconds, count_fn):
    """Slide a time window across the events and find where count_fn is highest.

    Picture a 5-minute window moving along a timeline. Each time a new event
    arrives, we add it to the window and drop any events that are now more than
    5 minutes older than it. Then we score what's left in the window.

    Returns (best_score, the events that were in the window at that moment).
    """
    window = timedelta(seconds=window_seconds)
    in_window = deque()  # a list that's fast to remove from the front
    best_score = 0
    best_events = []

    for event in events:
        in_window.append(event)

        # Drop events that are too old to be in the same window as this one.
        while event.ts - in_window[0].ts > window:
            in_window.popleft()

        score = count_fn(in_window)
        if score > best_score:
            best_score = score
            best_events = list(in_window)

    return best_score, best_events


def count_events(events):
    return len(events)


# =============================================================================
# The four rule types
# =============================================================================

def run_match_rule(rule, events):
    """Every matching event counts. Group them so 50 SQL injection lines from
    one IP become one finding, not 50."""
    findings = []
    for group, group_events in split_into_groups(events, rule).items():
        findings.append(make_finding(rule, group, group_events))
    return findings


def run_threshold_rule(rule, events):
    """Fire when one group has at least `threshold` events inside `window` seconds."""
    findings = []
    for group, group_events in split_into_groups(events, rule).items():
        most, burst = busiest_window(group_events, rule.window, count_events)
        if most >= rule.threshold:
            detail = f"{most} events within {rule.window}s"
            findings.append(make_finding(rule, group, burst, detail=detail))
    return findings


def run_distinct_rule(rule, events):
    """Fire when one group shows at least `threshold` different values of a
    field inside `window` seconds (e.g. many different usernames)."""

    def count_different_values(window_events):
        values = set()
        for event in window_events:
            values.add(event.get(rule.distinct))
        return len(values)

    findings = []
    for group, group_events in split_into_groups(events, rule).items():
        most, burst = busiest_window(group_events, rule.window, count_different_values)
        if most >= rule.threshold:
            values = sorted({str(event.get(rule.distinct)) for event in burst})
            shown = ", ".join(values[:6])
            if len(values) > 6:
                shown += " …"
            detail = f"{most} distinct {rule.distinct} values within {rule.window}s: {shown}"
            findings.append(make_finding(rule, group, burst, detail=detail))
    return findings


def run_sequence_rule(rule, events):
    """Fire when a group has at least `threshold` "first" events followed by a
    "then" event, all inside `window` seconds. Only the first hit per group is
    reported."""
    window = timedelta(seconds=rule.window)
    recent_firsts = {}  # group -> recent "first" events (e.g. failed logins)
    already_reported = set()
    findings = []

    for event in events:  # events are already in time order
        group = group_key(event, rule)
        if group in already_reported:
            continue

        if group not in recent_firsts:
            recent_firsts[group] = deque()
        firsts = recent_firsts[group]

        # Forget "first" events that are too old to count.
        while firsts and event.ts - firsts[0].ts > window:
            firsts.popleft()

        if event_matches(event, rule.where, rule.where_regex):
            firsts.append(event)  # e.g. another failed login

        elif event_matches(event, rule.then, rule.then_regex):
            if len(firsts) >= rule.threshold:  # e.g. a success after enough failures
                chain = list(firsts) + [event]
                detail = f"{len(firsts)} matching events, then success within {rule.window}s"
                findings.append(make_finding(rule, group, chain, detail=detail))
                already_reported.add(group)

    return findings


# =============================================================================
# Running everything
# =============================================================================

def run(rules, events):
    """Run every rule over the events and return findings, worst first."""
    events = sorted(events, key=lambda event: event.ts)
    findings = []

    for rule in rules:
        if rule.type == "sequence":
            # Sequence rules need to see every event, not just the matching ones,
            # because they look for two different kinds of event.
            findings += run_sequence_rule(rule, events)
            continue

        matching = [event for event in events if event_matches(event, rule.where, rule.where_regex)]
        if not matching:
            continue

        if rule.type == "match":
            findings += run_match_rule(rule, matching)
        elif rule.type == "threshold":
            findings += run_threshold_rule(rule, matching)
        elif rule.type == "distinct":
            findings += run_distinct_rule(rule, matching)

    # Sort: most severe first, then earliest first.
    findings.sort(key=lambda finding: (-SEVERITIES.index(finding.rule.severity), finding.first_seen))
    return findings
