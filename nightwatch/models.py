"""Core data types: one normalized Event shape for every log source, and Findings."""
from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_rank(name: str) -> int:
    return SEVERITIES.index(name)


@dataclass
class Event:
    """A single log line, normalized so detections work across sources.

    `action` is the shared vocabulary that makes cross-source rules possible:
    an SSH "Failed password" and a Windows 4625 are both `login_failed`.
    """

    ts: datetime
    source: str  # auth | web | windows
    action: str  # login_failed, login_success, sudo, http_request, process, ...
    user: str | None = None
    src_ip: str | None = None
    host: str | None = None
    fields: dict = field(default_factory=dict)
    raw: str = ""
    origin: str = ""  # file:line, so every finding points back to evidence

    def get(self, name: str):
        if name in ("ts", "source", "action", "user", "src_ip", "host"):
            return getattr(self, name)
        return self.fields.get(name)


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str  # match | threshold | distinct | sequence
    description: str = ""
    response: str = ""
    attack: list[str] = field(default_factory=list)
    where: dict = field(default_factory=dict)
    where_regex: dict = field(default_factory=dict)
    group_by: str | None = None
    threshold: int = 1
    window: int = 300  # seconds
    distinct: str | None = None
    then: dict = field(default_factory=dict)
    then_regex: dict = field(default_factory=dict)


@dataclass
class Finding:
    rule: Rule
    group: str | None
    count: int
    first_seen: datetime
    last_seen: datetime
    evidence: list[Event]
    detail: str = ""

    @property
    def entities(self):
        """The IPs, users and hosts involved, e.g. {"src_ip": ["203.0.113.45"], "user": ["deploy"]}."""
        found = {"src_ip": set(), "user": set(), "host": set()}
        for event in self.evidence:
            for kind in found:
                value = getattr(event, kind)
                if value:
                    found[kind].add(value)

        result = {}
        for kind, values in found.items():
            if values:
                result[kind] = sorted(values)
        return result
