"""Parsers: turn raw log files into Event objects.

There is one parser per log type:
    parse_auth     Linux auth.log (SSH logins and sudo)
    parse_web      Apache / Nginx access logs
    parse_windows  Windows Security events exported to JSON

Each parser reads lines, uses a regular expression to pull out the parts it
cares about (time, user, IP address...), and builds an Event. Lines it doesn't
recognize are skipped.

parse_file() at the bottom looks at a file's contents, works out which parser
to use, and runs it.
"""
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from .models import Event


# =============================================================================
# Linux auth.log
# =============================================================================
#
# A line looks like this:
#   Nov  6 02:14:07 web01 sshd[35835]: Accepted password for deploy from 198.51.100.23 port 44312 ssh2
#   └──── time ───┘ host  program       └──────────────────── message ────────────────────┘

SYSLOG_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) "
    r"(?P<host>\S+) (?P<program>[\w\-/.]+)(\[\d+\])?: (?P<message>.*)$"
)

# Patterns for the SSH and sudo messages we care about.
SSH_FAILED = re.compile(r"Failed (password|publickey) for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SSH_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SSH_INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SUDO_COMMAND = re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)$")


def parse_auth(lines, file_name, year):
    """Turn auth.log lines into Events.

    Syslog timestamps don't include a year ("Nov  6 02:14:07"), so the caller
    passes one in.
    """
    events = []

    for line_number, line in enumerate(lines, start=1):
        parts = SYSLOG_LINE.match(line)
        if parts is None:
            continue  # not a syslog line

        # Build a full timestamp from "2026 Nov 6 02:14:07".
        time_text = f"{year} {parts['month']} {parts['day']} {parts['time']}"
        try:
            timestamp = datetime.strptime(time_text, "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        timestamp = timestamp.replace(tzinfo=timezone.utc)

        program = parts["program"]
        message = parts["message"]

        # These are the same for every event that comes from this line.
        common = {
            "ts": timestamp,
            "source": "auth",
            "host": parts["host"],
            "raw": line,
            "origin": f"{file_name}:{line_number}",
        }

        if program == "sshd":
            failed = SSH_FAILED.search(message)
            accepted = SSH_ACCEPTED.search(message)
            invalid = SSH_INVALID_USER.search(message)

            if failed:
                events.append(Event(action="login_failed", user=failed["user"], src_ip=failed["ip"],
                                    fields={"service": "ssh"}, **common))
            elif accepted:
                events.append(Event(action="login_success", user=accepted["user"], src_ip=accepted["ip"],
                                    fields={"service": "ssh", "method": accepted["method"]}, **common))
            elif invalid:
                events.append(Event(action="invalid_user", user=invalid["user"], src_ip=invalid["ip"],
                                    fields={"service": "ssh"}, **common))

        elif program == "sudo":
            sudo = SUDO_COMMAND.match(message)
            if sudo:
                events.append(Event(action="sudo", user=sudo["user"],
                                    fields={"target_user": sudo["target"], "command": sudo["command"].strip()},
                                    **common))

    return events


# =============================================================================
# Web server access log ("combined" format, used by Apache and Nginx)
# =============================================================================
#
# A line looks like this:
#   203.0.113.45 - - [06/Nov/2026:01:33:00 +0000] "GET /uploads/a.php?cmd=id HTTP/1.1" 200 82 "-" "Mozilla/5.0"
#   └── ip ────┘     └──────── time ──────────┘  └───── request ─────────────────────┘ status   └ user agent ┘

ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)( [^"]*)?" '
    r'(?P<status>\d{3}) \S+'
    r'( "[^"]*" "(?P<agent>[^"]*)")?'
)


def decode_url(path):
    """Undo URL encoding, e.g. %3Cscript%3E becomes <script>.

    Attackers sometimes encode a payload twice to sneak past filters, so we
    decode twice. Rules match against the decoded text.
    """
    once = unquote_plus(path)
    twice = unquote_plus(once)
    return twice


def parse_web(lines, file_name):
    """Turn access log lines into Events."""
    events = []

    for line_number, line in enumerate(lines, start=1):
        parts = ACCESS_LINE.match(line)
        if parts is None:
            continue

        try:
            timestamp = datetime.strptime(parts["time"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        timestamp = timestamp.astimezone(timezone.utc)

        user = parts["user"]
        if user == "-":
            user = None

        event = Event(
            ts=timestamp,
            source="web",
            action="http_request",
            user=user,
            src_ip=parts["ip"],
            fields={
                "method": parts["method"],
                "path": parts["path"],
                "path_decoded": decode_url(parts["path"]),
                "status": int(parts["status"]),
                "user_agent": parts["agent"] or "",
            },
            raw=line,
            origin=f"{file_name}:{line_number}",
        )
        events.append(event)

    return events


# =============================================================================
# Windows Security events (JSON)
# =============================================================================
#
# Each record looks like this (see the README for the export command):
#   {"TimeCreated": "2026-11-06T04:05:02Z", "Id": 4624, "Computer": "WS-07",
#    "Data": {"TargetUserName": "helpdesk", "IpAddress": "203.0.113.80", "LogonType": "10"}}

# Windows event ID -> our action name. Other event IDs are ignored.
WINDOWS_EVENT_ACTIONS = {
    4624: "login_success",
    4625: "login_failed",
    4672: "special_privileges",
    4688: "process",
    4720: "user_created",
    4732: "group_member_added",
    1102: "log_cleared",
}

# Windows PowerShell 5.1 sometimes writes dates as "/Date(1793930400000)/" (milliseconds since 1970).
DOTNET_DATE = re.compile(r"/Date\((\d+)\)/")


def parse_windows_time(value):
    """Read a Windows timestamp in either ISO or /Date(...)/ form. Returns None if unreadable."""
    if not isinstance(value, str):
        return None

    dotnet = DOTNET_DATE.search(value)
    if dotnet:
        milliseconds = int(dotnet[1])
        return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)

    try:
        # Python's fromisoformat doesn't accept a trailing "Z", so swap it for +00:00.
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def clean_value(value):
    """Windows uses "-" or a loopback address to mean "no value"."""
    if value in (None, "", "-", "::1", "127.0.0.1"):
        return None
    return value


def parse_windows(text, file_name):
    """Turn exported Windows Security JSON into Events."""
    text = text.strip()

    # Accept either one JSON array, or one JSON object per line.
    if text.startswith("["):
        records = json.loads(text)
    else:
        records = []
        for line in text.splitlines():
            if line.strip():
                records.append(json.loads(line))

    if isinstance(records, dict):  # a single event
        records = [records]

    events = []
    for record_number, record in enumerate(records, start=1):
        event_id = int(record.get("Id") or record.get("EventID") or 0)
        action = WINDOWS_EVENT_ACTIONS.get(event_id)
        timestamp = parse_windows_time(record.get("TimeCreated"))
        if action is None or timestamp is None:
            continue

        data = record.get("Data") or {}
        computer = record.get("Computer") or record.get("MachineName")
        fields = {"event_id": event_id}

        # Different event IDs keep the interesting values in different places.
        if event_id in (4624, 4625):  # logon succeeded / failed
            user = data.get("TargetUserName")
            fields["logon_type"] = str(data.get("LogonType", ""))
        elif event_id == 4688:  # process started
            user = data.get("SubjectUserName")
            fields["process"] = data.get("NewProcessName", "")
            fields["command"] = data.get("CommandLine", "")
        elif event_id == 4720:  # account created
            user = data.get("SubjectUserName")  # who created it
            fields["new_account"] = data.get("TargetUserName", "")
        elif event_id == 4732:  # member added to a group
            user = data.get("SubjectUserName")  # who added them
            fields["group"] = data.get("TargetUserName", "")
            fields["member"] = data.get("MemberName", "")
        else:
            user = data.get("TargetUserName") or data.get("SubjectUserName")

        # A short, readable one-line version for the report's evidence section.
        details = " ".join(f"{key}={value}" for key, value in data.items())
        readable = f"EventID={event_id} {timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')} {computer or ''} {details}"

        events.append(Event(
            ts=timestamp,
            source="windows",
            action=action,
            user=clean_value(user),
            src_ip=clean_value(data.get("IpAddress")),
            host=computer,
            fields=fields,
            raw=readable[:600],
            origin=f"{file_name}:#{record_number}",
        ))

    return events


# =============================================================================
# Picking the right parser
# =============================================================================

def detect_format(sample):
    """Guess the log type from the first part of a file. Returns "auth", "web", "windows", or None."""
    if sample.lstrip().startswith(("[", "{")):
        return "windows"

    for line in sample.splitlines()[:20]:
        if ACCESS_LINE.match(line):
            return "web"
        if SYSLOG_LINE.match(line):
            return "auth"

    return None


def read_text(path):
    """Read a file as text.

    PowerShell 5.1 saves files as UTF-16 unless told otherwise, so check for
    the UTF-16 marker bytes before decoding.
    """
    data = path.read_bytes()
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def parse_file(path, year):
    """Parse one file. Returns (format_name, events)."""
    text = read_text(path)
    log_format = detect_format(text[:8000])

    if log_format == "auth":
        return log_format, parse_auth(text.splitlines(), path.name, year)

    if log_format == "web":
        return log_format, parse_web(text.splitlines(), path.name)

    if log_format == "windows":
        try:
            return log_format, parse_windows(text, path.name)
        except (ValueError, TypeError):  # broken JSON
            return None, []

    return None, []
