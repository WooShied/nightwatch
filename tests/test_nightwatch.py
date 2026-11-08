import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nightwatch.cli import main
from nightwatch.engine import RuleError, default_rules, parse_rules, run
from nightwatch.models import Event
from nightwatch.parsers import detect_format, parse_auth, parse_web, parse_windows
from nightwatch.report import to_html, to_json

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
T0 = datetime(2026, 11, 6, 2, 0, tzinfo=timezone.utc)


def ev(seconds, action, ip="198.51.100.9", user="bob", **fields):
    return Event(ts=T0 + timedelta(seconds=seconds), source="auth", action=action, user=user, src_ip=ip, fields=fields)


class ParserTests(unittest.TestCase):
    def test_auth(self):
        lines = [
            "Nov  6 02:00:01 web01 sshd[1]: Failed password for invalid user admin from 198.51.100.23 port 5 ssh2",
            "Nov  6 02:00:09 web01 sshd[1]: Accepted password for deploy from 198.51.100.23 port 6 ssh2",
            "Nov  6 02:01:00 web01 sudo[2]:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
            "Nov  6 02:02:00 web01 CRON[3]: something unrelated",
        ]
        evts = parse_auth(lines, "auth.log", 2026)
        self.assertEqual([e.action for e in evts], ["login_failed", "login_success", "sudo"])
        self.assertEqual(evts[0].user, "admin")
        self.assertEqual(evts[2].get("command"), "/bin/bash")
        self.assertEqual(evts[1].origin, "auth.log:2")

    def test_web_decodes_payloads(self):
        line = ('203.0.113.45 - - [06/Nov/2026:01:10:00 +0000] "GET /p?id=1%2520UNION%2520SELECT HTTP/1.1" '
                '200 10 "-" "sqlmap/1.8"')
        (e,) = parse_web([line], "access.log")
        self.assertEqual(e.get("status"), 200)
        self.assertIn("UNION SELECT", e.get("path_decoded"))  # double-encoded payload is decoded

    def test_windows_json_and_dotnet_dates(self):
        recs = [
            {"TimeCreated": "/Date(1793930400000)/", "Id": 4625, "Computer": "ws", "Data": {"TargetUserName": "admin", "IpAddress": "203.0.113.8"}},
            {"TimeCreated": "2026-11-06T04:12:20Z", "Id": 4732, "Data": {"SubjectUserName": "x", "TargetUserName": "Administrators", "MemberName": "svc"}},
            {"TimeCreated": "2026-11-06T04:12:20Z", "Id": 9999},
        ]
        evts = parse_windows(json.dumps(recs), "sec.json")
        self.assertEqual([e.action for e in evts], ["login_failed", "group_member_added"])
        self.assertEqual(evts[1].get("group"), "Administrators")

    def test_detect_format(self):
        self.assertEqual(detect_format("[{}]"), "windows")
        self.assertEqual(detect_format("Nov  6 02:00:01 web01 sshd[1]: hi"), "auth")
        self.assertIsNone(detect_format("just some text"))


class EngineTests(unittest.TestCase):
    def rule(self, body):
        return parse_rules('[[rule]]\nid="T-1"\ntitle="t"\nseverity="high"\n' + body)

    def test_threshold_respects_window(self):
        rules = self.rule('type="threshold"\nwhere={action="login_failed"}\ngroup_by="src_ip"\nthreshold=3\nwindow=60')
        spread = [ev(i * 120, "login_failed") for i in range(5)]  # never 3 inside 60s
        self.assertEqual(run(rules, spread), [])
        burst = [ev(i * 10, "login_failed") for i in range(3)]
        (f,) = run(rules, burst)
        self.assertEqual((f.group, f.count), ("198.51.100.9", 3))

    def test_distinct_spray(self):
        rules = self.rule('type="distinct"\nwhere={action="login_failed"}\ngroup_by="src_ip"\ndistinct="user"\nthreshold=3\nwindow=600')
        same_user = [ev(i, "login_failed", user="bob") for i in range(10)]
        self.assertEqual(run(rules, same_user), [])
        spray = [ev(i, "login_failed", user=u) for i, u in enumerate(["a", "b", "c"])]
        self.assertEqual(len(run(rules, spray)), 1)

    def test_sequence_needs_failures_first(self):
        rules = self.rule('type="sequence"\nwhere={action="login_failed"}\nthen={action="login_success"}\ngroup_by="src_ip"\nthreshold=3\nwindow=600')
        ok = [ev(0, "login_success")] + [ev(i + 1, "login_failed") for i in range(3)]
        self.assertEqual(run(rules, ok), [])  # success came before the failures
        bad = [ev(i, "login_failed") for i in range(3)] + [ev(10, "login_success")]
        (f,) = run(rules, bad)
        self.assertEqual(f.count, 4)

    def test_bad_rules_are_rejected(self):
        with self.assertRaises(RuleError):
            self.rule('type="nope"')
        with self.assertRaises(RuleError):
            self.rule('type="match"\nwhere_regex={path="("}')

    def test_default_rules_load_and_are_mapped(self):
        rules = default_rules()
        self.assertGreaterEqual(len(rules), 16)
        self.assertTrue(all(r.attack and r.response for r in rules))


class SampleStoryTests(unittest.TestCase):
    """The sample logs contain one known attack story; every stage should be caught."""

    @classmethod
    def setUpClass(cls):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["scan", str(SAMPLES), "--year", "2026", "-f", "json"])
        cls.report = json.loads(out.getvalue())
        cls.ids = {f["rule"] for f in cls.report["findings"]}

    def test_every_stage_detected(self):
        expected = {f"NW-{n:03d}" for n in range(1, 17)}
        self.assertEqual(self.ids, expected)

    def test_normal_activity_is_quiet(self):
        flagged = {ip for f in self.report["findings"] for ip in f["entities"].get("src_ip", [])}
        self.assertFalse(any(ip.startswith("192.0.2.") and ip != "192.0.2.77" for ip in flagged))


class ReportSafetyTests(unittest.TestCase):
    def test_html_escapes_attacker_input(self):
        line = ('203.0.113.45 - - [06/Nov/2026:01:18:00 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" '
                '200 1 "-" "<img src=x onerror=alert(2)>"')
        evts = parse_web([line], "access.log")
        evts[0].raw = evts[0].raw.replace("%3Cscript%3E", "<script>")
        findings = run(default_rules(), evts)
        page = to_html(findings, {"files": [], "events": 1, "start": evts[0].ts, "end": evts[0].ts})
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)  # CSP blocks scripts even if escaping failed

    def test_json_round_trips(self):
        data = json.loads(to_json([], {"files": [], "events": 0}))
        self.assertEqual(data["findings"], [])


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_fail_on_sets_exit_code(self):
        code, *_ = self.run_cli("scan", str(SAMPLES), "--year", "2026", "--fail-on", "critical")
        self.assertEqual(code, 1)
        with tempfile.TemporaryDirectory() as d:
            Path(d, "quiet.log").write_text("Nov  6 02:00:01 web01 sshd[1]: Accepted publickey for aadil from 192.0.2.10 port 1 ssh2\n")
            code, out, _ = self.run_cli("scan", d, "--fail-on", "low")
            self.assertEqual(code, 0)
            self.assertIn("Quiet night", out)

    def test_missing_path(self):
        code, _, err = self.run_cli("scan", "does/not/exist")
        self.assertEqual(code, 2)
        self.assertIn("does", err)

    def test_explain(self):
        code, out, _ = self.run_cli("explain", "nw-014")
        self.assertEqual(code, 0)
        self.assertIn("T1070.001", out)


if __name__ == "__main__":
    unittest.main()
