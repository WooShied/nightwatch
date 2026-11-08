"""MITRE ATT&CK names and tactics for the techniques the default rules use."""

TACTICS = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Command and Control",
]

# technique id -> (name, primary tactic)
TECHNIQUES = {
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
    "T1595.003": ("Wordlist Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Initial Access"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1505.003": ("Web Shell", "Persistence"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1098.007": ("Additional Local or Domain Groups", "Privilege Escalation"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion"),
    "T1027.010": ("Command Obfuscation", "Defense Evasion"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
}


def name(tid: str) -> str:
    return TECHNIQUES.get(tid, (tid, ""))[0]


def tactic(tid: str) -> str:
    return TECHNIQUES.get(tid, ("", "Other"))[1]


def url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
