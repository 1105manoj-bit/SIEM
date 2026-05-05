"""
Log Parser
Parses SSH auth logs and web access logs into structured events.
"""

import re
import os

# SSH patterns
SSH_PATTERNS = {
    "failed_password": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[.*\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    "accepted_password": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[.*\]:\s+Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    "invalid_user": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[.*\]:\s+Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
}

# Malicious activity patterns
MALICIOUS_PATTERNS = {
    "backdoor_download":    re.compile(r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*(?:wget|curl)\s+http.*(?:backdoor|malware|shell|payload)", re.IGNORECASE),
    "privilege_escalation": re.compile(r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*COMMAND=/bin/bash", re.IGNORECASE),
    "data_exfiltration":    re.compile(r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*scp.*/etc/passwd|scp.*/var/log", re.IGNORECASE),
    "log_tampering":        re.compile(r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*rm.*-rf.*/var/log|rm.*/var/log", re.IGNORECASE),
    "persistence":          re.compile(r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*cron.*CMD.*(?:backdoor|tmp)", re.IGNORECASE),
    "suspicious_service":   re.compile(r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Started suspicious", re.IGNORECASE),
}

# Web patterns
WEB_PATTERN = re.compile(
    r'(?P<ip>[\d.:a-fA-F]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>\S+) HTTP/[\d.]+" (?P<status>\d+) (?P<size>\d+)'
)

SUSPICIOUS_PATHS = [".env", "wp-admin", "phpmyadmin", ".git", "passwd",
                    "backup", "shell", "cmd", "eval", "UNION", "SELECT", "DROP", "--"]


def detect_log_type(filepath):
    """Auto detect if log is SSH or web format."""
    ssh_score = web_score = 0
    try:
        with open(filepath, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if i > 30: break
                if "sshd" in line or "Failed password" in line or "Accepted password" in line:
                    ssh_score += 1
                if re.search(r'"(GET|POST|PUT|DELETE) /', line):
                    web_score += 1
    except:
        pass
    if ssh_score >= web_score:
        return "ssh"
    return "web"


def parse_file(filepath):
    """Parse any log file — auto detects format."""
    if not os.path.exists(filepath):
        return [], "unknown"

    log_type = detect_log_type(filepath)
    events = []

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if log_type == "ssh":
                # Try SSH patterns
                for event_type, pattern in SSH_PATTERNS.items():
                    m = pattern.search(line)
                    if m:
                        d = m.groupdict()
                        events.append({
                            "source": "ssh",
                            "event_type": event_type,
                            "timestamp": d.get("timestamp", ""),
                            "ip": d.get("ip", ""),
                            "user": d.get("user", ""),
                            "raw": line
                        })
                        break
                else:
                    # Try malicious patterns
                    for event_type, pattern in MALICIOUS_PATTERNS.items():
                        m = pattern.search(line)
                        if m:
                            d = m.groupdict()
                            events.append({
                                "source": "ssh",
                                "event_type": event_type,
                                "timestamp": d.get("timestamp", ""),
                                "ip": "",
                                "user": "",
                                "raw": line
                            })
                            break
            else:
                m = WEB_PATTERN.search(line)
                if m:
                    d = m.groupdict()
                    path = d.get("path", "")
                    status = int(d.get("status", 200))
                    suspicious = any(s.lower() in path.lower() for s in SUSPICIOUS_PATHS)
                    event_type = "suspicious_request" if suspicious else ("server_error" if status >= 500 else "normal_request")
                    events.append({
                        "source": "web",
                        "event_type": event_type,
                        "timestamp": d.get("timestamp", ""),
                        "ip": d.get("ip", ""),
                        "user": "",
                        "method": d.get("method", ""),
                        "path": path,
                        "status": status,
                        "raw": line
                    })

    return events, log_type


def parse_line(line, log_type="ssh"):
    """Parse a single line for live monitoring."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if log_type == "ssh":
        for event_type, pattern in {**SSH_PATTERNS, **MALICIOUS_PATTERNS}.items():
            m = pattern.search(line)
            if m:
                d = m.groupdict()
                return {
                    "source": "ssh",
                    "event_type": event_type,
                    "timestamp": d.get("timestamp", ""),
                    "ip": d.get("ip", ""),
                    "user": d.get("user", ""),
                    "raw": line
                }
    else:
        m = WEB_PATTERN.search(line)
        if m:
            d = m.groupdict()
            path = d.get("path", "")
            suspicious = any(s.lower() in path.lower() for s in SUSPICIOUS_PATHS)
            return {
                "source": "web",
                "event_type": "suspicious_request" if suspicious else "normal_request",
                "timestamp": d.get("timestamp", ""),
                "ip": d.get("ip", ""),
                "user": "",
                "path": path,
                "raw": line
            }
    return None