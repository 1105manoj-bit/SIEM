"""
Detection Engine
Applies security rules to parsed events and returns alerts.
"""

from collections import defaultdict
from datetime import datetime


MITRE = {
    "ssh_brute_force":          ("T1110",  "Brute Force",                    "Credential Access"),
    "brute_force_success":      ("T1110",  "Brute Force Success",            "Credential Access"),
    "user_enumeration":         ("T1078",  "Valid Accounts",                 "Defense Evasion"),
    "web_scanning":             ("T1595",  "Active Scanning",                "Reconnaissance"),
    "sql_injection":            ("T1190",  "Exploit Public-Facing App",      "Initial Access"),
    "backdoor_download":        ("T1105",  "Ingress Tool Transfer",          "Command & Control"),
    "privilege_escalation":     ("T1548",  "Abuse Elevation Control",        "Privilege Escalation"),
    "data_exfiltration":        ("T1041",  "Exfiltration Over C2",           "Exfiltration"),
    "log_tampering":            ("T1070",  "Indicator Removal",              "Defense Evasion"),
    "persistence":              ("T1053",  "Scheduled Task/Job",             "Persistence"),
    "suspicious_service":       ("T1543",  "Create/Modify System Process",   "Persistence"),
}


def make_alert(alert_type, severity, ip, description, evidence, rule_key):
    tid, tname, tactic = MITRE.get(rule_key, ("T0000", "Unknown", "Unknown"))
    return {
        "alert_type":   alert_type,
        "severity":     severity,
        "severity_level": {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 1),
        "source_ip":    clean_ip(ip),
        "description":  description,
        "evidence_count": evidence,
        "mitre_id":     tid,
        "mitre_name":   tname,
        "mitre_tactic": tactic,
        "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status":       "OPEN"
    }


def clean_ip(ip):
    """Normalize IP addresses — convert IPv6 localhost to readable format."""
    if not ip: return "N/A"
    ip = ip.strip()
    if ip in ("::1", "0:0:0:0:0:0:0:1"): return "127.0.0.1 (localhost)"
    if ip == "::": return "localhost"
    return ip


def detect(events):
    """Run all detection rules. Returns list of alerts."""
    alerts = []
    ip_failures  = defaultdict(list)
    ip_success   = defaultdict(list)
    ip_web_scan  = defaultdict(list)
    ip_sqli      = defaultdict(list)

    for e in events:
        et = e.get("event_type", "")
        ip = e.get("ip", "")

        if et == "failed_password":
            ip_failures[ip].append(e)
        elif et == "accepted_password":
            ip_success[ip].append(e)
        elif et == "suspicious_request":
            ip_web_scan[ip].append(e)
            path = e.get("path", "")
            if any(k in path.upper() for k in ["UNION", "SELECT", "DROP", "' OR", "--", "1=1"]):
                ip_sqli[ip].append(e)

        # Direct malicious event detections
        elif et == "backdoor_download":
            alerts.append(make_alert("Backdoor Download Detected", "CRITICAL", ip,
                f"Backdoor download command detected: {e['raw'][:120]}", 1, "backdoor_download"))
        elif et == "privilege_escalation":
            alerts.append(make_alert("Privilege Escalation Detected", "CRITICAL", ip,
                f"Privilege escalation via sudo bash detected: {e['raw'][:120]}", 1, "privilege_escalation"))
        elif et == "data_exfiltration":
            alerts.append(make_alert("Data Exfiltration Detected", "CRITICAL", ip,
                f"Sensitive data being copied to attacker: {e['raw'][:120]}", 1, "data_exfiltration"))
        elif et == "log_tampering":
            alerts.append(make_alert("Log Tampering Detected", "CRITICAL", ip,
                f"Attacker attempting to delete logs to cover tracks: {e['raw'][:120]}", 1, "log_tampering"))
        elif et == "persistence":
            alerts.append(make_alert("Persistence Mechanism Detected", "HIGH", ip,
                f"Malicious cron job detected: {e['raw'][:120]}", 1, "persistence"))
        elif et == "suspicious_service":
            alerts.append(make_alert("Suspicious Service Started", "HIGH", ip,
                f"Suspicious system service started: {e['raw'][:120]}", 1, "suspicious_service"))

    # SSH brute force
    for ip, fails in ip_failures.items():
        if len(fails) >= 5:
            alerts.append(make_alert("SSH Brute Force", "CRITICAL" if len(fails) >= 20 else "HIGH",
                ip, f"IP {ip} made {len(fails)} failed SSH login attempts.", len(fails), "ssh_brute_force"))

    # Brute force success
    for ip, successes in ip_success.items():
        if ip_failures.get(ip) and len(ip_failures[ip]) >= 3:
            user = successes[0].get("user", "?")
            alerts.append(make_alert("Brute Force Success", "CRITICAL", ip,
                f"IP {ip} had {len(ip_failures[ip])} failures then logged in as '{user}'. Likely compromised!",
                len(ip_failures[ip]) + 1, "brute_force_success"))

    # Web scanning
    for ip, reqs in ip_web_scan.items():
        if len(reqs) >= 5:
            alerts.append(make_alert("Web Scanning / Directory Traversal", "HIGH", ip,
                f"IP {ip} made {len(reqs)} suspicious web requests. Possible scanner.",
                len(reqs), "web_scanning"))

    # SQL injection
    for ip, reqs in ip_sqli.items():
        alerts.append(make_alert("SQL Injection Attempt", "CRITICAL", ip,
            f"IP {ip} made {len(reqs)} SQL injection attempts.", len(reqs), "sql_injection"))

    # Sort by severity
    alerts.sort(key=lambda x: x["severity_level"], reverse=True)
    return alerts