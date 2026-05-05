"""
Log Finder - detects OS and finds real log files
"""
import os
import platform

def get_os_info():
    system  = platform.system()
    release = platform.release()
    node    = platform.node()
    icons   = {"Windows": "🪟", "Linux": "🐧", "Darwin": "🍎"}
    return {
        "name":    system,
        "release": release,
        "node":    node,
        "display": f"{system} {release}",
        "icon":    icons.get(system, "💻"),
        "type":    system.lower()
    }

def find_logs():
    os_info  = get_os_info()
    system   = os_info["type"]

    if system == "windows":
        candidates = [
            {"path": r"C:\xampp\apache\logs\access.log",  "type": "web",  "label": "Apache (XAMPP)"},
            {"path": r"C:\xampp\apache\logs\error.log",   "type": "web",  "label": "Apache Error"},
            {"path": r"C:\Apache24\logs\access.log",      "type": "web",  "label": "Apache"},
            {"path": r"C:\nginx\logs\access.log",         "type": "web",  "label": "Nginx"},
            {"path": r"C:\wamp64\logs\access.log",        "type": "web",  "label": "Apache (WAMP)"},
        ]
    elif system == "linux":
        candidates = [
            {"path": "/var/log/auth.log",           "type": "ssh", "label": "SSH Auth Log"},
            {"path": "/var/log/secure",             "type": "ssh", "label": "SSH Auth (RHEL/CentOS)"},
            {"path": "/var/log/apache2/access.log", "type": "web", "label": "Apache Access"},
            {"path": "/var/log/nginx/access.log",   "type": "web", "label": "Nginx Access"},
            {"path": "/var/log/syslog",             "type": "ssh", "label": "Syslog"},
        ]
    else:  # macOS
        candidates = [
            {"path": "/var/log/system.log",                 "type": "ssh", "label": "System Log"},
            {"path": "/usr/local/var/log/nginx/access.log", "type": "web", "label": "Nginx Access"},
        ]

    found = []
    for c in candidates:
        if os.path.exists(c["path"]) and os.access(c["path"], os.R_OK):
            found.append({
                "path":    c["path"],
                "type":    c["type"],
                "label":   c["label"],
                "size_kb": round(os.path.getsize(c["path"]) / 1024, 1)
            })

    return {"os": os_info, "found": found, "count": len(found)}