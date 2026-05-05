"""
SIEM Debug Script
Run this to diagnose exactly what's happening.
Usage: python debug.py
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.log_finder import find_logs, get_os_info
from modules.parser import parse_file
from modules.detector import detect

print("\n" + "="*60)
print("  SIEM DIAGNOSTIC REPORT")
print("="*60)

# 1. OS Info
os_info = get_os_info()
print(f"\n[1] OS DETECTED")
print(f"    Name    : {os_info['name']}")
print(f"    Release : {os_info['release']}")
print(f"    Display : {os_info['display']}")

# 2. Log files found
print(f"\n[2] LOG FILES FOUND ON THIS MACHINE")
logs = find_logs()
if not logs['found']:
    print("    NONE — no log files accessible")
else:
    for l in logs['found']:
        print(f"    ✓ {l['path']}")
        print(f"      Type : {l['type']} | Label: {l['label']} | Size: {l['size_kb']} KB")

# 3. Parse each log and show what's in it
print(f"\n[3] LOG FILE CONTENTS ANALYSIS")
for l in logs['found']:
    print(f"\n    Parsing: {l['path']}")
    events, log_type = parse_file(l['path'])
    print(f"    Format : {log_type}")
    print(f"    Events : {len(events)}")

    # Count event types
    from collections import Counter
    types = Counter(e['event_type'] for e in events)
    for t, c in types.most_common():
        print(f"      [{c:3d}] {t}")

    # Show unique IPs
    ips = set(e.get('ip','') for e in events if e.get('ip'))
    print(f"    IPs    : {', '.join(list(ips)[:5])}")

    # Run detection
    alerts = detect(events)
    print(f"    Alerts : {len(alerts)}")
    for a in alerts:
        print(f"      [{a['severity']}] {a['alert_type']} | IP: {a['source_ip']}")

# 4. Check for XAMPP specifically
print(f"\n[4] XAMPP CHECK")
xampp_log = r"C:\xampp\apache\logs\access.log"
if os.path.exists(xampp_log):
    size = os.path.getsize(xampp_log)
    print(f"    FOUND: {xampp_log}")
    print(f"    Size : {size} bytes")
    print(f"    *** This is causing your old attack data to show ***")
    print(f"    FIX  : Run this command to clear it:")
    print(f"           del \"{xampp_log}\"")
else:
    print(f"    Not found (good!)")

# 5. Check .secret_key
print(f"\n[5] SESSION KEY")
key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")
if os.path.exists(key_file):
    print(f"    ✓ Permanent key exists — sessions will survive restarts")
else:
    print(f"    ✗ No key file — sessions reset on every restart (causes 401 errors)")

print("\n" + "="*60)
print("  DONE")
print("="*60 + "\n")
