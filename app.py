"""
SIEM - Clean Version
Two features:
1. Upload log file → detect attacks
2. Live Monitor → scan THIS machine's real logs, show if attacked or clean
"""

import sys, os, uuid, secrets, time, threading
from datetime import datetime
from functools import wraps
from collections import deque

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
os.chdir(BASE_DIR)

from flask import Flask, jsonify, render_template, request, session, redirect
from modules.parser    import parse_file, parse_line
from modules.detector  import detect
from modules.log_finder import find_logs, get_os_info

app = Flask(__name__)
# Permanent secret key - stored in file so sessions survive restarts
_key_file = os.path.join(BASE_DIR, ".secret_key")
if os.path.exists(_key_file):
    with open(_key_file) as f:
        app.secret_key = f.read().strip()
else:
    _new_key = secrets.token_hex(32)
    with open(_key_file, 'w') as f:
        f.write(_new_key)
    app.secret_key = _new_key

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

PASSWORD = "siem1234"

# Live monitor state
live_events  = deque(maxlen=200)
monitor_status = {
    "running":  False,
    "files":    [],
    "scanned":  False,
    "clean":    False,
    "message":  "",
    "os":       {}
}


# ── Auth ──────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def dec(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return dec


@app.route("/login")
def login_page():
    if session.get("logged_in"): return redirect("/")
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    if data.get("password") == PASSWORD:
        session["logged_in"] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Wrong password"})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html")


# ── OS Info ───────────────────────────────────────────────────────────────────

@app.route("/api/os")
@login_required
def api_os():
    """Return current OS info — called on page load."""
    info = get_os_info()
    logs = find_logs()
    return jsonify({
        "os":      info,
        "logs":    logs["found"],
        "count":   logs["count"],
        "message": f"Found {logs['count']} log file(s) on {info['display']}" if logs["count"]
                   else f"No log files found on {info['display']}"
    })


# ── Feature 1: Upload ─────────────────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"success": False, "error": "No file selected"}), 400
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in [".log", ".txt"]:
        return jsonify({"success": False, "error": "Only .log and .txt files allowed"}), 400

    save_path = os.path.join(UPLOAD_DIR, secrets.token_hex(16) + ext)
    file.save(save_path)

    events, log_type = parse_file(save_path)
    alerts = detect(events)

    return jsonify({
        "success":      True,
        "filename":     file.filename,
        "log_type":     log_type,
        "events_found": len(events),
        "alerts_found": len(alerts),
        "alerts":       alerts,
        "severity_counts": {
            "CRITICAL": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "HIGH":     sum(1 for a in alerts if a["severity"] == "HIGH"),
            "MEDIUM":   sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            "LOW":      sum(1 for a in alerts if a["severity"] == "LOW"),
        }
    })


# ── Feature 2: Live Monitor ───────────────────────────────────────────────────

@app.route("/api/monitor/start", methods=["POST"])
@login_required
def api_monitor_start():
    """
    1. Find real log files on this machine
    2. Read and analyse them RIGHT NOW (historical scan)
    3. Report if system was attacked or is clean
    4. Start watching for NEW events
    """
    global live_events

    if monitor_status["running"]:
        stop_monitor()

    # Find real log files
    logs_info = find_logs()
    found     = logs_info["found"]

    # Allow custom path from request
    data        = request.get_json(silent=True) or {}
    custom_path = data.get("path", "").strip()
    if custom_path and os.path.exists(custom_path):
        log_type = "web" if any(x in custom_path.lower() for x in ["access", "nginx", "apache", "iis"]) else "ssh"
        found = [{"path": custom_path, "type": log_type, "label": "Custom Log", "size_kb": round(os.path.getsize(custom_path)/1024, 1)}]

    if not found:
        return jsonify({
            "success": False,
            "error":   f"No log files found on this {logs_info['os']['display']} machine.",
            "tip":     "Use the custom path field to specify a log file, or upload a file instead."
        })

    # ── STEP 1: Historical scan (read existing logs) ──
    all_events = []
    scanned_files = []
    for log in found:
        events, _ = parse_file(log["path"])
        all_events.extend(events)
        scanned_files.append(log["path"])

    alerts = detect(all_events)

    # ── STEP 2: Determine if attacked or clean ──
    critical = [a for a in alerts if a["severity"] == "CRITICAL"]
    high     = [a for a in alerts if a["severity"] == "HIGH"]

    files_str = ", ".join([os.path.basename(f) for f in scanned_files])

    if not alerts:
        status_msg = f"✅ System is Clean — No attacks detected in [{files_str}]"
        is_clean   = True
    elif critical:
        status_msg = f"🚨 SYSTEM UNDER ATTACK — {len(critical)} Critical, {len(high)} High alerts in [{files_str}]"
        is_clean   = False
    elif high:
        status_msg = f"⚠️ Suspicious Activity — {len(high)} High alerts found in [{files_str}]"
        is_clean   = False
    else:
        status_msg = f"ℹ️ Low Risk — {len(alerts)} alert(s) in [{files_str}]. Monitor closely."
        is_clean   = True

    # Store results
    monitor_status["scanned"]  = True
    monitor_status["clean"]    = is_clean
    monitor_status["message"]  = status_msg
    monitor_status["files"]    = scanned_files
    monitor_status["os"]       = logs_info["os"]

    # ── STEP 3: Start live watching for NEW events ──
    live_events.clear()
    start_monitor_threads(found)

    return jsonify({
        "success":      True,
        "status":       status_msg,
        "is_clean":     is_clean,
        "files":        scanned_files,
        "events_found": len(all_events),
        "alerts":       alerts,
        "severity_counts": {
            "CRITICAL": len(critical),
            "HIGH":     len(high),
            "MEDIUM":   sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            "LOW":      sum(1 for a in alerts if a["severity"] == "LOW"),
        }
    })


@app.route("/api/monitor/stop", methods=["POST"])
@login_required
def api_monitor_stop():
    stop_monitor()
    return jsonify({"success": True})


@app.route("/api/monitor/status")
@login_required
def api_monitor_status():
    return jsonify(monitor_status)


@app.route("/api/monitor/live")
@login_required
def api_monitor_live():
    """Return new live events and run detection on them."""
    events = list(live_events)
    alerts = detect(events) if events else []
    return jsonify({
        "events":      events[:25],
        "alerts":      alerts[:10],
        "event_count": len(events)
    })


# ── Monitor Thread ────────────────────────────────────────────────────────────

_tailers = []

class FileTailer(threading.Thread):
    def __init__(self, path, log_type):
        super().__init__(daemon=True)
        self.path     = path
        self.log_type = log_type
        self._stop    = threading.Event()

    def run(self):
        try:
            with open(self.path, "r", errors="ignore") as f:
                f.seek(0, 2)  # go to end — only new lines
                while not self._stop.is_set():
                    line = f.readline()
                    if line and line.strip():
                        event = parse_line(line, self.log_type)
                        if event:
                            live_events.appendleft(event)
                    else:
                        time.sleep(0.5)
        except Exception as e:
            print(f"[Watcher] Error: {e}")

    def stop(self):
        self._stop.set()


def start_monitor_threads(logs):
    global _tailers
    _tailers = [FileTailer(l["path"], l["type"]) for l in logs]
    for t in _tailers:
        t.start()
    monitor_status["running"] = True
    print(f"[Monitor] Watching {len(_tailers)} file(s)")


def stop_monitor():
    global _tailers
    for t in _tailers:
        t.stop()
    _tailers = []
    monitor_status["running"] = False
    monitor_status["scanned"] = False
    monitor_status["message"] = ""
    live_events.clear()
    print("[Monitor] Stopped")


# ── Debug Routes ─────────────────────────────────────────────────────────────

@app.route("/api/debug")
@login_required
def api_debug():
    """Debug endpoint - shows exactly what SIEM is doing."""
    from modules.log_finder import find_logs, get_os_info
    logs  = find_logs()
    os_i  = get_os_info()

    debug_info = {
        "os": os_i,
        "monitor_status": monitor_status,
        "log_files_found": logs["found"],
        "live_events_count": len(live_events),
    }

    # Analyse each found log
    analysis = []
    for l in logs["found"]:
        events, log_type = parse_file(l["path"])
        alerts = detect(events)
        analysis.append({
            "path":    l["path"],
            "type":    log_type,
            "events":  len(events),
            "alerts":  len(alerts),
            "alert_types": [a["alert_type"] for a in alerts]
        })

    debug_info["log_analysis"] = analysis
    return jsonify(debug_info)



# ── Threat Intelligence Routes ────────────────────────────────────────────────

from modules.threat_intel import lookup_ip, enrich_alerts_with_intel, is_private_ip

# Store API key in memory (set via dashboard)
_abuseipdb_key = ""


@app.route("/api/intel/lookup", methods=["POST"])
@login_required
def api_intel_lookup():
    """Look up a single IP for threat intelligence."""
    global _abuseipdb_key
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()
    key  = data.get("api_key", _abuseipdb_key).strip()

    if not ip:
        return jsonify({"success": False, "error": "No IP provided"}), 400

    if key:
        _abuseipdb_key = key  # save for future requests

    result = lookup_ip(ip, key)
    return jsonify({"success": True, "result": result})


@app.route("/api/intel/enrich", methods=["POST"])
@login_required
def api_intel_enrich():
    """Enrich a list of alerts with threat intel for all attacker IPs."""
    global _abuseipdb_key
    data    = request.get_json(silent=True) or {}
    alerts  = data.get("alerts", [])
    key     = data.get("api_key", _abuseipdb_key).strip()

    if key:
        _abuseipdb_key = key

    enriched = enrich_alerts_with_intel(alerts, key)
    return jsonify({"success": True, "alerts": enriched})


@app.route("/api/intel/key", methods=["POST"])
@login_required
def api_intel_set_key():
    """Save AbuseIPDB API key for this session."""
    global _abuseipdb_key
    data = request.get_json(silent=True) or {}
    key  = data.get("api_key", "").strip()
    _abuseipdb_key = key
    return jsonify({"success": True, "message": "API key saved for this session"})


# ── PDF Report Route ─────────────────────────────────────────────────────────

@app.route("/api/report", methods=["POST"])
@login_required
def api_generate_report():
    """Generate PDF report from real live alerts — no hardcoded data."""
    from modules.report_generator import generate_report
    from flask import send_file
    import tempfile

    data      = request.get_json(silent=True) or {}
    alerts    = data.get("alerts", [])
    scan_info = data.get("scan_info", {})

    if not alerts:
        return jsonify({"success": False, "error": "No alerts to include in report"}), 400

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"SIEM_Report_{timestamp}.pdf"
    tmp_path  = os.path.join(tempfile.gettempdir(), filename)

    generate_report(alerts, scan_info, tmp_path)

    return send_file(
        tmp_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Stop any leftover monitor from previous run
    stop_monitor()

    os_info = get_os_info()
    logs    = find_logs()
    print("\n" + "="*50)
    print("  SIEM — Log Analysis & Live Monitor")
    print("="*50)
    print(f"  OS       : {os_info['icon']} {os_info['display']}")
    print(f"  Log files: {logs['count']} found on this machine")
    for l in logs["found"]:
        print(f"             → {l['path']}")
    print(f"  Dashboard: http://localhost:5000")
    print(f"  Password : {PASSWORD}")
    print("="*50 + "\n")
    app.run(debug=False, port=5000, host="127.0.0.1", use_reloader=False)