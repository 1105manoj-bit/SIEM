"""
Live Log Watcher
Watches log files for new lines and detects attacks in real-time.
"""

import os
import sys
import time
import threading
from collections import deque

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from modules.parser import parse_line, detect_log_type

# Shared state
live_events = deque(maxlen=100)
live_alerts = deque(maxlen=50)
watch_status = {"running": False, "files": []}


class FileTailer(threading.Thread):
    """Watches a single file for new lines."""

    def __init__(self, filepath):
        super().__init__(daemon=True)
        self.filepath  = filepath
        self.log_type  = detect_log_type(filepath) if os.path.exists(filepath) else "ssh"
        self._stop     = threading.Event()

    def run(self):
        print(f"[Watcher] Watching: {self.filepath} (type={self.log_type})")
        try:
            with open(self.filepath, "r", errors="ignore") as f:
                f.seek(0, 2)  # jump to end — only watch NEW lines
                while not self._stop.is_set():
                    line = f.readline()
                    if line and line.strip():
                        event = parse_line(line, self.log_type)
                        if event:
                            live_events.appendleft(event)
                    else:
                        time.sleep(0.3)
        except FileNotFoundError:
            print(f"[Watcher] File not found: {self.filepath}")

    def stop(self):
        self._stop.set()


_tailers = []


def start_watching(paths):
    """Start watching a list of file paths."""
    global _tailers
    if watch_status["running"]:
        return

    _tailers = [FileTailer(p) for p in paths if p]
    for t in _tailers:
        t.start()

    watch_status["running"] = True
    watch_status["files"]   = paths
    print(f"[Watcher] Started watching {len(_tailers)} file(s)")


def stop_watching():
    """Stop all file watchers."""
    global _tailers
    for t in _tailers:
        t.stop()
    _tailers = []
    watch_status["running"] = False
    watch_status["files"]   = []
    print("[Watcher] Stopped")


def get_live_events(limit=25):
    return list(live_events)[:limit]
