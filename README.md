# SIEM — Log Analysis & Security Monitor

A tool built to monitor system logs and detect attacks in real time. You can either upload a log file to check for attacks, or point it at your machine's live logs and watch it detect attacks as they happen.

---

## What it does

There are two main things this tool does:

**1. Upload a log file**
Drop any log file into the browser and it will read through every line, figure out what format it is (SSH logs, web server logs, etc.), run detection rules on it, and show you every attack it found — with the MITRE ATT&CK technique ID and a severity rating.

**2. Live monitoring**
It detects what OS you're running, finds the real log files on your machine (like `/var/log/auth.log` on Linux or Apache logs on Windows with XAMPP), reads them right now to check if anything bad has already happened, then watches for new events live. If your system is clean it tells you. If something is wrong it shows you exactly what.

---

## Attacks it can detect

| Attack | What it looks for |
|---|---|
| SSH Brute Force | Many failed login attempts from the same IP |
| Successful Compromise | Someone failing many times then suddenly getting in |
| Web Scanning | Tools like Nikto hitting hundreds of paths on your web server |
| SQL Injection | SQLMap payloads showing up in web requests |
| Backdoor Download | Someone running wget to download a malicious script |
| Privilege Escalation | Attacker running sudo bash to get root access |
| Data Exfiltration | Files like /etc/passwd being copied to an attacker machine |
| Log Tampering | Attacker deleting log files to hide their tracks |
| Persistence | Malicious cron jobs being added |

Each detection is mapped to a MITRE ATT&CK technique (like T1110 for brute force) which is the industry standard way security teams classify attacks.

---

## Other features

- **PDF reports** — after any scan you can download a proper incident report with all the alerts, a timeline, and recommendations for fixing each issue
- **Threat intelligence** — looks up attacker IPs to find out what country they're from, what ISP they're using, and if they've been reported before
- **Login page** — password protected so the dashboard isn't just open to anyone
- **Auto detection** — figures out on its own what OS you're running and where your logs are

---

## How to run it

You need Python 3.8 or higher.

```bash
# Install dependencies
pip install flask reportlab requests

# Kali Linux
pip install flask reportlab requests --break-system-packages

# Run
python3 app.py

# Open in browser
http://localhost:5000
# Password: siem1234
```

---

## Setting up Threat Intelligence (Free)

By default the threat intel tab shows country, city and ISP for any IP. To also get abuse scores and report history, you need a free AbuseIPDB API key.

**Step 1** — Register free at `https://www.abuseipdb.com/register`

**Step 2** — After login go to `https://www.abuseipdb.com/account/api/keys` and click **Create Key** — copy it

**Step 3** — In the SIEM dashboard:
- Go to **🔍 Threat Intel** tab
- Paste your key in the API key field at the top
- Click **Save Key**

Now when you look up an IP you will also see:
- Abuse confidence score (0-100%)
- How many times it has been reported globally
- When it was last reported
- What type of network it is (data center, ISP, etc.)

The free tier allows 1000 IP checks per day which is more than enough for personal use.

---

## How I tested it

I set up Kali Linux in a VM and ran real attacks against my machine:

```bash
# SSH brute force against localhost
for i in {1..25}; do
    ssh -o StrictHostKeyChecking=no fakeuser$i@127.0.0.1 2>/dev/null
    sleep 0.3
done

# Web scan
nikto -h http://127.0.0.1

# SQL injection
sqlmap -u "http://127.0.0.1/?id=1" --batch --level=1
```

The SIEM caught all of it in real time — brute force, web scanning, SQL injection. The live feed updated as each attack line was written to the log file.

This creates realistic fake logs with a full attack chain — brute force, compromise, privilege escalation, backdoor download, data exfiltration, log tampering. Upload any of them to test the detection.

---

## Files

```
app.py                    main server
modules/
  parser.py               reads log files line by line
  detector.py             the detection rules
  watcher.py              watches live log files for new lines
  log_finder.py           finds log files on this machine
  threat_intel.py         IP lookups
  report_generator.py     makes the PDF
templates/
  index.html              the dashboard
  login.html              login page
generate_test_logs.py     makes fake attack logs for testing
debug.py                  shows what the tool can see on your machine
```

---

## Why I built this

I wanted to understand defensive security properly — not just run tools but actually know what's happening underneath. Building something from scratch forces you to understand every part of it.
This covers a lot of what a SOC analyst does every day — reading logs, spotting patterns, mapping attacks to MITRE techniques, writing up what happened. Having built one of these tools makes it much easier to understand and use the enterprise versions.


- The MITRE ATT&CK framework and how real attacks map to it
- How to use threat intel APIs to get context on attacker IPs
- How to run real attacks in a safe lab environment and verify they get detected
