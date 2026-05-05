"""
Threat Intelligence Module
Checks attacker IPs against:
1. AbuseIPDB — global IP blacklist (free API)
2. ip-api.com — IP geolocation (free, no key needed)
3. Local cache — avoids repeat lookups

Get your FREE AbuseIPDB API key at:
https://www.abuseipdb.com/register
(Free tier: 1000 checks/day)
"""

import os
import sys
import json
import time
import requests
from datetime import datetime, timedelta

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_FILE = os.path.join(BASE_DIR, "threat_cache.json")
CACHE_TTL  = 3600  # cache results for 1 hour

# ── Cache ─────────────────────────────────────────────────────────────────────

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                return json.load(f)
        except:
            pass
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def get_cached(ip):
    cache = load_cache()
    if ip in cache:
        entry = cache[ip]
        age   = time.time() - entry.get("cached_at", 0)
        if age < CACHE_TTL:
            return entry
    return None

def set_cached(ip, data):
    cache        = load_cache()
    data["cached_at"] = time.time()
    cache[ip]    = data
    save_cache(cache)


# ── Skip local/private IPs ────────────────────────────────────────────────────

SKIP_IPS = {
    "127.0.0.1", "::1", "localhost", "N/A",
    "127.0.0.1 (localhost)", "local"
}

def is_private_ip(ip):
    """Return True if IP is private/local — no point checking these."""
    if not ip or ip in SKIP_IPS:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
        # 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        if a == 10: return True
        if a == 172 and 16 <= b <= 31: return True
        if a == 192 and b == 168: return True
        if a == 127: return True
    except:
        return True
    return False


# ── IP Geolocation (free, no API key) ────────────────────────────────────────

def get_geolocation(ip):
    """Get IP geolocation from ip-api.com (free, no key needed)."""
    try:
        res  = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as",
            timeout=5
        )
        data = res.json()
        if data.get("status") == "success":
            return {
                "country":      data.get("country", "Unknown"),
                "country_code": data.get("countryCode", ""),
                "region":       data.get("regionName", ""),
                "city":         data.get("city", ""),
                "isp":          data.get("isp", "Unknown"),
                "org":          data.get("org", ""),
                "as":           data.get("as", ""),
            }
    except Exception as e:
        pass
    return {"country": "Unknown", "country_code": "", "region": "", "city": "", "isp": "Unknown", "org": "", "as": ""}


# ── AbuseIPDB Check ───────────────────────────────────────────────────────────

def check_abuseipdb(ip, api_key):
    """
    Check IP against AbuseIPDB.
    Get free API key at: https://www.abuseipdb.com/register
    """
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        return None

    try:
        res = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8
        )
        if res.status_code == 200:
            d = res.json().get("data", {})
            return {
                "abuse_score":    d.get("abuseConfidenceScore", 0),
                "total_reports":  d.get("totalReports", 0),
                "last_reported":  d.get("lastReportedAt", ""),
                "is_whitelisted": d.get("isWhitelisted", False),
                "usage_type":     d.get("usageType", ""),
                "domain":         d.get("domain", ""),
                "reports":        d.get("reports", [])[:3],  # last 3 reports
            }
        elif res.status_code == 429:
            return {"error": "Rate limit reached"}
    except Exception as e:
        pass
    return None


# ── Country Flag Emoji ────────────────────────────────────────────────────────

def country_flag(country_code):
    """Convert country code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return chr(ord(country_code[0].upper()) + 127397) + \
               chr(ord(country_code[1].upper()) + 127397)
    except:
        return "🌐"


# ── Risk Level from Abuse Score ───────────────────────────────────────────────

def get_risk_level(abuse_score):
    if abuse_score >= 80: return "CRITICAL",  "#ff4d6d"
    if abuse_score >= 50: return "HIGH",       "#ff8c42"
    if abuse_score >= 20: return "MEDIUM",     "#ffd166"
    if abuse_score >  0:  return "LOW",        "#06d6a0"
    return "UNKNOWN", "#6e7681"


# ── Main Lookup Function ──────────────────────────────────────────────────────

def lookup_ip(ip, api_key=""):
    """
    Full threat intelligence lookup for an IP.
    Returns enriched dict with geo + abuse data.
    """
    if is_private_ip(ip):
        return {
            "ip":          ip,
            "private":     True,
            "message":     "Private/local IP — no threat intel available",
            "geo":         {},
            "abuse":       None,
            "risk_level":  "N/A",
            "risk_color":  "#6e7681",
            "flag":        "🏠",
            "summary":     "Local/private address"
        }

    # Check cache first
    cached = get_cached(ip)
    if cached:
        cached["from_cache"] = True
        return cached

    result = {
        "ip":         ip,
        "private":    False,
        "from_cache": False,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Geolocation (always free)
    geo = get_geolocation(ip)
    result["geo"]  = geo
    result["flag"] = country_flag(geo.get("country_code", ""))

    # AbuseIPDB (needs API key)
    abuse = check_abuseipdb(ip, api_key)
    result["abuse"] = abuse

    # Risk level
    if abuse and "abuse_score" in abuse:
        level, color = get_risk_level(abuse["abuse_score"])
        result["risk_level"] = level
        result["risk_color"] = color
        result["abuse_score"] = abuse["abuse_score"]
    else:
        result["risk_level"] = "UNKNOWN"
        result["risk_color"] = "#6e7681"
        result["abuse_score"] = -1

    # Summary line
    city    = geo.get("city", "")
    country = geo.get("country", "Unknown")
    isp     = geo.get("isp", "Unknown ISP")
    location = f"{city}, {country}" if city else country

    if abuse and "abuse_score" in abuse:
        score = abuse["abuse_score"]
        reports = abuse.get("total_reports", 0)
        result["summary"] = f"{result['flag']} {location} | {isp} | Abuse Score: {score}% | {reports} reports"
    else:
        result["summary"] = f"{result['flag']} {location} | {isp} | No abuse data (add API key)"

    set_cached(ip, result)
    return result


def enrich_alerts_with_intel(alerts, api_key=""):
    """
    Add threat intel to each alert.
    Returns enriched alerts list.
    """
    seen_ips = {}
    enriched = []

    for alert in alerts:
        ip = alert.get("source_ip", "")
        if ip and ip not in seen_ips and not is_private_ip(ip):
            seen_ips[ip] = lookup_ip(ip, api_key)
            time.sleep(0.3)  # be polite to APIs

        alert = dict(alert)
        alert["threat_intel"] = seen_ips.get(ip, {})
        enriched.append(alert)

    return enriched


if __name__ == "__main__":
    # Test with a known malicious IP
    test_ip = "185.234.219.12"
    print(f"Looking up: {test_ip}")
    result = lookup_ip(test_ip)
    print(json.dumps(result, indent=2, default=str))

    print()
    print("Private IP test:")
    print(lookup_ip("192.168.1.1"))
