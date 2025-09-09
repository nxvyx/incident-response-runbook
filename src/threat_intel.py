"""
threat_intel.py
Provides functions to enrich alerts using VirusTotal and AbuseIPDB (optional).
Uses environment variables:
 - VT_API_KEY  -> VirusTotal v3 API key
 - ABUSEIPDB_KEY -> AbuseIPDB API key (optional)
"""
from dotenv import load_dotenv
load_dotenv()

# src/threat_intel.py  (replace existing vt_lookup_hash and vt_lookup_url)
import os
import requests
import time
import base64
from typing import Dict

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VT_BASE = "https://www.virustotal.com/api/v3"

def _rate_limit_sleep(seconds=5):
    time.sleep(seconds)

def _url_id_from_url(u: str) -> str:
    # base64 urlsafe (rstrip '='), used by VT v3 for GET /urls/{id}
    return base64.urlsafe_b64encode(u.encode()).rstrip(b"=").decode("ascii")

def vt_lookup_hash(file_hash: str) -> Dict:
    """Lookup a file hash on VirusTotal v3. Returns dict with normalized last_analysis_stats or error."""
    if not VT_API_KEY or not file_hash or file_hash.strip() in ("-", ""):
        return {"error": "no_key_or_hash"}

    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(f"{VT_BASE}/files/{file_hash}", headers=headers, timeout=30)
    except Exception as e:
        return {"error": "request_exception", "raw": str(e)}

    if r.status_code == 200:
        try:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            # normalize to ints (if possible)
            cleaned = {}
            for k, v in (stats.items() if isinstance(stats, dict) else []):
                try:
                    cleaned[k] = int(v)
                except Exception:
                    cleaned[k] = v
            return {"vt_status": "ok", "analysis_stats": cleaned}
        except Exception as e:
            return {"error": "parse_error", "raw": str(e)}
    elif r.status_code == 404:
        return {"vt_status": "not_found"}
    else:
        return {"error": f"vt_hash_status_{r.status_code}", "raw": r.text}


def vt_lookup_url(url_to_check: str, poll_attempts: int = 4, poll_delay: int = 3) -> Dict:
    """
    Lookup a URL on VirusTotal v3. Try GET with base64 id first, then POST + poll.
    Returns {"vt_status":"ok","analysis_stats": {...}} or an error dict.
    """
    if not VT_API_KEY or not url_to_check or url_to_check.strip() in ("-", ""):
        return {"error": "no_key_or_url"}

    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}
    # Try GET with base64 id (fast path)
    try:
        url_id = _url_id_from_url(url_to_check)
        r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=20)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            cleaned = {k: int(v) if str(v).isdigit() else v for k, v in stats.items()}
            return {"vt_status": "ok", "analysis_stats": cleaned}
    except Exception:
        pass  # fall back to submit + poll

    # Submit URL (POST) and then poll GET /urls/{id}
    try:
        submit = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url_to_check}, timeout=20)
    except Exception as e:
        return {"error": "request_exception_on_submit", "raw": str(e)}

    if submit.status_code in (200, 201):
        # get id if provided, else compute encoded id
        try:
            j = submit.json()
            url_id = j.get("data", {}).get("id") or _url_id_from_url(url_to_check)
        except Exception:
            url_id = _url_id_from_url(url_to_check)

        # poll a few times to allow VT to finish analyses
        last_stats = {}
        for _ in range(poll_attempts):
            _rate_limit_sleep(poll_delay)
            try:
                q = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=20)
                if q.status_code == 200:
                    stats = q.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
                    if stats:
                        cleaned = {k: int(v) if str(v).isdigit() else v for k, v in stats.items()}
                        return {"vt_status": "ok", "analysis_stats": cleaned}
                    last_stats = stats
            except Exception:
                continue
        # return whatever we have (may be empty)
        return {"vt_status": "ok", "analysis_stats": last_stats}
    else:
        # submit failed
        try:
            return {"error": f"vt_submit_failed_{submit.status_code}", "raw": submit.text}
        except Exception:
            return {"error": "vt_submit_failed_unknown"}
