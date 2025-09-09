"""
runbook.py
Main entrypoint. Usage:

python runbook.py --input data/alerts.csv --output outputs/incident_report.csv --pdf outputs/incident_report.pdf

Set env vars:
 - VT_API_KEY (required for real VT lookups)
 - ABUSEIPDB_KEY (optional)
"""
import json
import argparse
import os
import pandas as pd
from threat_intel import vt_lookup_hash, vt_lookup_url, _rate_limit_sleep
from report_generator import save_csv, create_pdf_report
from tqdm import tqdm

def load_alerts(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str)
    return df.fillna("")


def enrich_row(row):
    """Enrich a single alert row with threat intel. Returns dict of enrichment."""
    enrichment = {}
    file_hash = row.get("hash", "").strip()
    url = row.get("url", "").strip()
    src_ip = row.get("src_ip", "").strip()

    # VirusTotal hash
    if file_hash and file_hash not in ["-", ""]:
        vt_h = vt_lookup_hash(file_hash)
        enrichment["vt_hash"] = vt_h
        _rate_limit_sleep(15)
    else:
        enrichment["vt_hash"] = {"info": "no_hash"}

    # VirusTotal url
    if url and url not in ["-", ""]:
        vt_u = vt_lookup_url(url)
        enrichment["vt_url"] = vt_u
        _rate_limit_sleep(5)
    else:
        enrichment["vt_url"] = {"info": "no_url"}


    return enrichment

# prepare CSV-friendly summaries
def safe_get_malicious_count(enrich_field):
    # enrich_field is a dict like {"vt_status":"ok","analysis_stats": {...}} or {"error":...}
    if not isinstance(enrich_field, dict):
        return ""
    if enrich_field.get("vt_status") == "ok":
        stats = enrich_field.get("analysis_stats", {})
        # get malicious count (int) if present
        m = stats.get("malicious")
        return int(m) if (m is not None and str(m).isdigit()) else (m if m is not None else "")
    else:
        # return human-friendly error so you can see why it's blank
        return f"ERROR:{enrich_field.get('error')}" if enrich_field.get("error") else ""


def classify_incident(enrichment: dict, row: dict) -> str:
    """
    Simple rule-based classification:
    - If VT hash analysis indicates many malicious engines -> Malware
    - If URL analysis indicates suspicious engines or URL contains phishing keywords -> Phishing
    - If AbuseIPDB has high confidence -> Suspicious
    - Else -> Benign
    """
    # Check hash
    vt_h = enrichment.get("vt_hash", {})
    if isinstance(vt_h, dict) and "analysis_stats" in vt_h:
        stats = vt_h["analysis_stats"]
        malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
        if malicious and int(malicious) >= 3:
            return "Malware"

    # Check URL
    vt_u = enrichment.get("vt_url", {})
    if isinstance(vt_u, dict) and "analysis_stats" in vt_u:
        stats = vt_u["analysis_stats"]
        malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
        if malicious and int(malicious) >= 2:
            return "Phishing"

    # quick keyword heuristics
    url = row.get("url", "").lower()
    if any(k in url for k in ["phish", "login", "secure", "verify", "account"]):
        return "Phishing"

    return "Benign"


def recommend_action(classification: str, row: dict) -> str:
    if classification == "Malware":
        return "Isolate host, collect memory image, block hash on EDR, escalate to IR team"
    if classification in ("Phishing", "Suspicious-IP"):
        return "Block URL/IP at proxy/firewall, force password reset for impacted users, scan mailbox"
    return "Monitor and close if no further alerts"


def main(args):
    df = load_alerts(args.input)
    enriched_rows = []
    print("[*] Starting enrichment...")
    for _, r in tqdm(df.iterrows(), total=len(df)):
        row = r.to_dict()
        enrichment = enrich_row(row)
        classification = classify_incident(enrichment, row)
        action = recommend_action(classification, row)

        # attach enrichment summary to row
        row["classification"] = classification
        row["recommended_action"] = action

        # For CSV-friendly output
        row["vt_hash_malicious_count"] = safe_get_malicious_count(enrichment.get("vt_hash", {}))
        row["vt_url_malicious_count"] = safe_get_malicious_count(enrichment.get("vt_url", {}))

        # keep raw enrichment in debug field
        row["_debug_enrichment"] = enrichment

        enriched_rows.append(row)

    out_df = pd.DataFrame(enriched_rows)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    save_csv(out_df, args.output)


    if args.pdf:
        os.makedirs(os.path.dirname(args.pdf), exist_ok=True)
        create_pdf_report(out_df, args.pdf)

    with open("outputs/enrichment_debug.json", "w") as fh:
        json.dump(enriched_rows, fh, indent=2, default=str)

    print("[*] Done. CSV + optional PDF generated. Debug JSON saved in outputs/enrichment_debug.json")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Incident Response Runbook Automation")
    parser.add_argument("--input", required=True, help="Input alerts CSV")
    parser.add_argument("--output", required=True, help="Output enriched CSV")
    parser.add_argument("--pdf", required=False, help="Optional PDF path for executive report")
    args = parser.parse_args()
    main(args)
