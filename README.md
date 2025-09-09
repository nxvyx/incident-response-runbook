# 🛡️ Automated SOC Incident Response Runbook

A Python-based project that simulates how a Security Operations Center (SOC) analyst can automate **incident triage** and **report generation**.  
It ingests SIEM-style alerts (CSV), enriches them with **VirusTotal** threat intelligence, classifies them (Malware, Phishing, Benign, Suspicious IP), and outputs both a **detailed CSV** and a **polished PDF executive report**.

---

## 🚀 Features
- **Alert Enrichment**  
  - VirusTotal (hashes + URLs)  
- **Incident Classification**  
  - Malware, Phishing, Suspicious IP, or Benign  
- **Automated Recommendations**  
  - Suggested response playbook actions for each incident  
- **Reporting**  
  - CSV output with enrichment details  
  - Professional PDF report with:
    - Executive summary  
    - Classification breakdown chart  
    - Color-coded incident table  

---

## 🗂️ Project Structure
```

incident\_response\_runbook/
│
├── data/                  # sample input alerts
│   └── alerts.csv
├── outputs/               # generated CSVs, PDFs, debug logs
│
├── src/
│   ├── runbook.py         # main entrypoint
│   ├── threat\_intel.py    # VirusTotal & AbuseIPDB lookups
│   ├── report\_generator.py# CSV & PDF reporting
│   └── ...
│
├── requirements.txt       # Python dependencies
└── README.md              # this file

````

---

## ⚙️ Installation

1. **Clone the repo**
```bash
git clone https://github.com/<your-username>/incident-response-runbook.git
cd incident-response-runbook
````

2. **Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Set API keys in `.env` file**

```
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key   # optional
```

---

## ▶️ Usage

Run the automation with:

```bash
python src/runbook.py --input data/alerts.csv --output outputs/incident_report.csv --pdf outputs/incident_report.pdf
```

* **Enriched CSV** → `outputs/incident_report.csv`
* **PDF Report** → `outputs/incident_report.pdf`
* **Debug JSON** (raw enrichment) → `outputs/enrichment_debug.json`

---

## 📊 Sample Output

* **CSV:**
  Contains enriched alerts with VirusTotal/AbuseIPDB fields, classification, and recommended actions.
* **PDF:**

  * Executive summary of alerts
  * Classification breakdown chart
  * Color-coded incident table
<img width="616" height="753" alt="image" src="https://github.com/user-attachments/assets/b63de6b7-63f6-4865-a799-8aca929a06c8" />

---

## 🧑‍💻 Skills Highlighted

* Security Operations (SOC)
* Threat Intelligence Integration (VirusTotal, AbuseIPDB)
* Incident Classification & Response Automation
* Python (requests, pandas, reportlab, matplotlib)
* PDF Reporting & Visualization

---

## 📌 Notes

* VirusTotal free API has rate limits (4 lookups/minute). Script includes sleeps to avoid 429 errors.
* AbuseIPDB integration is optional.

