# AutomateX
AutomateX is a SOC-focused **Threat Intelligence &amp; IOC Reputation Checker** built with Python and Streamlit.  

pip install -r requirements.txt

to run the project in your local machine use the following command
streamlit run app.py

and do not forget to add the API key in .env file

#  AutomateX – Threat Intelligence Platform

AutomateX is a SOC-focused **Threat Intelligence & IOC Reputation Checker** built with Python and Streamlit.  
It automates IOC triage, reputation analysis, MITRE ATT&CK mapping, and visualization using VirusTotal intelligence.

This project is designed for **SOC Analysts, Blue Teamers, and Security Engineers** to speed up investigations and reduce manual effort.

---

##  Features
-  Multi-IOC analysis (IPs, Domains, URLs, Hashes)
-  Automated verdict scoring (Clean / Suspicious / Malicious)
-  VirusTotal integration with smart caching
-  MITRE ATT&CK technique suggestions
-  Interactive dashboards & analytics
-  Direct IOC pivoting to VirusTotal
-  Handles up to **500 IOCs per run**
-  JSON export for reporting & SIEM ingestion
-  Professional neon-style SOC dashboard UI

---

##  MITRE ATT&CK Mapping

AutomateX provides **suggested MITRE ATT&CK techniques** based on:
- IOC type (IP / Domain / URL / Hash)
- Analyst-selected context (Phishing, C2, Malware Delivery, Recon)

>  Mapping is **contextual guidance**, not automatic attribution.

---
Tech Stack

- **Python 3.10+**
- **Streamlit**
- **VirusTotal API**
- Pandas, Altair
- SQLite (local cache)
- dotenv

---

##  Screenshots

<img width="1439" height="655" alt="c" src="https://github.com/user-attachments/assets/ba03eefc-7307-411b-9de5-1e13def0c0bb" />
<img width="1918" height="869" alt="b" src="https://github.com/user-attachments/assets/e20e38e7-e901-4dd2-866c-ed5274f12d70" />
<img width="1918" height="890" alt="a" src="https://github.com/user-attachments/assets/9603230e-4685-40d4-9a1c-828d58899d7f" />
<img width="1717" height="815" alt="d" src="https://github.com/user-attachments/assets/714d9ac9-2ea1-4cd8-9b8b-6d26e1c12be7" />


---
##  Structure
AutomateX/
│
├── app.py
├── requirements.txt
├── .env
│
├── utils/
│   ├── ioc_detect.py
│   ├── scoring.py
│   ├── defang.py
│   ├── normalize.py
│   └── cache.py
│
├── providers/
│   └── virustotal.py
│
└── assets/
    └── favicon.png

##  Getting Started

### Clone the repo
```bash
git clone https://github.com/mahmoudibrahim29/AutomateX-Threat-Intel.git
cd AutomateX-Threat-Intel
