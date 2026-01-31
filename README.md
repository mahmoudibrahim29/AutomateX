# AutomateX
AutomateX is a SOC-focused **Threat Intelligence &amp; IOC Reputation Checker** built with Python and Streamlit.  

pip install -r requirements.txt
 
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

> Add screenshots here  
> (Dashboard, Results Table, IOC Details, MITRE Mapping)

---

##  Getting Started

### Clone the repo
```bash
git clone https://github.com/mahmoudibrahim29/AutomateX-Threat-Intel.git
cd AutomateX-Threat-Intel
