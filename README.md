# Log File Analyzer for Intrusion Detection System (IDS)

A log-based intrusion detection system that analyzes system, network, and application logs to identify suspicious activities, security threats, and potential intrusions using rule-based and statistical techniques.

This project focuses on **detection, not visualization-first nonsense**. Alerts and insights come from log intelligence, not pretty dashboards.

---

## 📌 Features

- Multi-source log ingestion (system, auth, web, firewall)
- Rule-based intrusion detection
- Threshold-based anomaly detection
- IP behavior analysis (brute force, scanning patterns)
- Timestamp correlation for attack sequences
- Severity-based alerting
- Structured output for further SIEM integration

---

## 🧠 Detection Capabilities

| Threat Type | Detection Logic |
|------------|-----------------|
| Brute Force Attack | Repeated failed logins from same IP |
| Port Scanning | High number of connection attempts in short time |
| Suspicious IP Activity | Access to restricted endpoints |
| Privilege Escalation | Unauthorized sudo or admin attempts |
| Malware Indicators | Known malicious patterns in logs |

---
## ⚙️ Tech Stack

- **Language:** Python 3.x
- **Parsing:** Regex + datetime
- **Storage:** JSON / CSV
- **Detection Type:** Rule-based + statistical thresholds
- **Platform:** Linux (recommended)

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/log-file-analyzer-ids.git
cd log-file-analyzer-ids
pip install -r requirements.txt
