# Basic Intrusion Detection System (IDS)

A simple Python-based Intrusion Detection System that detects **port scans** and **suspicious TCP activity** in real-time using [Scapy](https://scapy.readthedocs.io/).

##  Features
- Monitors live network traffic
- Detects possible port scans within a time window
- Logs alerts to both console and a log file (`alerts.log`)
- Customizable thresholds for detection
- Lightweight and easy to run

---

##  Requirements
- Python 3.8+
- [Scapy](https://scapy.readthedocs.io/en/latest/introduction.html)

Install dependencies:
```bash
pip install scapy
