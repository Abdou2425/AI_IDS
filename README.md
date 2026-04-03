# 🛡️ AI-IDS — Intelligent Intrusion Detection System
![Python](https://img.shields.io/badge/Python-14354C?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2C2D72?style=for-the-badge&logo=python&logoColor=white)
![ML](https://img.shields.io/badge/Machine_Learning-FF6F00?style=for-the-badge&logo=scikitlearn&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)

## 📌 Overview
**AI-IDS** is a network intrusion detection system built in Python using **Scapy** for real-time packet analysis. It combines **rule-based detection** with a **machine learning layer** (coming soon) to identify and alert on a wide range of network attacks.

The system logs every packet as a feature vector to **JSONL datasets**, making it ML-ready from day one. Each detector runs independently or together under a single unified manager.

> ⚠️ **This project is intended for ethical and educational use only.**  
> Deploy only on networks you own or have explicit permission to monitor.

---

## 🎯 Detectors

### 🔴 SYN Flood & SYN Scan — `detectors/syn.py`
- Detects **SYN flood** attacks by tracking per-port packet rates using a sliding window
- Detects **SYN scan / port scanning** by counting unique destination ports per source IP
- Severity tiers: LOW → MEDIUM → HIGH → CRITICAL

### 🟠 ARP Spoofing — `detectors/arp.py`
- Monitors ARP replies for MAC address changes on known IPs
- Detects **gratuitous ARP** and **broadcast poisoning**
- Uses a **suspicion scoring system** (MAC change, rate, uniqueness, broadcast)
- Severity tiers: LOW → MEDIUM → HIGH

### 🟡 ICMP Flood — `detectors/icmp.py`
- Tracks Echo Request (ping) rates per source IP using a sliding window
- Logs **average and max packet size** to detect amplification attempts
- Severity tiers: LOW → MEDIUM → HIGH → CRITICAL

### 🟢 DNS Flood & DNS Tunnel — `detectors/dns.py`
- Detects **DNS flood** by monitoring query rates per source IP
- Detects **DNS tunneling** via average query name length (`avg_qname_len > 50`)
- Rich feature set: domain diversity ratio, top domain ratio, query type distribution
- Severity tiers: LOW → MEDIUM → HIGH → CRITICAL

### 🔵 Brute Force & Credential Stuffing — `detectors/bruteforce.py`
- Monitors authentication ports only: **SSH (22), FTP (21), Telnet (23)**
- Detects **brute force** via high SYN ratio + focused port targeting
- Detects **credential stuffing** via spread across multiple ports
- Filters out false positives: private IP check, self-traffic skip, whitelist
- Severity tiers: LOW → MEDIUM → HIGH → CRITICAL

---

## 🧠 Core Module — `core/`
Shared logic extracted from all detectors into three reusable modules:

| File | Responsibility |
|---|---|
| `core/logger.py` | Persistent JSONL logger — opens once, flushes every write, closes on exit |
| `core/window.py` | `clean_old()` sliding window eviction + `prune_stale()` memory cleanup |
| `core/alerting.py` | `build_alert()` standardized alert builder + per-detector severity functions |

---

## 📂 Project Structure

```
ai-ids/
│
├── detectors/                  ← rule-based detection modules
│   ├── syn.py                  ← SYN Flood + SYN Scan
│   ├── arp.py                  ← ARP Spoofing
│   ├── icmp.py                 ← ICMP Flood
│   ├── dns.py                  ← DNS Flood + DNS Tunnel
│   └── bruteforce.py           ← Brute Force + Credential Stuffing
│
├── core/                       ← shared logic
│   ├── logger.py
│   ├── window.py
│   └── alerting.py
│
├── data/                       ← JSONL datasets (auto-generated)
│   ├── syn_dataset.jsonl
│   ├── arp_dataset.jsonl
│   ├── icmp_dataset.jsonl
│   ├── dns_logs.jsonl
│   └── bruteforce_logs.jsonl
│
├── ai/                         ← 🔜 ML layer (coming soon)
│
├── dashboard/                  ← 🔜 Real-time dashboard (coming soon)
│   ├── backend/                ← Node.js + Express + Socket.io + MongoDB
│   └── frontend/               ← React
│
├── reports/                    ← 🔜 Report generator (coming soon)
│
├── manager.py                  ← single entry point, runs all detectors
└── README.md
```

---

## 🛠️ Tech Stack

### Language
- Python 3.x

### Libraries
All dependencies are listed in `requirements.txt`

---

## 📦 Setup & Configuration

### 🔹 Prerequisites
- Python 3.8 or higher
- pip
- Root / Administrator privileges (required for raw packet capture)
- Linux recommended (Kali, Ubuntu) — Scapy works best on Linux

---

### 🔹 Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/ai-ids.git
cd ai-ids
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate it:
```bash
# Linux / Kali
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Create the data directory:
```bash
mkdir -p data
```

---

## ▶️ How to Run

### 🔹 1. Run all detectors at once
```bash
sudo python manager.py
```

### 🔹 2. Run a single detector
```bash
sudo python detectors/syn.py
sudo python detectors/arp.py
sudo python detectors/icmp.py
sudo python detectors/dns.py
sudo python detectors/bruteforce.py
```

### 🔹 3. Override the network interface
Set `IFACE` at the top of any detector file or in `manager.py`:
```python
IFACE = "eth0"   # or "wlan0", "ens33", etc.
```
Leave it as `None` for auto-detection.

---

## 📊 Dataset & ML Readiness

Every packet processed by any detector is logged to its JSONL file as a **feature vector**:

```json
{
  "timestamp": "2024-01-01 12:00:00",
  "source_ip": "192.168.1.5",
  "target_ip": "192.168.1.1",
  "pps": 4.2,
  "unique_ports": 3,
  "total_packets": 12,
  "label": 0
}
```

| `label` | Meaning |
|---|---|
| `0` | Normal traffic |
| `1` | Attack traffic (set by alert path) |

Loading the dataset for ML training:
```python
import json

data = [json.loads(line) for line in open("data/syn_dataset.jsonl")]
```

---

## 🚀 Roadmap

- [x] Rule-based SYN Flood / SYN Scan detection
- [x] Rule-based ARP Spoofing detection
- [x] Rule-based ICMP Flood detection
- [x] Rule-based DNS Flood / Tunnel detection
- [x] Rule-based Brute Force / Credential Stuffing detection
- [x] Shared `core/` module
- [x] JSONL dataset logging with `label` field
- [ ] 🔜 AI layer — train model on collected datasets
- [ ] 🔜 Real-time dashboard — React + Node.js + MongoDB
- [ ] 🔜 Report generator — PDF/HTML session reports
- [ ] 🔜 DHCP attack detection

---

## 📜 License
This project was built as part of a cybersecurity academic project.
Intended for ethical learning, lab environments, and research only.
Unauthorized use on networks without permission is prohibited.
