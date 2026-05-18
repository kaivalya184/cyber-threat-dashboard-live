# 🛡️ Cyber Threat Dashboard (Live)

A **real-time** cybersecurity threat monitoring dashboard that actually scans your local network, detects risky open ports, monitors your system health, and logs security events live.

---

## 🖼️ Screenshots
> *(Add screenshots after running)*

---

## ✨ What Makes It LIVE

| Feature | How it works |
|---------|-------------|
| 🔍 Network scan | Pings all 254 IPs on your subnet every 90 seconds |
| 🔐 Port detection | Checks 14 common ports per device (SSH, RDP, SMB, etc.) |
| ⚠️ Risk scoring | Auto-rates each device: CRITICAL / HIGH / MEDIUM / LOW / SAFE |
| 📊 System health | Real CPU & RAM usage from your machine |
| 🌐 Network traffic | Live MB sent/received, packet counts |
| 📋 Security log | Auto-logs every device found + risky port warnings |
| 🔄 Auto-refresh | Dashboard polls every 10 seconds, scan every 90 seconds |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask |
| System Monitoring | psutil |
| Network Scanning | socket, subprocess, concurrent.futures |
| Frontend | HTML5, CSS3, Vanilla JS |
| Concepts | Network Security, Port Scanning, SOC Dashboard |

---

## ⚙️ How to Run

```bash
# 1. Clone the repo
git clone https://github.com/KaivalyaIngole/cyber-threat-dashboard.git
cd cyber-threat-dashboard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py

# 4. Open in browser
# http://localhost:5000
```

> First scan starts automatically on launch (~30–60 seconds for full results)

---

## 📁 Project Structure

```
cyber-threat-dashboard/
├── app.py              ← Flask backend + real network scanner
├── requirements.txt    ← flask, psutil
├── .gitignore
├── README.md
└── templates/
    └── index.html      ← Live dashboard UI
```

---

## 🔐 Risk Level Logic

| Level | Condition |
|-------|-----------|
| CRITICAL | 2+ risky ports open (Telnet, FTP, RDP, SMB, VNC) |
| HIGH | 1 risky port open |
| MEDIUM | 3+ any ports open |
| LOW | 1–2 standard ports |
| SAFE | No open ports detected |

---

## ⚠️ Disclaimer

For **educational and authorized use only**. Only scan networks you own or have permission to scan.

---

## 👨‍💻 Author

**Kaivalya Ingole** — Cybersecurity Enthusiast | EC-Council Certified | Developer  
🔗 [GitHub](https://github.com/KaivalyaIngole)

---

> *"Knowing your network is the first step to securing it."*
