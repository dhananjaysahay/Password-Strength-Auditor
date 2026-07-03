# SecAudit — Security Auditing Toolkit

A modular Python toolkit for password strength analysis, local network auditing, and WPA handshake protocol analysis. Built for security engineers, penetration testers, and anyone learning about defensive security.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

> **Disclaimer:** This tool is for authorized security testing and education only. Only scan networks you own or have explicit permission to audit. The handshake analyzer performs protocol analysis — it does NOT crack passwords or recover keys.

## Modules

### Password Auditor
Estimate entropy, detect weak patterns (keyboard walks, dictionary words, leet speak, dates), check against a local breach database, and get actionable improvement suggestions.

```bash
python main.py password
python main.py password "MyP@ssw0rd!"
```

### Network Scanner
Discover devices on your local network, identify open ports, flag insecure configurations, and export HTML reports. Uses ARP discovery and TCP/nmap scanning.

```bash
python main.py network 192.168.1.0/24
```

### WPA Handshake Analyzer
Read `.pcap` captures, detect WPA 4-way handshake frames, display metadata (BSSID, SSID, channel, encryption), and get a stage-by-stage educational walkthrough of the authentication protocol.

```bash
python main.py handshake capture.pcap
```

### Web Dashboard
All three modules are also available as a FastAPI-backed web app with a dark, dashboard-style UI — password analysis is fully live, while network scanning and handshake analysis run in a demo mode (since both need local system/packet access unavailable to a hosted server).

```bash
uvicorn web.app:app --reload
```

Then open `http://localhost:8000`. A `render.yaml` is included for one-click deployment to [Render](https://render.com).

## Quick Start

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Dependencies
- **rich** — terminal UI, tables, progress bars
- **matplotlib** — strength charts and flow diagrams
- **scapy** — packet capture reading, ARP discovery
- **python-nmap** — port scanning (optional, falls back to socket scan)
- **fastapi** / **uvicorn** — web dashboard backend

## Architecture

```
toolkit/
├── common/
│   ├── reporter.py        # Shared HTML report generation
│   └── visualizer.py      # Matplotlib charts and diagrams
├── password/
│   ├── analyzer.py        # Entropy, char classes, structural analysis
│   ├── patterns.py        # Keyboard walks, dictionary, leet, dates
│   ├── breach_checker.py  # SQLite breach database lookup
│   └── scorer.py          # 0-100 scoring with explanations
├── network/
│   ├── scanner.py         # ARP discovery, port scanning, risk detection
│   ├── dashboard.py       # Rich terminal dashboard
│   └── exporter.py        # HTML report export
└── handshake/
    ├── pcap_reader.py     # Read .pcap files, extract metadata
    ├── detector.py        # 4-way handshake frame identification
    └── protocol.py        # Educational protocol explainer

web/
├── app.py                 # FastAPI backend exposing the toolkit over HTTP
└── static/                # Dashboard frontend (HTML/JS)
```

## Scoring System (Password)

| Factor | Max Points | Description |
|--------|-----------|-------------|
| Length | 25 | 2 points per character, capped at 25 |
| Entropy | 25 | Based on character pool and length |
| Character variety | 20 | 5 points per class (upper, lower, digits, special) |
| Uniqueness | 10 | Ratio of distinct characters |
| Pattern penalties | -30 | Deducted for keyboard walks, dictionary words, etc. |
| Breach penalty | -30 | Flat penalty if found in breach database |

## Running Tests

```bash
pytest tests/ -v
```

## License

MIT
