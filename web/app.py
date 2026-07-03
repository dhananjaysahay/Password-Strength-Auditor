"""
SecAudit Web — FastAPI backend serving the security toolkit as a web app.
"""

import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Add project root to path so toolkit imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

from toolkit.password.analyzer import PasswordAnalyzer
from toolkit.password.patterns import PatternDetector
from toolkit.password.breach_checker import BreachChecker
from toolkit.password.scorer import PasswordScorer
from toolkit.network.scanner import NetworkScanner

app = FastAPI(title="SecAudit", version="1.0.0")

# --- Singletons ---
common_file = Path(__file__).parent.parent / "data" / "common_passwords.txt"
_words = common_file.read_text().splitlines() if common_file.exists() else []
_analyzer = PasswordAnalyzer()
_detector = PatternDetector(common_words=_words)
_breach = BreachChecker()
_scorer = PasswordScorer()


# --- Schemas ---
class PasswordRequest(BaseModel):
    password: str


# --- API routes ---

@app.post("/api/password/analyze")
def analyze_password(req: PasswordRequest):
    analysis = _analyzer.analyze(req.password)
    patterns = _detector.detect_all(req.password)
    breach = _breach.check(req.password)
    score = _scorer.score(analysis, patterns, breach)

    return {
        "score": score.score,
        "label": score.label,
        "color": score.color,
        "breakdown": score.breakdown,
        "suggestions": score.suggestions,
        "patterns": [
            {"type": p.pattern_type, "matched": p.matched,
             "severity": p.severity, "description": p.description}
            for p in patterns
        ],
        "breach": {"is_breached": breach.is_breached, "message": breach.message},
        "analysis": {
            "length": analysis.length,
            "entropy": round(analysis.entropy, 1),
            "char_class_count": analysis.char_class_count,
            "has_uppercase": analysis.has_uppercase,
            "has_lowercase": analysis.has_lowercase,
            "has_digits": analysis.has_digits,
            "has_special": analysis.has_special,
            "unique_chars": analysis.unique_chars,
            "unique_ratio": round(analysis.unique_ratio, 2),
            "consecutive_repeats": analysis.consecutive_repeats,
            "sequential_chars": analysis.sequential_chars,
        },
    }


@app.get("/api/network/demo")
def network_demo():
    """Return realistic sample data since network scanning requires system access."""
    scanner = NetworkScanner()
    return {
        "target": "192.168.1.0/24",
        "mode": "demo",
        "note": "Live scanning requires local system access. This shows a sample audit.",
        "devices": [
            {
                "ip": "192.168.1.1", "mac": "A4:CF:12:B3:22:10",
                "hostname": "gateway.local", "vendor": "TP-Link",
                "open_ports": [
                    {"port": 80, "state": "open", "service": "http", "version": "lighttpd/1.4"},
                    {"port": 443, "state": "open", "service": "https", "version": ""},
                    {"port": 53, "state": "open", "service": "dns", "version": "dnsmasq-2.86"},
                ],
                "risks": [],
            },
            {
                "ip": "192.168.1.15", "mac": "DC:A6:32:AA:BB:CC",
                "hostname": "raspberrypi.local", "vendor": "Raspberry Pi",
                "open_ports": [
                    {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 9.2"},
                    {"port": 80, "state": "open", "service": "http", "version": "nginx/1.22"},
                    {"port": 3306, "state": "open", "service": "mysql", "version": "MySQL 8.0"},
                ],
                "risks": [scanner.INSECURE_PORTS[3306]],
            },
            {
                "ip": "192.168.1.20", "mac": "00:1A:2B:3C:4D:5E",
                "hostname": "NAS-backup", "vendor": "Synology",
                "open_ports": [
                    {"port": 443, "state": "open", "service": "https", "version": ""},
                    {"port": 445, "state": "open", "service": "smb", "version": "Samba 4.17"},
                    {"port": 5000, "state": "open", "service": "http", "version": "DSM 7.2"},
                ],
                "risks": [scanner.INSECURE_PORTS[445]],
            },
            {
                "ip": "192.168.1.42", "mac": "F0:18:98:11:22:33",
                "hostname": "dev-workstation", "vendor": "Apple",
                "open_ports": [
                    {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 9.6"},
                    {"port": 5900, "state": "open", "service": "vnc", "version": ""},
                ],
                "risks": [scanner.INSECURE_PORTS[5900]],
            },
            {
                "ip": "192.168.1.100", "mac": "B8:27:EB:44:55:66",
                "hostname": "iot-camera-01", "vendor": "Hikvision",
                "open_ports": [
                    {"port": 80, "state": "open", "service": "http", "version": ""},
                    {"port": 23, "state": "open", "service": "telnet", "version": ""},
                    {"port": 554, "state": "open", "service": "rtsp", "version": ""},
                ],
                "risks": [scanner.INSECURE_PORTS[23]],
            },
        ],
        "insecure_ports_reference": {
            str(k): v for k, v in scanner.INSECURE_PORTS.items()
        },
    }


@app.get("/api/handshake/demo")
def handshake_demo():
    """Return sample handshake analysis for educational walkthrough."""
    return {
        "mode": "demo",
        "note": "Upload a .pcap file locally to analyze real captures. This shows an educational walkthrough.",
        "capture": {
            "filename": "sample_capture.pcap",
            "total_packets": 14832,
            "dot11_packets": 12105,
            "eapol_packets": 8,
            "beacon_packets": 2947,
        },
        "networks": [
            {"ssid": "HomeNet-5G", "bssid": "A4:CF:12:B3:22:10",
             "channel": 36, "encryption": "WPA2-PSK (CCMP)"},
            {"ssid": "IoT-Network", "bssid": "00:1A:2B:3C:4D:5E",
             "channel": 6, "encryption": "WPA2-PSK (TKIP)"},
        ],
        "handshakes": [
            {
                "bssid": "A4:CF:12:B3:22:10",
                "client_mac": "DC:A6:32:AA:BB:CC",
                "ssid": "HomeNet-5G",
                "is_complete": True,
                "stages_found": [1, 2, 3, 4],
                "missing_stages": [],
                "walkthrough": [
                    {
                        "stage": 1, "title": "Message 1 — AP sends ANonce",
                        "captured": True,
                        "summary": "The access point generates a random number (ANonce) and sends it to the client. This starts the key negotiation process.",
                        "security_note": "The ANonce is sent in cleartext. An attacker who captures this can attempt offline key derivation.",
                        "direction": "AP → Client",
                    },
                    {
                        "stage": 2, "title": "Message 2 — Client sends SNonce + MIC",
                        "captured": True,
                        "summary": "The client generates its own random number (SNonce), derives the Pairwise Transient Key (PTK) from the PSK + ANonce + SNonce, and sends the SNonce along with a Message Integrity Code (MIC) to prove it knows the PSK.",
                        "security_note": "This is the critical frame for offline attacks. The MIC proves the client derived a valid PTK — enough for dictionary attacks against the PSK.",
                        "direction": "Client → AP",
                    },
                    {
                        "stage": 3, "title": "Message 3 — AP sends GTK + Install flag",
                        "captured": True,
                        "summary": "The AP verifies the MIC, derives the same PTK, then sends the Group Temporal Key (GTK) encrypted with the PTK. The Install flag tells the client to start using the keys.",
                        "security_note": "The GTK is encrypted. KRACK attacks exploited retransmissions of this message to force nonce reuse.",
                        "direction": "AP → Client",
                    },
                    {
                        "stage": 4, "title": "Message 4 — Client confirms",
                        "captured": True,
                        "summary": "The client confirms key installation. Both sides now use the PTK for unicast and GTK for broadcast/multicast traffic.",
                        "security_note": "After this, all data frames are encrypted. Missing this message doesn't prevent offline attacks but may cause AP to retransmit Message 3.",
                        "direction": "Client → AP",
                    },
                ],
            },
        ],
        "security_summary": {
            "total_handshakes": 1,
            "complete": 1,
            "incomplete": 0,
            "recommendations": [
                "Use WPA3-SAE when possible — it eliminates offline dictionary attacks entirely",
                "Ensure your PSK has high entropy (20+ random characters)",
                "Enable Protected Management Frames (PMF / 802.11w) to prevent deauth attacks",
                "Monitor for unusual deauthentication floods which may indicate capture attempts",
            ],
        },
    }


# Serve frontend
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
def index():
    return FileResponse(str(static_dir / "index.html"))
