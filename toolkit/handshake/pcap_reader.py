"""
Read and parse .pcap files for WPA/WPA2 handshake analysis.
Educational protocol analysis only — no key recovery or cracking.
"""

from dataclasses import dataclass, field
from pathlib import Path

try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, EAPOL, Dot11Auth
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class PcapMetadata:
    filename: str = ""
    total_packets: int = 0
    dot11_packets: int = 0
    eapol_packets: int = 0
    beacon_packets: int = 0
    networks: list[dict] = field(default_factory=list)


class PcapReader:
    """Read pcap files and extract 802.11 metadata."""

    def read(self, filepath: str) -> tuple[list, PcapMetadata]:
        if not HAS_SCAPY:
            raise ImportError("scapy is required for pcap analysis — pip install scapy")

        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        if path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
            raise ValueError(f"Unsupported file type: {path.suffix}")

        packets = rdpcap(str(path))
        meta = PcapMetadata(filename=path.name, total_packets=len(packets))

        networks = {}
        for pkt in packets:
            if pkt.haslayer(Dot11):
                meta.dot11_packets += 1
            if pkt.haslayer(EAPOL):
                meta.eapol_packets += 1
            if pkt.haslayer(Dot11Beacon):
                meta.beacon_packets += 1
                ssid = self._extract_ssid(pkt)
                bssid = pkt[Dot11].addr3
                if bssid and bssid not in networks:
                    networks[bssid] = {
                        "ssid": ssid,
                        "bssid": bssid.upper(),
                        "channel": self._extract_channel(pkt),
                        "encryption": self._extract_encryption(pkt),
                    }

        meta.networks = list(networks.values())
        return packets, meta

    def _extract_ssid(self, pkt) -> str:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID element
                try:
                    return elt.info.decode("utf-8", errors="replace")
                except Exception:
                    return "<hidden>"
            elt = elt.payload.getlayer(Dot11Elt)
        return "<hidden>"

    def _extract_channel(self, pkt) -> int:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3:  # DS Parameter Set
                return int.from_bytes(elt.info[:1], "little") if elt.info else 0
            elt = elt.payload.getlayer(Dot11Elt)
        return 0

    def _extract_encryption(self, pkt) -> str:
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").strip()
        if "privacy" not in cap.lower():
            return "Open"

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 48:  # RSN (WPA2)
                return "WPA2"
            if elt.ID == 221 and elt.info and elt.info[:4] == b"\x00\x50\xf2\x01":
                return "WPA"
            elt = elt.payload.getlayer(Dot11Elt)
        return "WEP"
