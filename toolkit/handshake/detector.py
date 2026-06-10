"""
WPA 4-way handshake detection and protocol stage identification.
Educational analysis only — identifies handshake completeness,
does NOT extract or recover keys.
"""

from dataclasses import dataclass, field

try:
    from scapy.all import Dot11, EAPOL, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class HandshakeFrame:
    """One frame of the 4-way handshake."""
    stage: int  # 1-4
    source: str
    destination: str
    bssid: str
    has_anonce: bool = False
    has_snonce: bool = False
    has_mic: bool = False
    has_install: bool = False
    raw_key_info: int = 0


@dataclass
class HandshakeResult:
    """Result of handshake detection for one AP-client pair."""
    bssid: str
    client_mac: str
    ssid: str = ""
    frames: list[HandshakeFrame] = field(default_factory=list)
    is_complete: bool = False
    stages_found: list[int] = field(default_factory=list)
    missing_stages: list[int] = field(default_factory=list)


class HandshakeDetector:
    """Detect and classify WPA 4-way handshake frames in a packet capture."""

    def detect(self, packets: list, networks: list[dict] | None = None) -> list[HandshakeResult]:
        if not HAS_SCAPY:
            raise ImportError("scapy is required")

        ssid_map = {}
        if networks:
            ssid_map = {n["bssid"].lower(): n.get("ssid", "") for n in networks}

        eapol_frames = [p for p in packets if p.haslayer(EAPOL)]
        pairs: dict[tuple[str, str], list[HandshakeFrame]] = {}

        for pkt in eapol_frames:
            if not pkt.haslayer(Dot11):
                continue

            dot11 = pkt[Dot11]
            src = dot11.addr2
            dst = dot11.addr1
            bssid = dot11.addr3 or ""

            eapol_data = bytes(pkt[EAPOL])
            if len(eapol_data) < 99:
                continue

            key_info = int.from_bytes(eapol_data[5:7], "big")
            stage = self._identify_stage(key_info, src, bssid)

            # Determine AP vs client
            if bssid and src and src.lower() == bssid.lower():
                client = dst
            else:
                client = src

            pair_key = (bssid.lower() if bssid else "", client.lower() if client else "")

            frame = HandshakeFrame(
                stage=stage,
                source=src.upper() if src else "",
                destination=dst.upper() if dst else "",
                bssid=bssid.upper() if bssid else "",
                has_anonce=stage in (1, 3),
                has_snonce=stage in (2, 3),
                has_mic=stage in (2, 3, 4),
                has_install=stage == 3,
                raw_key_info=key_info,
            )

            if pair_key not in pairs:
                pairs[pair_key] = []
            pairs[pair_key].append(frame)

        results = []
        for (bssid, client), frames in pairs.items():
            stages = sorted(set(f.stage for f in frames))
            results.append(HandshakeResult(
                bssid=bssid.upper(),
                client_mac=client.upper(),
                ssid=ssid_map.get(bssid, ""),
                frames=frames,
                is_complete=set(stages) >= {1, 2, 3, 4},
                stages_found=stages,
                missing_stages=[s for s in [1, 2, 3, 4] if s not in stages],
            ))

        return results

    def _identify_stage(self, key_info: int, src: str, bssid: str) -> int:
        """
        Identify which stage of the 4-way handshake based on key_info flags.
        Bit 3: Install, Bit 6: Ack, Bit 8: MIC, Bit 9: Secure
        """
        ack = bool(key_info & (1 << 7))
        mic = bool(key_info & (1 << 8))
        install = bool(key_info & (1 << 6))
        secure = bool(key_info & (1 << 9))

        is_from_ap = src and bssid and src.lower() == bssid.lower()

        if is_from_ap and ack and not mic:
            return 1  # AP sends ANonce
        if not is_from_ap and mic and not ack:
            return 2  # Client sends SNonce + MIC
        if is_from_ap and ack and mic and install:
            return 3  # AP sends GTK + Install
        if not is_from_ap and mic and secure:
            return 4  # Client confirms
        if is_from_ap:
            return 1 if not mic else 3
        return 2 if not secure else 4
