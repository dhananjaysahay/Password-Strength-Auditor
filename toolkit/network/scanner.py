"""
Network device discovery and port scanning.
Uses ARP for host discovery and python-nmap for port scanning.
Only for networks you own or have explicit permission to scan.
"""

import socket
from dataclasses import dataclass, field

try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    open_ports: list[dict] = field(default_factory=list)
    os_guess: str = ""


class NetworkScanner:
    """Discover devices and scan ports on a local network."""

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443]

    INSECURE_PORTS = {
        21: "FTP — credentials sent in plaintext",
        23: "Telnet — fully unencrypted remote access",
        25: "SMTP — may allow open relay",
        110: "POP3 — credentials in plaintext (use 995 instead)",
        135: "RPC — common Windows attack vector",
        139: "NetBIOS — prone to enumeration attacks",
        143: "IMAP — credentials in plaintext (use 993 instead)",
        445: "SMB — frequent target for ransomware",
        1433: "MSSQL — should not be internet-exposed",
        3306: "MySQL — should not be internet-exposed",
        3389: "RDP — brute-force target, use VPN instead",
        5432: "PostgreSQL — should not be internet-exposed",
        5900: "VNC — weak authentication, use SSH tunnel",
    }

    def discover_hosts(self, network: str = "192.168.1.0/24", timeout: int = 3) -> list[Device]:
        """ARP scan to discover live hosts on the local network."""
        if not HAS_SCAPY:
            return self._fallback_discover(network)

        arp = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(broadcast / arp, timeout=timeout, retry=1)

        devices = []
        for sent, received in answered:
            hostname = self._resolve_hostname(received.psrc)
            devices.append(Device(
                ip=received.psrc,
                mac=received.hwsrc.upper(),
                hostname=hostname,
                vendor=self._lookup_vendor(received.hwsrc),
            ))
        return sorted(devices, key=lambda d: socket.inet_aton(d.ip))

    def scan_ports(self, target: str, ports: list[int] | None = None) -> list[dict]:
        """Scan common ports on a target host."""
        ports = ports or self.COMMON_PORTS

        if HAS_NMAP:
            return self._nmap_scan(target, ports)
        return self._socket_scan(target, ports)

    def identify_risks(self, device: Device) -> list[str]:
        """Flag insecure configurations based on open ports."""
        risks = []
        for port_info in device.open_ports:
            port = port_info["port"]
            if port in self.INSECURE_PORTS:
                risks.append(f"Port {port} open — {self.INSECURE_PORTS[port]}")
        return risks

    def _nmap_scan(self, target: str, ports: list[int]) -> list[dict]:
        scanner = nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports)
        scanner.scan(target, port_str, arguments="-sV --open -T4")

        results = []
        if target in scanner.all_hosts():
            for proto in scanner[target].all_protocols():
                for port in scanner[target][proto]:
                    info = scanner[target][proto][port]
                    if info["state"] == "open":
                        results.append({
                            "port": port,
                            "state": "open",
                            "service": info.get("name", "unknown"),
                            "version": info.get("version", ""),
                        })
        return results

    def _socket_scan(self, target: str, ports: list[int]) -> list[dict]:
        """Fallback TCP connect scan when nmap is unavailable."""
        results = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((target, port)) == 0:
                results.append({
                    "port": port,
                    "state": "open",
                    "service": self._guess_service(port),
                    "version": "",
                })
            sock.close()
        return results

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ""

    def _lookup_vendor(self, mac: str) -> str:
        """Lookup vendor from OUI prefix."""
        from pathlib import Path
        oui_file = Path(__file__).parent.parent.parent / "data" / "oui_vendors.txt"
        if not oui_file.exists():
            return ""
        prefix = mac.upper().replace(":", "")[:6]
        try:
            with open(oui_file) as f:
                for line in f:
                    if line.startswith(prefix):
                        return line.split(None, 1)[1].strip()
        except (IOError, IndexError):
            pass
        return ""

    def _guess_service(self, port: int) -> str:
        common = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                  80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
                  3306: "mysql", 3389: "rdp", 5432: "postgresql", 8080: "http-proxy"}
        return common.get(port, "unknown")

    def _fallback_discover(self, network: str) -> list[Device]:
        """Basic ping sweep when scapy is not available."""
        import subprocess
        base = ".".join(network.split(".")[:3])
        devices = []
        for i in range(1, 255):
            ip = f"{base}.{i}"
            try:
                result = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                       capture_output=True, timeout=2)
                if result.returncode == 0:
                    devices.append(Device(ip=ip, mac="", hostname=self._resolve_hostname(ip)))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return devices
