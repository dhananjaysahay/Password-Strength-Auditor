"""Export network scan results to HTML reports."""

from pathlib import Path
from datetime import datetime
from .scanner import Device, NetworkScanner


class ReportExporter:
    """Generate HTML reports from network scan results."""

    def export_html(self, devices: list[Device], network: str, output_path: str | None = None) -> str:
        output = Path(output_path or f"reports_output/network_scan_{datetime.now():%Y%m%d_%H%M}.html")
        output.parent.mkdir(parents=True, exist_ok=True)
        scanner = NetworkScanner()

        rows = ""
        for dev in devices:
            ports = ", ".join(f"{p['port']}/{p['service']}" for p in dev.open_ports) or "None"
            risks = scanner.identify_risks(dev)
            risk_html = "<br>".join(f'<span class="risk">{r}</span>' for r in risks) or '<span class="ok">None</span>'
            rows += f"""
            <tr>
                <td>{dev.ip}</td><td>{dev.mac}</td><td>{dev.hostname or '—'}</td>
                <td>{dev.vendor or '—'}</td><td>{ports}</td><td>{risk_html}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Network Scan — {network}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 2rem; background: #0d1117; color: #c9d1d9; }}
    h1 {{ color: #58a6ff; }} h2 {{ color: #8b949e; margin-top: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th {{ background: #161b22; color: #58a6ff; padding: 10px; text-align: left; border: 1px solid #30363d; }}
    td {{ padding: 8px 10px; border: 1px solid #30363d; }}
    tr:hover {{ background: #161b22; }}
    .risk {{ color: #f85149; }} .ok {{ color: #3fb950; }}
    .meta {{ color: #8b949e; font-size: 0.9em; }}
</style></head><body>
<h1>Network Scan Report</h1>
<p class="meta">Target: {network} • Hosts: {len(devices)} • Generated: {datetime.now():%Y-%m-%d %H:%M}</p>
<table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Open Ports</th><th>Risks</th></tr>
{rows}
</table></body></html>"""

        output.write_text(html)
        return str(output)
