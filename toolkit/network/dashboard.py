"""Rich terminal dashboard for network scan results."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

from .scanner import Device


class NetworkDashboard:
    """Renders network scan results as a rich terminal dashboard."""

    def __init__(self):
        self.console = Console()

    def display(self, devices: list[Device], network: str):
        self.console.print()
        self.console.print(Panel(
            f"[bold]Network Scan Results[/bold]\n"
            f"Target: [cyan]{network}[/cyan]  •  "
            f"Hosts found: [green]{len(devices)}[/green]",
            border_style="blue",
        ))

        # Device table
        table = Table(title="Discovered Devices", show_lines=True, border_style="dim")
        table.add_column("#", style="dim", width=4)
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Hostname")
        table.add_column("Vendor", style="dim")
        table.add_column("Open Ports", style="green")
        table.add_column("Risks", style="red")

        for i, dev in enumerate(devices, 1):
            ports = ", ".join(str(p["port"]) for p in dev.open_ports) or "—"
            from .scanner import NetworkScanner
            risks = NetworkScanner().identify_risks(dev)
            risk_str = f"[red]{len(risks)} issue(s)[/red]" if risks else "[green]None[/green]"
            table.add_row(str(i), dev.ip, dev.mac, dev.hostname or "—",
                          dev.vendor or "—", ports, risk_str)

        self.console.print(table)

    def display_risks(self, devices: list[Device]):
        """Show detailed risk report."""
        from .scanner import NetworkScanner
        scanner = NetworkScanner()
        any_risks = False

        for dev in devices:
            risks = scanner.identify_risks(dev)
            if risks:
                any_risks = True
                self.console.print(f"\n[bold red]⚠ {dev.ip}[/bold red] ({dev.hostname or dev.mac})")
                for risk in risks:
                    self.console.print(f"  [red]•[/red] {risk}")

        if not any_risks:
            self.console.print("\n[green]✓ No insecure configurations detected[/green]")
