#!/usr/bin/env python3
"""
SecAudit — Security auditing toolkit.

Usage:
    python main.py password              Interactive password strength audit
    python main.py password "MyP@ss"     Analyze a specific password
    python main.py network [CIDR]        Scan local network (default: 192.168.1.0/24)
    python main.py handshake FILE.pcap   Analyze a WPA handshake capture
"""

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.prompt import Prompt
from rich import print as rprint


console = Console()


# ──────────────────────────────────────────────
#  Password module
# ──────────────────────────────────────────────

def cmd_password(password: str | None = None):
    from toolkit.password.analyzer import PasswordAnalyzer
    from toolkit.password.patterns import PatternDetector
    from toolkit.password.breach_checker import BreachChecker
    from toolkit.password.scorer import PasswordScorer
    from toolkit.common.visualizer import password_strength_chart

    common_file = Path("data/common_passwords.txt")
    words = common_file.read_text().splitlines() if common_file.exists() else []

    analyzer = PasswordAnalyzer()
    detector = PatternDetector(common_words=words)
    breach = BreachChecker()
    scorer = PasswordScorer()

    if not password:
        console.print(Panel("[bold]Password Strength Auditor[/bold]\nType a password to analyze (or 'quit' to exit)",
                            border_style="blue"))
        while True:
            password = Prompt.ask("\n[cyan]Password[/cyan]")
            if password.lower() == "quit":
                break
            _analyze_password(password, analyzer, detector, breach, scorer)
    else:
        _analyze_password(password, analyzer, detector, breach, scorer)


def _analyze_password(password, analyzer, detector, breach, scorer):
    analysis = analyzer.analyze(password)
    patterns = detector.detect_all(password)
    breach_result = breach.check(password)
    score = scorer.score(analysis, patterns, breach_result)

    # Score bar
    bar_filled = "█" * (score.score // 2)
    bar_empty = "░" * (50 - score.score // 2)
    console.print(f"\n[{score.color}]{bar_filled}[/{score.color}][dim]{bar_empty}[/dim] "
                  f"[bold {score.color}]{score.score}/100 — {score.label}[/bold {score.color}]")

    # Breakdown table
    table = Table(title="Score Breakdown", border_style="dim", show_lines=True)
    table.add_column("Factor", style="cyan")
    table.add_column("Points", justify="right")
    table.add_column("Detail")
    for b in score.breakdown:
        pts = f"[green]+{b['points']}[/green]" if b["points"] > 0 else f"[red]{b['points']}[/red]"
        table.add_row(b["factor"], pts, b["detail"])
    console.print(table)

    # Patterns
    if patterns:
        console.print("\n[bold yellow]Patterns Detected:[/bold yellow]")
        for p in patterns:
            icon = "🔴" if p.severity == "high" else "🟡"
            console.print(f"  {icon} {p.description}")

    # Breach
    if breach_result.is_breached:
        console.print(f"\n[bold red]⚠ BREACHED:[/bold red] {breach_result.message}")

    # Suggestions
    console.print("\n[bold]Suggestions:[/bold]")
    for s in score.suggestions:
        console.print(f"  [green]→[/green] {s}")

    # Entropy detail
    console.print(f"\n[dim]Entropy: {analysis.entropy:.1f} bits | "
                  f"Length: {analysis.length} | "
                  f"Unique: {analysis.unique_chars}/{analysis.length} | "
                  f"Classes: {analysis.char_class_count}/4[/dim]")

    # Save chart
    try:
        from toolkit.common.visualizer import password_strength_chart
        chart_path = password_strength_chart(score.score, score.label, score.breakdown)
        console.print(f"[dim]Chart saved: {chart_path}[/dim]")
    except Exception:
        pass


# ──────────────────────────────────────────────
#  Network module
# ──────────────────────────────────────────────

def cmd_network(target: str = "192.168.1.0/24"):
    from toolkit.network.scanner import NetworkScanner
    from toolkit.network.dashboard import NetworkDashboard
    from toolkit.network.exporter import ReportExporter

    console.print(Panel(
        f"[bold]Network Scanner[/bold]\n"
        f"Target: [cyan]{target}[/cyan]\n"
        f"[dim]Only scan networks you own or have permission to audit[/dim]",
        border_style="blue"))

    scanner = NetworkScanner()
    dashboard = NetworkDashboard()

    with console.status("[bold blue]Discovering hosts..."):
        devices = scanner.discover_hosts(target)

    if not devices:
        console.print("[yellow]No hosts discovered.[/yellow]")
        return

    # Port scan each device
    with Progress(TextColumn("[bold blue]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}")) as progress:
        task = progress.add_task("Scanning ports", total=len(devices))
        for dev in devices:
            dev.open_ports = scanner.scan_ports(dev.ip)
            progress.advance(task)

    dashboard.display(devices, target)
    dashboard.display_risks(devices)

    # Export report
    exporter = ReportExporter()
    path = exporter.export_html(devices, target)
    console.print(f"\n[dim]Report saved: {path}[/dim]")


# ──────────────────────────────────────────────
#  Handshake module
# ──────────────────────────────────────────────

def cmd_handshake(filepath: str):
    from toolkit.handshake.pcap_reader import PcapReader
    from toolkit.handshake.detector import HandshakeDetector
    from toolkit.handshake.protocol import ProtocolExplainer
    from toolkit.common.visualizer import handshake_flow_diagram

    console.print(Panel(
        f"[bold]WPA Handshake Analyzer[/bold]\n"
        f"File: [cyan]{filepath}[/cyan]\n"
        f"[dim]Educational protocol analysis — no key recovery[/dim]",
        border_style="blue"))

    reader = PcapReader()
    try:
        packets, meta = reader.read(filepath)
    except (FileNotFoundError, ValueError, ImportError) as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    console.print(f"\n[bold]Capture Metadata[/bold]")
    console.print(f"  Total packets: {meta.total_packets}")
    console.print(f"  802.11 frames: {meta.dot11_packets}")
    console.print(f"  EAPOL frames:  {meta.eapol_packets}")
    console.print(f"  Beacons:       {meta.beacon_packets}")

    if meta.networks:
        table = Table(title="Detected Networks", border_style="dim")
        table.add_column("SSID", style="cyan")
        table.add_column("BSSID", style="yellow")
        table.add_column("Channel")
        table.add_column("Encryption")
        for net in meta.networks:
            table.add_row(net["ssid"], net["bssid"], str(net["channel"]), net["encryption"])
        console.print(table)

    detector = HandshakeDetector()
    handshakes = detector.detect(packets, meta.networks)

    if not handshakes:
        console.print("\n[yellow]No WPA handshakes detected in this capture.[/yellow]")
        return

    explainer = ProtocolExplainer()
    for hs in handshakes:
        console.print(f"\n[bold]Handshake: {hs.bssid} ↔ {hs.client_mac}[/bold]")
        console.print(f"  SSID: {hs.ssid or 'Unknown'}")
        console.print(f"  Complete: {'[green]Yes[/green]' if hs.is_complete else '[red]No[/red]'}")
        console.print(f"  Stages captured: {hs.stages_found}")
        if hs.missing_stages:
            console.print(f"  Missing: [red]{hs.missing_stages}[/red]")

        explanations = explainer.explain(hs)
        console.print(f"\n[bold]4-Way Handshake Walkthrough:[/bold]")
        for exp in explanations:
            icon = "[green]✓[/green]" if exp["captured"] else "[red]✗[/red]"
            console.print(f"\n  {icon} [bold]{exp['title']}[/bold]")
            console.print(f"    {exp['summary']}")
            console.print(f"    [dim]{exp['security_note']}[/dim]")

        # Generate flow diagram
        try:
            chart = handshake_flow_diagram(explanations)
            console.print(f"\n[dim]Flow diagram saved: {chart}[/dim]")
        except Exception:
            pass


# ──────────────────────────────────────────────
#  CLI dispatch
# ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        console.print(Panel(
            "[bold]SecAudit[/bold] — Security Auditing Toolkit\n\n"
            "[cyan]python main.py password[/cyan]        Audit password strength\n"
            "[cyan]python main.py network[/cyan] [CIDR]   Scan local network\n"
            "[cyan]python main.py handshake[/cyan] FILE   Analyze WPA handshake",
            border_style="blue",
        ))
        return

    command = sys.argv[1].lower()

    if command == "password":
        pw = sys.argv[2] if len(sys.argv) > 2 else None
        cmd_password(pw)
    elif command == "network":
        target = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.0/24"
        cmd_network(target)
    elif command == "handshake":
        if len(sys.argv) < 3:
            console.print("[red]Usage: python main.py handshake <file.pcap>[/red]")
            return
        cmd_handshake(sys.argv[2])
    else:
        console.print(f"[red]Unknown command: {command}[/red]")


if __name__ == "__main__":
    main()
