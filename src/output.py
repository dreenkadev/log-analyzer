"""Log Analyzer - Report output"""

import json
from typing import Dict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def print_report(report: Dict, console=None):
    if not RICH_AVAILABLE or console is None:
        print(json.dumps(report, indent=2))
        return
    
    console.print("\n" + "═" * 70, style="cyan")
    console.print("              LOG ANALYZER REPORT", style="bold cyan")
    console.print("═" * 70, style="cyan")
    
    # Summary
    summary = report['summary']
    console.print(Panel.fit(
        f"Total Entries: [cyan]{summary['total_entries']:,}[/]\n"
        f"Total Threats: [{'red' if summary['total_threats'] > 0 else 'green'}]{summary['total_threats']:,}[/]\n"
        f"Unique IPs: [cyan]{summary['unique_ips']:,}[/]\n"
        f"Unique Paths: [cyan]{summary['unique_paths']:,}[/]",
        title="Summary",
        border_style="cyan"
    ))
    
    # Threats by severity
    if report['threats']['by_severity']:
        console.print("\n" + "─" * 70, style="cyan")
        console.print("THREATS BY SEVERITY", style="bold")
        for severity, count in sorted(report['threats']['by_severity'].items()):
            color = {'critical': 'red bold', 'high': 'red', 'medium': 'yellow', 'low': 'blue'}.get(severity, 'white')
            console.print(f"  {severity.upper()}: [{color}]{count}[/]")
    
    # Threats by type
    if report['threats']['by_type']:
        console.print("\n" + "─" * 70, style="cyan")
        console.print("THREATS BY TYPE", style="bold")
        table = Table(box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="red")
        for threat_type, count in report['threats']['by_type'].items():
            table.add_row(threat_type.replace('_', ' ').title(), str(count))
        console.print(table)
    
    # Top attackers
    if report['threats']['by_ip']:
        console.print("\n" + "─" * 70, style="cyan")
        console.print("TOP ATTACKERS", style="bold red")
        table = Table(box=box.ROUNDED)
        table.add_column("IP Address", style="red")
        table.add_column("Threats", style="yellow")
        for ip, count in list(report['threats']['by_ip'].items())[:10]:
            table.add_row(ip, str(count))
        console.print(table)
    
    # Top IPs
    console.print("\n" + "─" * 70, style="cyan")
    console.print("TOP IPs (by requests)", style="bold")
    table = Table(box=box.ROUNDED)
    table.add_column("IP Address", style="cyan")
    table.add_column("Requests", style="white")
    for ip, count in list(report['top_ips'].items())[:10]:
        table.add_row(ip, str(count))
    console.print(table)
    
    # Status codes
    console.print("\n" + "─" * 70, style="cyan")
    console.print("STATUS CODES", style="bold")
    for code, count in sorted(report['status_codes'].items()):
        color = 'green' if code < 400 else 'yellow' if code < 500 else 'red'
        console.print(f"  {code}: [{color}]{count}[/]")
    
    console.print("\n" + "═" * 70, style="cyan")
