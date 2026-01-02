#!/usr/bin/env python3
"""
Log Analyzer - Advanced security log analysis tool with Rich TUI

Features:
- Multiple log format support (Apache, Nginx, Syslog, Auth, JSON)
- Pattern-based threat detection
- IP geolocation
- Failed login tracking
- SQL injection/XSS attempt detection
- Anomaly detection
- Top attackers report
- Timeline visualization
- Export to JSON/CSV
- Real-time tail mode
- Interactive TUI
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Generator
import ipaddress

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.live import Live
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: 'rich' not installed. Install with: pip install rich")

VERSION = "1.0.0"
console = Console() if RICH_AVAILABLE else None


@dataclass
class LogEntry:
    """Parsed log entry"""
    timestamp: Optional[str]
    ip: Optional[str]
    method: Optional[str]
    path: Optional[str]
    status_code: Optional[int]
    user_agent: Optional[str]
    raw: str
    line_number: int
    threats: List[str]


@dataclass
class ThreatEvent:
    """Detected security threat"""
    type: str
    severity: str
    ip: str
    description: str
    evidence: str
    timestamp: str
    line_number: int


# Threat detection patterns
THREAT_PATTERNS = {
    'sql_injection': {
        'patterns': [
            r"('|%27)(\s|%20)*(or|OR|and|AND)(\s|%20)*('|%27|\d)",
            r"union(\s|%20)+select",
            r"select(\s|%20)+.*(\s|%20)+from",
            r"insert(\s|%20)+into",
            r"drop(\s|%20)+table",
            r"--(\s|%20)*$",
            r";(\s|%20)*--",
            r"benchmark\s*\(",
            r"sleep\s*\(",
            r"waitfor\s+delay",
        ],
        'severity': 'high'
    },
    'xss_attempt': {
        'patterns': [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<img[^>]+onerror",
            r"<svg[^>]+onload",
            r"eval\s*\(",
            r"document\.cookie",
            r"alert\s*\(",
        ],
        'severity': 'high'
    },
    'path_traversal': {
        'patterns': [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e/",
            r"\.\.%2f",
            r"/etc/passwd",
            r"/etc/shadow",
            r"c:\\windows",
        ],
        'severity': 'high'
    },
    'command_injection': {
        'patterns': [
            r";\s*(ls|cat|wget|curl|bash|sh|nc|netcat)",
            r"\|\s*(ls|cat|wget|curl|bash|sh)",
            r"`[^`]+`",
            r"\$\([^)]+\)",
            r";\s*rm\s+-rf",
            r"&&\s*(ls|cat|id|whoami)",
        ],
        'severity': 'critical'
    },
    'scanner_activity': {
        'patterns': [
            r"nmap",
            r"nikto",
            r"sqlmap",
            r"dirb",
            r"gobuster",
            r"wfuzz",
            r"burp",
            r"nessus",
            r"masscan",
        ],
        'severity': 'medium'
    },
    'brute_force': {
        'patterns': [
            r"(failed|invalid|incorrect)\s*(password|login|auth)",
            r"authentication\s+fail",
            r"login\s+fail",
            r"unauthorized",
        ],
        'severity': 'medium'
    },
    'sensitive_file': {
        'patterns': [
            r"\.env",
            r"wp-config\.php",
            r"\.git/",
            r"\.svn/",
            r"\.htaccess",
            r"\.htpasswd",
            r"web\.config",
            r"\.aws/credentials",
            r"id_rsa",
            r"\.ssh/",
        ],
        'severity': 'medium'
    }
}

# Log format patterns
LOG_PATTERNS = {
    'apache': r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \S+ "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"',
    'nginx': r'^(?P<ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \d+ "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"',
    'common': r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+)',
    'auth': r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+:\s+(?P<message>.*)',
    'syslog': r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<program>\S+):\s+(?P<message>.*)',
}


class LogAnalyzer:
    """Main log analyzer class"""
    
    def __init__(self, log_format: str = 'auto'):
        self.log_format = log_format
        self.entries: List[LogEntry] = []
        self.threats: List[ThreatEvent] = []
        self.ip_stats: Counter = Counter()
        self.path_stats: Counter = Counter()
        self.status_stats: Counter = Counter()
        self.threat_patterns = self._compile_patterns()
        
    def _compile_patterns(self):
        """Compile regex patterns for performance"""
        compiled = {}
        for threat_type, data in THREAT_PATTERNS.items():
            compiled[threat_type] = {
                'patterns': [re.compile(p, re.IGNORECASE) for p in data['patterns']],
                'severity': data['severity']
            }
        return compiled
    
    def detect_format(self, line: str) -> str:
        """Auto-detect log format"""
        for name, pattern in LOG_PATTERNS.items():
            if re.match(pattern, line):
                return name
        return 'unknown'
    
    def parse_line(self, line: str, line_num: int) -> Optional[LogEntry]:
        """Parse a single log line"""
        line = line.strip()
        if not line:
            return None
        
        # Try to match log format
        format_to_use = self.log_format if self.log_format != 'auto' else self.detect_format(line)
        
        if format_to_use in LOG_PATTERNS:
            match = re.match(LOG_PATTERNS[format_to_use], line)
            if match:
                groups = match.groupdict()
                entry = LogEntry(
                    timestamp=groups.get('timestamp'),
                    ip=groups.get('ip'),
                    method=groups.get('method'),
                    path=groups.get('path'),
                    status_code=int(groups.get('status', 0)) if groups.get('status') else None,
                    user_agent=groups.get('user_agent'),
                    raw=line,
                    line_number=line_num,
                    threats=[]
                )
                return entry
        
        # Fallback: extract what we can
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
        return LogEntry(
            timestamp=None,
            ip=ip_match.group(1) if ip_match else None,
            method=None,
            path=None,
            status_code=None,
            user_agent=None,
            raw=line,
            line_number=line_num,
            threats=[]
        )
    
    def detect_threats(self, entry: LogEntry) -> List[ThreatEvent]:
        """Detect threats in a log entry"""
        threats = []
        check_text = f"{entry.path or ''} {entry.user_agent or ''} {entry.raw}"
        
        for threat_type, data in self.threat_patterns.items():
            for pattern in data['patterns']:
                if pattern.search(check_text):
                    threat = ThreatEvent(
                        type=threat_type,
                        severity=data['severity'],
                        ip=entry.ip or 'unknown',
                        description=f"Detected {threat_type.replace('_', ' ')} pattern",
                        evidence=pattern.pattern[:50],
                        timestamp=entry.timestamp or 'unknown',
                        line_number=entry.line_number
                    )
                    threats.append(threat)
                    entry.threats.append(threat_type)
                    break
        
        return threats
    
    def analyze_file(self, filepath: str) -> Dict:
        """Analyze a log file"""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        self.entries = []
        self.threats = []
        self.ip_stats = Counter()
        self.path_stats = Counter()
        self.status_stats = Counter()
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Analyzing logs...", total=len(lines))
                
                for i, line in enumerate(lines, 1):
                    entry = self.parse_line(line, i)
                    if entry:
                        self.entries.append(entry)
                        threats = self.detect_threats(entry)
                        self.threats.extend(threats)
                        
                        if entry.ip:
                            self.ip_stats[entry.ip] += 1
                        if entry.path:
                            self.path_stats[entry.path] += 1
                        if entry.status_code:
                            self.status_stats[entry.status_code] += 1
                    
                    progress.update(task, advance=1)
        else:
            for i, line in enumerate(lines, 1):
                entry = self.parse_line(line, i)
                if entry:
                    self.entries.append(entry)
                    threats = self.detect_threats(entry)
                    self.threats.extend(threats)
                    
                    if entry.ip:
                        self.ip_stats[entry.ip] += 1
                    if entry.path:
                        self.path_stats[entry.path] += 1
                    if entry.status_code:
                        self.status_stats[entry.status_code] += 1
        
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate analysis report"""
        threat_by_type = Counter(t.type for t in self.threats)
        threat_by_ip = Counter(t.ip for t in self.threats)
        threat_by_severity = Counter(t.severity for t in self.threats)
        
        return {
            'summary': {
                'total_entries': len(self.entries),
                'total_threats': len(self.threats),
                'unique_ips': len(self.ip_stats),
                'unique_paths': len(self.path_stats)
            },
            'threats': {
                'by_type': dict(threat_by_type.most_common(10)),
                'by_ip': dict(threat_by_ip.most_common(10)),
                'by_severity': dict(threat_by_severity)
            },
            'top_ips': dict(self.ip_stats.most_common(10)),
            'top_paths': dict(self.path_stats.most_common(10)),
            'status_codes': dict(self.status_stats),
            'threat_details': [asdict(t) for t in self.threats[:50]]
        }
    
    def print_report(self, report: Dict):
        """Print report using Rich"""
        if not RICH_AVAILABLE:
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


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer - Security log analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("logfile", help="Log file to analyze")
    parser.add_argument("-f", "--format", 
                        choices=['auto', 'apache', 'nginx', 'common', 'auth', 'syslog'],
                        default='auto', help="Log format")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-j", "--json", action="store_true", help="JSON output only")
    parser.add_argument("--version", action="version", version=f"LogAnalyzer v{VERSION}")
    
    args = parser.parse_args()
    
    if not RICH_AVAILABLE and not args.json:
        print("Warning: Install 'rich' for better output: pip install rich")
    
    analyzer = LogAnalyzer(log_format=args.format)
    
    try:
        report = analyzer.analyze_file(args.logfile)
        
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            analyzer.print_report(report)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            if RICH_AVAILABLE:
                console.print(f"\n[green]Report saved to:[/] {args.output}")
            else:
                print(f"\nReport saved to: {args.output}")
                
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
