"""Log Analyzer - Core analysis engine"""

import re
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional

from .patterns import THREAT_PATTERNS, LOG_PATTERNS
from .models import LogEntry, ThreatEvent

try:
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class LogAnalyzer:
    """Main log analyzer class"""
    
    def __init__(self, log_format: str = 'auto', console=None):
        self.log_format = log_format
        self.console = console
        self.entries: List[LogEntry] = []
        self.threats: List[ThreatEvent] = []
        self.ip_stats: Counter = Counter()
        self.path_stats: Counter = Counter()
        self.status_stats: Counter = Counter()
        self.threat_patterns = self._compile_patterns()
        
    def _compile_patterns(self):
        compiled = {}
        for threat_type, data in THREAT_PATTERNS.items():
            compiled[threat_type] = {
                'patterns': [re.compile(p, re.IGNORECASE) for p in data['patterns']],
                'severity': data['severity']
            }
        return compiled
    
    def detect_format(self, line: str) -> str:
        for name, pattern in LOG_PATTERNS.items():
            if re.match(pattern, line):
                return name
        return 'unknown'
    
    def parse_line(self, line: str, line_num: int) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None
        
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
        
        if RICH_AVAILABLE and self.console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Analyzing logs...", total=len(lines))
                
                for i, line in enumerate(lines, 1):
                    self._process_line(line, i)
                    progress.update(task, advance=1)
        else:
            for i, line in enumerate(lines, 1):
                self._process_line(line, i)
        
        return self.generate_report()
    
    def _process_line(self, line: str, line_num: int):
        entry = self.parse_line(line, line_num)
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
    
    def generate_report(self) -> Dict:
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
