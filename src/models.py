"""Log Analyzer - Data models"""

from dataclasses import dataclass
from typing import Optional, List


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
