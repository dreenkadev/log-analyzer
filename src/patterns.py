"""Log Analyzer - Constants and patterns"""

VERSION = "1.0.0"

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
