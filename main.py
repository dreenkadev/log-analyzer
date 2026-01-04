#!/usr/bin/env python3
"""Log Analyzer - Entry point"""

import argparse
import json
import sys

try:
    from rich.console import Console
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

from src import VERSION, LogAnalyzer, print_report


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
    
    analyzer = LogAnalyzer(log_format=args.format, console=console)
    
    try:
        report = analyzer.analyze_file(args.logfile)
        
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print_report(report, console)
        
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
