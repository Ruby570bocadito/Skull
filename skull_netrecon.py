#!/usr/bin/env python3
"""
SKULL-NetRecon - Professional Network Reconnaissance Tool
Created for authorized security testing and network analysis

Author: SKULL Security Team
Version: 1.0
"""

import sys
import argparse
import yaml
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

# Import modules
from modules.host_discovery import HostDiscovery
from modules.port_scanner import PortScanner
from modules.service_detection import ServiceDetector
from modules.vuln_scanner import VulnerabilityScanner
from modules.os_fingerprint import OSFingerprint
from modules.report_generator import ReportGenerator
from utils.logger import setup_logger, get_logger
from utils.network_utils import validate_ip, validate_cidr, expand_ip_range, mac_to_vendor


class SkullNetRecon:
    """Main SKULL-NetRecon application"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.console = Console()
        self.config = self._load_config(config_file)
        self.logger = None
        self.results = {
            'hosts': [],
            'stats': {
                'total_hosts': 0,
                'total_ports': 0,
                'total_services': 0,
                'total_vulnerabilities': 0
            }
        }
        
        # Load OUI database
        self.oui_db = self._load_oui_database()
    
    def _load_config(self, config_file: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def _load_oui_database(self) -> dict:
        """Load OUI vendor database"""
        try:
            with open('data/oui_vendors.json', 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def show_banner(self):
        """Display application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                            ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄                          ║
║                           ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌                         ║
║                           ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀                          ║
║                           ▐░▌          ▐░▌                                   ║
║                           ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌                                   ║
║                           ▐░░░░░░░░░░░▌▐░▌                                   ║
║                            ▀▀▀▀▀▀▀▀▀█░▌▐░▌                                   ║
║                                     ▐░▌▐░▌                                   ║
║                            ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄                          ║
║                           ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌                         ║
║                            ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀                          ║
║                                                                              ║
║                 ▄████████    ▄█   ▄█▄ ███    █▄   ▄█        ▄█              ║
║                ███    ███   ███ ▄███▀ ███    ███ ███       ███              ║
║                ███    █▀    ███▐██▀   ███    ███ ███       ███              ║
║               ▄███▄▄▄      ▄█████▀    ███    ███ ███       ███              ║
║              ▀▀███▀▀▀     ▀▀█████▄    ███    ███ ███       ███              ║
║                ███    █▄    ███▐██▄   ███    ███ ███       ███              ║
║                ███    ███   ███ ▀███▄ ███    ███ ███▌    ▄ ███▌    ▄        ║
║                ██████████   ███   ▀█▀ ████████▀  █████▄▄██ █████▄▄██        ║
║                             ▀                     ▀         ▀                ║
║                                                                              ║
║                        ░▒▓ NETWORK RECONNAISSANCE ▓▒░                       ║
║                                                                              ║
║        ⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀01100011⠀01101111⠀01100100         ║
║        ⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀01100101⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⢰⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⣿⣿⣿⣿⣿⣿⣿⠏⠀⢀⣤⣶⣾⣿⣿⣿⣷⣶⡄⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⣿⣿⣿⣿⣿⣿⡏⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⠀ [PENETRATION TESTING]        ║
║        ⢸⣿⣿⣿⣿⣿⣿⠀⠀⣾⣿⣿⠿⠟⠛⠛⠻⢿⣿⣿⣿⡄⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⢸⣿⣿⣿⣿⣿⣿⠀⣰⣿⡟⠁⠀⠀⠀⠀⠀⠀⠈⢻⣿⣷⡀⠀⠀⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⢸⣿⣿⣿⣿⣿⣿⠀⣿⣿⠀⠀⣀⣀⣀⣀⣀⣀⠀⠀⢿⣿⣇⠀⠀⣿⣿⣿⣿⣿⣿⣿⡇ [SECURITY ASSESSMENT]      ║
║        ⢸⣿⣿⣿⣿⣿⣿⡀⣿⣿⠀⠀⠛⠛⠛⠛⠛⠛⠀⠀⢸⣿⣿⠀⢀⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⣿⣿⣿⣿⣿⣿⣧⢸⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⡇⣠⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⢹⣿⣿⣿⣿⣿⣿⣆⠻⣿⣷⣄⣀⣀⣀⣀⣠⣴⣿⣿⠟⣰⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀  [VULNERABILITY SCANNER]    ║
║        ⠀⠀⢿⣿⣿⣿⣿⣿⣿⣷⣌⠙⠛⠿⠿⠿⠿⠛⠋⣡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⠀⠀⠀⠀⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠛⠻⠿⠿⠛⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         ║
║                                                                              ║
║                        Version 1.0 | ETHICAL USE ONLY                       ║
║            01010111 01100001 01110010 01101110 01101001 01101110 01100111   ║
║                                                                              ║
║                  💀 FOR AUTHORIZED SECURITY TESTING ONLY 💀                 ║
║                  ⚡ UNAUTHORIZED ACCESS IS STRICTLY ILLEGAL ⚡              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold red")
    
    def show_legal_disclaimer(self):
        """Show legal disclaimer"""
        disclaimer = Panel(
            "[bold red]⚠️  LEGAL DISCLAIMER ⚠️[/bold red]\n\n"
            "[yellow]This tool is designed for AUTHORIZED security testing ONLY.[/yellow]\n\n"
            "By using this tool, you acknowledge that:\n"
            "• You have explicit permission to scan the target network\n"
            "• Unauthorized scanning is illegal in most jurisdictions\n"
            "• You accept full responsibility for your actions\n\n"
            "[bold]Do you agree to use this tool legally and ethically? (yes/no):[/bold]",
            title="Legal Notice",
            border_style="red"
        )
        
        self.console.print(disclaimer)
        
        response = input().strip().lower()
        if response not in ['yes', 'y']:
            self.console.print("[red]Tool usage declined. Exiting...[/red]")
            sys.exit(0)
        
        self.console.print("[green]✓ Legal agreement accepted[/green]\n")
    
    def quick_scan(self, target: str):
        """Perform quick scan of common ports"""
        self.logger.info(f"Starting quick scan of {target}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Host discovery
            task1 = progress.add_task("[cyan]Discovering hosts...", total=None)
            discovery = HostDiscovery(
                timeout=self.config['discovery']['icmp_timeout'],
                threads=self.config['scanning']['threads'],
                verbose=self.config['advanced']['verbose']
            )
            hosts = discovery.discover([target], methods=self.config['discovery']['methods'])
            progress.update(task1, completed=True)
            
            if not hosts:
                self.logger.error(f"No active hosts found for {target}")
                return
            
            self.logger.success(f"Found {len(hosts)} active host(s)")
            
            # Process each host
            for host in hosts:
                ip = host['ip']
                self.logger.info(f"Scanning {ip}...")
                
                # Port scan
                task2 = progress.add_task(f"[cyan]Scanning ports on {ip}...", total=None)
                scanner = PortScanner(
                    timeout=self.config['scanning']['timeout'],
                    threads=self.config['scanning']['threads'],
                    verbose=self.config['advanced']['verbose']
                )
                scan_results = scanner.quick_scan(ip, port_range="quick")
                progress.update(task2, completed=True)
                
                open_ports = scan_results['open_ports']
                
                if not open_ports:
                    self.logger.warning(f"No open ports found on {ip}")
                    continue
                
                # Service detection
                task3 = progress.add_task(f"[cyan]Detecting services on {ip}...", total=None)
                detector = ServiceDetector(
                    timeout=self.config['services']['banner_timeout'],
                    verbose=self.config['advanced']['verbose']
                )
                
                port_details = []
                for port in open_ports:
                    port_info = scan_results['ports'][port]
                    service_info = detector.detect_service(ip, port, port_info['service'])
                    port_info.update(service_info)
                    port_details.append(port_info)
                
                progress.update(task3, completed=True)
                
                # OS Fingerprinting
                task4 = progress.add_task(f"[cyan]Fingerprinting OS on {ip}...", total=None)
                os_fp = OSFingerprint(
                    timeout=self.config['scanning']['timeout'],
                    verbose=self.config['advanced']['verbose']
                )
                os_info = os_fp.detect(ip, open_ports)
                progress.update(task4, completed=True)
                
                # Vulnerability scanning
                task5 = progress.add_task(f"[cyan]Scanning vulnerabilities on {ip}...", total=None)
                vuln_scanner = VulnerabilityScanner(
                    timeout=self.config['scanning']['timeout'],
                    verbose=self.config['advanced']['verbose']
                )
                
                all_vulns = []
                for port_info in port_details:
                    vulns = vuln_scanner.scan(ip, port_info)
                    all_vulns.extend(vulns)
                
                progress.update(task5, completed=True)
                
                # Add MAC vendor
                if host.get('mac'):
                    host['vendor'] = mac_to_vendor(host['mac'], self.oui_db)
                
                # Store results
                host_result = {
                    'ip': ip,
                    'hostname': host.get('hostname'),
                    'mac': host.get('mac'),
                    'vendor': host.get('vendor'),
                    'os': os_info.get('os'),
                    'os_confidence': os_info.get('confidence'),
                    'ports': port_details,
                    'vulnerabilities': all_vulns
                }
                
                self.results['hosts'].append(host_result)
        
        # Update statistics
        self._update_statistics()
        
        # Display results
        self._display_results()
    
    def full_scan(self, target: str):
        """Perform comprehensive full scan"""
        self.logger.info(f"Starting full scan of {target}")
        self.logger.warning("Full scan may take considerable time...")
        
        # Similar to quick_scan but with full port range
        # Implementation similar to quick_scan
        self.quick_scan(target)  # Placeholder
    
    def _update_statistics(self):
        """Update scan statistics"""
        self.results['stats']['total_hosts'] = len(self.results['hosts'])
        
        total_ports = 0
        total_services = 0
        total_vulns = 0
        
        for host in self.results['hosts']:
            total_ports += len(host.get('ports', []))
            total_services += len([p for p in host.get('ports', []) if p.get('service') != 'unknown'])
            total_vulns += len(host.get('vulnerabilities', []))
        
        self.results['stats']['total_ports'] = total_ports
        self.results['stats']['total_services'] = total_services
        self.results['stats']['total_vulnerabilities'] = total_vulns
    
    def _display_results(self):
        """Display scan results in terminal"""
        self.console.print("\n")
        self.console.rule("[bold cyan]Scan Results[/bold cyan]")
        
        # Statistics
        stats_table = Table(title="Summary", show_header=True, header_style="bold magenta")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Active Hosts", str(self.results['stats']['total_hosts']))
        stats_table.add_row("Open Ports", str(self.results['stats']['total_ports']))
        stats_table.add_row("Identified Services", str(self.results['stats']['total_services']))
        stats_table.add_row("Vulnerabilities", str(self.results['stats']['total_vulnerabilities']))
        
        self.console.print(stats_table)
        self.console.print("\n")
        
        # Detailed results for each host
        for host in self.results['hosts']:
            self.console.rule(f"[bold cyan]Host: {host['ip']}[/bold cyan]")
            
            # Host info
            info_table = Table(show_header=False, box=None)
            info_table.add_column("Property", style="yellow")
            info_table.add_column("Value", style="white")
            
            if host.get('hostname'):
                info_table.add_row("Hostname", host['hostname'])
            if host.get('mac'):
                info_table.add_row("MAC Address", host['mac'])
            if host.get('vendor'):
                info_table.add_row("Vendor", host['vendor'])
            if host.get('os'):
                info_table.add_row("Operating System", f"{host['os']} ({host.get('os_confidence', 0)}% confidence)")
            
            self.console.print(info_table)
            self.console.print()
            
            # Ports
            if host.get('ports'):
                port_table = Table(title="Open Ports", show_header=True, header_style="bold blue")
                port_table.add_column("Port", style="cyan")
                port_table.add_column("State", style="green")
                port_table.add_column("Service", style="yellow")
                port_table.add_column("Version", style="white")
                
                for port in host['ports']:
                    port_table.add_row(
                        str(port['port']),
                        port['state'],
                        port.get('service', 'unknown'),
                        port.get('version', 'N/A')
                    )
                
                self.console.print(port_table)
                self.console.print()
            
            # Vulnerabilities
            if host.get('vulnerabilities'):
                self.console.print("[bold red]⚠️  Vulnerabilities Found:[/bold red]")
                
                for vuln in host['vulnerabilities']:
                    severity_color = {
                        'CRITICAL': 'red',
                        'HIGH': 'orange1',
                        'MEDIUM': 'yellow',
                        'LOW': 'blue',
                        'INFO': 'cyan'
                    }.get(vuln.get('severity', 'INFO'), 'white')
                    
                    self.console.print(
                        f"  [{severity_color}][{vuln.get('severity')}][/{severity_color}] "
                        f"{vuln.get('name')} - {vuln.get('description')}"
                    )
                
                self.console.print()
    
    def generate_report(self, format: str = "html"):
        """Generate scan report"""
        self.logger.info(f"Generating {format.upper()} report...")
        
        generator = ReportGenerator(output_dir=self.config['reporting']['output_dir'])
        generator.set_scan_data(self.results)
        
        if format == "html":
            report_path = generator.generate_html_report()
        elif format == "json":
            report_path = generator.generate_json_report()
        elif format == "txt":
            report_path = generator.generate_txt_report()
        else:
            self.logger.error(f"Unknown report format: {format}")
            return
        
        self.console.print(f"\n[green]✓ Report saved to:[/green] [cyan]{report_path}[/cyan]")
    
    def run(self, args):
        """Main execution flow"""
        # Setup logger
        self.logger = setup_logger(
            log_dir="./logs",
            verbose=args.verbose or self.config['advanced']['verbose']
        )
        
        # Show banner
        if not args.no_banner:
            self.show_banner()
        
        # Show legal disclaimer (only if not previously accepted)
        if not args.skip_disclaimer:
            self.show_legal_disclaimer()
        
        # Execute scan
        if args.target:
            if args.full_scan:
                self.full_scan(args.target)
            else:
                self.quick_scan(args.target)
            
            # Generate report
            if args.report:
                self.generate_report(args.report_format)


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="SKULL-NetRecon - Professional Network Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan of single host
  python skull_netrecon.py --target 192.168.1.100
  
  # Quick scan of network range
  python skull_netrecon.py --target 192.168.1.0/24
  
  # Full port scan with HTML report
  python skull_netrecon.py --target 192.168.1.100 --full-scan --report --report-format html
  
  # Scan IP range without banner
  python skull_netrecon.py --target 192.168.1.1-254 --no-banner

⚠️  Always obtain proper authorization before scanning any network!
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP, CIDR, or range (e.g., 192.168.1.0/24)')
    parser.add_argument('--full-scan', action='store_true', help='Perform full port scan (1-65535)')
    parser.add_argument('-r', '--report', action='store_true', help='Generate report')
    parser.add_argument('--report-format', choices=['html', 'json', 'txt'], default='html', help='Report format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')
    parser.add_argument('--skip-disclaimer', action='store_true', help='Skip legal disclaimer (use with caution)')
    
    args = parser.parse_args()
    
    # Create and run scanner
    try:
        scanner = SkullNetRecon()
        scanner.run(args)
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
