"""SKULL-NetRecon - Professional CLI Interface"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="skull-netrecon",
    help="Professional Network Reconnaissance Tool",
    add_completion=False,
)

console = Console()


def version_callback(value: bool) -> None:
    """Display version information."""
    if value:
        console.print("[bold cyan]SKULL-NetRecon[/bold cyan] v1.0.0")
        raise typer.Exit()


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path"),
    version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True),
) -> None:
    """SKULL-NetRecon - Professional Network Reconnaissance Tool."""
    pass


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, CIDR, or range"),
    full: bool = typer.Option(False, "--full", help="Full port scan (1-65535)"),
    scan_type: str = typer.Option("connect", "--scan-type", "-s", help="Scan type: connect, syn, udp"),
    threads: int = typer.Option(50, "--threads", "-t", help="Number of concurrent threads"),
    timeout: float = typer.Option(2.0, "--timeout", help="Connection timeout in seconds"),
    report: bool = typer.Option(False, "--report/--no-report", help="Generate report"),
    report_format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, txt"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    skip_discovery: bool = typer.Option(False, "--skip-discovery", help="Skip host discovery"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Hide banner"),
) -> None:
    """Execute network scan."""
    from skull_netrecon.core.scanner import Scanner
    
    if not no_banner:
        _show_banner()
    
    console.print(f"\n[cyan]Target:[/cyan] {target}")
    console.print(f"[cyan]Mode:[/cyan] {'Full' if full else 'Quick'} scan")
    
    scanner = Scanner(
        threads=threads,
        timeout=timeout,
        verbose=False,
    )
    
    results = scanner.run(
        target=target,
        full_scan=full,
        skip_discovery=skip_discovery,
    )
    
    _display_results(results)
    
    if report:
        from skull_netrecon.core.report import ReportGenerator
        generator = ReportGenerator(output_dir=output or Path("./reports"))
        generator.generate(results, format=report_format)
        console.print(f"\n[green]✓ Report saved to:[/green] ./reports")


@app.command()
def discover(
    target: str = typer.Argument(..., help="Target network (CIDR or IP range)"),
    method: str = typer.Option("arp", "--method", "-m", help="Discovery method: arp, icmp, tcp, all"),
    timeout: float = typer.Option(2.0, "--timeout", help="Timeout in seconds"),
) -> None:
    """Discover active hosts on network."""
    from skull_netrecon.core.discovery import HostDiscovery
    
    console.print(f"\n[cyan]Discovering hosts on:[/cyan] {target}")
    
    discovery = HostDiscovery(timeout=int(timeout), verbose=False)
    hosts = discovery.discover([target], methods=[method] if method != "all" else None)
    
    if not hosts:
        console.print("[yellow]No hosts found[/yellow]")
        return
    
    for host in hosts:
        console.print(f"\n[bold cyan]Host:[/bold cyan] {host.get('ip', 'N/A')}")
        if host.get("hostname"):
            console.print(f"[yellow]Hostname:[/yellow] {host.get('hostname')}")
        if host.get("mac"):
            console.print(f"[yellow]MAC:[/yellow] {host.get('mac')}")
        
        open_ports = host.get("open_ports", [])
        if open_ports:
            ports_str = ", ".join(str(p) for p in open_ports)
            console.print(f"[green]Open Ports:[/green] {ports_str}")


@app.command()
def ports(
    target: str = typer.Argument(..., help="Target IP address"),
    port_range: str = typer.Option("quick", "--range", "-r", help="Port range: quick, common, full, or custom"),
    scan_type: str = typer.Option("connect", "--type", "-t", help="Scan type: connect, syn"),
    timeout: float = typer.Option(2.0, "--timeout", help="Connection timeout"),
) -> None:
    """Scan ports on target host."""
    from skull_netrecon.core.scanner import PortScanner
    
    scanner = PortScanner(timeout=timeout, verbose=False)
    results = scanner.scan(target, port_range=port_range, scan_type=scan_type)
    
    table = Table(title=f"Open Ports on {target}")
    table.add_column("Port", style="cyan")
    table.add_column("State", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Version", style="white")
    
    for port, info in results.get("ports", {}).items():
        if info.get("state") == "open":
            table.add_row(
                str(port),
                info.get("state", "unknown"),
                info.get("service", "unknown"),
                info.get("version", "N/A"),
            )
    
    console.print(table)


@app.command()
def config_show() -> None:
    """Show current configuration."""
    import yaml
    
    config_path = Path("config.yaml")
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
        console.print_json(data=config)
    else:
        console.print("[yellow]No config.yaml found[/yellow]")


def _show_banner() -> None:
    """Display application banner."""
    banner = """
[bold red]
    ╔═══════════════════════════════════════════════════════════════╗
    ║   ███████╗ █████╗ ████████╗██╗██╗   ██╗███████╗             ║
    ║   ██╔════╝██╔══██╗╚══██╔══╝██║██║   ██║╚══██╔══╝             ║
    ║   ███████╗███████║   ██║   ██║██║   ██║   ██║                ║
    ║   ╚════██║██╔══██║   ██║   ██║╚═╝   ██║   ██║                ║
    ║   ███████║██║  ██║   ██║   ██║     ██║   ██║                ║
    ║   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝   ╚═╝                ║
    ║              NETWORK RECONNAISSANCE                          ║
    ╚═══════════════════════════════════════════════════════════════╝
[/bold red]
    """
    console.print(banner)


def _display_results(results) -> None:
    """Display scan results."""
    data = results.to_dict() if hasattr(results, "to_dict") else results
    
    if not data.get("hosts"):
        console.print("[yellow]No hosts found[/yellow]")
        return
    
    for host in data.get("hosts", []):
        console.print(f"\n[bold cyan]Host:[/bold cyan] {host.get('ip', 'N/A')}")
        
        if host.get("hostname"):
            console.print(f"[yellow]Hostname:[/yellow] {host.get('hostname')}")
        if host.get("os"):
            os_name = host["os"].get("name", "Unknown")
            console.print(f"[yellow]OS:[/yellow] {os_name} ({host['os'].get('confidence', 0)}% confidence)")
        
        if host.get("ports"):
            ports_table = Table(title="Open Ports", show_header=True)
            ports_table.add_column("Port", style="cyan", width=8)
            ports_table.add_column("State", style="green", width=8)
            ports_table.add_column("Service", style="yellow", width=15)
            ports_table.add_column("Version", style="white")
            
            for port in host["ports"]:
                ports_table.add_row(
                    str(port.get("port", "")),
                    port.get("state", ""),
                    port.get("service", ""),
                    port.get("version", "N/A"),
                )
            
            console.print(ports_table)
        
        if host.get("vulnerabilities"):
            console.print("[bold red]Vulnerabilities:[/bold red]")
            for vuln in host["vulnerabilities"]:
                console.print(f"  [{vuln.get('severity', 'INFO')}] {vuln.get('name')}")
        else:
            console.print("[dim]No vulnerabilities detected[/dim]")
        
        console.print()
