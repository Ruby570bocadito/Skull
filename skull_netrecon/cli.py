"""SKULL-NetRecon - Professional CLI Interface"""

from __future__ import annotations

import ipaddress
import sys
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
    if value:
        console.print("[bold cyan]SKULL-NetRecon[/bold cyan] v1.0.0")
        raise typer.Exit()


def _load_config(config_path: Path | None) -> dict:
    """Load configuration from YAML file."""
    if config_path and config_path.exists():
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    default = Path("config.yaml")
    if default.exists():
        import yaml
        with open(default) as f:
            return yaml.safe_load(f) or {}
    return {}


def _validate_target(target: str) -> bool:
    """Validate that target is a valid IP, CIDR, or IP range."""
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
            return True
        if "-" in target:
            parts = target.split("-", 1)
            ipaddress.ip_address(parts[0].strip())
            end = parts[1].strip()
            if "." in end:
                ipaddress.ip_address(end)
            else:
                int(end)
            return True
        ipaddress.ip_address(target)
        return True
    except (ValueError, TypeError):
        return False


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
    targets: list[str] = typer.Argument(..., help="Target IP(s), CIDR, or range(s)"),
    full: bool = typer.Option(False, "--full", help="Full port scan (1-65535)"),
    scan_type: str = typer.Option("connect", "--scan-type", "-s", help="Scan type: connect, syn"),
    threads: int = typer.Option(50, "--threads", "-t", help="Number of concurrent threads"),
    timeout: float = typer.Option(2.0, "--timeout", help="Connection timeout in seconds"),
    rate_limit: float = typer.Option(0.0, "--rate-limit", help="Delay between probes (seconds)"),
    report: bool = typer.Option(False, "--report/--no-report", help="Generate report"),
    report_format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, txt, csv"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    skip_discovery: bool = typer.Option(False, "--skip-discovery", help="Skip host discovery"),
    no_services: bool = typer.Option(False, "--no-services", help="Skip service detection"),
    no_os: bool = typer.Option(False, "--no-os", help="Skip OS fingerprinting"),
    no_vulns: bool = typer.Option(False, "--no-vulns", help="Skip vulnerability scanning"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Hide banner"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path"),
) -> None:
    """Execute network scan against one or more targets."""
    from skull_netrecon.core.scanner import Scanner

    for target in targets:
        if not _validate_target(target):
            console.print(f"[red]Invalid target: {target}[/red]")
            raise typer.Exit(code=1)

    config = _load_config(config_path)

    if not no_banner:
        _show_banner()

    for target in targets:
        if len(targets) > 1:
            console.print(f"\n[cyan]Target:[/cyan] {target}")
        console.print(f"[cyan]Mode:[/cyan] {'Full' if full else 'Quick'} scan")

        try:
            scanner = Scanner(
                threads=threads,
                timeout=timeout,
                verbose=False,
                config=config,
            )
            if rate_limit > 0:
                scanner.rate_limit = rate_limit

            results = scanner.run(
                target=target,
                full_scan=full,
                skip_discovery=skip_discovery,
                scan_type=scan_type,
                detect_services=not no_services,
                detect_os=not no_os,
                scan_vulns=not no_vulns,
            )
            _display_results(results)

            if report:
                from skull_netrecon.core.report import ReportGenerator
                generator = ReportGenerator(output_dir=output or Path("./reports"))
                generator.generate(results, format=report_format)
                console.print(f"\n[green]✓ Report saved to:[/green] ./reports")

        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            raise typer.Exit(code=0)
        except PermissionError:
            console.print("[red]Permission denied. Try running with sudo for SYN scans.[/red]")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[red]Error scanning {target}: {e}[/red]")
            raise typer.Exit(code=1)


@app.command()
def discover(
    target: str = typer.Argument(..., help="Target network (CIDR or IP range)"),
    method: str = typer.Option("all", "--method", "-m", help="Discovery method: arp, icmp, tcp, all"),
    timeout: float = typer.Option(2.0, "--timeout", help="Timeout in seconds"),
) -> None:
    """Discover active hosts on network."""
    from skull_netrecon.core.discovery import HostDiscovery

    console.print(f"\n[cyan]Discovering hosts on:[/cyan] {target}")

    if method == "all":
        methods = ["arp", "icmp", "tcp"]
    else:
        methods = [method]

    discovery = HostDiscovery(timeout=int(timeout), verbose=False)
    hosts = discovery.discover([target], methods=methods)

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

    try:
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
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


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
        if host.get("mac"):
            console.print(f"[yellow]MAC:[/yellow] {host.get('mac')}")
        if host.get("vendor"):
            console.print(f"[yellow]Vendor:[/yellow] {host.get('vendor')}")
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
