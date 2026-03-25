"""SKULL-NetRecon - Main Scanner Module"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn


@dataclass
class HostResult:
    """Represents a scanned host."""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[dict] = None
    ports: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)


@dataclass
class ScanResults:
    """Container for scan results."""
    hosts: list[HostResult] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def add_host(self, host: HostResult) -> None:
        """Add a host to results."""
        self.hosts.append(host)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "mac": h.mac,
                    "vendor": h.vendor,
                    "os": h.os,
                    "ports": h.ports,
                    "vulnerabilities": h.vulnerabilities,
                }
                for h in self.hosts
            ],
            "metadata": self.metadata,
        }


class PortScanner:
    """Port scanning engine."""
    
    def __init__(self, timeout: float = 2.0, threads: int = 50, verbose: bool = False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
    
    def scan(self, target: str, port_range: str = "quick", scan_type: str = "connect") -> dict:
        """Scan ports on target."""
        ports = self._parse_port_range(port_range)
        
        if scan_type == "syn":
            return self._syn_scan(target, ports)
        return self._connect_scan(target, ports)
    
    def _parse_port_range(self, port_range: str) -> list[int]:
        """Parse port range string to list."""
        if port_range == "quick":
            ports_str = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5900,8080"
        elif port_range == "common":
            ports_str = "1-1000"
        elif port_range == "full":
            ports_str = "1-65535"
        else:
            ports_str = port_range
        
        ports = set()
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        
        return sorted(ports)
    
    def _connect_scan(self, target: str, ports: list[int]) -> dict:
        """TCP Connect scan."""
        results: dict = {}
        
        def scan_port(port: int) -> tuple[int, dict]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                
                port_info = {
                    "port": port,
                    "state": "open" if result == 0 else "closed",
                    "service": self._get_service(port),
                    "protocol": "tcp",
                }
                
                if result == 0:
                    try:
                        sock.settimeout(1)
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        if banner:
                            port_info["banner"] = banner[:200]
                    except:
                        pass
                
                sock.close()
                return port, port_info
            
            except Exception:
                return port, {
                    "port": port,
                    "state": "filtered",
                    "service": self._get_service(port),
                    "protocol": "tcp",
                }
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_port, p): p for p in ports}
            for future in as_completed(futures):
                port, info = future.result()
                results[port] = info
        
        return {
            "ip": target,
            "ports": results,
            "open_ports": [p for p, i in results.items() if i["state"] == "open"],
            "filtered_ports": [p for p, i in results.items() if i["state"] == "filtered"],
        }
    
    def _syn_scan(self, target: str, ports: list[int]) -> dict:
        """TCP SYN scan (requires root)."""
        try:
            from scapy.all import IP, TCP, sr1
            
            results = {}
            
            def syn_probe(port: int) -> tuple[int, dict]:
                try:
                    pkt = IP(dst=target) / TCP(dport=port, flags="S")
                    resp = sr1(pkt, timeout=self.timeout, verbose=0)
                    
                    if resp is None:
                        state = "filtered"
                    elif resp.haslayer(TCP):
                        flags = resp.getlayer(TCP).flags
                        if flags == 0x12:
                            state = "open"
                        elif flags == 0x14:
                            state = "closed"
                        else:
                            state = "filtered"
                    else:
                        state = "filtered"
                    
                    return port, {
                        "port": port,
                        "state": state,
                        "service": self._get_service(port),
                        "protocol": "tcp",
                    }
                except Exception:
                    return port, {
                        "port": port,
                        "state": "filtered",
                        "service": self._get_service(port),
                        "protocol": "tcp",
                    }
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(syn_probe, p): p for p in ports}
                for future in as_completed(futures):
                    port, info = future.result()
                    results[port] = info
            
            return {
                "ip": target,
                "ports": results,
                "open_ports": [p for p, i in results.items() if i["state"] == "open"],
            }
        
        except ImportError:
            return self._connect_scan(target, ports)
    
    def _get_service(self, port: int) -> str:
        """Get service name for port."""
        try:
            return socket.getservbyport(port)
        except OSError:
            return "unknown"


class Scanner:
    """Main network scanner orchestrator."""
    
    def __init__(
        self,
        threads: int = 50,
        timeout: float = 2.0,
        verbose: bool = False,
    ) -> None:
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.console = Console()
        self.results = ScanResults()
    
    def run(
        self,
        target: str,
        full_scan: bool = False,
        skip_discovery: bool = False,
    ) -> ScanResults:
        """Execute complete scan workflow."""
        from skull_netrecon.core.discovery import HostDiscovery
        
        self.console.print(f"[cyan]Initializing scan on {target}...[/cyan]")
        
        if not skip_discovery:
            discovery = HostDiscovery(timeout=int(self.timeout), threads=self.threads)
            hosts = discovery.discover([target])
        else:
            hosts = [{"ip": target, "mac": None, "hostname": None}]
        
        if not hosts:
            self.console.print("[yellow]No hosts discovered[/yellow]")
            return self.results
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            for host_info in progress.track(hosts, description="Scanning hosts..."):
                self._scan_host(host_info, full_scan, progress)
        
        self._update_metadata()
        return self.results
    
    def _scan_host(
        self,
        host_info: dict,
        full_scan: bool,
        progress: Progress,
    ) -> None:
        """Scan a single host."""
        ip = host_info["ip"]
        
        task = progress.add_task(f"[cyan]Scanning {ip}...", total=None)
        
        port_results = self._scan_ports(ip, full_scan)
        progress.update(task, completed=True)
        
        service_results = self._get_services_from_ports(port_results)
        os_results = self._detect_os_simple(ip, port_results)
        
        host = HostResult(
            ip=ip,
            hostname=host_info.get("hostname"),
            mac=host_info.get("mac"),
            vendor=host_info.get("vendor"),
            os=os_results,
            ports=service_results,
            vulnerabilities=[],
        )
        
        self.results.add_host(host)
    
    def _scan_ports(self, ip: str, full_scan: bool) -> dict:
        """Scan ports on target."""
        port_range = "1-65535" if full_scan else "quick"
        
        scanner = PortScanner(timeout=self.timeout, threads=self.threads)
        return scanner.scan(ip, port_range=port_range)
    
    def _get_services_from_ports(self, port_results: dict) -> list:
        """Get service info from port results."""
        services = []
        for port in port_results.get("open_ports", []):
            port_info = port_results["ports"].get(port, {})
            services.append(port_info)
        return services
    
    def _detect_os_simple(self, ip: str, port_results: dict) -> Optional[dict]:
        """Simple OS detection based on open ports."""
        open_ports = port_results.get("open_ports", [])
        
        os_hints = {
            "Windows": [135, 139, 445, 3389],
            "Linux": [22, 80, 443],
            "Router": [23, 80, 443, 8080],
        }
        
        for os_name, ports in os_hints.items():
            matches = sum(1 for p in open_ports if p in ports)
            if matches >= 2:
                return {"name": os_name, "confidence": matches * 30}
        
        return {"name": "Unknown", "confidence": 0}
    
    def _update_metadata(self) -> None:
        """Update scan metadata."""
        self.results.metadata = {
            "total_hosts": len(self.results.hosts),
            "total_ports": sum(len(h.ports) for h in self.results.hosts),
            "total_vulns": sum(len(h.vulnerabilities) for h in self.results.hosts),
        }
