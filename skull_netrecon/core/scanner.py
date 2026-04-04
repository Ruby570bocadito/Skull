"""SKULL-NetRecon - Main Scanner Module"""

from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from skull_netrecon.modules.service_detection import ServiceDetector
from skull_netrecon.modules.os_fingerprint import OSFingerprint
from skull_netrecon.modules.vuln_scanner import VulnerabilityScanner


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
        self.hosts.append(host)

    def to_dict(self) -> dict:
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

    def __init__(
        self,
        timeout: float = 2.0,
        threads: int = 50,
        verbose: bool = False,
        rate_limit: float = 0.0,
    ) -> None:
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.rate_limit = rate_limit

    def scan(
        self,
        target: str,
        port_range: str = "quick",
        scan_type: str = "connect",
    ) -> dict:
        ports = self._parse_port_range(port_range)
        if scan_type == "syn":
            return self._syn_scan(target, ports)
        return self._connect_scan(target, ports)

    def _parse_port_range(self, port_range: str) -> list[int]:
        if port_range == "quick":
            ports_str = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5900,8080"
        elif port_range == "common":
            ports_str = "1-1000"
        elif port_range == "full":
            ports_str = "1-65535"
        else:
            ports_str = port_range

        ports: set[int] = set()
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def _connect_scan(self, target: str, ports: list[int]) -> dict:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results: dict = {}

        def scan_port(port: int) -> tuple[int, dict]:
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                port_info: dict[str, Any] = {
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
                    except Exception:
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
        from concurrent.futures import ThreadPoolExecutor, as_completed

        try:
            from scapy.all import IP, TCP, sr1
        except ImportError:
            return self._connect_scan(target, ports)

        results: dict = {}

        def syn_probe(port: int) -> tuple[int, dict]:
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
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

    def _get_service(self, port: int) -> str:
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
        config: Optional[dict] = None,
    ) -> None:
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.config = config or {}
        self.console = Console()
        self.results = ScanResults()
        self.rate_limit = self.config.get("scanning", {}).get("rate_limit", 0.0)

    def run(
        self,
        target: str,
        full_scan: bool = False,
        skip_discovery: bool = False,
        scan_type: str = "connect",
        detect_services: bool = True,
        detect_os: bool = True,
        scan_vulns: bool = True,
    ) -> ScanResults:
        """Execute complete scan workflow."""
        from skull_netrecon.core.discovery import HostDiscovery

        self.console.print(f"[cyan]Initializing scan on {target}...[/cyan]")

        if not skip_discovery:
            discovery = HostDiscovery(timeout=int(self.timeout), threads=self.threads, verbose=self.verbose)
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
                self._scan_host(
                    host_info,
                    full_scan=full_scan,
                    scan_type=scan_type,
                    detect_services=detect_services,
                    detect_os=detect_os,
                    scan_vulns=scan_vulns,
                    progress=progress,
                )

        self._update_metadata()
        return self.results

    def _scan_host(
        self,
        host_info: dict,
        full_scan: bool,
        scan_type: str,
        detect_services: bool,
        detect_os: bool,
        scan_vulns: bool,
        progress: Progress,
    ) -> None:
        ip = host_info["ip"]
        task = progress.add_task(f"[cyan]Scanning {ip}...", total=None)

        port_results = self._scan_ports(ip, full_scan, scan_type)
        open_ports = port_results.get("open_ports", [])

        service_results: list = []
        if detect_services and open_ports:
            service_results = self._detect_services(ip, port_results)

        os_results: dict | None = None
        if detect_os and open_ports:
            os_results = self._detect_os(ip, open_ports)

        vulns: list = []
        if scan_vulns and service_results:
            vulns = self._scan_vulnerabilities(ip, service_results)

        vendor = host_info.get("vendor")
        if not vendor and host_info.get("mac"):
            vendor = self._lookup_mac_vendor(host_info["mac"])

        host = HostResult(
            ip=ip,
            hostname=host_info.get("hostname"),
            mac=host_info.get("mac"),
            vendor=vendor,
            os=os_results,
            ports=service_results,
            vulnerabilities=vulns,
        )
        self.results.add_host(host)
        progress.update(task, completed=True)

    def _scan_ports(self, ip: str, full_scan: bool, scan_type: str) -> dict:
        port_range = "1-65535" if full_scan else "quick"
        scanner = PortScanner(
            timeout=self.timeout,
            threads=self.threads,
            verbose=self.verbose,
            rate_limit=self.rate_limit,
        )
        return scanner.scan(ip, port_range=port_range, scan_type=scan_type)

    def _detect_services(self, ip: str, port_results: dict) -> list:
        detector = ServiceDetector(timeout=int(self.timeout), verbose=self.verbose)
        services = []
        for port in port_results.get("open_ports", []):
            port_info = port_results["ports"].get(port, {})
            service_hint = port_info.get("service")
            detected = detector.detect_service(ip, port, service_hint)
            port_info.update(detected)
            services.append(port_info)
        return services

    def _detect_os(self, ip: str, open_ports: list[int]) -> dict | None:
        if open_ports:
            fp = OSFingerprint(timeout=int(self.timeout), verbose=self.verbose)
            return fp.detect(ip, known_ports=open_ports)
        return {"name": "Unknown", "confidence": 0}

    def _scan_vulnerabilities(self, ip: str, services: list) -> list:
        vuln_scanner = VulnerabilityScanner(timeout=int(self.timeout), verbose=self.verbose)
        all_vulns = []
        for svc in services:
            vulns = vuln_scanner.scan(ip, svc)
            all_vulns.extend(vulns)
        return all_vulns

    def _lookup_mac_vendor(self, mac: str) -> str | None:
        from skull_netrecon.utils.network import mac_to_vendor

        oui_path = Path(__file__).parent.parent.parent / "data" / "oui_vendors.json"
        if oui_path.exists():
            try:
                with open(oui_path) as f:
                    oui_db = json.load(f)
                return mac_to_vendor(mac, oui_db)
            except Exception:
                pass
        return None

    def _update_metadata(self) -> None:
        self.results.metadata = {
            "total_hosts": len(self.results.hosts),
            "total_ports": sum(len(h.ports) for h in self.results.hosts),
            "total_vulns": sum(len(h.vulnerabilities) for h in self.results.hosts),
        }
