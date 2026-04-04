"""SKULL-NetRecon - Host Discovery Module"""

from __future__ import annotations

import socket
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class HostDiscovery:
    """Host discovery engine."""
    
    def __init__(
        self,
        timeout: int = 2,
        threads: int = 50,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.active_hosts: list[dict] = []
    
    def discover(
        self,
        targets: list[str],
        methods: Optional[list[str]] = None,
    ) -> list[dict]:
        """Discover active hosts."""
        if methods is None:
            methods = ["tcp", "icmp"]
        
        all_ips = self._expand_targets(targets)
        
        if not all_ips:
            return []
        
        discovered: dict = {}
        
        def check_host(ip: str) -> Optional[dict]:
            if self._is_host_alive(ip):
                return {"ip": ip, "method": "tcp", "mac": None, "open_ports": self._get_open_ports(ip)}
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in all_ips}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered[result["ip"]] = result
        
        self.active_hosts = list(discovered.values())
        
        if self.active_hosts:
            self._resolve_hostnames()
        
        return self.active_hosts
    
    def _get_open_ports(self, ip: str) -> list[int]:
        """Get open ports on host."""
        ports = []
        quick_ports = [22, 80, 443, 445, 139, 3389, 8080]
        
        for port in quick_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    ports.append(port)
            except Exception:
                continue
        return ports
    
    def _is_host_alive(self, ip: str) -> bool:
        """Quick check if host is alive using TCP connect."""
        quick_ports = [80, 443]
        
        for port in quick_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except Exception:
                continue
        return False
    
    def _expand_targets(self, targets: list[str]) -> list[str]:
        """Expand targets to IP list."""
        from skull_netrecon.utils.network import expand_ip_range
        
        ips = []
        for target in targets:
            ips.extend(expand_ip_range(target))
        return ips
    
    def _arp_scan(self, ips: list[str]) -> list[dict]:
        """ARP scan for local networks."""
        hosts = []
        
        try:
            from scapy.all import ARP, Ether, srp
            
            networks = set()
            for ip in ips:
                try:
                    network = ".".join(ip.split(".")[:3]) + ".0/24"
                    networks.add(network)
                except Exception:
                    pass
            
            for network in networks:
                try:
                    arp_req = ARP(pdst=network)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    answered, _ = srp(broadcast / arp_req, timeout=self.timeout, verbose=0)
                    
                    for _, received in answered:
                        if received.psrc in ips:
                            hosts.append({
                                "ip": received.psrc,
                                "mac": received.hwsrc,
                                "method": "ARP",
                            })
                except Exception:
                    pass
        
        except ImportError:
            pass
        
        return hosts
    
    def _icmp_scan(self, ips: list[str]) -> list[dict]:
        """ICMP ping sweep."""
        hosts = []
        
        try:
            from scapy.all import IP, ICMP, sr1
            
            def ping(ip: str) -> Optional[dict]:
                try:
                    pkt = IP(dst=ip) / ICMP()
                    resp = sr1(pkt, timeout=self.timeout, verbose=0)
                    if resp:
                        return {"ip": ip, "method": "ICMP", "ttl": getattr(resp, "ttl", None)}
                except Exception:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(ping, ip): ip for ip in ips}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        hosts.append(result)
        
        except ImportError:
            for ip in ips:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((ip, 80))
                    hosts.append({"ip": ip, "method": "TCP"})
                    sock.close()
                except Exception:
                    pass
        
        return hosts
    
    def _tcp_scan(self, ips: list[str]) -> list[dict]:
        """TCP SYN discovery."""
        hosts = []
        ports = [80, 443, 22, 21, 445]
        
        try:
            from scapy.all import IP, TCP, sr1
            
            def probe(ip: str, port: int) -> Optional[str]:
                try:
                    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
                    resp = sr1(pkt, timeout=self.timeout, verbose=0)
                    if resp and resp.haslayer(TCP):
                        flags = resp.getlayer(TCP).flags
                        if flags in (0x12, 0x14):
                            return ip
                except Exception:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for ip in ips:
                    for port in ports:
                        futures.append(executor.submit(probe, ip, port))
                
                for future in as_completed(futures):
                    result = future.result()
                    if result and result not in [h["ip"] for h in hosts]:
                        hosts.append({"ip": result, "method": "TCP-SYN"})
        
        except ImportError:
            pass
        
        return hosts
    
    def _resolve_hostnames(self) -> None:
        """Resolve hostnames for discovered hosts."""
        for host in self.active_hosts:
            try:
                hostname, _, _ = socket.gethostbyaddr(host["ip"])
                host["hostname"] = hostname
            except (socket.herror, socket.gaierror):
                host["hostname"] = None
