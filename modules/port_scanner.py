"""
SKULL-NetRecon - Port Scanner Module
Advanced port scanning with service detection
"""

import socket
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, sr1, conf
from utils.logger import get_logger

# Suppress Scapy warnings
conf.verb = 0


class PortScanner:
    """Advanced port scanner with multiple scan types"""
    
    def __init__(self, timeout: float = 2.0, threads: int = 100, verbose: bool = False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.logger = get_logger()
        
        # Load port database
        self.port_db = self._load_port_database()
        
        self.scan_results = {}
    
    def _load_port_database(self) -> Dict:
        """Load port service database"""
        try:
            db_path = Path(__file__).parent.parent / "data" / "ports_database.json"
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load port database: {e}")
            return {"common_ports": {}}
    
    def scan(self, target: str, ports: List[int], scan_type: str = "connect") -> Dict:
        """
        Scan ports on target host
        
        Args:
            target: Target IP address
            ports: List of ports to scan
            scan_type: Type of scan ('connect', 'syn', 'udp')
        
        Returns:
            Dictionary with scan results
        """
        self.logger.info(f"Scanning {len(ports)} ports on {target} using {scan_type.upper()} scan")
        
        if scan_type == "syn":
            results = self._syn_scan(target, ports)
        elif scan_type == "udp":
            results = self._udp_scan(target, ports)
        else:  # connect scan
            results = self._connect_scan(target, ports)
        
        self.scan_results[target] = {
            'ip': target,
            'ports': results,
            'open_ports': [p for p, info in results.items() if info['state'] == 'open'],
            'filtered_ports': [p for p, info in results.items() if info['state'] == 'filtered'],
            'closed_ports': [p for p, info in results.items() if info['state'] == 'closed']
        }
        
        open_count = len(self.scan_results[target]['open_ports'])
        self.logger.success(f"Found {open_count} open ports on {target}")
        
        return self.scan_results[target]
    
    def _connect_scan(self, target: str, ports: List[int]) -> Dict:
        """
        TCP Connect scan - Full TCP handshake
        Most reliable but easier to detect
        """
        results = {}
        
        def scan_port(port: int) -> Tuple[int, Dict]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                
                port_info = {
                    'port': port,
                    'state': 'open' if result == 0 else 'closed',
                    'service': self._get_service_name(port),
                    'protocol': 'tcp',
                    'banner': None
                }
                
                # Try to grab banner if port is open
                if result == 0:
                    try:
                        sock.settimeout(1)
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            port_info['banner'] = banner[:200]  # Limit banner length
                    except:
                        pass
                
                sock.close()
                
                if self.verbose and result == 0:
                    self.logger.debug(f"Port {port} is OPEN on {target}")
                
                return port, port_info
            
            except Exception as e:
                if self.verbose:
                    self.logger.debug(f"Error scanning port {port}: {e}")
                return port, {
                    'port': port,
                    'state': 'filtered',
                    'service': self._get_service_name(port),
                    'protocol': 'tcp',
                    'banner': None
                }
        
        # Multithreaded scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(futures):
                port, info = future.result()
                results[port] = info
        
        return results
    
    def _syn_scan(self, target: str, ports: List[int]) -> Dict:
        """
        TCP SYN scan - Half-open scan
        Stealthier than connect scan but requires privileges
        """
        results = {}
        
        def syn_probe(port: int) -> Tuple[int, Dict]:
            try:
                # Send SYN packet
                syn_packet = IP(dst=target) / TCP(dport=port, flags='S')
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    state = 'filtered'
                elif response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        state = 'open'
                        # Send RST to close connection
                        rst_packet = IP(dst=target) / TCP(dport=port, flags='R')
                        sr1(rst_packet, timeout=0.5, verbose=0)
                    elif response.getlayer(TCP).flags == 0x14:  # RST
                        state = 'closed'
                    else:
                        state = 'filtered'
                else:
                    state = 'filtered'
                
                port_info = {
                    'port': port,
                    'state': state,
                    'service': self._get_service_name(port),
                    'protocol': 'tcp',
                    'banner': None
                }
                
                if self.verbose and state == 'open':
                    self.logger.debug(f"Port {port} is OPEN on {target}")
                
                return port, port_info
            
            except Exception as e:
                if self.verbose:
                    self.logger.debug(f"SYN scan error on port {port}: {e}")
                return port, {
                    'port': port,
                    'state': 'filtered',
                    'service': self._get_service_name(port),
                    'protocol': 'tcp',
                    'banner': None
                }
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(syn_probe, port): port for port in ports}
            
            for future in as_completed(futures):
                port, info = future.result()
                results[port] = info
        
        return results
    
    def _udp_scan(self, target: str, ports: List[int]) -> Dict:
        """
        UDP scan
        Slower and less reliable than TCP scans
        """
        results = {}
        
        # UDP scan implementation (simplified)
        for port in ports:
            results[port] = {
                'port': port,
                'state': 'open|filtered',
                'service': self._get_service_name(port),
                'protocol': 'udp',
                'banner': None
            }
        
        return results
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port from database"""
        port_str = str(port)
        if port_str in self.port_db.get('common_ports', {}):
            return self.port_db['common_ports'][port_str]['service']
        
        # Fallback to socket.getservbyport
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"
    
    def quick_scan(self, target: str, port_range: str = "quick") -> Dict:
        """
        Quick scan of common ports
        
        Args:
            target: Target IP
            port_range: 'quick', 'common', or custom port list
        """
        if port_range == "quick":
            ports_str = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5900,8080"
        elif port_range == "common":
            ports_str = "1-1000"
        else:
            ports_str = port_range
        
        ports = self._parse_ports(ports_str)
        return self.scan(target, ports, scan_type="connect")
    
    def full_scan(self, target: str) -> Dict:
        """Full TCP port scan (1-65535)"""
        ports = list(range(1, 65536))
        self.logger.warning("Full port scan will take considerable time...")
        return self.scan(target, ports, scan_type="syn")
    
    def _parse_ports(self, port_str: str) -> List[int]:
        """Parse port string to list of integers"""
        ports = set()
        
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        
        return sorted(list(ports))
    
    def get_results(self, target: str = None) -> Dict:
        """Get scan results for target or all targets"""
        if target:
            return self.scan_results.get(target, {})
        return self.scan_results
