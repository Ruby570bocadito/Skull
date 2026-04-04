"""
SKULL-NetRecon - Host Discovery Module
Discover active hosts on the network using multiple techniques
"""

import socket
import struct
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP, conf
import netifaces
from utils.network_utils import expand_ip_range, resolve_hostname, get_local_ip
from utils.logger import get_logger

# Suppress Scapy warnings
conf.verb = 0


class HostDiscovery:
    """Host discovery engine using multiple detection methods"""
    
    def __init__(self, timeout: int = 2, threads: int = 50, verbose: bool = False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.logger = get_logger()
        self.active_hosts = []
    
    def discover(self, targets: List[str], methods: List[str] = None) -> List[Dict]:
        """
        Discover active hosts using specified methods
        
        Args:
            targets: List of IP addresses, CIDR ranges, or IP ranges
            methods: List of discovery methods ['arp', 'icmp', 'tcp']
        
        Returns:
            List of discovered hosts with metadata
        """
        if methods is None:
            methods = ['arp', 'icmp']
        
        # Expand targets to individual IPs
        all_ips = []
        for target in targets:
            all_ips.extend(expand_ip_range(target))
        
        if not all_ips:
            self.logger.error("No valid IP addresses to scan")
            return []
        
        self.logger.info(f"Starting host discovery for {len(all_ips)} addresses using methods: {', '.join(methods)}")
        
        discovered = {}
        
        # Try each discovery method
        if 'arp' in methods:
            self.logger.info("Running ARP scan...")
            arp_hosts = self._arp_scan(all_ips)
            for host in arp_hosts:
                discovered[host['ip']] = host
        
        if 'icmp' in methods:
            self.logger.info("Running ICMP ping sweep...")
            icmp_hosts = self._icmp_scan(all_ips)
            for host in icmp_hosts:
                if host['ip'] not in discovered:
                    discovered[host['ip']] = host
                else:
                    # Merge information
                    discovered[host['ip']].update(host)
        
        if 'tcp' in methods:
            self.logger.info("Running TCP SYN discovery...")
            tcp_hosts = self._tcp_syn_scan(all_ips)
            for host in tcp_hosts:
                if host['ip'] not in discovered:
                    discovered[host['ip']] = host
                else:
                    discovered[host['ip']].update(host)
        
        # Convert to list and add hostnames
        self.active_hosts = list(discovered.values())
        
        # Resolve hostnames
        self._resolve_hostnames()
        
        self.logger.success(f"Discovered {len(self.active_hosts)} active hosts")
        
        return self.active_hosts
    
    def _arp_scan(self, ips: List[str]) -> List[Dict]:
        """
        ARP scan for local network discovery
        Fast and reliable for local networks
        """
        hosts = []
        
        try:
            # Group IPs by network for efficient ARP scanning
            networks = set()
            for ip in ips:
                try:
                    network = '.'.join(ip.split('.')[:3]) + '.0/24'
                    networks.add(network)
                except:
                    pass
            
            for network in networks:
                try:
                    # Create ARP request
                    arp_request = ARP(pdst=network)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast / arp_request
                    
                    # Send and receive
                    answered, _ = srp(arp_request_broadcast, timeout=self.timeout, verbose=0, retry=1)
                    
                    for sent, received in answered:
                        if received.psrc in ips:
                            hosts.append({
                                'ip': received.psrc,
                                'mac': received.hwsrc,
                                'method': 'ARP',
                                'hostname': None
                            })
                            if self.verbose:
                                self.logger.debug(f"ARP: Found {received.psrc} ({received.hwsrc})")
                
                except Exception as e:
                    if self.verbose:
                        self.logger.debug(f"ARP scan error for {network}: {e}")
        
        except Exception as e:
            self.logger.warning(f"ARP scan failed: {e}")
        
        return hosts
    
    def _icmp_scan(self, ips: List[str]) -> List[Dict]:
        """
        ICMP ping sweep
        Works across networks but may be blocked by firewalls
        """
        hosts = []
        
        def ping_host(ip: str) -> Optional[Dict]:
            try:
                # Send ICMP echo request
                icmp_packet = IP(dst=ip) / ICMP()
                response = sr1(icmp_packet, timeout=self.timeout, verbose=0)
                
                if response:
                    if self.verbose:
                        self.logger.debug(f"ICMP: Host {ip} is alive")
                    
                    return {
                        'ip': ip,
                        'mac': None,
                        'method': 'ICMP',
                        'hostname': None,
                        'ttl': response.ttl if hasattr(response, 'ttl') else None
                    }
            except Exception as e:
                if self.verbose:
                    self.logger.debug(f"ICMP ping failed for {ip}: {e}")
            
            return None
        
        # Multithreaded ping
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in ips}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    hosts.append(result)
        
        return hosts
    
    def _tcp_syn_scan(self, ips: List[str], ports: List[int] = None) -> List[Dict]:
        """
        TCP SYN scan on common ports
        Useful when ICMP is blocked
        """
        if ports is None:
            ports = [80, 443, 22, 21, 445]  # Common ports
        
        hosts = []
        discovered_ips = set()
        
        def syn_probe(ip: str, port: int) -> Optional[str]:
            try:
                # Send SYN packet
                syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)
                
                if response and response.haslayer(TCP):
                    flags = response.getlayer(TCP).flags
                    # SYN-ACK or RST means host is up
                    if flags == 0x12 or flags == 0x14:  # SYN-ACK or RST
                        return ip
            except Exception as e:
                if self.verbose:
                    self.logger.debug(f"TCP SYN probe failed for {ip}:{port}: {e}")
            
            return None
        
        # Scan each IP on multiple ports
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for ip in ips:
                for port in ports:
                    futures.append(executor.submit(syn_probe, ip, port))
            
            for future in as_completed(futures):
                result = future.result()
                if result and result not in discovered_ips:
                    discovered_ips.add(result)
                    hosts.append({
                        'ip': result,
                        'mac': None,
                        'method': 'TCP-SYN',
                        'hostname': None
                    })
                    if self.verbose:
                        self.logger.debug(f"TCP-SYN: Host {result} is alive")
        
        return hosts
    
    def _resolve_hostnames(self):
        """Resolve hostnames for discovered hosts"""
        def resolve(host: Dict):
            hostname = resolve_hostname(host['ip'], timeout=1)
            if hostname:
                host['hostname'] = hostname
                if self.verbose:
                    self.logger.debug(f"Resolved {host['ip']} to {hostname}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(resolve, host) for host in self.active_hosts]
            for future in as_completed(futures):
                future.result()
    
    def get_results(self) -> List[Dict]:
        """Get discovery results"""
        return self.active_hosts
    
    def quick_scan(self, target: str) -> List[Dict]:
        """Quick scan using only ARP (fastest for local networks)"""
        return self.discover([target], methods=['arp'])
    
    def thorough_scan(self, target: str) -> List[Dict]:
        """Thorough scan using all methods"""
        return self.discover([target], methods=['arp', 'icmp', 'tcp'])
