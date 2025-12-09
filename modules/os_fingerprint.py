"""
SKULL-NetRecon - OS Fingerprinting Module
Detect operating systems through various techniques
"""

import socket
from typing import Dict, Optional
from scapy.all import IP, ICMP, sr1, TCP, conf
from utils.logger import get_logger

# Suppress Scapy warnings
conf.verb = 0


class OSFingerprint:
    """Operating System detection and fingerprinting"""
    
    def __init__(self, timeout: int = 2, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.logger = get_logger()
        
        # TTL to OS mapping
        self.ttl_signatures = {
            64: ['Linux', 'Unix', 'Android'],
            128: ['Windows'],
            255: ['Cisco', 'Network Device'],
            60: ['macOS', 'BSD']
        }
        
        # TCP Window size signatures
        self.window_signatures = {
            8192: ['Windows (older)'],
            65535: ['Linux', 'FreeBSD'],
            5840: ['Windows 7/8/10'],
            64240: ['Windows Server 2008+']
        }
    
    def detect(self, target: str, known_ports: list = None) -> Dict:
        """
        Detect operating system
        
        Args:
            target: Target IP address
            known_ports: List of known open ports (optional)
        
        Returns:
            Dictionary with OS detection results
        """
        result = {
            'ip': target,
            'os': 'Unknown',
            'confidence': 0,
            'details': {},
            'methods': []
        }
        
        # TTL-based detection
        ttl_result = self._ttl_based_detection(target)
        if ttl_result:
            result['details']['ttl'] = ttl_result
            result['methods'].append('TTL Analysis')
            
            # Update OS guess
            if ttl_result.get('os_guess'):
                result['os'] = ttl_result['os_guess'][0]
                result['confidence'] = 60
        
        # TCP/IP stack fingerprinting
        if known_ports:
            tcp_result = self._tcp_stack_fingerprinting(target, known_ports[0])
            if tcp_result:
                result['details']['tcp_stack'] = tcp_result
                result['methods'].append('TCP Stack Fingerprinting')
                
                # Refine OS guess
                if tcp_result.get('os_guess'):
                    if result['os'] == 'Unknown':
                        result['os'] = tcp_result['os_guess'][0]
                        result['confidence'] = 50
                    elif tcp_result['os_guess'][0] == result['os']:
                        result['confidence'] = min(90, result['confidence'] + 30)
        
        # Banner-based hints
        if known_ports:
            banner_hints = self._banner_os_hints(target, known_ports)
            if banner_hints:
                result['details']['banner_hints'] = banner_hints
                result['methods'].append('Banner Analysis')
                
                if banner_hints.get('os'):
                    if result['os'] == 'Unknown':
                        result['os'] = banner_hints['os']
                        result['confidence'] = 70
                    elif banner_hints['os'].lower() in result['os'].lower():
                        result['confidence'] = min(95, result['confidence'] + 25)
        
        if self.verbose:
            self.logger.debug(f"OS Detection for {target}: {result['os']} ({result['confidence']}% confidence)")
        
        return result
    
    def _ttl_based_detection(self, target: str) -> Optional[Dict]:
        """Detect OS based on TTL value from ICMP response"""
        try:
            # Send ICMP echo request
            icmp_packet = IP(dst=target) / ICMP()
            response = sr1(icmp_packet, timeout=self.timeout, verbose=0)
            
            if response and hasattr(response, 'ttl'):
                ttl = response.ttl
                
                # Find closest TTL signature
                closest_ttl = min(self.ttl_signatures.keys(), key=lambda x: abs(x - ttl))
                
                # Calculate initial TTL (usually 64, 128, or 255)
                initial_ttl = closest_ttl
                hops = initial_ttl - ttl
                
                return {
                    'received_ttl': ttl,
                    'initial_ttl': initial_ttl,
                    'hops': hops,
                    'os_guess': self.ttl_signatures.get(closest_ttl, ['Unknown'])
                }
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"TTL detection failed for {target}: {e}")
        
        return None
    
    def _tcp_stack_fingerprinting(self, target: str, port: int) -> Optional[Dict]:
        """Fingerprint OS based on TCP/IP stack behavior"""
        try:
            # Send SYN packet
            syn_packet = IP(dst=target) / TCP(dport=port, flags='S')
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                
                window_size = tcp_layer.window
                ttl = response.ttl
                
                # Analyze window size
                os_guess = []
                
                if window_size in self.window_signatures:
                    os_guess = self.window_signatures[window_size]
                elif window_size > 60000:
                    os_guess = ['Linux', 'Unix']
                elif window_size < 20000:
                    os_guess = ['Windows']
                
                # Combine with TTL
                closest_ttl = min(self.ttl_signatures.keys(), key=lambda x: abs(x - ttl))
                ttl_guess = self.ttl_signatures.get(closest_ttl, [])
                
                # Find intersection or use both
                combined_guess = list(set(os_guess) & set(ttl_guess))
                if not combined_guess:
                    combined_guess = os_guess if os_guess else ttl_guess
                
                # Send RST to close connection
                rst_packet = IP(dst=target) / TCP(dport=port, flags='R')
                sr1(rst_packet, timeout=0.5, verbose=0)
                
                return {
                    'window_size': window_size,
                    'ttl': ttl,
                    'tcp_options': tcp_layer.options if hasattr(tcp_layer, 'options') else [],
                    'os_guess': combined_guess
                }
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"TCP fingerprinting failed for {target}:{port}: {e}")
        
        return None
    
    def _banner_os_hints(self, target: str, ports: list) -> Optional[Dict]:
        """Extract OS hints from service banners"""
        for port in ports[:3]:  # Check first 3 open ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                
                # Receive banner
                sock.settimeout(1)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').lower()
                sock.close()
                
                if banner:
                    # Look for OS hints in banner
                    if 'ubuntu' in banner or 'debian' in banner:
                        return {'os': 'Linux (Debian-based)', 'banner_port': port}
                    elif 'centos' in banner or 'redhat' in banner or 'rhel' in banner:
                        return {'os': 'Linux (RedHat-based)', 'banner_port': port}
                    elif 'windows' in banner or 'microsoft' in banner:
                        return {'os': 'Windows', 'banner_port': port}
                    elif 'freebsd' in banner:
                        return {'os': 'FreeBSD', 'banner_port': port}
                    elif 'openbsd' in banner:
                        return {'os': 'OpenBSD', 'banner_port': port}
                    elif 'darwin' in banner or 'macos' in banner:
                        return {'os': 'macOS', 'banner_port': port}
            
            except:
                continue
        
        return None
    
    def get_os_details(self, os_name: str) -> Dict:
        """Get additional details about detected OS"""
        os_info = {
            'Linux': {
                'type': 'Unix-like',
                'common_services': ['SSH', 'HTTP', 'MySQL'],
                'default_shell': 'bash',
                'package_manager': 'apt/yum/dnf'
            },
            'Windows': {
                'type': 'Microsoft',
                'common_services': ['RDP', 'SMB', 'WinRM'],
                'default_shell': 'cmd/powershell',
                'package_manager': 'Windows Update'
            },
            'macOS': {
                'type': 'Unix-like (BSD)',
                'common_services': ['SSH', 'AFP', 'HTTP'],
                'default_shell': 'zsh/bash',
                'package_manager': 'Homebrew'
            },
            'FreeBSD': {
                'type': 'BSD Unix',
                'common_services': ['SSH', 'HTTP'],
                'default_shell': 'tcsh/bash',
                'package_manager': 'pkg'
            }
        }
        
        for os_key, details in os_info.items():
            if os_key.lower() in os_name.lower():
                return details
        
        return {'type': 'Unknown', 'common_services': [], 'default_shell': 'unknown', 'package_manager': 'unknown'}
