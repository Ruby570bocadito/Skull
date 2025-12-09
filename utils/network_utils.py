"""
SKULL-NetRecon - Network Utilities
Professional utility functions for network operations
"""

import socket
import struct
import ipaddress
from typing import List, Tuple, Optional
import netifaces


def validate_ip(ip: str) -> bool:
    """Validate if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Validate if string is a valid CIDR notation"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str) -> List[str]:
    """
    Expand CIDR notation to list of IP addresses
    Example: 192.168.1.0/24 -> ['192.168.1.0', '192.168.1.1', ..., '192.168.1.255']
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def expand_ip_range(ip_range: str) -> List[str]:
    """
    Expand IP range to list of IPs
    Supports formats:
    - CIDR: 192.168.1.0/24
    - Range: 192.168.1.1-192.168.1.254
    - Single: 192.168.1.1
    """
    if '/' in ip_range:
        # CIDR notation
        return expand_cidr(ip_range)
    elif '-' in ip_range:
        # Range notation
        start_ip, end_ip = ip_range.split('-')
        start_ip = start_ip.strip()
        end_ip = end_ip.strip()
        
        # Handle partial end IP (e.g., 192.168.1.1-254)
        if '.' not in end_ip:
            parts = start_ip.split('.')
            end_ip = '.'.join(parts[:3] + [end_ip])
        
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            ips = []
            current = int(start)
            end_int = int(end)
            
            while current <= end_int:
                ips.append(str(ipaddress.ip_address(current)))
                current += 1
            
            return ips
        except ValueError:
            return []
    else:
        # Single IP
        if validate_ip(ip_range):
            return [ip_range]
        return []


def parse_port_range(port_str: str) -> List[int]:
    """
    Parse port range string to list of ports
    Supports: "80", "80,443,8080", "1-1000", "1-100,443,8000-9000"
    """
    ports = set()
    
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            # Range
            try:
                start, end = part.split('-')
                start, end = int(start), int(end)
                if 1 <= start <= 65535 and 1 <= end <= 65535:
                    ports.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                continue
    
    return sorted(list(ports))


def get_local_ip() -> str:
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_network_interfaces() -> List[Tuple[str, str]]:
    """
    Get all network interfaces with their IPs
    Returns: [(interface_name, ip_address), ...]
    """
    interfaces = []
    
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get('addr')
                if ip and ip != '127.0.0.1':
                    interfaces.append((iface, ip))
    
    return interfaces


def get_default_gateway() -> Optional[str]:
    """Get default gateway IP"""
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
        if default_gateway:
            return default_gateway[0]
    except Exception:
        pass
    return None


def calculate_network(ip: str, netmask: str = "255.255.255.0") -> str:
    """Calculate network address from IP and netmask"""
    try:
        interface = ipaddress.ip_interface(f"{ip}/{netmask}")
        return str(interface.network)
    except ValueError:
        return ""


def mac_to_vendor(mac: str, oui_db: dict) -> str:
    """
    Lookup vendor from MAC address using OUI database
    MAC format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
    """
    # Normalize MAC address
    mac = mac.upper().replace('-', ':')
    oui = mac[:8]  # First 3 octets (AA:BB:CC)
    
    return oui_db.get(oui, "Unknown")


def resolve_hostname(ip: str, timeout: int = 2) -> Optional[str]:
    """Resolve IP to hostname"""
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return None


def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Quick TCP connect test to check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def generate_ip_list(targets: List[str]) -> List[str]:
    """
    Generate complete list of IPs from mixed target formats
    Handles: single IPs, CIDR, ranges, hostnames
    """
    all_ips = []
    
    for target in targets:
        target = target.strip()
        
        # Try as hostname first
        if not any(c.isdigit() for c in target.split('.')[0]):
            try:
                ip = socket.gethostbyname(target)
                all_ips.append(ip)
                continue
            except socket.gaierror:
                pass
        
        # Expand as IP range
        ips = expand_ip_range(target)
        all_ips.extend(ips)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_ips = []
    for ip in all_ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    
    return unique_ips


def format_mac(mac: str) -> str:
    """Format MAC address to standard AA:BB:CC:DD:EE:FF format"""
    # Remove common separators
    mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
    
    # Add colons every 2 characters
    if len(mac) == 12:
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    
    return mac


def cidr_to_netmask(cidr: int) -> str:
    """Convert CIDR notation to netmask (e.g., 24 -> 255.255.255.0)"""
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return socket.inet_ntoa(struct.pack('>I', mask))


def netmask_to_cidr(netmask: str) -> int:
    """Convert netmask to CIDR notation (e.g., 255.255.255.0 -> 24)"""
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))
