"""SKULL-NetRecon - Network Utilities"""

import ipaddress
import socket
from typing import Iterator


def expand_ip_range(target: str) -> list[str]:
    """Expand IP range to list of IPs."""
    ips = []
    
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        elif "-" in target:
            start, end = target.split("-")
            start = start.strip()
            end = end.strip()
            
            if "." not in end:
                end_octet = int(end)
                start_octets = start.split(".")
                start_last = int(start_octets[3]) if len(start_octets) == 4 else 1
                prefix = ".".join(start_octets[:3])
                
                for i in range(start_last, end_octet + 1):
                    ips.append(f"{prefix}.{i}")
            else:
                start_ip = ipaddress.ip_address(start)
                end_ip = ipaddress.ip_address(end)
                
                current = int(start_ip)
                end_int = int(end_ip)
                while current <= end_int:
                    ips.append(str(ipaddress.ip_address(current)))
                    current += 1
        else:
            if validate_ip(target):
                ips = [target]
    
    except ValueError:
        pass
    
    return ips


def validate_ip(ip: str) -> bool:
    """Validate IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def resolve_hostname(ip: str, timeout: int = 1) -> str | None:
    """Resolve hostname from IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def get_local_ip() -> str:
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def mac_to_vendor(mac: str, oui_db: dict) -> str | None:
    """Lookup MAC vendor from OUI database."""
    if not mac:
        return None
    
    try:
        mac_normalized = mac.upper().replace("-", ":")
        oui = mac_normalized[:8]
        return oui_db.get(oui, "Unknown")
    except Exception:
        return None
