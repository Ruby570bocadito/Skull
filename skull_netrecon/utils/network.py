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
            start_ip = ipaddress.ip_address(start.strip())
            endOctet = int(end.strip())
            startOctets = start.split(".")[:3]
            
            for i in range(startOctets[-1], endOctet + 1):
                ip = ".".join(startOctets[:3] + [str(i)])
                ips.append(ip)
        else:
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
    if not mac or not oui_db:
        return None
    
    try:
        oui = mac.replace(":", "").upper()[:6]
        return oui_db.get("vendors", {}).get(oui)
    except Exception:
        return None
