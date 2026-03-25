"""SKULL-NetRecon - Professional Network Reconnaissance Tool"""

__version__ = "1.0.0"
__author__ = "SKULL Security Team"

from skull_netrecon.core.scanner import Scanner
from skull_netrecon.core.discovery import HostDiscovery

__all__ = ["Scanner", "HostDiscovery", "__version__"]
