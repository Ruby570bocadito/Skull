"""SKULL-NetRecon - Professional Network Reconnaissance Tool"""

__version__ = "1.0.0"
__author__ = "SKULL Security Team"

__all__ = ["Scanner", "HostDiscovery", "__version__"]


def __getattr__(name: str):
    if name == "Scanner":
        from skull_netrecon.core.scanner import Scanner
        return Scanner
    if name == "HostDiscovery":
        from skull_netrecon.core.discovery import HostDiscovery
        return HostDiscovery
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
