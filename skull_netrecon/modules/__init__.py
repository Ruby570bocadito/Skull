"""SKULL-NetRecon Modules - Re-export from original modules"""

import sys
from pathlib import Path

_module_dir = Path(__file__).parent.parent.parent / "modules"
if _module_dir.exists():
    sys.path.insert(0, str(_module_dir.parent))

from modules.port_scanner import PortScanner as _PortScanner
from modules.service_detection import ServiceDetector as _ServiceDetector
from modules.os_fingerprint import OSFingerprint as _OSFingerprint
from modules.vuln_scanner import VulnerabilityScanner as _VulnScanner

PortScanner = _PortScanner
ServiceDetector = _ServiceDetector
OSFingerprint = _OSFingerprint
VulnerabilityScanner = _VulnScanner

__all__ = ["PortScanner", "ServiceDetector", "OSFingerprint", "VulnerabilityScanner"]
