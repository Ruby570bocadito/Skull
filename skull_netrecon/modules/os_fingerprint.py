"""SKULL-NetRecon - OS Fingerprinting Module"""

from __future__ import annotations

import socket
from typing import Dict, Optional


class OSFingerprint:
    """Operating System detection and fingerprinting."""

    TTL_SIGNATURES: Dict[int, list[str]] = {
        64: ["Linux", "Unix", "Android"],
        128: ["Windows"],
        255: ["Cisco", "Network Device"],
        60: ["macOS", "BSD"],
    }

    WINDOW_SIGNATURES: Dict[int, list[str]] = {
        8192: ["Windows (older)"],
        65535: ["Linux", "FreeBSD"],
        5840: ["Windows 7/8/10"],
        64240: ["Windows Server 2008+"],
    }

    def __init__(self, timeout: int = 2, verbose: bool = False) -> None:
        self.timeout = timeout
        self.verbose = verbose

    def detect(self, target: str, known_ports: list[int] | None = None) -> Dict:
        """Detect operating system."""
        result: Dict = {
            "ip": target,
            "os": "Unknown",
            "confidence": 0,
            "details": {},
            "methods": [],
        }

        ttl_result = self._ttl_based_detection(target)
        if ttl_result:
            result["details"]["ttl"] = ttl_result
            result["methods"].append("TTL Analysis")
            if ttl_result.get("os_guess"):
                result["os"] = ttl_result["os_guess"][0]
                result["confidence"] = 60

        if known_ports:
            tcp_result = self._tcp_stack_fingerprinting(target, known_ports[0])
            if tcp_result:
                result["details"]["tcp_stack"] = tcp_result
                result["methods"].append("TCP Stack Fingerprinting")
                if tcp_result.get("os_guess"):
                    if result["os"] == "Unknown":
                        result["os"] = tcp_result["os_guess"][0]
                        result["confidence"] = 50
                    elif tcp_result["os_guess"][0] == result["os"]:
                        result["confidence"] = min(90, result["confidence"] + 30)

        if known_ports:
            banner_hints = self._banner_os_hints(target, known_ports)
            if banner_hints:
                result["details"]["banner_hints"] = banner_hints
                result["methods"].append("Banner Analysis")
                if banner_hints.get("os"):
                    if result["os"] == "Unknown":
                        result["os"] = banner_hints["os"]
                        result["confidence"] = 70
                    elif banner_hints["os"].lower() in result["os"].lower():
                        result["confidence"] = min(95, result["confidence"] + 25)

        return result

    def _ttl_based_detection(self, target: str) -> Dict | None:
        """Detect OS based on TTL value from ICMP response."""
        try:
            from scapy.all import IP, ICMP, sr1

            icmp_packet = IP(dst=target) / ICMP()
            response = sr1(icmp_packet, timeout=self.timeout, verbose=0)

            if response and hasattr(response, "ttl"):
                ttl = response.ttl
                closest_ttl = min(self.TTL_SIGNATURES.keys(), key=lambda x: abs(x - ttl))
                initial_ttl = closest_ttl
                hops = initial_ttl - ttl

                return {
                    "received_ttl": ttl,
                    "initial_ttl": initial_ttl,
                    "hops": hops,
                    "os_guess": self.TTL_SIGNATURES.get(closest_ttl, ["Unknown"]),
                }
        except ImportError:
            return self._ttl_via_socket(target)
        except Exception:
            pass
        return None

    def _ttl_via_socket(self, target: str) -> Dict | None:
        """Fallback TTL detection using raw sockets."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            sock.sendto(b"\x08\x00\x00\x00\x00\x01\x00\x01", (target, 0))
            data, _ = sock.recvfrom(1024)
            sock.close()

            if len(data) >= 24:
                ttl = data[8]
                closest_ttl = min(self.TTL_SIGNATURES.keys(), key=lambda x: abs(x - ttl))
                return {
                    "received_ttl": ttl,
                    "initial_ttl": closest_ttl,
                    "hops": closest_ttl - ttl,
                    "os_guess": self.TTL_SIGNATURES.get(closest_ttl, ["Unknown"]),
                }
        except Exception:
            pass
        return None

    def _tcp_stack_fingerprinting(self, target: str, port: int) -> Dict | None:
        """Fingerprint OS based on TCP/IP stack behavior."""
        try:
            from scapy.all import IP, TCP, sr1

            syn_packet = IP(dst=target) / TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)

            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                window_size = tcp_layer.window
                ttl = response.ttl

                os_guess: list[str] = []
                if window_size in self.WINDOW_SIGNATURES:
                    os_guess = self.WINDOW_SIGNATURES[window_size]
                elif window_size > 60000:
                    os_guess = ["Linux", "Unix"]
                elif window_size < 20000:
                    os_guess = ["Windows"]

                closest_ttl = min(self.TTL_SIGNATURES.keys(), key=lambda x: abs(x - ttl))
                ttl_guess = self.TTL_SIGNATURES.get(closest_ttl, [])

                combined = list(set(os_guess) & set(ttl_guess))
                if not combined:
                    combined = os_guess if os_guess else ttl_guess

                rst_packet = IP(dst=target) / TCP(dport=port, flags="R")
                sr1(rst_packet, timeout=0.5, verbose=0)

                return {
                    "window_size": window_size,
                    "ttl": ttl,
                    "tcp_options": tcp_layer.options if hasattr(tcp_layer, "options") else [],
                    "os_guess": combined,
                }
        except Exception:
            pass
        return None

    def _banner_os_hints(self, target: str, ports: list[int]) -> Dict | None:
        """Extract OS hints from service banners."""
        for port in ports[:3]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                sock.settimeout(1)
                banner = sock.recv(1024).decode("utf-8", errors="ignore").lower()
                sock.close()

                if banner:
                    for keyword, os_name in [
                        ("ubuntu", "Linux (Debian-based)"),
                        ("debian", "Linux (Debian-based)"),
                        ("centos", "Linux (RedHat-based)"),
                        ("redhat", "Linux (RedHat-based)"),
                        ("rhel", "Linux (RedHat-based)"),
                        ("windows", "Windows"),
                        ("microsoft", "Windows"),
                        ("freebsd", "FreeBSD"),
                        ("openbsd", "OpenBSD"),
                        ("darwin", "macOS"),
                        ("macos", "macOS"),
                    ]:
                        if keyword in banner:
                            return {"os": os_name, "banner_port": port}
            except Exception:
                continue
        return None
