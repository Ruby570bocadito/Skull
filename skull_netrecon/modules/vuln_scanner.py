"""SKULL-NetRecon - Vulnerability Scanner Module"""

from __future__ import annotations

import json
import socket
import ssl
from pathlib import Path
from typing import Any, Dict, List


class VulnerabilityScanner:
    """Scan for known vulnerabilities."""

    def __init__(self, timeout: int = 3, verbose: bool = False) -> None:
        self.timeout = timeout
        self.verbose = verbose
        self.cve_db = self._load_json("data/cve_database.json")
        self.default_creds = self._load_json("data/default_credentials.json")

    def scan(self, target: str, service_info: Dict) -> List[Dict]:
        """Scan for vulnerabilities based on service information."""
        vulns: List[Dict] = []

        version_vulns = self._check_version_vulnerabilities(service_info)
        vulns.extend(version_vulns)

        if service_info.get("ssl") or service_info.get("port") == 443:
            ssl_vulns = self._check_ssl_vulnerabilities(target, service_info.get("port"))
            vulns.extend(ssl_vulns)

        default_cred_vulns = self._check_default_credentials(target, service_info)
        vulns.extend(default_cred_vulns)

        service = service_info.get("service", "").lower()
        port = service_info.get("port")

        if "http" in service or port in (80, 443, 8080, 8443):
            http_vulns = self._check_http_vulnerabilities(target, port or 80)
            vulns.extend(http_vulns)

        if "smb" in service or port == 445:
            smb_vulns = self._check_smb_vulnerabilities(target, service_info)
            vulns.extend(smb_vulns)

        if "ftp" in service or port == 21:
            ftp_vulns = self._check_ftp_vulnerabilities(target, service_info)
            vulns.extend(ftp_vulns)

        return vulns

    def _check_version_vulnerabilities(self, service_info: Dict) -> List[Dict]:
        """Check for known CVEs based on service version."""
        vulns: List[Dict] = []
        service = service_info.get("service", "")
        version = service_info.get("version")
        if not version:
            return vulns

        version_checks = self.cve_db.get("version_checks", {})
        for product, vuln_versions in version_checks.items():
            if product.lower() in service.lower():
                for version_pattern, cves in vuln_versions.get("vulnerable_versions", {}).items():
                    if self._is_version_vulnerable(version, version_pattern):
                        for cve in cves:
                            vulns.append({
                                "type": "CVE",
                                "name": cve,
                                "severity": "HIGH",
                                "description": f"{service} {version} is vulnerable to {cve}",
                                "service": service,
                                "version": version,
                                "port": service_info.get("port"),
                            })

        for vuln_category, vulns_list in self.cve_db.get("vulnerabilities", {}).items():
            for vuln_id, vuln_data in vulns_list.items():
                affected = vuln_data.get("affected_versions", [])
                for affected_version in affected:
                    if affected_version.lower() in f"{service} {version}".lower():
                        vulns.append({
                            "type": "CVE",
                            "cve": vuln_data.get("cve"),
                            "name": vuln_data.get("name"),
                            "severity": vuln_data.get("severity", "MEDIUM"),
                            "description": vuln_data.get("description"),
                            "service": service,
                            "version": version,
                            "port": service_info.get("port"),
                            "exploits": vuln_data.get("exploits", []),
                        })
        return vulns

    def _is_version_vulnerable(self, version: str, pattern: str) -> bool:
        """Check if version matches vulnerability pattern."""
        try:
            if pattern.startswith("<="):
                threshold = pattern.strip("<= ")
                return self._compare_versions(version, threshold) <= 0
            if pattern.startswith("<"):
                threshold = pattern.strip("< ")
                return self._compare_versions(version, threshold) < 0
            if pattern.startswith(">="):
                threshold = pattern.strip(">= ")
                return self._compare_versions(version, threshold) >= 0
            if pattern.startswith(">"):
                threshold = pattern.strip("> ")
                return self._compare_versions(version, threshold) > 0
            return version == pattern
        except Exception:
            return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings."""
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]
            while len(parts1) < len(parts2):
                parts1.append(0)
            while len(parts2) < len(parts1):
                parts2.append(0)
            for p1, p2 in zip(parts1, parts2):
                if p1 < p2:
                    return -1
                if p1 > p2:
                    return 1
            return 0
        except Exception:
            return 0

    def _check_ssl_vulnerabilities(self, target: str, port: int | None) -> List[Dict]:
        """Check for SSL/TLS vulnerabilities."""
        vulns: List[Dict] = []
        if not port:
            return vulns
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    ssl_version = ssock.version()
                    cipher = ssock.cipher()
                    if ssl_version in ("SSLv2", "SSLv3"):
                        vulns.append({
                            "type": "SSL/TLS",
                            "name": "Outdated SSL/TLS Version",
                            "severity": "HIGH",
                            "description": f"Server supports {ssl_version} which is deprecated",
                            "port": port,
                            "details": {"version": ssl_version},
                        })
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ["DES", "RC4", "MD5", "NULL"]):
                            vulns.append({
                                "type": "SSL/TLS",
                                "name": "Weak Cipher Suite",
                                "severity": "MEDIUM",
                                "description": f"Server uses weak cipher: {cipher_name}",
                                "port": port,
                                "details": {"cipher": cipher_name},
                            })
        except Exception:
            pass
        return vulns

    def _check_default_credentials(self, target: str, service_info: Dict) -> List[Dict]:
        """Check for default credentials (informational only)."""
        vulns: List[Dict] = []
        service = service_info.get("service", "").lower()
        port = service_info.get("port")
        for service_name, creds in self.default_creds.get("services", {}).items():
            if service_name.lower() in service:
                vulns.append({
                    "type": "Default Credentials",
                    "name": "Potential Default Credentials",
                    "severity": "MEDIUM",
                    "description": f"{service_name} service may have default credentials",
                    "port": port,
                    "details": {"info": "Manual testing recommended", "common_credentials": len(creds)},
                })
                break
        return vulns

    def _check_http_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Check for HTTP-specific vulnerabilities."""
        vulns: List[Dict] = []
        try:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{target}:{port}"
            response = requests.get(url, timeout=self.timeout, verify=False)
            headers = response.headers

            security_headers = {
                "X-Frame-Options": "Clickjacking Protection",
                "X-Content-Type-Options": "MIME Sniffing Protection",
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-XSS-Protection": "XSS Protection",
            }
            missing = [f"{h} ({d})" for h, d in security_headers.items() if h not in headers]
            if missing:
                vulns.append({
                    "type": "HTTP Security",
                    "name": "Missing Security Headers",
                    "severity": "LOW",
                    "description": "Server is missing important security headers",
                    "port": port,
                    "details": {"missing_headers": missing},
                })

            server_header = headers.get("Server", "")
            if server_header and any(c in server_header for c in ["/", "."]):
                vulns.append({
                    "type": "Information Disclosure",
                    "name": "Server Version Disclosure",
                    "severity": "INFO",
                    "description": f"Server header reveals version information: {server_header}",
                    "port": port,
                })
        except Exception:
            pass
        return vulns

    def _check_smb_vulnerabilities(self, target: str, service_info: Dict) -> List[Dict]:
        """Check for SMB vulnerabilities (informational)."""
        return [{
            "type": "SMB",
            "name": "SMB Service Detected",
            "severity": "INFO",
            "description": "SMB service should be checked for MS17-010 (EternalBlue)",
            "port": 445,
            "details": {"recommendation": "Run: nmap -p445 --script smb-vuln-ms17-010"},
        }]

    def _check_ftp_vulnerabilities(self, target: str, service_info: Dict) -> List[Dict]:
        """Check for FTP vulnerabilities."""
        vulns: List[Dict] = []
        service = service_info.get("service", "")
        version = service_info.get("version", "")
        port = service_info.get("port", 21)

        if "vsftpd" in service.lower() and "2.3.4" in version:
            vulns.append({
                "type": "FTP",
                "name": "vsftpd 2.3.4 Backdoor",
                "severity": "CRITICAL",
                "description": "vsftpd 2.3.4 contains a backdoor",
                "cve": "CVE-2011-2523",
                "port": port,
                "exploits": ["exploit/unix/ftp/vsftpd_234_backdoor"],
            })

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            sock.recv(1024)
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            if "230" in response or "331" in response:
                vulns.append({
                    "type": "FTP",
                    "name": "Anonymous FTP Login",
                    "severity": "MEDIUM",
                    "description": "FTP server allows anonymous login",
                    "port": port,
                })
        except Exception:
            pass
        return vulns

    def _load_json(self, path: str) -> Dict[str, Any]:
        """Load a JSON file, return empty dict on failure."""
        try:
            full = Path(__file__).parent.parent.parent / path
            with open(full) as f:
                return json.load(f)
        except Exception:
            return {}
