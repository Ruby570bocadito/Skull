"""SKULL-NetRecon - Service Detection Module"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Dict, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ServiceDetector:
    """Advanced service detection and version fingerprinting."""

    SIGNATURES: Dict[str, list[tuple[str, str]]] = {
        "SSH": [
            (r"OpenSSH[_\s]([\d\.]+)", "OpenSSH"),
            (r"Dropbear sshd ([\d\.]+)", "Dropbear"),
        ],
        "FTP": [
            (r"220.*vsftpd ([\d\.]+)", "vsftpd"),
            (r"220.*ProFTPD ([\d\.]+)", "ProFTPD"),
            (r"220.*FileZilla Server ([\d\.]+)", "FileZilla"),
            (r"220.*Microsoft FTP Service", "Microsoft FTP"),
        ],
        "HTTP": [
            (r"Apache/([\d\.]+)", "Apache"),
            (r"nginx/([\d\.]+)", "Nginx"),
            (r"Microsoft-IIS/([\d\.]+)", "IIS"),
        ],
        "SMTP": [
            (r"220.*Postfix", "Postfix"),
            (r"220.*Sendmail ([\d\.]+)", "Sendmail"),
            (r"220.*Microsoft ESMTP", "Microsoft SMTP"),
        ],
        "MySQL": [
            (r"[\d\.]+-([\d\.]+)-MariaDB", "MariaDB"),
            (r"([\d\.]+)-MySQL", "MySQL"),
        ],
        "SMB": [
            (r"Samba ([\d\.]+)", "Samba"),
        ],
    }

    def __init__(self, timeout: int = 3, verbose: bool = False) -> None:
        self.timeout = timeout
        self.verbose = verbose

    def detect_service(self, ip: str, port: int, service_hint: str | None = None) -> Dict:
        """Detect service version and details."""
        service_info: Dict = {
            "ip": ip,
            "port": port,
            "service": service_hint or "unknown",
            "version": None,
            "banner": None,
            "ssl": False,
            "details": {},
        }

        banner = self._grab_banner(ip, port)
        if banner:
            service_info["banner"] = banner
            detected = self._fingerprint_banner(banner, service_hint)
            if detected:
                service_info.update(detected)

        if port in (80, 8080) or (service_hint and service_hint.upper() == "HTTP"):
            http_info = self._detect_http(ip, port, use_https=False)
            service_info.update(http_info)
        elif port in (443, 8443) or (service_hint and service_hint.upper() == "HTTPS"):
            https_info = self._detect_http(ip, port, use_https=True)
            service_info.update(https_info)
        elif port == 22 or (service_hint and service_hint.upper() == "SSH"):
            ssh_info = self._detect_ssh(ip, port)
            service_info.update(ssh_info)
        elif port == 21 or (service_hint and service_hint.upper() == "FTP"):
            ftp_info = self._detect_ftp(ip, port)
            service_info.update(ftp_info)
        elif port == 25 or (service_hint and service_hint.upper() == "SMTP"):
            smtp_info = self._detect_smtp(ip, port)
            service_info.update(smtp_info)
        elif port == 3306 or (service_hint and service_hint.upper() == "MYSQL"):
            mysql_info = self._detect_mysql(ip, port)
            service_info.update(mysql_info)

        return service_info

    def _grab_banner(self, ip: str, port: int) -> str | None:
        """Grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.settimeout(2)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner if banner else None
        except Exception:
            return None

    def _fingerprint_banner(self, banner: str, service_hint: str | None = None) -> Dict | None:
        """Fingerprint service from banner."""
        for service_type, patterns in self.SIGNATURES.items():
            if service_hint and service_hint.upper() != service_type:
                continue
            for pattern, product in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result: Dict = {"service": product}
                    if match.groups():
                        result["version"] = match.group(1)
                    return result
        return None

    def _detect_http(self, ip: str, port: int, use_https: bool = False) -> Dict:
        """Detect HTTP/HTTPS service details."""
        protocol = "https" if use_https else "http"
        url = f"{protocol}://{ip}:{port}"
        info: Dict = {"service": "HTTPS" if use_https else "HTTP", "ssl": use_https, "details": {}}

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            server = response.headers.get("Server", "")
            if server:
                info["banner"] = server
                for pattern, product, version_group in [
                    (r"Apache/([\d\.]+)", "Apache", 1),
                    (r"nginx/([\d\.]+)", "Nginx", 1),
                    (r"Microsoft-IIS/([\d\.]+)", "IIS", 1),
                ]:
                    match = re.search(pattern, server)
                    if match:
                        info["service"] = product
                        info["version"] = match.group(version_group)
                        break

            info["details"]["x_powered_by"] = response.headers.get("X-Powered-By")
            info["details"]["status_code"] = response.status_code
            info["details"]["title"] = self._extract_title(response.text)
            cms = self._detect_cms(response.text, response.headers)
            if cms:
                info["details"]["cms"] = cms
        except Exception:
            pass

        return info

    def _detect_ssh(self, ip: str, port: int) -> Dict:
        """Detect SSH service details."""
        info: Dict = {"service": "SSH"}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            if banner:
                info["banner"] = banner
                if "OpenSSH" in banner:
                    match = re.search(r"OpenSSH[_\s]([\d\.]+)", banner)
                    if match:
                        info["service"] = "OpenSSH"
                        info["version"] = match.group(1)
        except Exception:
            pass
        return info

    def _detect_ftp(self, ip: str, port: int) -> Dict:
        """Detect FTP service details."""
        info: Dict = {"service": "FTP"}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            if banner:
                info["banner"] = banner
                for pattern, product in [(r"vsftpd ([\d\.]+)", "vsftpd"), (r"ProFTPD ([\d\.]+)", "ProFTPD")]:
                    match = re.search(pattern, banner)
                    if match:
                        info["service"] = product
                        info["version"] = match.group(1)
                        break
        except Exception:
            pass
        return info

    def _detect_smtp(self, ip: str, port: int) -> Dict:
        """Detect SMTP service details."""
        info: Dict = {"service": "SMTP"}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            if banner:
                info["banner"] = banner
                if "Postfix" in banner:
                    info["service"] = "Postfix"
                elif "Sendmail" in banner:
                    info["service"] = "Sendmail"
        except Exception:
            pass
        return info

    def _detect_mysql(self, ip: str, port: int) -> Dict:
        """Detect MySQL service details."""
        info: Dict = {"service": "MySQL"}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            data = sock.recv(1024)
            sock.close()
            if data:
                version_str = data.decode("utf-8", errors="ignore")
                if "MariaDB" in version_str:
                    info["service"] = "MariaDB"
        except Exception:
            pass
        return info

    def _extract_title(self, html: str) -> str | None:
        """Extract page title from HTML."""
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return None

    def _detect_cms(self, html: str, headers: Dict) -> str | None:
        """Detect CMS or framework."""
        html_lower = html.lower()
        if "wp-content" in html_lower or "wordpress" in html_lower:
            return "WordPress"
        if "joomla" in html_lower:
            return "Joomla"
        if "drupal" in html_lower or headers.get("X-Generator", "").startswith("Drupal"):
            return "Drupal"
        return None
