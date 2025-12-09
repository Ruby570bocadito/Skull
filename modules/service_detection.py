"""
SKULL-NetRecon - Service Detection Module
Advanced service version detection and fingerprinting
"""

import socket
import ssl
import json
import re
from pathlib import Path
from typing import Dict, Optional, List
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from utils.logger import get_logger

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ServiceDetector:
    """Advanced service detection and version fingerprinting"""
    
    def __init__(self, timeout: int = 3, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.logger = get_logger()
        
        # Service signatures
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict:
        """Load service signatures for fingerprinting"""
        return {
            'SSH': [
                (r'OpenSSH[_\s]([\d\.]+)', 'OpenSSH'),
                (r'Dropbear sshd ([\d\.]+)', 'Dropbear'),
            ],
            'FTP': [
                (r'220.*vsftpd ([\d\.]+)', 'vsftpd'),
                (r'220.*ProFTPD ([\d\.]+)', 'ProFTPD'),
                (r'220.*FileZilla Server ([\d\.]+)', 'FileZilla'),
                (r'220.*Microsoft FTP Service', 'Microsoft FTP'),
            ],
            'HTTP': [
                (r'Apache/([\d\.]+)', 'Apache'),
                (r'nginx/([\d\.]+)', 'Nginx'),
                (r'Microsoft-IIS/([\d\.]+)', 'IIS'),
            ],
            'SMTP': [
                (r'220.*Postfix', 'Postfix'),
                (r'220.*Sendmail ([\d\.]+)', 'Sendmail'),
                (r'220.*Microsoft ESMTP', 'Microsoft SMTP'),
            ],
            'MySQL': [
                (r'[\d\.]+-([\d\.]+)-MariaDB', 'MariaDB'),
                (r'([\d\.]+)-MySQL', 'MySQL'),
            ],
            'SMB': [
                (r'Samba ([\d\.]+)', 'Samba'),
            ]
        }
    
    def detect_service(self, ip: str, port: int, service_hint: str = None) -> Dict:
        """
        Detect service version and details
        
        Args:
            ip: Target IP
            port: Target port
            service_hint: Known service name (optional)
        
        Returns:
            Dictionary with service information
        """
        service_info = {
            'ip': ip,
            'port': port,
            'service': service_hint or 'unknown',
            'version': None,
            'banner': None,
            'ssl': False,
            'details': {}
        }
        
        # Try banner grabbing
        banner = self._grab_banner(ip, port)
        if banner:
            service_info['banner'] = banner
            
            # Fingerprint from banner
            detected = self._fingerprint_banner(banner, service_hint)
            if detected:
                service_info.update(detected)
        
        # Service-specific detection
        if port == 80 or port == 8080 or service_hint in ['HTTP', 'http']:
            http_info = self._detect_http(ip, port, use_https=False)
            service_info.update(http_info)
        
        elif port == 443 or port == 8443 or service_hint in ['HTTPS', 'https']:
            https_info = self._detect_http(ip, port, use_https=True)
            service_info.update(https_info)
        
        elif port == 22 or service_hint in ['SSH', 'ssh']:
            ssh_info = self._detect_ssh(ip, port)
            service_info.update(ssh_info)
        
        elif port == 21 or service_hint in ['FTP', 'ftp']:
            ftp_info = self._detect_ftp(ip, port)
            service_info.update(ftp_info)
        
        elif port == 25 or service_hint in ['SMTP', 'smtp']:
            smtp_info = self._detect_smtp(ip, port)
            service_info.update(smtp_info)
        
        elif port == 3306 or service_hint in ['MySQL', 'mysql']:
            mysql_info = self._detect_mysql(ip, port)
            service_info.update(mysql_info)
        
        if self.verbose:
            self.logger.debug(f"Detected service on {ip}:{port} - {service_info.get('service')} {service_info.get('version', '')}")
        
        return service_info
    
    def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Some services send banner immediately
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            sock.close()
            return banner if banner else None
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"Banner grab failed for {ip}:{port}: {e}")
            return None
    
    def _fingerprint_banner(self, banner: str, service_hint: str = None) -> Optional[Dict]:
        """Fingerprint service from banner"""
        result = {}
        
        # Try to match against signatures
        for service_type, patterns in self.signatures.items():
            if service_hint and service_hint.upper() != service_type:
                continue
            
            for pattern, product in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result['service'] = product
                    if match.groups():
                        result['version'] = match.group(1)
                    return result
        
        return result if result else None
    
    def _detect_http(self, ip: str, port: int, use_https: bool = False) -> Dict:
        """Detect HTTP/HTTPS service details"""
        protocol = 'https' if use_https else 'http'
        url = f"{protocol}://{ip}:{port}"
        
        info = {
            'service': 'HTTPS' if use_https else 'HTTP',
            'ssl': use_https,
            'details': {}
        }
        
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            
            # Extract server header
            server = response.headers.get('Server', '')
            if server:
                info['banner'] = server
                
                # Try to extract version
                if 'Apache' in server:
                    match = re.search(r'Apache/([\d\.]+)', server)
                    if match:
                        info['service'] = 'Apache'
                        info['version'] = match.group(1)
                
                elif 'nginx' in server:
                    match = re.search(r'nginx/([\d\.]+)', server)
                    if match:
                        info['service'] = 'Nginx'
                        info['version'] = match.group(1)
                
                elif 'IIS' in server:
                    match = re.search(r'Microsoft-IIS/([\d\.]+)', server)
                    if match:
                        info['service'] = 'IIS'
                        info['version'] = match.group(1)
            
            # Additional headers
            info['details']['x_powered_by'] = response.headers.get('X-Powered-By', None)
            info['details']['status_code'] = response.status_code
            info['details']['title'] = self._extract_title(response.text)
            
            # Detect CMS/Framework
            cms = self._detect_cms(response.text, response.headers)
            if cms:
                info['details']['cms'] = cms
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"HTTP detection failed for {url}: {e}")
        
        return info
    
    def _detect_ssh(self, ip: str, port: int) -> Dict:
        """Detect SSH service details"""
        info = {'service': 'SSH'}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                info['banner'] = banner
                
                # Extract version
                if 'OpenSSH' in banner:
                    match = re.search(r'OpenSSH[_\s]([\d\.]+)', banner)
                    if match:
                        info['service'] = 'OpenSSH'
                        info['version'] = match.group(1)
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"SSH detection failed for {ip}:{port}: {e}")
        
        return info
    
    def _detect_ftp(self, ip: str, port: int) -> Dict:
        """Detect FTP service details"""
        info = {'service': 'FTP'}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                info['banner'] = banner
                
                # Detect FTP server type
                if 'vsftpd' in banner:
                    match = re.search(r'vsftpd ([\d\.]+)', banner)
                    if match:
                        info['service'] = 'vsftpd'
                        info['version'] = match.group(1)
                
                elif 'ProFTPD' in banner:
                    match = re.search(r'ProFTPD ([\d\.]+)', banner)
                    if match:
                        info['service'] = 'ProFTPD'
                        info['version'] = match.group(1)
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"FTP detection failed for {ip}:{port}: {e}")
        
        return info
    
    def _detect_smtp(self, ip: str, port: int) -> Dict:
        """Detect SMTP service details"""
        info = {'service': 'SMTP'}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                info['banner'] = banner
                
                if 'Postfix' in banner:
                    info['service'] = 'Postfix'
                elif 'Sendmail' in banner:
                    info['service'] = 'Sendmail'
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"SMTP detection failed for {ip}:{port}: {e}")
        
        return info
    
    def _detect_mysql(self, ip: str, port: int) -> Dict:
        """Detect MySQL service details"""
        info = {'service': 'MySQL'}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # MySQL sends greeting packet
            data = sock.recv(1024)
            sock.close()
            
            if data:
                # Try to extract version from greeting
                version_str = data.decode('utf-8', errors='ignore')
                
                if 'MariaDB' in version_str:
                    info['service'] = 'MariaDB'
                else:
                    info['service'] = 'MySQL'
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"MySQL detection failed for {ip}:{port}: {e}")
        
        return info
    
    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title from HTML"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]  # Limit length
        return None
    
    def _detect_cms(self, html: str, headers: Dict) -> Optional[str]:
        """Detect CMS or framework"""
        html_lower = html.lower()
        
        if 'wp-content' in html_lower or 'wordpress' in html_lower:
            return 'WordPress'
        elif 'joomla' in html_lower:
            return 'Joomla'
        elif 'drupal' in html_lower:
            return 'Drupal'
        elif headers.get('X-Generator', '').startswith('Drupal'):
            return 'Drupal'
        
        return None
