"""
SKULL-NetRecon - Vulnerability Scanner Module
Detect common vulnerabilities in network services
"""

import json
import socket
import ssl
from pathlib import Path
from typing import Dict, List, Optional
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from utils.logger import get_logger

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class VulnerabilityScanner:
    """Scan for known vulnerabilities"""
    
    def __init__(self, timeout: int = 3, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.logger = get_logger()
        
        # Load vulnerability databases
        self.cve_db = self._load_cve_database()
        self.default_creds = self._load_default_credentials()
        
        self.vulnerabilities = []
    
    def _load_cve_database(self) -> Dict:
        """Load CVE database"""
        try:
            db_path = Path(__file__).parent.parent / "data" / "cve_database.json"
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load CVE database: {e}")
            return {}
    
    def _load_default_credentials(self) -> Dict:
        """Load default credentials database"""
        try:
            db_path = Path(__file__).parent.parent / "data" / "default_credentials.json"
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load default credentials: {e}")
            return {}
    
    def scan(self, target: str, service_info: Dict) -> List[Dict]:
        """
        Scan for vulnerabilities based on service information
        
        Args:
            target: Target IP
            service_info: Service detection results
        
        Returns:
            List of discovered vulnerabilities
        """
        vulns = []
        
        # Check for version-based vulnerabilities
        version_vulns = self._check_version_vulnerabilities(service_info)
        vulns.extend(version_vulns)
        
        # Check for SSL/TLS vulnerabilities
        if service_info.get('ssl') or service_info.get('port') == 443:
            ssl_vulns = self._check_ssl_vulnerabilities(target, service_info.get('port'))
            vulns.extend(ssl_vulns)
        
        # Check for default credentials
        default_cred_vulns = self._check_default_credentials(target, service_info)
        vulns.extend(default_cred_vulns)
        
        # Service-specific checks
        service = service_info.get('service', '').lower()
        
        if 'http' in service:
            http_vulns = self._check_http_vulnerabilities(target, service_info.get('port'))
            vulns.extend(http_vulns)
        
        if 'smb' in service or service_info.get('port') == 445:
            smb_vulns = self._check_smb_vulnerabilities(target, service_info)
            vulns.extend(smb_vulns)
        
        if 'ftp' in service:
            ftp_vulns = self._check_ftp_vulnerabilities(target, service_info)
            vulns.extend(ftp_vulns)
        
        self.vulnerabilities.extend(vulns)
        
        if vulns and self.verbose:
            self.logger.warning(f"Found {len(vulns)} vulnerabilities on {target}:{service_info.get('port')}")
        
        return vulns
    
    def _check_version_vulnerabilities(self, service_info: Dict) -> List[Dict]:
        """Check for known CVEs based on service version"""
        vulns = []
        
        service = service_info.get('service', '')
        version = service_info.get('version')
        
        if not version:
            return vulns
        
        # Check version_checks in CVE database
        version_checks = self.cve_db.get('version_checks', {})
        
        for product, vuln_versions in version_checks.items():
            if product.lower() in service.lower():
                for version_pattern, cves in vuln_versions.get('vulnerable_versions', {}).items():
                    if self._is_version_vulnerable(version, version_pattern):
                        for cve in cves:
                            vulns.append({
                                'type': 'CVE',
                                'name': cve,
                                'severity': 'HIGH',
                                'description': f'{service} {version} is vulnerable to {cve}',
                                'service': service,
                                'version': version,
                                'port': service_info.get('port')
                            })
        
        # Check specific vulnerabilities
        for vuln_category, vulns_list in self.cve_db.get('vulnerabilities', {}).items():
            for vuln_id, vuln_data in vulns_list.items():
                affected = vuln_data.get('affected_versions', [])
                
                for affected_version in affected:
                    if affected_version.lower() in f"{service} {version}".lower():
                        vulns.append({
                            'type': 'CVE',
                            'cve': vuln_data.get('cve'),
                            'name': vuln_data.get('name'),
                            'severity': vuln_data.get('severity', 'MEDIUM'),
                            'description': vuln_data.get('description'),
                            'service': service,
                            'version': version,
                            'port': service_info.get('port'),
                            'exploits': vuln_data.get('exploits', [])
                        })
        
        return vulns
    
    def _is_version_vulnerable(self, version: str, pattern: str) -> bool:
        """Check if version matches vulnerability pattern"""
        try:
            # Simple version comparison for patterns like "< 7.4"
            if pattern.startswith('<'):
                threshold = pattern.strip('< ').strip()
                return self._compare_versions(version, threshold) < 0
            elif pattern.startswith('<='):
                threshold = pattern.strip('<= ').strip()
                return self._compare_versions(version, threshold) <= 0
            elif pattern.startswith('>'):
                threshold = pattern.strip('> ').strip()
                return self._compare_versions(version, threshold) > 0
            elif pattern.startswith('>='):
                threshold = pattern.strip('>= ').strip()
                return self._compare_versions(version, threshold) >= 0
            else:
                # Exact match
                return version == pattern
        except:
            return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings"""
        try:
            parts1 = [int(x) for x in v1.split('.')]
            parts2 = [int(x) for x in v2.split('.')]
            
            # Pad shorter version
            while len(parts1) < len(parts2):
                parts1.append(0)
            while len(parts2) < len(parts1):
                parts2.append(0)
            
            for p1, p2 in zip(parts1, parts2):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            
            return 0
        except:
            return 0
    
    def _check_ssl_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Check for SSL/TLS vulnerabilities"""
        vulns = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get SSL version
                    ssl_version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check for outdated SSL/TLS versions
                    if ssl_version in ['SSLv2', 'SSLv3']:
                        vulns.append({
                            'type': 'SSL/TLS',
                            'name': 'Outdated SSL/TLS Version',
                            'severity': 'HIGH',
                            'description': f'Server supports {ssl_version} which is deprecated',
                            'port': port,
                            'details': {'version': ssl_version}
                        })
                    
                    # Check for weak ciphers
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['DES', 'RC4', 'MD5', 'NULL']):
                            vulns.append({
                                'type': 'SSL/TLS',
                                'name': 'Weak Cipher Suite',
                                'severity': 'MEDIUM',
                                'description': f'Server uses weak cipher: {cipher_name}',
                                'port': port,
                                'details': {'cipher': cipher_name}
                            })
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"SSL check failed for {target}:{port}: {e}")
        
        return vulns
    
    def _check_default_credentials(self, target: str, service_info: Dict) -> List[Dict]:
        """Check for default credentials (informational only)"""
        vulns = []
        
        service = service_info.get('service', '').lower()
        port = service_info.get('port')
        
        # Check if service has known default credentials
        for service_name, creds in self.default_creds.get('services', {}).items():
            if service_name.lower() in service:
                vulns.append({
                    'type': 'Default Credentials',
                    'name': 'Potential Default Credentials',
                    'severity': 'MEDIUM',
                    'description': f'{service_name} service may have default credentials',
                    'port': port,
                    'details': {
                        'info': 'Manual testing recommended',
                        'common_credentials': len(creds)
                    }
                })
                break
        
        return vulns
    
    def _check_http_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Check for HTTP-specific vulnerabilities"""
        vulns = []
        
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target}:{port}"
            
            response = requests.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-XSS-Protection': 'XSS Protection'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers:
                vulns.append({
                    'type': 'HTTP Security',
                    'name': 'Missing Security Headers',
                    'severity': 'LOW',
                    'description': 'Server is missing important security headers',
                    'port': port,
                    'details': {'missing_headers': missing_headers}
                })
            
            # Check for information disclosure
            server_header = headers.get('Server', '')
            if server_header and any(version in server_header for version in ['/', '.']):
                vulns.append({
                    'type': 'Information Disclosure',
                    'name': 'Server Version Disclosure',
                    'severity': 'INFO',
                    'description': f'Server header reveals version information: {server_header}',
                    'port': port
                })
            
            # Check for dangerous HTTP methods
            try:
                options_response = requests.options(url, timeout=self.timeout, verify=False)
                allowed_methods = options_response.headers.get('Allow', '')
                
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in dangerous_methods if m in allowed_methods.upper()]
                
                if found_dangerous:
                    vulns.append({
                        'type': 'HTTP Security',
                        'name': 'Dangerous HTTP Methods Enabled',
                        'severity': 'MEDIUM',
                        'description': f'Server allows dangerous methods: {", ".join(found_dangerous)}',
                        'port': port,
                        'details': {'methods': found_dangerous}
                    })
            except:
                pass
        
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"HTTP vuln check failed for {target}:{port}: {e}")
        
        return vulns
    
    def _check_smb_vulnerabilities(self, target: str, service_info: Dict) -> List[Dict]:
        """Check for SMB vulnerabilities (informational)"""
        vulns = []
        
        # Add informational vulnerability about checking for EternalBlue
        vulns.append({
            'type': 'SMB',
            'name': 'SMB Service Detected',
            'severity': 'INFO',
            'description': 'SMB service should be checked for MS17-010 (EternalBlue)',
            'port': 445,
            'details': {
                'recommendation': 'Run: nmap -p445 --script smb-vuln-ms17-010'
            }
        })
        
        return vulns
    
    def _check_ftp_vulnerabilities(self, target: str, service_info: Dict) -> List[Dict]:
        """Check for FTP vulnerabilities"""
        vulns = []
        
        version = service_info.get('version', '')
        
        # Check for vsftpd 2.3.4 backdoor
        if 'vsftpd' in service_info.get('service', '').lower() and '2.3.4' in version:
            vulns.append({
                'type': 'FTP',
                'name': 'vsftpd 2.3.4 Backdoor',
                'severity': 'CRITICAL',
                'description': 'vsftpd 2.3.4 contains a backdoor',
                'cve': 'CVE-2011-2523',
                'port': service_info.get('port'),
                'exploits': ['exploit/unix/ftp/vsftpd_234_backdoor']
            })
        
        # Check for anonymous FTP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, service_info.get('port', 21)))
            
            sock.recv(1024)  # Banner
            sock.send(b'USER anonymous\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '230' in response or '331' in response:
                vulns.append({
                    'type': 'FTP',
                    'name': 'Anonymous FTP Login',
                    'severity': 'MEDIUM',
                    'description': 'FTP server allows anonymous login',
                    'port': service_info.get('port')
                })
            
            sock.close()
        except:
            pass
        
        return vulns
    
    def get_all_vulnerabilities(self) -> List[Dict]:
        """Get all discovered vulnerabilities"""
        return self.vulnerabilities
    
    def get_critical_vulnerabilities(self) -> List[Dict]:
        """Get only critical vulnerabilities"""
        return [v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']
    
    def get_vulnerabilities_by_severity(self) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by severity"""
        grouped = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            grouped[severity].append(vuln)
        
        return grouped
