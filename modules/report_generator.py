"""
SKULL-NetRecon - Report Generator Module
Generate professional reports in multiple formats
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from jinja2 import Template
from utils.logger import get_logger


class ReportGenerator:
    """Generate professional scan reports"""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = get_logger()
        
        self.scan_data = {}
    
    def set_scan_data(self, data: Dict):
        """Set scan data for report generation"""
        self.scan_data = data
    
    def generate_html_report(self, filename: str = None) -> Path:
        """Generate HTML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"skull_netrecon_{timestamp}.html"
        
        output_path = self.output_dir / filename
        
        # HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SKULL-NetRecon Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.15);
        }
        
        .stat-card .number {
            font-size: 3em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .stat-card .label {
            font-size: 1.1em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #1e3c72;
            font-size: 2em;
            margin-bottom: 20px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        
        .host-card {
            background: white;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
            transition: all 0.3s ease;
        }
        
        .host-card:hover {
            border-color: #667eea;
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.2);
        }
        
        .host-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .host-ip {
            font-size: 1.8em;
            font-weight: bold;
            color: #1e3c72;
        }
        
        .host-os {
            background: #667eea;
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        
        .port-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .port-table th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #dee2e6;
        }
        
        .port-table td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .port-table tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-open {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-filtered {
            background: #fff3cd;
            color: #856404;
        }
        
        .vulnerability {
            background: #fff;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .vuln-critical {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
        
        .vuln-high {
            border-left-color: #fd7e14;
            background: #fff9f0;
        }
        
        .vuln-medium {
            border-left-color: #ffc107;
            background: #fffbf0;
        }
        
        .vuln-low {
            border-left-color: #17a2b8;
            background: #f0f9ff;
        }
        
        .vuln-header {
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 8px;
            color: #333;
        }
        
        .vuln-severity {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .severity-CRITICAL {
            background: #dc3545;
            color: white;
        }
        
        .severity-HIGH {
            background: #fd7e14;
            color: white;
        }
        
        .severity-MEDIUM {
            background: #ffc107;
            color: #333;
        }
        
        .severity-LOW {
            background: #17a2b8;
            color: white;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 2px solid #dee2e6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>💀 SKULL-NetRecon</h1>
            <div class="subtitle">Network Reconnaissance Report</div>
            <div class="subtitle" style="margin-top: 10px;">Generated: {{ timestamp }}</div>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <div class="number">{{ stats.total_hosts }}</div>
                <div class="label">Active Hosts</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.total_ports }}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.total_services }}</div>
                <div class="label">Services</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.total_vulnerabilities }}</div>
                <div class="label">Vulnerabilities</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>🎯 Discovered Hosts</h2>
                {% for host in hosts %}
                <div class="host-card">
                    <div class="host-header">
                        <div class="host-ip">{{ host.ip }}</div>
                        {% if host.os %}
                        <div class="host-os">{{ host.os }}</div>
                        {% endif %}
                    </div>
                    
                    {% if host.hostname %}
                    <p><strong>Hostname:</strong> {{ host.hostname }}</p>
                    {% endif %}
                    
                    {% if host.mac %}
                    <p><strong>MAC Address:</strong> {{ host.mac }}</p>
                    {% endif %}
                    
                    {% if host.ports %}
                    <h3 style="margin-top: 20px; color: #667eea;">Open Ports</h3>
                    <table class="port-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Version</th>
                                <th>Banner</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for port in host.ports %}
                            <tr>
                                <td><strong>{{ port.port }}</strong></td>
                                <td><span class="badge badge-{{ port.state }}">{{ port.state }}</span></td>
                                <td>{{ port.service }}</td>
                                <td>{{ port.version or 'N/A' }}</td>
                                <td>{{ port.banner or 'N/A' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% endif %}
                    
                    {% if host.vulnerabilities %}
                    <h3 style="margin-top: 20px; color: #dc3545;">⚠️ Vulnerabilities</h3>
                    {% for vuln in host.vulnerabilities %}
                    <div class="vulnerability vuln-{{ vuln.severity|lower }}">
                        <div class="vuln-header">
                            {{ vuln.name }}
                            <span class="vuln-severity severity-{{ vuln.severity }}">{{ vuln.severity }}</span>
                        </div>
                        <p>{{ vuln.description }}</p>
                        {% if vuln.cve %}
                        <p><strong>CVE:</strong> {{ vuln.cve }}</p>
                        {% endif %}
                    </div>
                    {% endfor %}
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="footer">
            <p><strong>SKULL-NetRecon</strong> - Professional Network Reconnaissance Tool</p>
            <p style="margin-top: 10px; font-size: 0.9em;">⚠️ For Authorized Security Testing Only</p>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        
        # Prepare data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = template.render(
            timestamp=timestamp,
            stats=self.scan_data.get('stats', {}),
            hosts=self.scan_data.get('hosts', [])
        )
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.success(f"HTML report generated: {output_path}")
        
        return output_path
    
    def generate_json_report(self, filename: str = None) -> Path:
        """Generate JSON report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"skull_netrecon_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        # Add metadata
        report_data = {
            'metadata': {
                'tool': 'SKULL-NetRecon',
                'version': '1.0',
                'timestamp': datetime.now().isoformat(),
            },
            'scan_results': self.scan_data
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.success(f"JSON report generated: {output_path}")
        
        return output_path
    
    def generate_txt_report(self, filename: str = None) -> Path:
        """Generate plain text report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"skull_netrecon_{timestamp}.txt"
        
        output_path = self.output_dir / filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SKULL-NetRecon - Network Reconnaissance Report\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Statistics
            stats = self.scan_data.get('stats', {})
            f.write("SUMMARY:\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Hosts:          {stats.get('total_hosts', 0)}\n")
            f.write(f"Total Open Ports:     {stats.get('total_ports', 0)}\n")
            f.write(f"Total Services:       {stats.get('total_services', 0)}\n")
            f.write(f"Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}\n")
            f.write("\n")
            
            # Hosts
            hosts = self.scan_data.get('hosts', [])
            for host in hosts:
                f.write("=" * 80 + "\n")
                f.write(f"HOST: {host.get('ip')}\n")
                f.write("=" * 80 + "\n")
                
                if host.get('hostname'):
                    f.write(f"Hostname: {host['hostname']}\n")
                if host.get('mac'):
                    f.write(f"MAC:      {host['mac']}\n")
                if host.get('os'):
                    f.write(f"OS:       {host['os']}\n")
                
                f.write("\n")
                
                # Ports
                ports = host.get('ports', [])
                if ports:
                    f.write("OPEN PORTS:\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"{'Port':<10} {'State':<15} {'Service':<20} {'Version':<20}\n")
                    f.write("-" * 80 + "\n")
                    
                    for port in ports:
                        f.write(f"{port.get('port'):<10} {port.get('state'):<15} {port.get('service'):<20} {port.get('version', 'N/A'):<20}\n")
                    
                    f.write("\n")
                
                # Vulnerabilities
                vulns = host.get('vulnerabilities', [])
                if vulns:
                    f.write("VULNERABILITIES:\n")
                    f.write("-" * 80 + "\n")
                    
                    for vuln in vulns:
                        f.write(f"[{vuln.get('severity')}] {vuln.get('name')}\n")
                        f.write(f"    {vuln.get('description')}\n")
                        if vuln.get('cve'):
                            f.write(f"    CVE: {vuln['cve']}\n")
                        f.write("\n")
                
                f.write("\n")
        
        self.logger.success(f"Text report generated: {output_path}")
        
        return output_path
