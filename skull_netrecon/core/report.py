"""SKULL-NetRecon - Report Generator"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any


class ReportGenerator:
    """Generate scan reports in various formats."""

    def __init__(self, output_dir: Path | str = "./reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: Any, format: str = "html") -> Path:
        """Generate report in specified format."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == "json":
            return self._generate_json(results, timestamp)
        elif format == "html":
            return self._generate_html(results, timestamp)
        elif format == "csv":
            return self._generate_csv(results, timestamp)
        else:
            return self._generate_txt(results, timestamp)
    
    def _generate_json(self, results: Any, timestamp: str) -> Path:
        """Generate JSON report."""
        data = {
            "metadata": {
                "tool": "SKULL-NetRecon",
                "version": "1.0.0",
                "timestamp": datetime.now().isoformat(),
            },
            "results": results.to_dict() if hasattr(results, "to_dict") else results,
        }
        
        output_path = self.output_dir / f"scan_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        
        return output_path
    
    def _generate_html(self, results: Any, timestamp: str) -> Path:
        """Generate HTML report."""
        data = results.to_dict() if hasattr(results, "to_dict") else results
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SKULL-NetRecon Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        h1 {{ color: #ef4444; margin-bottom: 0.5rem; }}
        .meta {{ color: #94a3b8; margin-bottom: 2rem; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .card h2 {{ color: #38bdf8; margin-bottom: 1rem; }}
        .stat {{ display: flex; gap: 2rem; margin-bottom: 1rem; }}
        .stat-item {{ text-align: center; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: #4ade80; }}
        .stat-label {{ color: #94a3b8; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ color: #94a3b8; font-weight: 600; }}
        .port-open {{ color: #4ade80; }}
        .vuln-critical {{ color: #ef4444; }}
        .vuln-high {{ color: #f97316; }}
        .vuln-medium {{ color: #eab308; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SKULL-NetRecon Scan Report</h1>
        <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="card">
            <h2>Summary</h2>
            <div class="stat">
                <div class="stat-item">
                    <div class="stat-value">{len(data.get('hosts', []))}</div>
                    <div class="stat-label">Hosts</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{sum(len(h.get('ports', [])) for h in data.get('hosts', []))}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{sum(len(h.get('vulnerabilities', [])) for h in data.get('hosts', []))}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
            </div>
        </div>
"""
        
        for host in data.get("hosts", []):
            html += f"""
        <div class="card">
            <h2>Host: {host.get('ip', 'N/A')}</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
"""
            if host.get("hostname"):
                html += f"                <tr><td>Hostname</td><td>{host['hostname']}</td></tr>\n"
            if host.get("mac"):
                html += f"                <tr><td>MAC</td><td>{host['mac']}</td></tr>\n"
            if host.get("os"):
                html += f"                <tr><td>OS</td><td>{host['os'].get('name', 'Unknown')}</td></tr>\n"
            
            html += "            </table>\n"
            
            if host.get("ports"):
                html += """
            <h3 style="margin: 1rem 0; color: #38bdf8;">Open Ports</h3>
            <table>
                <tr><th>Port</th><th>Service</th><th>Version</th></tr>
"""
                for port in host["ports"]:
                    html += f"                <tr><td class=\"port-open\">{port.get('port')}</td><td>{port.get('service', 'unknown')}</td><td>{port.get('version', 'N/A')}</td></tr>\n"
                html += "            </table>\n"
            
            html += "        </div>\n"
        
        html += """
    </div>
</body>
</html>"""
        
        output_path = self.output_dir / f"scan_{timestamp}.html"
        with open(output_path, "w") as f:
            f.write(html)
        
        return output_path
    
    def _generate_txt(self, results: Any, timestamp: str) -> Path:
        """Generate text report."""
        data = results.to_dict() if hasattr(results, "to_dict") else results
        
        lines = [
            "=" * 60,
            "SKULL-NETRECON SCAN REPORT",
            "=" * 60,
            f"Generated: {datetime.now().isoformat()}",
            "",
            f"Total Hosts: {len(data.get('hosts', []))}",
            f"Total Ports: {sum(len(h.get('ports', [])) for h in data.get('hosts', []))}",
            "",
        ]
        
        for host in data.get("hosts", []):
            lines.append("-" * 40)
            lines.append(f"Host: {host.get('ip', 'N/A')}")
            
            if host.get("hostname"):
                lines.append(f"Hostname: {host['hostname']}")
            if host.get("mac"):
                lines.append(f"MAC: {host['mac']}")
            if host.get("os"):
                lines.append(f"OS: {host['os'].get('name', 'Unknown')}")
            
            if host.get("ports"):
                lines.append("")
                lines.append("Open Ports:")
                for port in host["ports"]:
                    lines.append(f"  {port.get('port')}/tcp - {port.get('service', 'unknown')}")
            
            lines.append("")
        
        output_path = self.output_dir / f"scan_{timestamp}.txt"
        with open(output_path, "w") as f:
            f.write("\n".join(lines))

        return output_path

    def _generate_csv(self, results: Any, timestamp: str) -> Path:
        """Generate CSV report."""
        data = results.to_dict() if hasattr(results, "to_dict") else results
        output_path = self.output_dir / f"scan_{timestamp}.csv"

        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Hostname", "MAC", "Vendor", "OS", "OS_Confidence", "Port", "State", "Service", "Version", "Banner"])

            for host in data.get("hosts", []):
                os_name = host.get("os", {}).get("name", "") if host.get("os") else ""
                os_conf = host.get("os", {}).get("confidence", "") if host.get("os") else ""

                ports = host.get("ports", [])
                if ports:
                    for port in ports:
                        writer.writerow([
                            host.get("ip", ""),
                            host.get("hostname", ""),
                            host.get("mac", ""),
                            host.get("vendor", ""),
                            os_name,
                            os_conf,
                            port.get("port", ""),
                            port.get("state", ""),
                            port.get("service", ""),
                            port.get("version", ""),
                            port.get("banner", ""),
                        ])
                else:
                    writer.writerow([
                        host.get("ip", ""),
                        host.get("hostname", ""),
                        host.get("mac", ""),
                        host.get("vendor", ""),
                        os_name,
                        os_conf,
                        "", "", "", "", "",
                    ])

        return output_path
