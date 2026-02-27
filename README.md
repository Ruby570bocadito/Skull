# 💀 SKULL-NetRecon

**Professional Network Reconnaissance Tool for Ethical Pentesting**

SKULL-NetRecon is a powerful, feature-rich network reconnaissance and security assessment tool designed for authorized penetration testing and security audits.

---

## ⚠️ LEGAL DISCLAIMER

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

By using this tool, you acknowledge and agree that:
- You have **explicit written authorization** to scan the target network
- Unauthorized network scanning is **ILLEGAL** in most jurisdictions
- You are **solely responsible** for ensuring proper authorization
- You will use this tool **ethically and legally**

For complete legal information, see [LEGAL.md](LEGAL.md)

---

## ✨ Features

### Core Capabilities
- 🔍 **Multi-Method Host Discovery**: ARP, ICMP, TCP SYN scanning
- 🚪 **Advanced Port Scanning**: TCP Connect, SYN, UDP scans
- 🔧 **Service Detection**: Banner grabbing and version fingerprinting
- 🎯 **OS Fingerprinting**: TTL analysis, TCP stack fingerprinting
- 🔐 **Vulnerability Scanning**: CVE detection, SSL/TLS analysis, default credentials
- 📊 **Professional Reporting**: HTML, JSON, and TXT reports

### Advanced Features
- 🌐 **MAC Vendor Lookup**: Identify device manufacturers
- 🛡️ **Security Analysis**: Missing headers, dangerous HTTP methods
- 📈 **Network Mapping**: Topology discovery and visualization
- ⚡ **Multi-threaded**: Fast concurrent scanning
- 🎨 **Rich Terminal UI**: Beautiful progress indicators and tables
- 📝 **Detailed Logging**: Comprehensive logs for all operations

---

## 📋 Requirements

### System Requirements
- **Operating System**: Windows 10/11, Linux, macOS
- **Python**: 3.8 or higher
- **Privileges**: Administrator/root for certain scan types (SYN scan, ARP)

### Python Dependencies
```bash
scapy>=2.5.0
python-nmap>=0.7.1
netifaces>=0.11.0
rich>=13.7.0
colorama>=0.4.6
pyyaml>=6.0.1
requests>=2.31.0
jinja2>=3.1.2
```

---

## 🚀 Installation

### 1. Clone or Download
```bash
cd C:\Users\rafag\Downloads\SKULL
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
python skull_netrecon.py --help
```

---

## 📖 Usage

### Basic Scans

#### Quick Scan (Common Ports)
```bash
python skull_netrecon.py --target 192.168.1.100
```

#### Scan Network Range (CIDR)
```bash
python skull_netrecon.py --target 192.168.1.0/24
```

#### Scan IP Range
```bash
python skull_netrecon.py --target 192.168.1.1-254
```

### Advanced Scans

#### Full Port Scan (All 65535 ports)
```bash
python skull_netrecon.py --target 192.168.1.100 --full-scan
```

#### Scan with HTML Report
```bash
python skull_netrecon.py --target 192.168.1.100 --report --report-format html
```

#### Verbose Output for Debugging
```bash
python skull_netrecon.py --target 192.168.1.100 --verbose
```

#### Skip Banner and Disclaimer (Automated Scanning)
```bash
python skull_netrecon.py --target 192.168.1.100 --no-banner --skip-disclaimer
```

### Report Formats

#### Generate HTML Report (Default)
```bash
python skull_netrecon.py --target 192.168.1.100 --report --report-format html
```

#### Generate JSON Report
```bash
python skull_netrecon.py --target 192.168.1.100 --report --report-format json
```

#### Generate Text Report
```bash
python skull_netrecon.py --target 192.168.1.100 --report --report-format txt
```

---

## 🎯 Command-Line Options

| Option | Description |
|--------|-------------|
| `-t`, `--target` | **Required**. Target IP, CIDR, or range |
| `--full-scan` | Perform full port scan (1-65535) |
| `-r`, `--report` | Generate report after scan |
| `--report-format` | Report format: `html`, `json`, `txt` (default: html) |
| `-v`, `--verbose` | Enable verbose output for debugging |
| `--no-banner` | Hide ASCII banner on startup |
| `--skip-disclaimer` | Skip legal disclaimer (use with caution) |

---

## ⚙️ Configuration

Edit `config.yaml` to customize scanning behavior:

### Scanning Configuration
```yaml
scanning:
  timeout: 2              # Connection timeout in seconds
  threads: 50             # Concurrent threads
  port_ranges:
    quick: "21,22,23,25,53,80,..."  # Quick scan ports
    common: "1-1000"      # Common ports
    full: "1-65535"       # Full range
```

### Host Discovery
```yaml
discovery:
  methods:
    - arp               # ARP scanning
    - icmp              # ICMP ping
    - tcp               # TCP SYN discovery
```

### Vulnerability Scanning
```yaml
vulnerabilities:
  enabled: true
  check_default_creds: true
  check_cves: true
  check_ssl_vulns: true
```

---

## 📂 Project Structure

```
SKULL/
├── skull_netrecon.py          # Main application
├── config.yaml                # Configuration file
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── LEGAL.md                   # Legal disclaimer
│
├── modules/                   # Core modules
│   ├── host_discovery.py      # Host detection (ARP, ICMP, TCP)
│   ├── port_scanner.py        # Port scanning engine
│   ├── service_detection.py   # Service fingerprinting
│   ├── vuln_scanner.py        # Vulnerability detection
│   ├── os_fingerprint.py      # OS detection
│   └── report_generator.py    # Report generation
│
├── utils/                     # Utility modules
│   ├── network_utils.py       # Network helper functions
│   └── logger.py              # Logging system
│
├── data/                      # Data files
│   ├── ports_database.json    # Port/service mappings
│   ├── cve_database.json      # CVE information
│   ├── default_credentials.json  # Default credentials DB
│   └── oui_vendors.json       # MAC vendor lookup
│
├── logs/                      # Log files (auto-created)
└── reports/                   # Generated reports (auto-created)
```

---

## 🔍 Detection Capabilities

### Host Discovery Methods
1. **ARP Scanning**: Fast layer-2 discovery (local networks)
2. **ICMP Ping Sweep**: Traditional ping-based detection
3. **TCP SYN Discovery**: Detect hosts by sending SYN packets

### Port Scanning Techniques
1. **TCP Connect Scan**: Full three-way handshake
2. **TCP SYN Scan**: Half-open scan (requires privileges)
3. **UDP Scan**: UDP port detection

### Service Detection
- Banner grabbing for version identification
- HTTP/HTTPS analysis with CMS detection
- SSH, FTP, SMTP, MySQL fingerprinting
- SSL/TLS certificate analysis

### OS Fingerprinting
- TTL-based detection
- TCP/IP stack fingerprinting
- Banner analysis for OS hints
- Window size analysis

### Vulnerability Detection
- **CVE Matching**: Known vulnerabilities by version
- **SSL/TLS Issues**: Heartbleed, POODLE, weak ciphers
- **Default Credentials**: Common default passwords
- **HTTP Security**: Missing security headers
- **SMB Vulnerabilities**: EternalBlue detection hints
- **FTP Issues**: Anonymous login, vsftpd backdoor

---

## 📊 Report Examples

### HTML Report Features
- 🎨 Beautiful, modern design with gradients
- 📈 Summary statistics dashboard
- 📋 Detailed host information cards
- 🚨 Color-coded vulnerability alerts
- 📱 Responsive design

### JSON Report Structure
```json
{
  "metadata": {
    "tool": "SKULL-NetRecon",
    "version": "1.0",
    "timestamp": "2025-12-08T17:00:00"
  },
  "scan_results": {
    "stats": {...},
    "hosts": [...]
  }
}
```

---

## 🛠️ Troubleshooting

### Permission Errors
**Problem**: "Operation not permitted" when running SYN scans

**Solution**: Run with administrator/root privileges:
```bash
# Windows (Run as Administrator)
python skull_netrecon.py --target 192.168.1.100

# Linux/macOS
sudo python3 skull_netrecon.py --target 192.168.1.100
```

### Scapy Warnings
**Problem**: Scapy shows warnings about routing or interfaces

**Solution**: These are usually informational. Add `--verbose` to see detailed logs.

### No Hosts Found
**Problem**: Scan reports no active hosts

**Solutions**:
- Verify target IP/range is correct
- Check firewall rules (both local and remote)
- Try different discovery methods in `config.yaml`
- Ensure network connectivity with `ping`

### Slow Scans
**Problem**: Scans take too long

**Solutions**:
- Reduce timeout in `config.yaml`
- Increase thread count (be careful not to overwhelm network)
- Use quick scan instead of full scan
- Use SYN scan instead of connect scan

---

## 🎓 Best Practices

### Before Scanning
1. ✅ **Get Written Authorization**: Always obtain explicit permission
2. ✅ **Define Scope**: Know exactly what you're allowed to scan
3. ✅ **Inform Stakeholders**: Notify relevant parties about the test
4. ✅ **Have Emergency Contacts**: Know who to call if issues arise

### During Scanning
1. ⏰ **Scan During Off-Hours**: Minimize business impact
2. 📊 **Monitor Impact**: Watch for performance degradation
3. 💾 **Save Logs**: Keep detailed records of all actions
4. 🔄 **Throttle Scans**: Use appropriate thread counts

### After Scanning
1. 📝 **Document Findings**: Create comprehensive reports
2. 🔒 **Secure Data**: Protect scan results and reports
3. 📢 **Responsible Disclosure**: Report vulnerabilities appropriately
4. 🗑️ **Clean Up**: Remove any test artifacts

---