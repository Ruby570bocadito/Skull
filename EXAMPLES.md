# SKULL-NetRecon Usage Examples

This document provides practical examples for using SKULL-NetRecon in various scenarios.

---

## Table of Contents
1. [Basic Scans](#basic-scans)
2. [Advanced Scans](#advanced-scans)
3. [Reporting](#reporting)
4. [Real-World Scenarios](#real-world-scenarios)
5. [Tips and Tricks](#tips-and-tricks)

---

## Basic Scans

### Example 1: Scan Single Host
```bash
python skull_netrecon.py --target 192.168.1.100
```

**What it does:**
- Discovers if host is active
- Scans common ports (21, 22, 23, 25, 53, 80, 443, etc.)
- Detects services and versions
- Fingerprints OS
- Checks for vulnerabilities

**Expected output:**
- Host information (IP, MAC, vendor)
- List of open ports with services
- OS detection results
- Any found vulnerabilities

---

### Example 2: Scan Network Range (CIDR)
```bash
python skull_netrecon.py --target 192.168.1.0/24
```

**What it does:**
- Scans all 254 hosts in the subnet
- Identifies active hosts
- Performs quick scan on each

**Use case:** Discovering all devices on your local network

---

### Example 3: Scan IP Range
```bash
python skull_netrecon.py --target 192.168.1.1-50
```

**What it does:**
- Scans IPs from 192.168.1.1 to 192.168.1.50
- Useful for targeting specific segments

---

## Advanced Scans

### Example 4: Full Port Scan
```bash
python skull_netrecon.py --target 192.168.1.100 --full-scan
```

**Warning:** This scans all 65,535 ports and may take significant time!

**Use case:** Comprehensive security assessment when time is not a constraint

---

### Example 5: Verbose Mode
```bash
python skull_netrecon.py --target 192.168.1.100 --verbose
```

**What it does:**
- Shows detailed debugging information
- Displays each step of the scanning process
- Helpful for troubleshooting

---

### Example 6: Skip Banner and Disclaimer (Automated)
```bash
python skull_netrecon.py --target 192.168.1.100 --no-banner --skip-disclaimer
```

**Use case:** Automated scanning in scripts or CI/CD pipelines

**Warning:** Only use with proper authorization!

---

## Reporting

### Example 7: Generate HTML Report
```bash
python skull_netrecon.py --target 192.168.1.0/24 --report --report-format html
```

**Output:**
- Beautiful HTML report in `./reports/` directory
- Includes:
  - Summary statistics
  - Host details with color-coded vulnerabilities
  - Professional styling

---

### Example 8: Generate JSON Report
```bash
python skull_netrecon.py --target 192.168.1.100 --report --report-format json
```

**Output:**
- Machine-readable JSON file
- Perfect for:
  - Automation
  - Integration with other tools
  - Custom analysis scripts

---

### Example 9: Generate Text Report
```bash
python skull_netrecon.py --target 192.168.1.100 --report --report-format txt
```

**Output:**
- Plain text report
- Easy to read in terminal
- Good for quick reviews

---

## Real-World Scenarios

### Scenario 1: Home Network Audit
**Goal:** Identify all devices on your home network

```bash
# Step 1: Discover all devices
python skull_netrecon.py --target 192.168.1.0/24

# Step 2: Full scan on suspicious devices
python skull_netrecon.py --target 192.168.1.XXX --full-scan --report
```

**Look for:**
- Unknown devices
- Unnecessary open ports
- Outdated services
- Default credentials warnings

---

### Scenario 2: Server Security Assessment
**Goal:** Assess security of a web server

```bash
python skull_netrecon.py --target 10.0.0.50 --report --report-format html --verbose
```

**Check for:**
- Exposed management interfaces
- Unencrypted services
- Missing security headers
- Known CVEs in detected versions

---

### Scenario 3: Network Segmentation Test
**Goal:** Verify network segmentation is working

```bash
# Scan from different VLANs
python skull_netrecon.py --target 10.10.1.0/24  # Management VLAN
python skull_netrecon.py --target 10.10.2.0/24  # User VLAN
python skull_netrecon.py --target 10.10.3.0/24  # DMZ
```

**Verify:**
- Devices in one VLAN can't access others
- Only allowed services are accessible

---

### Scenario 4: Pre-Deployment Check
**Goal:** Scan new server before deployment

```bash
python skull_netrecon.py --target 192.168.1.200 --full-scan --report --verbose
```

**Checklist:**
- [ ] Only required ports are open
- [ ] No unnecessary services running
- [ ] OS and services are up-to-date
- [ ] No critical vulnerabilities
- [ ] Security headers configured
- [ ] No default credentials

---

## Tips and Tricks

### Tip 1: Scan Multiple Targets
Create a script to scan multiple targets:

```bash
# scan_multiple.bat (Windows)
python skull_netrecon.py --target 192.168.1.10 --report
python skull_netrecon.py --target 192.168.1.20 --report
python skull_netrecon.py --target 192.168.1.30 --report
```

---

### Tip 2: Speed Up Scans
Edit `config.yaml`:

```yaml
scanning:
  timeout: 1        # Reduce timeout
  threads: 100      # Increase threads
```

**Warning:** Higher threads may trigger IDS/IPS!

---

### Tip 3: Custom Port Ranges
Edit `config.yaml`:

```yaml
scanning:
  port_ranges:
    custom: "80,443,8080,8443,3000,5000"
```

Then modify code to use custom range.

---

### Tip 4: Scheduled Scans (Windows Task Scheduler)
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "python" -Argument "C:\path\to\skull_netrecon.py --target 192.168.1.0/24 --report --skip-disclaimer"
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "NetRecon Daily Scan"
```

---

### Tip 5: Logging for Compliance
All scans are automatically logged to `./logs/`

Logs include:
- Timestamp
- Targets scanned
- Actions performed
- Results

Keep logs for compliance and audit trails!

---

### Tip 6: Analyzing JSON Output
Use `jq` to parse JSON reports:

```bash
# Extract all critical vulnerabilities
cat reports/skull_netrecon_*.json | jq '.scan_results.hosts[].vulnerabilities[] | select(.severity=="CRITICAL")'

# Count open ports per host
cat reports/skull_netrecon_*.json | jq '.scan_results.hosts[] | {ip: .ip, open_ports: (.ports | length)}'
```

---

## Common Scan Combinations

### Quick Network Overview
```bash
python skull_netrecon.py --target 192.168.1.0/24 --no-banner --skip-disclaimer
```

### Detailed Single Host
```bash
python skull_netrecon.py --target 192.168.1.100 --full-scan --report --verbose
```

### Fast Automated Scan
```bash
python skull_netrecon.py --target 192.168.1.0/24 --no-banner --skip-disclaimer --report --report-format json
```

### Production-Ready Report
```bash
python skull_netrecon.py --target 10.0.0.0/24 --report --report-format html
```

---

## Interpreting Results

### Open Ports
- **Port 22 (SSH)**: Should only be open on servers
- **Port 23 (Telnet)**: **DANGEROUS** - unencrypted
- **Port 445 (SMB)**: Check for EternalBlue vulnerability
- **Port 3389 (RDP)**: Ensure strong passwords, consider VPN
- **Port 3306 (MySQL)**: Should not be publicly accessible

### Vulnerability Severity
- **CRITICAL**: Immediate action required
- **HIGH**: Fix within days
- **MEDIUM**: Fix within weeks
- **LOW**: Fix when convenient
- **INFO**: Informational only

### OS Detection Confidence
- **90-100%**: Highly confident
- **70-89%**: Likely correct
- **50-69%**: Moderate confidence
- **<50%**: Low confidence, may be incorrect

---

## Troubleshooting Scans

### No Hosts Found
```bash
# Try with verbose mode
python skull_netrecon.py --target 192.168.1.100 --verbose

# Check connectivity
ping 192.168.1.100
```

### Permission Errors
```bash
# Windows: Run PowerShell as Administrator
# Linux/macOS: Use sudo
sudo python3 skull_netrecon.py --target 192.168.1.100
```

### Slow Scans
```bash
# Use quick scan instead of full
python skull_netrecon.py --target 192.168.1.100
# Don't use --full-scan unless necessary
```

---

**Remember:** Always scan ethically and with proper authorization!

---

*For more information, see [README.md](README.md) and [LEGAL.md](LEGAL.md)*
