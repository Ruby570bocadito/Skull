# SKULL-NetRecon

> Professional Network Reconnaissance Tool for Ethical Security Testing

```
╔═══════════════════════════════════════════════════════════╗
║   ███████╗ █████╗ ████████╗██╗██╗   ██╗███████╗          ║
║   ██╔════╝██╔══██╗╚══██╔══╝██║██║   ██║╚══██╔══╝          ║
║   ███████╗███████║   ██║   ██║██║   ██║   ██║             ║
║   ╚════██║██╔══██║   ██║   ██║╚═╝   ██║   ██║             ║
║   ███████║██║  ██║   ██║   ██║     ██║   ██║             ║
║   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝   ╚═╝             ║
║              NETWORK RECONNAISSANCE                        ║
╚═══════════════════════════════════════════════════════════╝
```

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com)

## ⚠️ Warning

**This tool is for authorized security testing only.** Unauthorized network scanning is illegal. Use responsibly.

---

## Features

- **Host Discovery** - ARP, ICMP, TCP SYN scanning
- **Port Scanning** - TCP Connect, SYN scans with rate limiting
- **Service Detection** - Banner grabbing, version fingerprinting, CMS detection
- **OS Fingerprinting** - TTL analysis, TCP stack fingerprinting, banner analysis
- **Vulnerability Scanning** - CVE detection, SSL/TLS analysis, default credential checks
- **Reporting** - HTML, JSON, CSV, TXT formats
- **Multi-target** - Scan multiple targets in a single run
- **Configurable** - YAML-based configuration with CLI overrides

---

## Installation

```bash
# Clone repository
git clone https://github.com/Ruby570bocadito/Skull.git
cd Skull

# Install dependencies
pip install -r requirements.txt

# Verify
python -m skull_netrecon --help
```

---

## Quick Start

```bash
# Basic scan
python -m skull_netrecon scan 192.168.1.1

# Network scan
python -m skull_netrecon scan 192.168.1.0/24

# Multiple targets
python -m skull_netrecon scan 192.168.1.1 10.0.0.1 192.168.2.0/24

# Full port scan with report
python -m skull_netrecon scan 192.168.1.1 --full --report --format html

# SYN scan with rate limiting
python -m skull_netrecon scan 192.168.1.1 --scan-type syn --rate-limit 0.01
```

---

## Usage

```
$ python -m skull_netrecon --help

 Usage: skull-netrecon [OPTIONS] COMMAND [ARGS]...

 Professional Network Reconnaissance Tool

 ╭─ Options ─────────────────────────────────────────────╮
 │ --version          Show version                      │
 │ --verbose  -v      Enable verbose output             │
 │ --config   -c PATH  Config file path                 │
 ╰─────────────────────────────────────────────────────╯

 ╭─ Commands ───────────────────────────────────────────╮
 │ scan        Execute network scan                     │
 │ discover    Discover active hosts on network         │
 │ ports       Scan ports on target host                │
 │ config-show Show current configuration               │
 ╰─────────────────────────────────────────────────────╯
```

### Scan Command

```
python -m skull_netrecon scan TARGET [TARGETS...] [OPTIONS]

Options:
  --full                  Full port scan (1-65535)
  --scan-type, -s TEXT    Scan type: connect, syn (default: connect)
  --threads, -t INT       Number of concurrent threads (default: 50)
  --timeout FLOAT         Connection timeout in seconds (default: 2.0)
  --rate-limit FLOAT      Delay between probes in seconds (default: 0.0)
  --report / --no-report  Generate report
  --format, -f TEXT       Report format: html, json, txt, csv
  --output, -o PATH       Output directory for reports
  --skip-discovery        Skip host discovery
  --no-services           Skip service detection
  --no-os                 Skip OS fingerprinting
  --no-vulns              Skip vulnerability scanning
  --no-banner             Hide banner
  --config, -c PATH       Config file path
```

### Discover Command

```
python -m skull_netrecon discover TARGET [OPTIONS]

Options:
  --method, -m TEXT   Discovery method: arp, icmp, tcp, all (default: all)
  --timeout FLOAT     Timeout in seconds (default: 2.0)
```

### Ports Command

```
python -m skull_netrecon ports TARGET [OPTIONS]

Options:
  --range, -r TEXT    Port range: quick, common, full, or custom
  --type, -t TEXT     Scan type: connect, syn (default: connect)
  --timeout FLOAT     Connection timeout (default: 2.0)
```

---

## Configuration

Edit `config.yaml` to customize:

```yaml
scanning:
  timeout: 2
  threads: 50
  rate_limit: 0.0  # Delay between probes (seconds)

  port_ranges:
    quick: "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    common: "1-1000"
    full: "1-65535"

discovery:
  methods:
    - arp
    - icmp
    - tcp

services:
  banner_grabbing: true
  banner_timeout: 3
  ssl_analysis: true

vulnerabilities:
  enabled: true
  check_default_creds: true
  check_cves: true
  check_ssl_vulns: true

reporting:
  output_dir: "./reports"
  default_format: "html"
```

---

## Project Structure

```
skull-netrecon/
├── skull_netrecon/          # Main package
│   ├── __main__.py          # Entry point
│   ├── cli.py               # CLI interface (Typer)
│   ├── core/                # Core modules
│   │   ├── scanner.py       # Main scanner + PortScanner
│   │   ├── discovery.py     # Host discovery engine
│   │   └── report.py        # Report generator
│   ├── modules/             # Advanced scan modules
│   │   ├── service_detection.py
│   │   ├── os_fingerprint.py
│   │   └── vuln_scanner.py
│   └── utils/
│       ├── network.py       # Network utilities
│       └── logger.py        # Logging system
├── data/                    # Data files
│   ├── cve_database.json
│   ├── default_credentials.json
│   ├── oui_vendors.json
│   └── ports_database.json
├── tests/                   # Test suite
├── config.yaml
├── requirements.txt
└── pyproject.toml
```

---

## Requirements

- Python 3.8+
- Root/Administrator privileges (for SYN scans, ARP discovery)
- Linux/macOS/Windows

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## License

Proprietary - All rights reserved. See [LICENSE](LICENSE) for details.
