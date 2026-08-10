# NetSentry — Scanner Module

Core network vulnerability scanning module for the NetSentry mini-project.

## What it does
Scans a target host or subnet for open ports, running services, service
versions, and OS fingerprint using Nmap. Also supports fast live-host
discovery via Scapy ARP scanning.

## Dependencies
- Python 3.10+
- `python-nmap`
- `scapy`
- System `nmap` binary installed
- Root/sudo privileges required (for OS detection and ARP scanning)

Install:
## Usage

### As a module
```python
from scanner_pkg.core import NetworkScanner

scanner = NetworkScanner(scan_mode='full')  # or 'fast', 'stealth'
result = scanner.scan_single('192.168.1.10')
