"""
core.py - Network vulnerability scanner core module.

Provides the NetworkScanner class for host/subnet scanning using
Nmap (port/service/OS detection) and Scapy (ARP-based live host discovery).
"""

import nmap
import json
import time
import ipaddress
from scapy.all import ARP, Ether, srp


class NetworkScanner:
    """
    Main scanner class wrapping Nmap and Scapy functionality.

    Supports single-host scans, subnet scans, and live host discovery
    via ARP. Scan depth is configurable via named modes: fast, full, stealth.
    """

    SCAN_MODES = {
        "fast": "-F -sV",
        "full": "-sV -sC -O",
        "stealth": "-sS -sV"
    }

    def __init__(self, scan_mode='full'):
        """
        Initialize the scanner.

        Args:
            scan_mode (str): One of 'fast', 'full', 'stealth'. Defaults to 'full'.
        """
        self.nm = nmap.PortScanner()
        self.set_scan_type(scan_mode)

    def set_scan_type(self, scan_mode):
        """
        Set the Nmap argument string based on a named scan mode.

        Args:
            scan_mode (str): One of 'fast', 'full', 'stealth'.

        Raises:
            ValueError: if scan_mode is not a recognized mode.
        """
        if scan_mode not in self.SCAN_MODES:
            raise ValueError(f"Invalid scan_mode '{scan_mode}'. Choose from {list(self.SCAN_MODES.keys())}")
        self.scan_mode = scan_mode
        self.scan_type = self.SCAN_MODES[scan_mode]

    def scan_single(self, ip):
        """
        Scan a single IP address for open ports, services, and OS.

        Args:
            ip (str): Target IP address.

        Returns:
            dict: {
                "ip": str,
                "os": str,
                "scan_duration": float,
                "open_ports": [ {port, service, version, banner_scripts} ],
                "message": str or None
            }
            On failure, returns {"ip": ip, "error": str, ...}
        """
        print(f"[+] Starting {self.scan_mode} scan on {ip} ...")
        start_time = time.time()
        try:
            self.nm.scan(ip, arguments=f'{self.scan_type} --host-timeout 120s')
        except Exception as e:
            print(f"[!] Scan error on {ip}: {e}")
            return {"ip": ip, "error": f"Scan failed: {str(e)}"}

        duration = round(time.time() - start_time, 2)

        if ip not in self.nm.all_hosts():
            print(f"[!] {ip} unreachable/timed out ({duration}s)")
            return {"ip": ip, "error": "Host unreachable, timed out, or no response", "scan_duration": duration}

        os_guess = "Unknown"
        if 'osmatch' in self.nm[ip] and self.nm[ip]['osmatch']:
            os_guess = self.nm[ip]['osmatch'][0]['name']

        open_ports = []
        for proto in self.nm[ip].all_protocols():
            for port in self.nm[ip][proto].keys():
                service = self.nm[ip][proto][port]
                if service.get('state') == 'open':
                    script_output = service.get('script', {})
                    open_ports.append({
                        "port": port,
                        "service": service.get('name'),
                        "version": f"{service.get('product', '')} {service.get('version', '')}".strip(),
                        "banner_scripts": script_output if script_output else {}
                    })

        print(f"[+] {ip} scan complete in {duration}s — {len(open_ports)} open ports found")

        return {
            "ip": ip,
            "os": os_guess,
            "scan_duration": duration,
            "open_ports": open_ports,
            "message": "No open ports found" if not open_ports else None
        }

    def scan_range(self, subnet):
        """
        Scan every host in a subnet individually using scan_single.

        Args:
            subnet (str): CIDR notation subnet, e.g. '192.168.56.0/24'.

        Returns:
            list[dict]: list of scan_single results, one per host.
        """
        results = []
        network = ipaddress.ip_network(subnet, strict=False)
        total = len(list(network.hosts()))
        print(f"[+] Starting subnet scan on {subnet} ({total} hosts)")
        for i, ip in enumerate(network.hosts(), 1):
            print(f"[{i}/{total}] Scanning {ip} ...")
            result = self.scan_single(str(ip))
            results.append(result)
        print(f"[+] Subnet scan complete — {total} hosts processed")
        return results

    def arp_scan(self, subnet, iface=None, timeout=2):
        """
        Perform a fast ARP-based live host discovery scan using Scapy.

        Much faster than a full Nmap sweep for simply finding which
        hosts are alive on a local subnet.

        Args:
            subnet (str): CIDR notation subnet, e.g. '192.168.56.0/24'.
            iface (str, optional): Network interface to use. Defaults to Scapy's default.
            timeout (int): Seconds to wait for ARP replies.

        Returns:
            list[dict]: [{"ip": str, "mac": str}, ...] for each live host found.
        """
        print(f"[+] Starting ARP scan on {subnet} ...")
        start_time = time.time()

        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        try:
            if iface:
                answered = srp(packet, timeout=timeout, iface=iface, verbose=False)[0]
            else:
                answered = srp(packet, timeout=timeout, verbose=False)[0]
        except Exception as e:
            print(f"[!] ARP scan failed: {e}")
            return []

        live_hosts = []
        for sent, received in answered:
            live_hosts.append({"ip": received.psrc, "mac": received.hwsrc})

        duration = round(time.time() - start_time, 2)
        print(f"[+] ARP scan complete in {duration}s — {len(live_hosts)} live hosts found")
        return live_hosts


if __name__ == "__main__":
    mode = input("Scan mode - (1) Single IP, (2) Subnet, (3) ARP live host discovery: ")

    if mode == "1":
        depth = input("Scan depth - fast/full/stealth [default: full]: ") or "full"
        scanner = NetworkScanner(scan_mode=depth)
        target = input("Enter target IP: ")
        result = scanner.scan_single(target)
        print(json.dumps(result, indent=2))

    elif mode == "2":
        depth = input("Scan depth - fast/full/stealth [default: full]: ") or "full"
        scanner = NetworkScanner(scan_mode=depth)
        subnet = input("Enter subnet (e.g. 192.168.56.0/24): ")
        results = scanner.scan_range(subnet)
        print(json.dumps(results, indent=2))

    elif mode == "3":
        scanner = NetworkScanner()
        subnet = input("Enter subnet for ARP scan (e.g. 192.168.56.0/24): ")
        results = scanner.arp_scan(subnet)
        print(json.dumps(results, indent=2))

    else:
        print("Invalid choice")
