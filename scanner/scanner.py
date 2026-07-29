import nmap
import json
import time
import ipaddress

class NetworkScanner:
    def __init__(self, scan_type='-sV'):
        self.nm = nmap.PortScanner()
        self.scan_type = scan_type

    def set_scan_type(self, scan_type):
        self.scan_type = scan_type

    def scan_single(self, ip):
        start_time = time.time()
        try:
            self.nm.scan(ip, arguments=f'{self.scan_type} -O --host-timeout 240s')
        except Exception as e:
            return {"ip": ip, "error": f"Scan failed: {str(e)}"}

        duration = round(time.time() - start_time, 2)

        if ip not in self.nm.all_hosts():
            return {"ip": ip, "error": "Host unreachable, timed out, or no response", "scan_duration": duration}

        os_guess = "Unknown"
        if 'osmatch' in self.nm[ip] and self.nm[ip]['osmatch']:
            os_guess = self.nm[ip]['osmatch'][0]['name']

        open_ports = []
        for proto in self.nm[ip].all_protocols():
            for port in self.nm[ip][proto].keys():
                service = self.nm[ip][proto][port]
                if service.get('state') == 'open':
                    open_ports.append({
                        "port": port,
                        "service": service.get('name'),
                        "version": f"{service.get('product', '')} {service.get('version', '')}".strip()
                    })

        return {
            "ip": ip,
            "os": os_guess,
            "scan_duration": duration,
            "open_ports": open_ports if open_ports else [],
            "message": "No open ports found" if not open_ports else None
        }

    def scan_range(self, subnet):
        results = []
        network = ipaddress.ip_network(subnet, strict=False)
        for ip in network.hosts():
            result = self.scan_single(str(ip))
            results.append(result)
        return results


if __name__ == "__main__":
    scanner = NetworkScanner(scan_type='-sV')

    mode = input("Scan mode - (1) Single IP or (2) Subnet: ")

    if mode == "1":
        target = input("Enter target IP: ")
        result = scanner.scan_single(target)
        print(json.dumps(result, indent=2))
    elif mode == "2":
        subnet = input("Enter subnet (e.g. 192.168.56.0/24): ")
        results = scanner.scan_range(subnet)
        print(json.dumps(results, indent=2))
    else:
        print("Invalid choice")
