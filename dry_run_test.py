from scanner_pkg.core import NetworkScanner

def simulate_flask_call(ip):
    scanner = NetworkScanner(scan_mode='full')
    result = scanner.scan_single(ip)
    return result

if __name__ == "__main__":
    test_ip = "192.168.56.104"
    print("Simulating Flask endpoint call...")
    output = simulate_flask_call(test_ip)
    import json
    print(json.dumps(output, indent=2))
