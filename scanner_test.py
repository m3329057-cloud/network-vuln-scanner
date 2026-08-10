import nmap
def scan_host(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sV')
    result={}
    for proto in nm[ip].all_protocols():
        ports=nm[ip][proto].keys()
        for port in ports:
            service=nm[ip][proto][port]
            result [port]={
                'name': service.get('name'),
                'product': service.get('product'),  
                'version':service.get('version'),
                'state':service.get('state')
            }
    return result
if __name__ == "__main__":
    ip = input("Enter target IP: ")
    data = scan_host(ip)
    print(data)
