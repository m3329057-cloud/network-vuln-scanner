import nmap
import json
def scan_target(ip,scan_type='sV'):
    nm=nmap.PortScanner()
    try:
        nm.scan(ip, arguments=scan_type)
    except Exception as e:
          return {"ip":ip, "error": f"Scan failed: {str(e)}"}
    if ip not in nm.all_hosts():
        return{"ip": ip, "error": "Host unreachable or no response"}
    open_ports=[]
    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto].keys():
            service=nm[ip][proto][port]
            if service.get('state')== 'open':
               open_ports.append({
                   "port":port,
                   "service":service.get('name'),
                   "version": f"{service.get('product','')} {service.get('version','')}".strip()
               })
    if not open_ports:
        return {"ip": ip,"open_ports": [],"message":"No open ports found"}
    return {"ip": ip, "open_ports": open_ports}
if __name__ == "__main__":
     target = input ("Enter target IP:")
     result=scan_target(target)
     print(json.dumps(result,indent=2))
