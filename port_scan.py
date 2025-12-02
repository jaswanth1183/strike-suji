import socket
from typing import List, Dict, Any
import nmap

def port_scan(host: str, ports: List[int] | None = None, timeout: float = 1.0) -> Dict[str, Any]:
    # Prefer nmap if available
    report = {"host": host, "open_ports": [], "method": None}
    if ports is None:
        ports = [21,22,23,25,53,80,443,3306,6379,8080]
    try:
        nm = nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports)
        nm.scan(hosts=host, ports=port_str, arguments='-sS -Pn -T4')
        report["method"] = "nmap"
        for h in nm.all_hosts():
            for proto in nm[h].all_protocols():
                lports = nm[h][proto].keys()
                for p in lports:
                    state = nm[h][proto][p]['state']
                    if state == 'open':
                        report["open_ports"].append({"port": p, "service": nm[h][proto][p].get("name")})
    except Exception as e:
        # fallback simple socket scan
        report["method"] = "socket"
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                conn = s.connect_ex((host, p))
                if conn == 0:
                    report["open_ports"].append({"port": p, "service": ""})
                s.close()
            except Exception:
                pass
    return report
