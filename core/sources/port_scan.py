# osint_aggregator/core/sources/port_scan.py
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Alt2",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

def _check_port(host, port, service, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"port": port, "service": service, "open": True}
    except Exception:
        return {"port": port, "service": service, "open": False}

def scan_ports(host, timeout=2):
    open_ports = []
    closed_ports = []

    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {
            executor.submit(_check_port, host, port, svc, timeout): port
            for port, svc in COMMON_PORTS.items()
        }
        for future in as_completed(futures):
            result = future.result()
            if result["open"]:
                open_ports.append(result)
            else:
                closed_ports.append(result)

    return {
        "host": host,
        "open": sorted(open_ports, key=lambda x: x["port"]),
        "closed": sorted(closed_ports, key=lambda x: x["port"]),
        "total_scanned": len(COMMON_PORTS),
    }
