import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
]

def _probe(ip: str, port: int, timeout: float) -> Optional[int]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return port if sock.connect_ex((ip, port)) == 0 else None

def scan_ports(ip: str, ports: Optional[List[int]] = None, timeout: float = 0.75, workers: int = 50) -> List[int]:
    targets = ports or DEFAULT_PORTS
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda port: _probe(ip, port, timeout), targets))
    return sorted(port for port in results if port)
