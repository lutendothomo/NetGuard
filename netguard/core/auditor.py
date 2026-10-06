import socket
from typing import List, Dict

COMMON_TARGET_PORTS = [21, 22, 80, 443, 8080]

def inspect_endpoint(ip: str, ports: List[int] = COMMON_TARGET_PORTS) -> Dict[int, str]:
    findings = {}
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.75)
            if sock.connect_ex((ip, port)) == 0:
                try:
                    if port in [80, 8080]:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(512).decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner = "Service Active"
                findings[port] = banner or "Open"
    return findings