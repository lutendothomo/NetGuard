import re
import socket
from typing import Dict, Optional

HTTP_PORTS = {80, 8000, 8080, 8888}
PASSIVE_WAIT = 0.5

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http", 8080: "http", 8443: "https",
    9200: "elasticsearch", 27017: "mongodb",
}

FINGERPRINTS = [
    ("ssh", "OpenSSH", re.compile(r"ssh-\d\.\d+-openssh_([\w.]+)", re.I)),
    ("ssh", "Dropbear", re.compile(r"ssh-\d\.\d+-dropbear_([\w.]+)", re.I)),
    ("http", "Apache", re.compile(r"server:\s*apache/([\d.]+)", re.I)),
    ("http", "nginx", re.compile(r"server:\s*nginx/([\d.]+)", re.I)),
    ("http", "lighttpd", re.compile(r"server:\s*lighttpd/([\d.]+)", re.I)),
    ("ftp", "vsFTPd", re.compile(r"\(vsftpd ([\d.]+)\)", re.I)),
    ("ftp", "ProFTPD", re.compile(r"proftpd ([\w.]+)", re.I)),
    ("smtp", "Postfix", re.compile(r"^220 .*\bpostfix\b", re.I)),
]

def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore").strip()

def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            if port not in HTTP_PORTS:
                sock.settimeout(PASSIVE_WAIT)
                try:
                    data = sock.recv(512)
                except socket.timeout:
                    data = b""
                if data:
                    return _decode(data)
            sock.settimeout(timeout)
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            return _decode(sock.recv(512))
    except OSError:
        return ""

def identify(port: int, banner: str) -> Dict[str, Optional[str]]:
    for service, product, pattern in FINGERPRINTS:
        match = pattern.search(banner or "")
        if match:
            version = match.group(1) if match.groups() else None
            return {"service": service, "product": product, "version": version}
    if (banner or "").startswith("HTTP/"):
        return {"service": "http", "product": None, "version": None}
    return {"service": PORT_SERVICES.get(port, "unknown"), "product": None, "version": None}
