import errno
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

PROBE_PORTS = [22, 80, 443, 445, 3389, 8080]
PROBE_TIMEOUT = 0.4
MAX_WORKERS = 64

OUI_VENDORS = {
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
}

def _is_alive(ip: str) -> bool:
    for port in PROBE_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(PROBE_TIMEOUT)
            if sock.connect_ex((ip, port)) in (0, errno.ECONNREFUSED):
                return True
    return False

def _arp_table() -> Dict[str, str]:
    table = {}
    try:
        with open("/proc/net/arp") as handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3].upper()
    except OSError:
        pass
    return table

def _vendor(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return OUI_VENDORS.get(mac[:8], "Unknown")

def discover_hosts(subnet: str) -> List[Dict[str, Optional[str]]]:
    addresses = [str(ip) for ip in ipaddress.ip_network(subnet, strict=False).hosts()]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        alive = [ip for ip, up in zip(addresses, pool.map(_is_alive, addresses)) if up]
    arp = _arp_table()
    return [{"ip": ip, "mac": arp.get(ip), "vendor": _vendor(arp.get(ip))} for ip in alive]
