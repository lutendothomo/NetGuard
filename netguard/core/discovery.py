"""Network host discovery module for NetGuard.

Provides multi-threaded active TCP probing and cross-platform ARP cache
inspection to discover alive hosts, MAC addresses, and hardware vendors
within a target IPv4 subnet.
"""

import errno
import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

PROBE_PORTS = [22, 80, 443, 445, 3389, 8080]
PROBE_TIMEOUT = 0.4
MAX_WORKERS = 64

# Common OUI vendor prefixes (first 3 octets formatted as XX:XX:XX)
OUI_VENDORS = {
    # Virtualization & Cloud
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V",
    "00:16:3E": "Xen",
    "00:1C:42": "Parallels",
    # Single-board Computers & IoT
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "24:0A:C4": "Espressif",
    "30:AE:A4": "Espressif",
    "84:0D:8E": "Espressif",
    "A4:CF:12": "Espressif",
    "EC:FA:BC": "Espressif",
    # Hardware & Network Infrastructure
    "00:00:0C": "Cisco",
    "00:01:42": "Cisco",
    "00:01:43": "Cisco",
    "00:05:9A": "Cisco",
    "00:03:FF": "Microsoft",
    "00:0D:3A": "Microsoft",
    "00:1D:D8": "Microsoft",
    "00:03:93": "Apple",
    "00:0A:95": "Apple",
    "00:17:F2": "Apple",
    "3C:22:FB": "Apple",
    "70:35:60": "Apple",
    "AC:DE:48": "Apple",
    "F0:18:98": "Apple",
    "BC:D0:74": "Apple",
    "00:02:B3": "Intel",
    "00:1A:11": "Google",
    "00:1E:67": "Intel",
    "00:21:6A": "Intel",
    "80:86:F2": "Intel",
    "00:14:22": "Dell",
    "18:66:DA": "Dell",
    "B8:AC:6F": "Dell",
    "F8:DB:88": "Dell",
    "00:1E:0B": "HP",
    "3C:D9:2B": "HP",
    "70:5A:0F": "HP",
    "3C:5A:B4": "Google",
    "F4:03:04": "Google",
    "54:60:09": "Google",
    "F0:27:2D": "Amazon",
    "44:65:0D": "Amazon",
    "AC:63:BE": "Amazon",
    "00:14:6C": "Netgear",
    "00:1B:2F": "Netgear",
    "14:CC:20": "TP-Link",
    "50:C7:BF": "TP-Link",
    "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
}

# Error codes indicating that an active network stack is responding
_ALIVE_ERRNOS = {0, errno.ECONNREFUSED}
if hasattr(errno, "ECONNRESET"):
    _ALIVE_ERRNOS.add(errno.ECONNRESET)
if hasattr(errno, "WSAECONNREFUSED"):
    _ALIVE_ERRNOS.add(errno.WSAECONNREFUSED)
if hasattr(errno, "WSAECONNRESET"):
    _ALIVE_ERRNOS.add(errno.WSAECONNRESET)

# Error codes indicating destination host/network is unreachable (abort early)
_UNREACHABLE_ERRNOS = set()
for err_name in ("EHOSTUNREACH", "ENETUNREACH", "WSAEHOSTUNREACH", "WSAENETUNREACH"):
    if hasattr(errno, err_name):
        _UNREACHABLE_ERRNOS.add(getattr(errno, err_name))


def _normalize_mac(raw_mac: Optional[str]) -> Optional[str]:
    """Normalizes MAC string to uppercase standard XX:XX:XX:XX:XX:XX format."""
    if not raw_mac:
        return None
    hex_digits = re.sub(r"[^0-9a-fA-F]", "", raw_mac)
    if len(hex_digits) != 12:
        return None
    return ":".join(hex_digits[i : i + 2].upper() for i in range(0, 12, 2))


def _is_alive(
    ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = PROBE_TIMEOUT,
) -> bool:
    """Probes candidate TCP ports to determine if a target host IP is alive."""
    target_ports = ports or PROBE_PORTS
    for port in target_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                res = sock.connect_ex((ip, port))
                if res in _ALIVE_ERRNOS:
                    return True
                if res in _UNREACHABLE_ERRNOS:
                    # Abort probing remaining ports if host/network is fundamentally unreachable
                    return False
        except OSError:
            continue
    return False


def _arp_table() -> Dict[str, str]:
    """Retrieves current ARP table mapping IPv4 addresses to MAC addresses.

    Supports Linux (/proc/net/arp), Windows ('arp -a'), and macOS/BSD ('arp -an').
    """
    table: Dict[str, str] = {}

    # 1. Linux procfs read (fast, zero subprocess overhead)
    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = _normalize_mac(parts[3])
                    if mac and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                        table[ip] = mac
    except OSError:
        pass

    if table:
        return table

    # 2. Windows / macOS / BSD fallback via system arp command
    try:
        proc = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
        if proc.stdout:
            # Matches IPv4 followed by physical MAC address in : or - format
            pattern = re.compile(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})"
            )
            for ip, raw_mac in pattern.findall(proc.stdout):
                try:
                    first_octet = int(ip.split(".")[0])
                    # Exclude multicast (224+) and broadcast addresses
                    if first_octet >= 224 or first_octet == 0:
                        continue
                except (ValueError, IndexError):
                    continue
                mac = _normalize_mac(raw_mac)
                if mac and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                    table[ip] = mac
    except (subprocess.SubprocessError, OSError):
        pass

    return table


def _vendor(mac: Optional[str]) -> Optional[str]:
    """Resolves the hardware vendor name from a MAC address via OUI prefix."""
    if not mac:
        return None
    normalized = _normalize_mac(mac)
    if not normalized:
        return None
    return OUI_VENDORS.get(normalized[:8], "Unknown")


def discover_hosts(
    subnet: str,
    ports: Optional[List[int]] = None,
    timeout: float = PROBE_TIMEOUT,
    max_workers: int = MAX_WORKERS,
) -> List[Dict[str, Optional[str]]]:
    """Discovers alive IPv4 hosts within a subnet and enriches with MAC/vendor data.

    Args:
        subnet: CIDR notation subnet string (e.g. '192.168.1.0/24').
        ports: Optional list of TCP probe ports (defaults to PROBE_PORTS).
        timeout: Socket connection timeout in seconds per probe.
        max_workers: Thread pool concurrency limit.

    Returns:
        List of dictionaries containing 'ip', 'mac', and 'vendor' for each alive host.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    # Handle /32 and /31 edge cases where .hosts() yields an empty list
    if network.num_addresses in (1, 2):
        addresses = [str(ip) for ip in network]
    else:
        addresses = [str(ip) for ip in network.hosts()]

    if not addresses:
        return []

    probe_ports = ports or PROBE_PORTS

    def probe_worker(ip: str) -> bool:
        return _is_alive(ip, ports=probe_ports, timeout=timeout)

    worker_count = min(max_workers, len(addresses)) if addresses else 1
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        alive_flags = list(pool.map(probe_worker, addresses))

    arp = _arp_table()

    # Correlate TCP alive status with ARP table entries
    # Hosts that responded to TCP or have valid LAN ARP entries are alive
    results: List[Dict[str, Optional[str]]] = []
    for ip, up in zip(addresses, alive_flags):
        mac = arp.get(ip)
        if up or mac is not None:
            results.append({
                "ip": ip,
                "mac": mac,
                "vendor": _vendor(mac),
            })

    return results

