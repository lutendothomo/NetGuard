from typing import Dict, List
from netguard.core.portscan import scan_ports
from netguard.core.services import grab_banner

COMMON_TARGET_PORTS = [21, 22, 80, 443, 8080]

def inspect_endpoint(ip: str, ports: List[int] = COMMON_TARGET_PORTS) -> Dict[int, str]:
    return {port: grab_banner(ip, port) or "Open" for port in scan_ports(ip, ports)}
