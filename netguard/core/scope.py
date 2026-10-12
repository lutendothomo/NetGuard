import ipaddress
from netguard.config import settings

def allowed_networks() -> list:
    return [ipaddress.ip_network(c.strip()) for c in settings.ALLOWED_TARGETS.split(",") if c.strip()]

def ip_in_scope(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr.version == net.version and addr in net for net in allowed_networks())

def network_in_scope(subnet: str) -> bool:
    target = ipaddress.ip_network(subnet, strict=False)
    return any(target.version == net.version and target.subnet_of(net) for net in allowed_networks())
