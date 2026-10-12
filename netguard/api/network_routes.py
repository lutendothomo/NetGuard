import ipaddress
import json
import time
from fastapi import APIRouter, Depends, HTTPException
from netguard import inventory
from netguard.api.schemas import DiscoverRequest, ScanRequest
from netguard.auth.rbac import require_role
from netguard.core.discovery import discover_hosts
from netguard.core.limits import scan_slot
from netguard.core.portscan import DEFAULT_PORTS, scan_ports
from netguard.core.services import grab_banner, identify
from netguard.core.vuln_mapper import correlate_vulnerabilities
from netguard.database import connection

router = APIRouter(prefix="/api/network", tags=["Network Inventory"])

def _log(operator: str, target: str, summary: list) -> None:
    with connection() as conn:
        conn.execute(
            "INSERT INTO audit_logs (operator, target, timestamp, findings_summary) VALUES (?, ?, ?, ?)",
            (operator, target, time.time(), json.dumps(summary)),
        )

@router.post("/discover")
def discover(request: DiscoverRequest, current_user: dict = Depends(require_role(["admin", "analyst"]))):
    with scan_slot():
        found = discover_hosts(request.subnet)
    for host in found:
        inventory.upsert_host(host["ip"], host["mac"], host["vendor"])
    _log(current_user["username"], request.subnet, found)
    return {"subnet": request.subnet, "operator": current_user["username"], "hosts": found}

@router.post("/scan")
def scan(request: ScanRequest, current_user: dict = Depends(require_role(["admin", "analyst"]))):
    ports = request.ports or DEFAULT_PORTS
    services = {}
    with scan_slot():
        for port in scan_ports(request.target_ip, ports):
            banner = grab_banner(request.target_ip, port)
            services[port] = {**identify(port, banner), "banner": banner}

    host_id = inventory.upsert_host(request.target_ip)
    inventory.record_scan(host_id, ports, services)

    findings = [
        {
            "port": port,
            "service": info["service"],
            "product": info["product"],
            "version": info["version"],
            "banner": info["banner"] or "Open",
            "vulnerabilities": correlate_vulnerabilities(info["banner"]),
        }
        for port, info in services.items()
    ]
    _log(current_user["username"], request.target_ip, findings)
    return {"target": request.target_ip, "operator": current_user["username"], "results": findings}

@router.get("/hosts")
def list_hosts(current_user: dict = Depends(require_role(["admin", "analyst", "auditor"]))):
    return inventory.list_hosts()

@router.get("/hosts/{ip}")
def get_host(ip: str, current_user: dict = Depends(require_role(["admin", "analyst", "auditor"]))):
    try:
        ip = str(ipaddress.IPv4Address(ip))
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid IPv4 address.")
    host = inventory.get_host(ip)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found.")
    for port in host["ports"]:
        port["vulnerabilities"] = correlate_vulnerabilities(port["banner"])
    return host
