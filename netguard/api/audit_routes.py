import time, json
from fastapi import APIRouter, Depends
from netguard.api.schemas import AuditRequest
from netguard.auth.rbac import require_role
from netguard.core.auditor import inspect_endpoint
from netguard.core.limits import scan_slot
from netguard.core.vuln_mapper import correlate_vulnerabilities
from netguard.database import get_connection

router = APIRouter(prefix="/api/audit", tags=["Security Audits"])

@router.post("/run")
def run_security_audit(request: AuditRequest, current_user: dict = Depends(require_role(["admin", "analyst"]))):
    with scan_slot():
        open_services = inspect_endpoint(request.target_ip)

    findings = []
    for port, banner in open_services.items():
        cves = correlate_vulnerabilities(banner)
        findings.append({"port": port, "banner": banner, "vulnerabilities": cves})

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (operator, target, timestamp, findings_summary) VALUES (?, ?, ?, ?)",
            (current_user["username"], request.target_ip, time.time(), json.dumps(findings))
        )
        conn.commit()

    return {"target": request.target_ip, "operator": current_user["username"], "results": findings}

@router.get("/logs")
def view_audit_logs(current_user: dict = Depends(require_role(["admin", "analyst", "auditor"]))):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, operator, target, timestamp, findings_summary FROM audit_logs ORDER BY id DESC")
        rows = cursor.fetchall()

    return [
        {"id": r["id"], "operator": r["operator"], "target": r["target"], "timestamp": r["timestamp"], "findings": json.loads(r["findings_summary"])}
        for r in rows
    ]
