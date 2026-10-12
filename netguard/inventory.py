import ipaddress
import time
from typing import Dict, List, Optional
from netguard.database import connection

def upsert_host(ip: str, mac: Optional[str] = None, vendor: Optional[str] = None) -> int:
    now = time.time()
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO hosts (ip, mac, vendor, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen = excluded.last_seen,
                mac = COALESCE(excluded.mac, hosts.mac),
                vendor = COALESCE(excluded.vendor, hosts.vendor)
            """,
            (ip, mac, vendor, now, now),
        )
        return conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()["id"]

def record_scan(host_id: int, scanned_ports: List[int], services: Dict[int, dict]) -> None:
    now = time.time()
    with connection() as conn:
        for port in scanned_ports:
            info = services.get(port)
            if info:
                conn.execute(
                    """
                    INSERT INTO ports (host_id, port, protocol, state, service, product, version, banner, first_seen, last_seen)
                    VALUES (?, ?, 'tcp', 'open', ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                        state = 'open',
                        service = excluded.service,
                        product = excluded.product,
                        version = excluded.version,
                        banner = excluded.banner,
                        last_seen = excluded.last_seen
                    """,
                    (host_id, port, info["service"], info["product"], info["version"], info["banner"], now, now),
                )
            else:
                conn.execute(
                    "UPDATE ports SET state = 'closed', last_seen = ? WHERE host_id = ? AND port = ? AND protocol = 'tcp'",
                    (now, host_id, port),
                )

def list_hosts() -> List[dict]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT h.*, (SELECT COUNT(*) FROM ports p WHERE p.host_id = h.id AND p.state = 'open') AS open_ports
            FROM hosts h
            """
        ).fetchall()
    return sorted((dict(row) for row in rows), key=lambda row: ipaddress.ip_address(row["ip"]))

def get_host(ip: str) -> Optional[dict]:
    with connection() as conn:
        host = conn.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)).fetchone()
        if not host:
            return None
        ports = conn.execute(
            "SELECT port, protocol, service, product, version, banner, first_seen, last_seen FROM ports "
            "WHERE host_id = ? AND state = 'open' ORDER BY port",
            (host["id"],),
        ).fetchall()
    return {**dict(host), "ports": [dict(row) for row in ports]}
