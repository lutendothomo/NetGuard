import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import pytest
from netguard.auth.security import hash_password, verify_password
from netguard.core.services import identify
from netguard.core.vuln_mapper import correlate_vulnerabilities
from conftest import PASSWORD


def test_first_user_is_admin_and_self_registration_cannot_escalate(client):
    first = client.post("/api/auth/register", json={"username": "first_user", "password": PASSWORD})
    assert first.json()["role"] == "admin"

    second = client.post("/api/auth/register", json={"username": "second_user", "password": PASSWORD, "role": "admin"})
    assert second.status_code == 201
    assert second.json()["role"] == "analyst"

    login = client.post("/api/auth/login", json={"username": "second_user", "password": PASSWORD})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    created = client.post("/api/auth/users", json={"username": "third_user", "password": PASSWORD, "role": "admin"}, headers=headers)
    assert created.status_code == 403


def test_admin_can_create_users_with_roles(client, admin_headers):
    response = client.post("/api/auth/users", json={"username": "aud_user", "password": PASSWORD, "role": "auditor"}, headers=admin_headers)
    assert response.status_code == 201
    assert response.json()["role"] == "auditor"


def test_unauthenticated_requests_are_rejected(client):
    assert client.post("/api/network/scan", json={"target_ip": "127.0.0.1"}).status_code == 401
    assert client.get("/api/network/hosts").status_code == 401
    assert client.get("/api/audit/logs").status_code == 401


def test_ssrf_metadata_address_blocked(client, admin_headers):
    response = client.post("/api/audit/run", json={"target_ip": "169.254.169.254"}, headers=admin_headers)
    assert response.status_code == 422


@pytest.mark.parametrize("target", ["8.8.8.8", "10.0.0.5", "192.168.1.1"])
def test_out_of_scope_targets_rejected(client, admin_headers, target):
    assert client.post("/api/audit/run", json={"target_ip": target}, headers=admin_headers).status_code == 422
    assert client.post("/api/network/scan", json={"target_ip": target}, headers=admin_headers).status_code == 422


def test_auditor_cannot_run_scans(client, make_user):
    auditor = make_user("aud_user", "auditor")
    assert client.post("/api/audit/run", json={"target_ip": "127.0.0.1"}, headers=auditor).status_code == 403
    assert client.post("/api/network/scan", json={"target_ip": "127.0.0.1"}, headers=auditor).status_code == 403
    assert client.post("/api/network/discover", json={"subnet": "127.0.0.0/30"}, headers=auditor).status_code == 403


def test_scan_identifies_service_and_maps_cve(client, admin_headers, banner_server):
    port, _ = banner_server
    response = client.post("/api/network/scan", json={"target_ip": "127.0.0.1", "ports": [port]}, headers=admin_headers)
    assert response.status_code == 200
    finding = response.json()["results"][0]
    assert finding["port"] == port
    assert finding["service"] == "ssh"
    assert finding["product"] == "OpenSSH"
    assert finding["version"] == "7.2p2"
    assert finding["vulnerabilities"][0]["cve"] == "CVE-2016-6210"


def test_scan_persists_inventory_and_tracks_closed_ports(client, admin_headers, banner_server):
    port, close = banner_server
    client.post("/api/network/scan", json={"target_ip": "127.0.0.1", "ports": [port]}, headers=admin_headers)

    hosts = client.get("/api/network/hosts", headers=admin_headers).json()
    assert hosts[0]["ip"] == "127.0.0.1"
    assert hosts[0]["open_ports"] == 1

    detail = client.get("/api/network/hosts/127.0.0.1", headers=admin_headers).json()
    assert detail["ports"][0]["port"] == port
    assert detail["ports"][0]["vulnerabilities"][0]["cve"] == "CVE-2016-6210"

    close()
    client.post("/api/network/scan", json={"target_ip": "127.0.0.1", "ports": [port]}, headers=admin_headers)
    assert client.get("/api/network/hosts", headers=admin_headers).json()[0]["open_ports"] == 0
    assert client.get("/api/network/hosts/127.0.0.1", headers=admin_headers).json()["ports"] == []


def test_unknown_and_invalid_host_lookups(client, admin_headers):
    assert client.get("/api/network/hosts/127.0.0.9", headers=admin_headers).status_code == 404
    assert client.get("/api/network/hosts/not-an-ip", headers=admin_headers).status_code == 422


def test_invalid_port_lists_rejected(client, admin_headers):
    for ports in ([0], [70000], [], list(range(1, 1100))):
        response = client.post("/api/network/scan", json={"target_ip": "127.0.0.1", "ports": ports}, headers=admin_headers)
        assert response.status_code == 422


def test_discovery_finds_loopback_and_validates_subnet(client, admin_headers):
    response = client.post("/api/network/discover", json={"subnet": "127.0.0.0/30"}, headers=admin_headers)
    assert response.status_code == 200
    assert "127.0.0.1" in [host["ip"] for host in response.json()["hosts"]]
    assert any(host["ip"] == "127.0.0.1" for host in client.get("/api/network/hosts", headers=admin_headers).json())

    assert client.post("/api/network/discover", json={"subnet": "10.0.0.0/24"}, headers=admin_headers).status_code == 422
    assert client.post("/api/network/discover", json={"subnet": "127.0.0.0/16"}, headers=admin_headers).status_code == 422


def test_scans_are_written_to_audit_log(client, admin_headers, make_user, banner_server):
    port, _ = banner_server
    client.post("/api/network/scan", json={"target_ip": "127.0.0.1", "ports": [port]}, headers=admin_headers)
    auditor = make_user("aud_user", "auditor")
    logs = client.get("/api/audit/logs", headers=auditor)
    assert logs.status_code == 200
    assert logs.json()[0]["operator"] == "admin_user"
    assert logs.json()[0]["target"] == "127.0.0.1"


def test_scanner_busy_returns_429(client, admin_headers, monkeypatch):
    monkeypatch.setattr("netguard.core.limits._slots", threading.BoundedSemaphore(0))
    response = client.post("/api/network/scan", json={"target_ip": "127.0.0.1", "ports": [22]}, headers=admin_headers)
    assert response.status_code == 429


def test_login_lockout_after_repeated_failures(client, admin_headers):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "admin_user", "password": "wrong-password"}).status_code == 401
    locked = client.post("/api/auth/login", json={"username": "admin_user", "password": PASSWORD})
    assert locked.status_code == 429


def test_password_hashing_and_legacy_format():
    stored = hash_password("StrongPassword123!")
    assert stored.startswith("600000$")
    assert verify_password("StrongPassword123!", stored)
    assert not verify_password("wrong", stored)

    import hashlib, os
    salt = os.urandom(16)
    legacy = f"{salt.hex()}${hashlib.pbkdf2_hmac('sha256', b'oldpassword', salt, 100000).hex()}"
    assert verify_password("oldpassword", legacy)


@pytest.mark.parametrize("port,banner,expected", [
    (22, "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8", ("ssh", "OpenSSH", "7.2p2")),
    (80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)", ("http", "Apache", "2.4.49")),
    (8080, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0", ("http", "nginx", "1.18.0")),
    (21, "220 (vsFTPd 2.3.4)", ("ftp", "vsFTPd", "2.3.4")),
    (3306, "", ("mysql", None, None)),
    (31337, "", ("unknown", None, None)),
])
def test_service_identification(port, banner, expected):
    result = identify(port, banner)
    assert (result["service"], result["product"], result["version"]) == expected


def test_vulnerability_mapping():
    assert correlate_vulnerabilities("220 (vsFTPd 2.3.4)")[0]["cve"] == "CVE-2011-2523"
    assert correlate_vulnerabilities("Server: Apache/2.4.50")[0]["cve"] == "CVE-2021-42013"
    assert correlate_vulnerabilities("Server: nginx/1.25.0") == []
    assert correlate_vulnerabilities("") == []


def test_http_detected_on_nonstandard_port(client, admin_headers):
    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        response = client.post("/api/network/scan", json={"target_ip": "127.0.0.1", "ports": [port]}, headers=admin_headers)
        finding = response.json()["results"][0]
        assert finding["service"] == "http"
        assert finding["banner"].startswith("HTTP/")
    finally:
        server.shutdown()
        server.server_close()
