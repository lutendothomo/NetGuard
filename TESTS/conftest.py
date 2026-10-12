import socket
import threading
import pytest
from fastapi.testclient import TestClient
from netguard.auth import throttle
from netguard.config import settings

PASSWORD = "StrongPassword123!"

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "test.db"))
    throttle._failures.clear()
    from run import app
    with TestClient(app) as test_client:
        yield test_client

def _login(client, username, password=PASSWORD):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}

@pytest.fixture
def admin_headers(client):
    client.post("/api/auth/register", json={"username": "admin_user", "password": PASSWORD})
    return _login(client, "admin_user")

@pytest.fixture
def make_user(client, admin_headers):
    def factory(username, role):
        client.post("/api/auth/users", json={"username": username, "password": PASSWORD, "role": role}, headers=admin_headers)
        return _login(client, username)
    return factory

@pytest.fixture
def banner_server():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    conn.sendall(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n")
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def close():
        stop.set()
        thread.join()
        listener.close()

    yield port, close
    close()
