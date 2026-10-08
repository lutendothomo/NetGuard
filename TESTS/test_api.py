import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000/api"

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
YELLOW = "\033[93m"

def print_result(test_name, success, details=""):
    if success:
        print(f"{GREEN}[PASS]{RESET} {test_name} {details}")
    else:
        print(f"{RED}[FAIL]{RESET} {test_name} {details}")
        sys.exit(1)

def setup_users():
    """Generates unique users for each test run to avoid 'already registered' errors."""
    suffix = int(time.time())
    admin = {"username": f"admin_{suffix}", "password": "StrongPassword123!", "role": "admin"}
    auditor = {"username": f"auditor_{suffix}", "password": "StrongPassword123!", "role": "auditor"}
    
    # Register Users
    requests.post(f"{BASE_URL}/auth/register", json=admin)
    requests.post(f"{BASE_URL}/auth/register", json=auditor)
    
    # Login and get tokens
    admin_token = requests.post(f"{BASE_URL}/auth/login", json={"username": admin["username"], "password": admin["password"]}).json()["access_token"]
    auditor_token = requests.post(f"{BASE_URL}/auth/login", json={"username": auditor["username"], "password": auditor["password"]}).json()["access_token"]
    
    return admin_token, auditor_token

def test_ssrf_protection(admin_token):
    print(f"\n{YELLOW}[*] Testing SSRF Protection (OWASP A10)...{RESET}")
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {"target_ip": "169.254.169.254"} # AWS/GCP Metadata IP
    
    response = requests.post(f"{BASE_URL}/audit/run", json=payload, headers=headers)
    
    # We expect a 422 Unprocessable Entity because Pydantic blocked it
    if response.status_code == 422:
        print_result("SSRF Blocked", True, "(Metadata IP safely rejected)")
    else:
        print_result("SSRF Blocked", False, f"(Expected 422, got {response.status_code})")

def test_rbac_privilege_escalation(auditor_token):
    print(f"\n{YELLOW}[*] Testing RBAC Privilege Escalation (OWASP A01)...{RESET}")
    headers = {"Authorization": f"Bearer {auditor_token}"}
    payload = {"target_ip": "127.0.0.1"}
    
    response = requests.post(f"{BASE_URL}/audit/run", json=payload, headers=headers)
    
    # We expect 403 Forbidden because auditors cannot run scans
    if response.status_code == 403:
        print_result("RBAC Enforcement", True, "(Auditor prevented from executing scan)")
    else:
        print_result("RBAC Enforcement", False, f"(Expected 403, got {response.status_code})")

def test_valid_scan_and_logs(admin_token, auditor_token):
    print(f"\n{YELLOW}[*] Testing Happy Path (Valid Scan & Log Access)...{RESET}")
    
    # 1. Admin runs a valid scan
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    scan_response = requests.post(f"{BASE_URL}/audit/run", json={"target_ip": "127.0.0.1"}, headers=admin_headers)
    
    if scan_response.status_code == 200:
        print_result("Admin Scan Execution", True, "(Scan completed successfully)")
    else:
        print_result("Admin Scan Execution", False, f"(Failed with {scan_response.status_code})")

    # 2. Auditor views the logs
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}
    logs_response = requests.get(f"{BASE_URL}/audit/logs", headers=auditor_headers)
    
    if logs_response.status_code == 200 and len(logs_response.json()) > 0:
        print_result("Auditor Log Access", True, "(Logs successfully retrieved)")
    else:
        print_result("Auditor Log Access", False, "(Failed to retrieve logs)")

if __name__ == "__main__":
    print(f"=== NetGuard Automated Security Test Suite ===")
    
    try:
        
        requests.get("http://127.0.0.1:8000/docs")
    except requests.exceptions.ConnectionError:
        print(f"{RED}[FATAL]{RESET} FastAPI server is not running. Start it with 'python run.py' first.")
        sys.exit(1)

    print("Setting up temporary test accounts...")
    admin_jwt, auditor_jwt = setup_users()
    
    test_ssrf_protection(admin_jwt)
    test_rbac_privilege_escalation(auditor_jwt)
    test_valid_scan_and_logs(admin_jwt, auditor_jwt)
    
    print(f"\n{GREEN}=== ALL SECURITY TESTS PASSED ==={RESET}")