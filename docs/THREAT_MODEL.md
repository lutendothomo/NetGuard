# NetGuard Threat Model & Security Architecture

## 1. System Overview & Trust Boundaries
NetGuard is a centralized defensive dashboard that allows authenticated security analysts to schedule and review asset audits. 
**Trust Boundaries:** External API requests -> FastAPI Application -> SQLite Data Layer.

## 2. STRIDE Analysis Matrix
| Threat | Defensive Mitigation |
| :--- | :--- |
| **Spoofing** | Cryptographically signed, short-lived JWT tokens; passwords hashed with PBKDF2-HMAC-SHA256 (600,000 iterations); failed-login throttling per IP and username. |
| **Tampering** | Strict Pydantic validation of IPs, subnets, and ports; targets must fall inside the configured authorized scope. |
| **Repudiation** | Structured audit logging capturing `operator`, `timestamp`, and `target`. |
| **Information Disclosure** | Role-Based Access Control (RBAC) enforced at router dependencies. |
| **Denial of Service** | Global cap on concurrent scans (excess requests get 429), bounded thread pools, connection timeouts, /24 maximum subnet size, 1024 maximum ports per scan. |
| **Elevation of Privilege**| Declarative role checks applied directly to endpoints; self-registration can never grant a role above analyst (the first account bootstraps as admin); only admins can create privileged users. |

## 3. The CIA Triad Mapping
- **Confidentiality:** Exposure reports are restricted via strict RBAC.
- **Integrity:** Parameterized database interactions prevent SQL Injection (SQLi).
- **Availability:** Non-blocking endpoints and timeouts prevent worker exhaustion.
## 4. Authorization Scope
Every scan target is checked against `NETGUARD_ALLOWED_TARGETS` (default: loopback and the VirtualBox host-only range). A request outside that list is rejected with 422 before any packet is sent, so a compromised or careless analyst account cannot point the scanner at third-party or internal-metadata addresses.

## 5. Known Limitations
- Login throttling is held in process memory, so it resets on restart and is not shared across multiple workers.
- JWTs cannot be revoked before they expire.
- The application does not terminate TLS itself; run it behind a TLS-terminating proxy outside localhost.
- Banner and CVE matching is signature-based and will miss anything not in the signature list.
