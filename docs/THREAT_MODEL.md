# NetGuard Threat Model & Security Architecture

## 1. System Overview & Trust Boundaries
NetGuard is a centralized defensive dashboard that allows authenticated security analysts to schedule and review asset audits. 
**Trust Boundaries:** External API requests -> FastAPI Application -> SQLite Data Layer.

## 2. STRIDE Analysis Matrix
| Threat | Defensive Mitigation |
| :--- | :--- |
| **Spoofing** | Cryptographically signed, short-lived JWT tokens; passwords hashed using `pbkdf2_hmac`. |
| **Tampering** | Strict Pydantic IP validation to prevent SSRF and injection. |
| **Repudiation** | Structured audit logging capturing `operator`, `timestamp`, and `target`. |
| **Information Disclosure** | Role-Based Access Control (RBAC) enforced at router dependencies. |
| **Denial of Service** | Scan concurrency limits, connection timeouts (0.75s). |
| **Elevation of Privilege**| Declarative role checks (`admin`, `analyst`, `auditor`) applied directly to endpoints. |

## 3. The CIA Triad Mapping
- **Confidentiality:** Exposure reports are restricted via strict RBAC.
- **Integrity:** Parameterized database interactions prevent SQL Injection (SQLi).
- **Availability:** Non-blocking endpoints and timeouts prevent worker exhaustion.