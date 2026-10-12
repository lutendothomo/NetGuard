# NetGuard

A defensive network inventory and security auditing platform for authorized lab networks. Built in versions, each one adding a capability on top of the last, with security controls (auth, RBAC, audit logging, scope enforcement) in place from the start.

**Authorized use only.** NetGuard refuses any target outside `NETGUARD_ALLOWED_TARGETS`. Only add ranges you own or have written permission to test.

## Roadmap

| Version | Capability | Status |
|---|---|---|
| Platform | JWT auth, RBAC, audit logs, threat model, DevSecOps CI | Done |
| V1 | Host discovery (`POST /api/network/discover`) | Done |
| V2 | Threaded TCP port scanning (`POST /api/network/scan`) | Done |
| V3 | Banner grabbing and service/version fingerprinting | Done |
| V4 | Known-vulnerability checking | Started: small local signature list, to be replaced by an NVD feed |
| V5 | Suspicious activity detection | Planned |
| V6 | Security reports | Planned |
| V7 | Dashboard and continuous monitoring | Planned |

## Setup

Python 3.11 or 3.12.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

## Run

```bash
export NETGUARD_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export NETGUARD_ALLOWED_TARGETS="127.0.0.0/8,192.168.56.0/24"
python run.py
```

If `NETGUARD_SECRET_KEY` is not set, a random key is generated per process and tokens stop working on restart.

The first account registered through `/api/auth/register` becomes `admin`. Every later self-registration is `analyst`. Admins create other users, including auditors, through `POST /api/auth/users`.

## API

| Endpoint | Roles | Purpose |
|---|---|---|
| `POST /api/auth/register` | public | Self-register (first user is admin, later users are analysts) |
| `POST /api/auth/users` | admin | Create a user with a chosen role |
| `POST /api/auth/login` | public | Get a JWT (5 failures per 5 minutes locks that IP and username) |
| `POST /api/network/discover` | admin, analyst | Find live hosts in a subnet (/24 or smaller) |
| `POST /api/network/scan` | admin, analyst | Port scan, identify services, map known CVEs |
| `GET /api/network/hosts` | all | Inventory of discovered hosts |
| `GET /api/network/hosts/{ip}` | all | Open ports and findings for one host |
| `POST /api/audit/run` | admin, analyst | Quick scan of common ports |
| `GET /api/audit/logs` | all | Audit trail of every scan |

## Test

```bash
python -m pytest -q
```

CI runs Bandit, pip-audit, and the test suite on every push.

## Notes

Discovery uses TCP probes (a refused connection still proves a host is up), so it needs no root access. MAC addresses and vendors appear only for hosts on the same local segment, read from the Linux ARP cache.
