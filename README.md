# NetGuard Security Platform: Full Build Guide & Documentation

NetGuard is a defensive Web Application Security Management Platform. It is designed to safely execute network and endpoint hygiene checks while demonstrating strict adherence to secure coding principles, DevSecOps pipelines, and the OWASP Top 10 mitigation strategies.

This document serves as the master blueprint, containing the codebase and documentation broken down into the 5 phases of the Secure Software Development Lifecycle (SSDLC).

---

## Prerequisites & Setup

* **Python:** 3.11 or 3.12 *(Do not use 3.14 due to missing Rust binaries for `pydantic-core`)*.
* **OS:** Linux VM (Ubuntu/Kali) recommended for native socket handling, or Windows with a version-specific `venv`.

```bash
# 1. Clone or create the repository folder
mkdir netguard
cd netguard

# 2. Create and activate a Python virtual environment (using Python 3.11/3.12)
py -3.11 -m venv venv           # Windows
source venv/bin/activate        # Linux / Mac
.\venv\Scripts\activate         # Windows Activation

# 3. Proceed through the build phases below to populate your files.