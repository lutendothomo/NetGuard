# NetGuard Security Platform

NetGuard is a defensive Web Application Security Management Platform. It is designed to safely execute network and endpoint hygiene checks while demonstrating strict adherence to secure coding principles, DevSecOps pipelines, and the OWASP Top 10 mitigation strategies.

## Prerequisites
* **Python:** 3.11 or 3.12 (Do not use 3.14 due to missing Rust binaries for `pydantic-core`).
* **OS:** Linux VM (Ubuntu/Kali) recommended for native socket handling, or Windows with a version-specific `venv`.

## Installation

```bash
# 1. Clone the repository
git clone git@github.com:lutendothomo/NetGuard.git
cd NetGuard

# 2. Create and activate a Python virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt