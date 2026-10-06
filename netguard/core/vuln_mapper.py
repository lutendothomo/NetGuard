KNOWN_SIGNATURES = {
    "apache/2.4.49": [{"cve": "CVE-2021-41773", "cvss": "7.5", "summary": "Path traversal flaw."}],
    "openssh_7.2p2": [{"cve": "CVE-2016-6210", "cvss": "5.3", "summary": "User enumeration flaw."}]
}

def correlate_vulnerabilities(service_banner: str) -> list:
    results = []
    normalized = service_banner.lower()
    for signature, cve_list in KNOWN_SIGNATURES.items():
        if signature in normalized:
            results.extend(cve_list)
    return results