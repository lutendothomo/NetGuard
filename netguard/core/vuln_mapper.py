KNOWN_SIGNATURES = {
    "apache/2.4.49": [{"cve": "CVE-2021-41773", "cvss": "7.5", "summary": "Path traversal flaw."}],
    "apache/2.4.50": [{"cve": "CVE-2021-42013", "cvss": "9.8", "summary": "Path traversal and remote code execution (incomplete fix for CVE-2021-41773)."}],
    "openssh_7.2p2": [{"cve": "CVE-2016-6210", "cvss": "5.3", "summary": "User enumeration flaw."}],
    "vsftpd 2.3.4": [{"cve": "CVE-2011-2523", "cvss": "9.8", "summary": "Backdoor in vsftpd 2.3.4 source package allows remote command execution."}],
}

def correlate_vulnerabilities(service_banner: str) -> list:
    results = []
    normalized = (service_banner or "").lower()
    for signature, cve_list in KNOWN_SIGNATURES.items():
        if signature in normalized:
            results.extend(cve_list)
    return results