"""
CVE Lookup Module for Recon+

Maps CPE/product/version information from Nmap to known CVEs.
This is a local database approach - no external API calls.

For real-world usage, consider integrating with:
- NVD API (https://nvd.nist.gov/developers/vulnerabilities)
- CVE Search API
- Local CVE database
"""

import re
from dataclasses import dataclass


@dataclass
class CVEEntry:
    cve_id: str
    severity: str
    title: str
    affected_products: list[str]
    affected_versions: list[str]


KNOWN_CVES = [
    CVEEntry(
        cve_id="CVE-2021-44228",
        severity="critical",
        title="Log4Shell - Apache Log4j RCE",
        affected_products=["log4j", "apache log4j"],
        affected_versions=["2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14"],
    ),
    CVEEntry(
        cve_id="CVE-2023-44487",
        severity="high",
        title="HTTP/2 Rapid Reset Attack",
        affected_products=["nginx", "apache", "httpd"],
        affected_versions=[],
    ),
    CVEEntry(
        cve_id="CVE-2021-41773",
        severity="critical",
        title="Apache HTTP Server Path Traversal",
        affected_products=["apache", "httpd", "apache httpd"],
        affected_versions=["2.4.49"],
    ),
    CVEEntry(
        cve_id="CVE-2021-42013",
        severity="critical",
        title="Apache HTTP Server Path Traversal (Bypass)",
        affected_products=["apache", "httpd", "apache httpd"],
        affected_versions=["2.4.49", "2.4.50"],
    ),
    CVEEntry(
        cve_id="CVE-2022-22965",
        severity="critical",
        title="Spring4Shell - Spring Framework RCE",
        affected_products=["spring", "spring framework", "spring boot"],
        affected_versions=["5.3.0", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5", "5.3.6", "5.3.7", "5.3.8", "5.3.9", "5.3.10", "5.3.11", "5.3.12", "5.3.13", "5.3.14", "5.3.15", "5.3.16", "5.3.17"],
    ),
    CVEEntry(
        cve_id="CVE-2023-22515",
        severity="critical",
        title="Atlassian Confluence Broken Access Control",
        affected_products=["confluence", "atlassian confluence"],
        affected_versions=["8.0.0", "8.0.1", "8.0.2", "8.0.3", "8.0.4", "8.1.0", "8.1.1", "8.1.3", "8.1.4", "8.2.0", "8.2.1", "8.2.2", "8.2.3", "8.3.0", "8.3.1", "8.3.2", "8.4.0", "8.4.1", "8.4.2", "8.5.0", "8.5.1"],
    ),
    CVEEntry(
        cve_id="CVE-2023-46747",
        severity="critical",
        title="F5 BIG-IP Authentication Bypass",
        affected_products=["big-ip", "f5 big-ip"],
        affected_versions=[],
    ),
    CVEEntry(
        cve_id="CVE-2024-3400",
        severity="critical",
        title="Palo Alto Networks PAN-OS Command Injection",
        affected_products=["pan-os", "palo alto"],
        affected_versions=["10.2", "11.0", "11.1"],
    ),
    CVEEntry(
        cve_id="CVE-2023-27997",
        severity="critical",
        title="Fortinet FortiOS SSL-VPN Heap Buffer Overflow",
        affected_products=["fortios", "fortigate", "fortinet"],
        affected_versions=["6.0", "6.2", "6.4", "7.0", "7.2"],
    ),
    CVEEntry(
        cve_id="CVE-2022-1388",
        severity="critical",
        title="F5 BIG-IP iControl REST Authentication Bypass",
        affected_products=["big-ip", "f5 big-ip"],
        affected_versions=["11.6", "12.1", "13.1", "14.1", "15.1", "16.0", "16.1"],
    ),
    CVEEntry(
        cve_id="CVE-2021-26855",
        severity="critical",
        title="Microsoft Exchange Server ProxyLogon",
        affected_products=["exchange", "microsoft exchange"],
        affected_versions=["2013", "2016", "2019"],
    ),
    CVEEntry(
        cve_id="CVE-2019-19781",
        severity="critical",
        title="Citrix ADC/Gateway Directory Traversal",
        affected_products=["citrix", "netscaler", "adc", "gateway"],
        affected_versions=["10.5", "11.1", "12.0", "12.1", "13.0"],
    ),
    CVEEntry(
        cve_id="CVE-2020-5902",
        severity="critical",
        title="F5 BIG-IP TMUI RCE",
        affected_products=["big-ip", "f5 big-ip"],
        affected_versions=["11.6", "12.1", "13.1", "14.1", "15.0", "15.1"],
    ),
    CVEEntry(
        cve_id="CVE-2023-20198",
        severity="critical",
        title="Cisco IOS XE Web UI Command Injection",
        affected_products=["ios xe", "cisco ios xe"],
        affected_versions=[],
    ),
    CVEEntry(
        cve_id="CVE-2022-41040",
        severity="high",
        title="Microsoft Exchange Server ProxyNotShell SSRF",
        affected_products=["exchange", "microsoft exchange"],
        affected_versions=["2013", "2016", "2019"],
    ),
    CVEEntry(
        cve_id="CVE-2020-1472",
        severity="critical",
        title="Zerologon - Netlogon Elevation of Privilege",
        affected_products=["windows server", "netlogon", "active directory"],
        affected_versions=["2008", "2012", "2016", "2019"],
    ),
    CVEEntry(
        cve_id="CVE-2017-0144",
        severity="critical",
        title="EternalBlue - SMBv1 RCE",
        affected_products=["smb", "smbv1", "windows"],
        affected_versions=[],
    ),
    CVEEntry(
        cve_id="CVE-2021-34473",
        severity="critical",
        title="Microsoft Exchange ProxyShell Pre-Auth Path Confusion",
        affected_products=["exchange", "microsoft exchange"],
        affected_versions=["2013", "2016", "2019"],
    ),
    CVEEntry(
        cve_id="CVE-2023-23397",
        severity="critical",
        title="Microsoft Outlook Elevation of Privilege",
        affected_products=["outlook", "microsoft outlook"],
        affected_versions=[],
    ),
    CVEEntry(
        cve_id="CVE-2020-0688",
        severity="high",
        title="Microsoft Exchange Validation Key RCE",
        affected_products=["exchange", "microsoft exchange"],
        affected_versions=["2010", "2013", "2016", "2019"],
    ),
    CVEEntry(
        cve_id="CVE-2023-38831",
        severity="high",
        title="WinRAR Code Execution via ZIP Archive",
        affected_products=["winrar"],
        affected_versions=["6.22", "6.21", "6.20", "6.11", "6.10", "6.02"],
    ),
    CVEEntry(
        cve_id="CVE-2024-21762",
        severity="critical",
        title="Fortinet FortiOS Out-of-Bounds Write",
        affected_products=["fortios", "fortigate", "fortinet"],
        affected_versions=["6.0", "6.2", "6.4", "7.0", "7.2", "7.4"],
    ),
    CVEEntry(
        cve_id="CVE-2023-4966",
        severity="critical",
        title="Citrix NetScaler ADC/Gateway Information Disclosure (Citrix Bleed)",
        affected_products=["citrix", "netscaler", "adc", "gateway"],
        affected_versions=["12.1", "13.0", "13.1", "14.1"],
    ),
]


def normalize_product(product: str) -> str:
    return product.lower().strip()


def normalize_version(version: str) -> str:
    version = version.lower().strip()
    version = re.sub(r"[^\d.]", "", version)
    return version


def extract_major_version(version: str) -> str:
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0] if parts else ""


def lookup_cves_for_port(port_info: dict) -> list[dict]:
    service = normalize_product(port_info.get("service", ""))
    product = normalize_product(port_info.get("product", ""))
    version = normalize_version(port_info.get("version", ""))
    cpes = port_info.get("cpes", [])
    
    combined_product = f"{service} {product}".strip()
    major_version = extract_major_version(version)
    
    matches = []
    
    for cve in KNOWN_CVES:
        product_match = False
        version_match = False
        
        for affected_product in cve.affected_products:
            if affected_product in combined_product or combined_product in affected_product:
                product_match = True
                break
            if affected_product in service or service in affected_product:
                product_match = True
                break
            if product and (affected_product in product or product in affected_product):
                product_match = True
                break
        
        if not product_match:
            for cpe in cpes:
                cpe_lower = cpe.lower()
                for affected_product in cve.affected_products:
                    if affected_product.replace(" ", "_") in cpe_lower:
                        product_match = True
                        break
        
        if not product_match:
            continue
        
        if not cve.affected_versions:
            version_match = True
        elif version:
            if version in cve.affected_versions:
                version_match = True
            elif major_version in cve.affected_versions:
                version_match = True
        
        if product_match and version_match:
            matches.append({
                "cve_id": cve.cve_id,
                "severity": cve.severity,
                "title": cve.title,
            })
    
    return matches


def enrich_ports_with_cves(ports: list[dict]) -> list[dict]:
    enriched = []
    
    for port in ports:
        port_copy = dict(port)
        cves = lookup_cves_for_port(port)
        
        if cves:
            port_copy["cves"] = cves
        
        enriched.append(port_copy)
    
    return enriched


def format_port_with_cves(port: dict) -> str:
    port_id = port.get("port", "")
    protocol = port.get("protocol", "tcp")
    state = port.get("state", "open")
    service = port.get("service", "")
    product = port.get("product", "")
    version = port.get("version", "")
    
    service_text = " ".join(part for part in [service, product, version] if part).strip()
    
    line = f"- {port_id}/{protocol} {state} {service_text}".rstrip()
    
    cves = port.get("cves", [])
    
    if cves:
        cve_lines = []
        for cve in cves[:3]:
            severity = cve.get("severity", "").upper()
            cve_id = cve.get("cve_id", "")
            title = cve.get("title", "")
            cve_lines.append(f"  CVE: {cve_id} [{severity}] {title}")
        
        line += "\n" + "\n".join(cve_lines)
    
    return line
