# rapidrecon/rapidrecon/enumerator.py
"""
Asset Enumeration Module for RapidRecon
- Subdomain discovery via crt.sh, VirusTotal, SecurityTrails
- Optional WHOIS lookups and DNS resolution to collect IPs or networks
"""
import logging
import socket
from typing import Dict, List
import requests
import ipaddress

# Optional imports for extended sources
try:
    from pythonwhois import get_whois
except ImportError:
    get_whois = None


def fetch_crtsh_subdomains(domain: str, timeout: int = 10) -> List[str]:
    """
    Query crt.sh for Certificate Transparency logs to discover subdomains.
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    resp = requests.get(url, params=params, timeout=timeout)
    resp.raise_for_status()
    data = resp.json() or []
    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for sd in name_value.splitlines():
            sd = sd.strip().lower()
            if sd and sd.endswith(domain):
                subdomains.add(sd)
    return list(subdomains)


def resolve_to_ips(hosts: List[str]) -> List[str]:
    """
    Resolve a list of hostnames to their A-record IPs.
    """
    ips = []
    for host in hosts:
        try:
            results = socket.getaddrinfo(host, None)
            for res in results:
                ip = res[4][0]
                ips.append(ip)
        except Exception:
            continue
    return list(set(ips))


def enumerate_assets(target: str, enum_cfg: Dict) -> Dict[str, List[str]]:
    """
    Main entrypoint for asset enumeration.
    Returns a dict with 'subdomains' and 'ips'.
    Detects IPs or CIDR networks and skips enumeration accordingly.
    """
    tgt = target.strip().lower()
    # Directly handle IPs or CIDR networks
    try:
        ipaddress.ip_network(tgt, strict=False)
        logging.debug(f"Target '{tgt}' detected as IP/network; skipping enumeration.")
        return {"subdomains": [], "ips": [tgt]}
    except ValueError:
        pass

    subdomains: List[str] = []
    ips: List[str] = []
    sources = enum_cfg.get("sources", {})
    api_keys = enum_cfg.get("api_keys", {})

    # Subdomain enumeration
    if sources.get("crtsh", False):
        logging.debug(f"Fetching subdomains from crt.sh for {tgt}")
        try:
            subdomains += fetch_crtsh_subdomains(tgt)
        except Exception as e:
            logging.warning(f"crt.sh enumeration failed: {e}")

    # Placeholder: VirusTotal enumeration
    if sources.get("virustotal", False) and api_keys.get("virustotal"):
        logging.debug("VirusTotal enumeration not yet implemented.")

    # Placeholder: SecurityTrails enumeration
    if sources.get("securitytrails", False) and api_keys.get("securitytrails"):
        logging.debug("SecurityTrails enumeration not yet implemented.")

    # Resolve subdomains to IPs
    if subdomains:
        logging.debug(f"Resolving {len(subdomains)} subdomains to IPs...")
        ips += resolve_to_ips(subdomains)

    # WHOIS-based IP enumeration (optional)
    if enum_cfg.get("whois", False) and get_whois:
        try:
            logging.debug(f"Performing WHOIS lookup for {tgt}")
            whois_data = get_whois(tgt)
            for net in whois_data.get("nets", []):
                cidrs = net.get("cidr")
                if cidrs:
                    ips.append(cidrs)
        except Exception as e:
            logging.warning(f"WHOIS lookup failed: {e}")

    subdomains = sorted(set(subdomains))
    ips = sorted(set(ips))
    return {"subdomains": subdomains, "ips": ips}
