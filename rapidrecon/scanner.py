# rapidrecon/rapidrecon/scanner.py
"""
Port & Service Scanning Module for RapidRecon
- Fast SYN scans via python-nmap
- Concurrency controlled via ThreadPoolExecutor
- Returns structured scan results
"""
import logging
from typing import Dict, List
import nmap
import concurrent.futures


def scan_host(host: str, ports: str, args: str, timeout: int) -> Dict:
    """
    Scan a single host for specified ports using nmap.
    Returns a dict with host and list of port info.
    """
    scanner = nmap.PortScanner()
    try:
        # Perform scan
        logging.debug(f"Scanning {host} with ports={ports} args='{args}'")
        scanner.scan(hosts=host, ports=ports, arguments=args)
    except Exception as e:
        logging.warning(f"Nmap scan error on {host}: {e}")
        return {"host": host, "ports": []}

    results = []
    if host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            lports = scanner[host][proto].keys()
            for port in sorted(lports):
                port_info = scanner[host][proto][port]
                results.append({
                    "port": port,
                    "protocol": proto,
                    "state": port_info.get("state"),
                    "name": port_info.get("name"),
                    "product": port_info.get("product"),
                    "version": port_info.get("version"),
                })
    return {"host": host, "ports": results}


def scan_assets(assets: Dict[str, List[str]], scan_cfg: Dict) -> List[Dict]:
    """
    Entry point for scanning assets.
    Takes assets dict with 'subdomains' and 'ips', and scan settings.
    Returns list of scan result dicts.
    """
    # Combine hosts: prefer subdomains for banner info, but include ips
    hosts = []
    hosts += assets.get("subdomains", [])
    hosts += assets.get("ips", [])
    # Remove empties and duplicates
    hosts = sorted(set([h for h in hosts if h]))

    # Pull config
    nmap_cfg = scan_cfg.get("nmap", {})
    ports = nmap_cfg.get("ports", "1-1024")
    args = nmap_cfg.get("args", "-sS -Pn")
    timeout = scan_cfg.get("timeout", 10)
    max_workers = scan_cfg.get("max_concurrency", 5)

    logging.info(f"Beginning scan on {len(hosts)} hosts with up to {max_workers} threads")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # schedule scans
        future_to_host = {
            executor.submit(scan_host, host, ports, args, timeout): host
            for host in hosts
        }
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                res = future.result()
                results.append(res)
                logging.debug(f"Scan complete for {host}: {len(res['ports'])} ports found")
            except Exception as e:
                logging.warning(f"Scan exception for {host}: {e}")
    return results
