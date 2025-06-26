#!/usr/bin/env python3
"""
RapidRecon Core Orchestration Module

This script ties together asset enumeration, scanning, and reporting.
"""
import argparse
import logging
import sys

from rapidrecon.utils import load_config, ensure_env_vars
from rapidrecon.enumerator import enumerate_assets
from rapidrecon.scanner import scan_assets
from rapidrecon.reporter import generate_report


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="RapidRecon: Asset enumeration & quick scanning tool"
    )
    parser.add_argument(
        "target",
        help="Target domain or IP range to scan (e.g. example.com or 192.168.1.0/24)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        help="Directory to write reports (overrides config)",
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose (debug) logging",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)
    logging.info("Starting RapidRecon...")

    # Load config and ensure API keys for enabled services
    try:
        config = load_config()
        ensure_env_vars()
    except Exception as e:
        logging.error(f"Configuration error: {e}")
        sys.exit(1)

    # Override report directory if provided on CLI
    if args.output_dir:
        config["report"]["directory"] = args.output_dir
        logging.debug(f"Overriding report directory: {args.output_dir}")

    # 1. Asset Enumeration
    logging.info(f"Enumerating assets for target: {args.target}")
    assets = enumerate_assets(args.target, config.get("enumeration", {}))
    subdomains = assets.get("subdomains", [])
    ips = assets.get("ips", [])
    logging.info(f"Discovered {len(subdomains)} subdomains and {len(ips)} IPs.")

    # 2. Scanning
    logging.info("Starting port & service scans...")
    scan_results = scan_assets(assets, config.get("scan", {}))
    logging.info(f"Scan complete: {len(scan_results)} results.")

    # 3. Report Generation
    logging.info("Generating report...")
    report_path = generate_report(scan_results, config.get("report", {}))
    logging.info(f"Report successfully written to: {report_path}")


if __name__ == "__main__":
    main()
