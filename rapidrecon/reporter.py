# rapidrecon/rapidrecon/reporter.py
"""
Report Generation Module for RapidRecon
- Outputs JSON and HTML reports based on scan results
- Uses Jinja2 templating for a clean, informative HTML layout
"""
import os
import json
import logging
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

def generate_report(scan_results, report_cfg):
    """
    Generate JSON and/or HTML reports from scan_results.
    Returns path(s) to generated report files.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d_%H%M%SZ")
    generated = datetime.utcnow().isoformat() + "Z"

    out_dir = Path(report_cfg.get("directory", "reports"))
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []

    if "json" in report_cfg.get("output", {}).get("formats", []):
        json_cfg = report_cfg.get("json", {})
        json_name = json_cfg.get("filename", f"report_{now}.json")
        json_path = out_dir / json_name
        with open(json_path, "w") as jf:
            json.dump({"generated": generated, "results": scan_results}, jf, indent=2)
        paths.append(str(json_path))
        logging.info(f"Written JSON report: {json_path}")

    if "html" in report_cfg.get("output", {}).get("formats", []):
        html_cfg = report_cfg.get("html", {})
        template_name = html_cfg.get("template", "report.html")
        env = Environment(
            loader=FileSystemLoader(Path(__file__).parent.parent / "templates"),
            autoescape=True
        )
        template = env.get_template(template_name)
        html_content = template.render(results=scan_results, generated=generated)

        html_filename = f"report_{now}.html"
        html_path = out_dir / html_filename
        with open(html_path, "w") as hf:
            hf.write(html_content)
        paths.append(str(html_path))
        logging.info(f"Written HTML report: {html_path}")

    return paths
