"""
Runs a live Nmap service scan of the isolated VirtualBox lab.

Safety controls
  - only targets inside config/scan_targets.json "allowed_targets" (the
    host-only lab network); anything else is refused before Nmap starts
  - Nmap is started directly (no shell), with a fixed argument list, so a
    target string cannot inject commands
  - unprivileged TCP connect scan: no administrator rights needed
  - time limit (timeout_seconds); the result is saved as Nmap XML in
    data/lab/scans/ and imported by the same parser as uploaded scans

Run from the project root:
    python -m src.asset_discovery.run_nmap [targets]
"""

import ipaddress
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

CONFIG_FILE = Path("config/scan_targets.json")
DEFAULT_NMAP_PATHS = [Path(r"C:\Program Files (x86)\Nmap\nmap.exe"), Path(r"C:\Program Files\Nmap\nmap.exe")]

# Well-known ports plus common server applications outside Nmap's default
# top-1000 list (e.g. Redis 6379, Elasticsearch 9200, MongoDB 27017)
PORTS = ("1-1024,1099,1433,1521,1524,2049,2121,2375,3000,3306,3389,3632,5000,5432,5601,5900,"
         "5985,6000,6379,6667,7001,8000,8009,8080,8081,8180,8443,8888,9000,9090,9200,11211,27017")

PROFILES = {
    # Service and version detection: what the exposure assessment needs
    "full": ["--unprivileged", "-sT", "-sV", "--version-intensity", "7", "-T4", "-p", PORTS,
             "-PS21,22,80,443,445,3306,6379,8080"],
    # Which hosts are up (no services, so nothing to assess)
    "discovery": ["--unprivileged", "-sn", "-T4", "-PS21,22,80,443,445,3306,6379,8080"],
}

TOKEN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})(?:-(\d{1,3}))?$")


def load_config(path=CONFIG_FILE):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def find_nmap(config):
    configured = config.get("nmap_path")
    for candidate in [configured, shutil.which("nmap"), *DEFAULT_NMAP_PATHS]:
        if candidate and Path(candidate).exists():
            return str(candidate)
    return None


def parse_targets(text):
    """
    Target text -> (Nmap tokens, networks covered). Accepts IPv4 addresses,
    CIDR ranges (192.168.56.0/24) and last-octet ranges (192.168.56.101-103),
    separated by spaces or commas. Raises ValueError for anything else.
    """
    tokens, networks = [], []
    for token in [t for t in re.split(r"[,\s]+", text.strip()) if t]:
        if "/" in token:
            network = ipaddress.ip_network(token, strict=False)
            if network.version != 4:
                raise ValueError(f"'{token}' is not an IPv4 range")
            tokens.append(str(network))
            networks.append(network)
            continue
        match = TOKEN.match(token)
        if not match:
            raise ValueError(f"'{token}' is not an IP address, CIDR range or a.b.c.x-y range")
        prefix, first, last = match.group(1), int(match.group(2)), int(match.group(3) or match.group(2))
        if not (0 <= first <= last <= 255):
            raise ValueError(f"'{token}' is not a valid range")
        ipaddress.ip_address(f"{prefix}{first}")      # validates the first three octets
        tokens.append(token)
        networks += [ipaddress.ip_network(f"{prefix}{n}/32") for n in (first, last)]
    if not tokens:
        raise ValueError("enter at least one target")
    return tokens, networks


def target_problems(text, config):
    """Reasons the targets may not be scanned (empty list = allowed)."""
    try:
        _, networks = parse_targets(text)
    except ValueError as error:
        return [str(error)]
    allowed = [ipaddress.ip_network(a) for a in config["allowed_targets"]]
    outside = [str(n) for n in networks if not any(n.subnet_of(a) for a in allowed)]
    return ([f"{', '.join(sorted(set(outside)))} is outside the approved lab ranges "
             f"({', '.join(config['allowed_targets'])})"] if outside else [])


def summarise(xml_path):
    """Hosts up, open services and versioned services in an Nmap XML file."""
    root = ET.parse(xml_path).getroot()
    hosts = [h for h in root.findall("host") if h.find("status").get("state") == "up"]
    ports = [p for h in hosts for p in h.findall("ports/port") if p.find("state").get("state") == "open"]
    versioned = [p for p in ports if p.find("service") is not None and p.find("service").get("version")]
    return {
        "hosts_up": [h.find("address[@addrtype='ipv4']").get("addr") for h in hosts],
        "open_services": len(ports),
        "versioned_services": len(versioned),
    }


def run_scan(targets_text, profile="full", config=None):
    """Runs Nmap; returns (xml path, summary). Raises ValueError or RuntimeError."""
    config = config or load_config()
    problems = target_problems(targets_text, config)
    if problems:
        raise ValueError("; ".join(problems))
    nmap = find_nmap(config)
    if nmap is None:
        raise RuntimeError("Nmap was not found. Install it from nmap.org or set nmap_path in "
                           "config/scan_targets.json")

    tokens, _ = parse_targets(targets_text)
    out_dir = Path(config["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    xml_path = out_dir / f"scan-{datetime.now():%Y%m%d-%H%M%S}-{profile}.xml"

    command = [nmap, *PROFILES[profile], "-oX", str(xml_path), *tokens]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=config["timeout_seconds"])
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"The scan did not finish within {config['timeout_seconds']} seconds")
    if result.returncode != 0 or not xml_path.exists():
        raise RuntimeError(f"Nmap failed: {(result.stderr or result.stdout).strip()[:300]}")

    summary = summarise(xml_path)
    if not summary["hosts_up"]:
        # Nothing to assess: do not keep an empty scan in the scan list
        xml_path.unlink()
        raise RuntimeError("No hosts answered. Check that the lab VMs are running "
                           "(they need about a minute after starting) and scan again")

    return xml_path, summary | {"command": " ".join(["nmap", *PROFILES[profile],
                                                                  "-oX", xml_path.name, *tokens])}


if __name__ == "__main__":
    config = load_config()
    target = sys.argv[1] if len(sys.argv) > 1 else config["default_target"]
    path, summary = run_scan(target, "full", config)
    print(f"Scan saved to {path}")
    print(f"Hosts up: {', '.join(summary['hosts_up']) or 'none'}")
    print(f"Open services: {summary['open_services']} ({summary['versioned_services']} with versions)")
