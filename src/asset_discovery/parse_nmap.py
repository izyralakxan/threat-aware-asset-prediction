"""
Parses Nmap XML output (nmap -sV -oX scan.xml <targets>) into one row
per discovered service and CPE.

Run from the project root:
    python -m src.asset_discovery.parse_nmap <scan.xml>
"""

import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import pandas as pd

COLUMNS = [
    "scan_time", "ip_address", "hostname", "port", "protocol", "service",
    "product", "version", "cpe", "part", "vendor", "cpe_product", "cpe_version",
]


def parse_cpe22(cpe):
    # Nmap reports CPE 2.2 URIs: cpe:/a:vendor:product:version
    fields = cpe[len("cpe:/"):].split(":") if cpe.startswith("cpe:/") else []
    fields += [None] * (4 - len(fields))
    part, vendor, product, version = fields[:4]
    return {"part": part, "vendor": vendor, "cpe_product": product,
            "cpe_version": version or None}


def parse_nmap_xml(path):
    root = ET.parse(path).getroot()

    scan_time = datetime.fromtimestamp(int(root.get("start")), tz=timezone.utc)
    rows = []

    for host in root.findall("host"):

        if host.find("status").get("state") != "up":
            continue

        address = host.find("address[@addrtype='ipv4']")
        hostname = host.find("hostnames/hostname")

        for port in host.findall("ports/port"):

            if port.find("state").get("state") != "open":
                continue

            service = port.find("service")
            service = service if service is not None else ET.Element("service")

            base = {
                "scan_time": scan_time,
                "ip_address": address.get("addr") if address is not None else None,
                "hostname": hostname.get("name") if hostname is not None else None,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": service.get("name"),
                "product": service.get("product"),
                "version": service.get("version"),
            }

            cpes = [element.text for element in service.findall("cpe")]

            if not cpes:
                rows.append({**base, "cpe": None, **parse_cpe22("")})

            for cpe in cpes:
                rows.append({**base, "cpe": cpe, **parse_cpe22(cpe)})

    return pd.DataFrame(rows, columns=COLUMNS)


if __name__ == "__main__":
    pd.set_option("display.width", 200)
    print(parse_nmap_xml(sys.argv[1]).drop(columns=["scan_time"]).to_string(index=False))
