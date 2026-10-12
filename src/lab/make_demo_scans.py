"""
Builds three DEMO scan sheets for three fictional IT companies, in place
of a VMware lab, at three patch states:

  Zentrova Systems           20 hosts, neglected: about 18 months behind
  Kyvora Cloud Services      14 hosts, a realistic mix of patch levels
  Quantelix Data Solutions   18 hosts, fully patched (no legacy wiki or
                             Windows 10 PC)

The company names are invented and do not describe real organisations.

Versions are not invented. As in the synthetic lab (build_lab_db.py),
each product's version is the real NVD fix version as of
(scan date - patch lag). The sheets are SIMULATED scan results, not
output of a real scan, and must be described that way.

Run from the project root:
    python -m src.lab.make_demo_scans

Output: data/demo_scans/*.csv and scan_sheet_template.csv
"""

from pathlib import Path

import pandas as pd

from src.lab.build_lab_db import (
    APACHE, BIND, CONFLUENCE, CPE_MATCHES_FILE, FORTIOS, GITLAB, GRAFANA, INTEGRATED_FILE, JENKINS,
    MYSQL, NETSCALER, NGINX, OPENSSH, OS_NAMES, PATCH_LAG_DAYS, PHP, POSTGRES, ROUNDCUBE, SAMBA,
    TOMCAT, WIN10, WIN11, WS2019, WS2022, fixed_versions, version_as_of,
)
from src.asset_discovery.parse_scan_sheet import SHEET_COLUMNS
from src.asset_exposure.importance import overall, suggest_cia

OUTPUT_DIR = Path("data/demo_scans")
SCAN_DATE = "2026-10-03"          # latest date covered by the frozen NVD/KEV data

# Windows hosts: Nmap sees SMB on 445; the build number comes from the host
WIN10_SMB = WIN10[:4] + (445, "microsoft-ds")
WIN11_SMB = WIN11[:4] + (445, "microsoft-ds")
PHP_WEB = PHP[:4] + (443, "https")

# (asset_id, hostname, ip, type, OS, criticality, internet, mixed-state hygiene, software)
HOSTS = [
    ("D001", "fw-edge-01", "192.168.10.1", "Firewall / VPN", "FortiOS", "High", "Yes", "typical", [FORTIOS]),
    ("D002", "vpn-01", "192.168.10.2", "Remote Access Gateway", "NetScaler", "High", "Yes", "lagging", [NETSCALER]),
    ("D003", "web-01", "192.168.10.10", "Web Server", "Ubuntu Server", "High", "Yes", "typical", [APACHE, OPENSSH]),
    ("D004", "web-02", "192.168.10.11", "Web Server", "Ubuntu Server", "Medium", "Yes", "lagging", [NGINX, PHP_WEB, OPENSSH]),
    ("D005", "mail-01", "192.168.10.20", "Webmail Server", "Ubuntu Server", "High", "Yes", "lagging", [ROUNDCUBE, OPENSSH]),
    ("D010", "dc-01", "192.168.20.10", "Domain Controller", "Windows Server 2022", "High", "No", "current", [WS2022]),
    ("D011", "file-01", "192.168.20.20", "File Server", "Windows Server 2019", "High", "No", "lagging", [WS2019]),
    ("D012", "db-01", "192.168.20.30", "Database Server", "Ubuntu Server", "High", "No", "typical", [MYSQL, OPENSSH]),
    ("D013", "app-01", "192.168.20.40", "Application Server", "Ubuntu Server", "Medium", "No", "lagging", [TOMCAT, OPENSSH]),
    ("D014", "ci-01", "192.168.20.41", "Build Server", "Ubuntu Server", "Medium", "No", "neglected", [JENKINS, OPENSSH]),
    ("D015", "dns-01", "192.168.20.53", "DNS Server", "Ubuntu Server", "High", "No", "current", [BIND, OPENSSH]),
    ("D016", "mon-01", "192.168.20.60", "Monitoring Server", "Ubuntu Server", "Low", "No", "typical", [GRAFANA, OPENSSH]),
    ("D101", "ws-fin-01", "192.168.30.101", "Workstation", "Windows 11", "Medium", "No", "current", [WIN11_SMB]),
    ("D102", "ws-ops-01", "192.168.30.102", "Workstation", "Windows 10", "Low", "No", "lagging", [WIN10_SMB]),
    # Further hosts seen only in the full scans (demo 1 and demo 3)
    ("D006", "git-01", "192.168.10.30", "Source Code Server", "Ubuntu Server", "High", "Yes", "typical", [GITLAB, OPENSSH]),
    ("D007", "wiki-01", "192.168.10.40", "Collaboration Server", "Ubuntu Server", "Medium", "Yes", "neglected", [CONFLUENCE, OPENSSH]),
    ("D017", "db-02", "192.168.20.31", "Database Server", "Ubuntu Server", "High", "No", "lagging", [POSTGRES, OPENSSH]),
    ("D018", "nas-01", "192.168.20.70", "Backup / NAS", "Ubuntu Server", "High", "No", "neglected", [SAMBA, OPENSSH]),
    ("D103", "ws-hr-01", "192.168.30.103", "Workstation", "Windows 11", "Medium", "No", "typical", [WIN11_SMB]),
    ("D104", "ws-dev-01", "192.168.30.104", "Developer Workstation", "Windows 11", "Medium", "No", "current", [WIN11_SMB]),
]

ALL_HOSTS = [h[0] for h in HOSTS]
FIRST_14 = ALL_HOSTS[:14]
RETIRED = {"D007", "D102"}    # old wiki and the Windows 10 PC, decommissioned during remediation

# Three FICTIONAL IT companies (names invented for the demonstration)
# (file, hygiene for every host or None for each host's own, hosts in the scan)
SCENARIOS = [
    ("demo_scan_1_zentrova_systems.csv", "neglected", ALL_HOSTS),                        # 20 hosts
    ("demo_scan_2_kyvora_cloud_services.csv", None, FIRST_14),                          # 14 hosts
    ("demo_scan_3_quantelix_data_solutions.csv", "patched",
     [h for h in ALL_HOSTS if h not in RETIRED]),                                       # 18 hosts
]
LAG_DAYS = {**PATCH_LAG_DAYS, "patched": 0}


def build_sheet(fixes, hygiene_override, include=None):
    rows = []
    for asset_id, hostname, ip, asset_type, os_name, criticality, internet, hygiene, stack in HOSTS:
        if include is not None and asset_id not in include:
            continue
        # Business importance from the documented FIPS 199 device-type defaults
        criticality = overall(*suggest_cia(asset_type, hostname))
        hygiene = hygiene_override or hygiene
        patch_date = pd.Timestamp(SCAN_DATE) - pd.Timedelta(days=LAG_DAYS[hygiene])
        for item in stack:
            vendor, product, _, name, port, service = item
            version = version_as_of(fixes, item, patch_date)
            if version is None:
                print(f"  no version for {hostname} {vendor}:{product}, skipped")
                continue
            is_os = item[:2] in {s[:2] for s in OS_NAMES}
            rows.append({
                "scan_date": SCAN_DATE, "asset_id": asset_id, "hostname": hostname,
                "ip_address": ip, "asset_type": asset_type, "operating_system": os_name,
                "criticality": criticality, "internet_exposed": internet,
                "port": port or "", "protocol": "tcp" if port else "", "service": service or "",
                "product": name, "version": version,
                "cpe": f"cpe:/{'o' if is_os else 'a'}:{vendor}:{product}:{version}",
            })
    return pd.DataFrame(rows, columns=SHEET_COLUMNS)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading NVD version ranges...")
    cpe_matches = pd.read_csv(
        CPE_MATCHES_FILE, dtype=str,
        usecols=["cve_id", "vendor", "product", "version_end_excluding", "version_end_including"])
    published = pd.read_csv(INTEGRATED_FILE, usecols=["cve_id", "published_date"])
    published["published_date"] = pd.to_datetime(published["published_date"]).dt.normalize()
    fixes = fixed_versions(cpe_matches, published)

    for file_name, hygiene, include in SCENARIOS:
        sheet = build_sheet(fixes, hygiene, include)
        sheet.to_csv(OUTPUT_DIR / file_name, index=False)
        print(f"{file_name}: {sheet['ip_address'].nunique()} hosts, {len(sheet)} services")

    # Blank template: header plus two example rows to copy
    template = build_sheet(fixes, "current").query("hostname in ['web-01', 'ws-fin-01']")
    template.to_csv(OUTPUT_DIR / "scan_sheet_template.csv", index=False)
    print("scan_sheet_template.csv written")


if __name__ == "__main__":
    main()
