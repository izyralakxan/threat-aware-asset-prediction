"""
Builds the SYNTHETIC sample lab environment database.

A fictional mid-sized organisation (DMZ, servers, workstations,
management network) used until the VMware lab exists. Nothing here
describes a real organisation.

Installed versions are not invented: each asset has a patch-hygiene
profile (how far behind it is), and every product's version is the
real NVD fixed version as of (snapshot date - patch lag). So a
"lagging" asset runs exactly the version a host patched 9 months
earlier would run.

Two snapshots:
  backtest  2025-08-27  (KEV follow-up available for the next 12 months)
  current   2026-10-03

Run from the project root:
    python -m src.lab.build_lab_db

Output: data/lab/lab_environment.db (SQLite)
"""

import re
import sqlite3
from pathlib import Path

import pandas as pd

from src.asset_exposure.versions import next_version, version_key

DB_FILE = Path("data/lab/lab_environment.db")
CPE_MATCHES_FILE = Path("data/processed/nvd_cpe_matches.csv.gz")
INTEGRATED_FILE = Path("data/processed/nvd_kev_integrated.csv")

SNAPSHOTS = [
    ("backtest", "2025-08-27", "Backtest snapshot: KEV follow-up to 2026-08-27"),
    ("current", "2026-10-03", "Current snapshot"),
]

# Days behind the snapshot date that each profile's patch level reflects
PATCH_LAG_DAYS = {"current": 30, "typical": 120, "lagging": 270, "neglected": 540}

SEGMENTS = [
    ("DMZ", "10.10.10.0/24", "Internet-facing services", "Yes"),
    ("SERVERS", "10.10.20.0/24", "Internal server network", "No"),
    ("WORKSTATIONS", "10.10.30.0/24", "Employee endpoints", "No"),
    ("MGMT", "10.10.99.0/24", "Network management", "No"),
]

# Software: (vendor, product, branch prefix, display name, port, service)
# Branch prefix pins the release line (e.g. FortiOS 7.2.x). Port None =
# installed software reported by endpoint inventory, not a network service.
FORTIOS = ("fortinet", "fortios", "7.2.", "FortiOS", 443, "https")
NETSCALER = ("citrix", "netscaler_application_delivery_controller", "14.1-", "NetScaler ADC", 443, "https")
CISCO_ASA = ("cisco", "adaptive_security_appliance_software", "9.18.", "Cisco ASA", 443, "https")
APACHE = ("apache", "http_server", "2.4.", "Apache httpd", 443, "https")
NGINX = ("f5", "nginx", "1.", "nginx", 443, "https")
PHP = ("php", "php", "8.2.", "PHP", None, None)
OPENSSH = ("openbsd", "openssh", "", "OpenSSH", 22, "ssh")
ROUNDCUBE = ("roundcube", "webmail", "1.6.", "Roundcube Webmail", 443, "https")
MOVEIT = ("progress", "moveit_transfer", "2024.", "MOVEit Transfer", 443, "https")
CONFLUENCE = ("atlassian", "confluence_data_center", "8.5.", "Confluence Data Center", 8090, "http")
GITLAB = ("gitlab", "gitlab", "17.", "GitLab", 443, "https")
MYSQL = ("oracle", "mysql", "8.0.", "MySQL", 3306, "mysql")
POSTGRES = ("postgresql", "postgresql", "15.", "PostgreSQL", 5432, "postgresql")
TOMCAT = ("apache", "tomcat", "9.0.", "Apache Tomcat", 8080, "http")
JENKINS = ("jenkins", "jenkins", "2.", "Jenkins", 8080, "http")
GRAFANA = ("grafana", "grafana", "", "Grafana", 3000, "http")
BIND = ("isc", "bind", "9.18.", "ISC BIND", 53, "domain")
SAMBA = ("samba", "samba", "4.", "Samba", 445, "microsoft-ds")
SHAREPOINT = ("microsoft", "sharepoint_server", "16.0.", "SharePoint Server", 443, "https")
WS2022 = ("microsoft", "windows_server_2022", "10.0.20348.", "Windows Server 2022", 445, "microsoft-ds")
WS2019 = ("microsoft", "windows_server_2019", "10.0.17763.", "Windows Server 2019", 445, "microsoft-ds")
WIN11 = ("microsoft", "windows_11_23h2", "10.0.22631.", "Windows 11 23H2", None, None)
WIN10 = ("microsoft", "windows_10_22h2", "10.0.19045.", "Windows 10 22H2", None, None)
CHROME = ("google", "chrome", "", "Google Chrome", None, None)
FIREFOX = ("mozilla", "firefox", "", "Mozilla Firefox", None, None)
SEVENZIP = ("7-zip", "7-zip", "", "7-Zip", None, None)
WINRAR = ("rarlab", "winrar", "", "WinRAR", None, None)

OS_NAMES = {WS2022: "Windows Server 2022", WS2019: "Windows Server 2019",
            WIN11: "Windows 11", WIN10: "Windows 10"}

# (asset_id, hostname, segment, host number, type, criticality, hygiene, software)
ASSETS = [
    # DMZ
    ("L001", "fw-edge-01", "DMZ", 1, "Firewall / SSL-VPN", "High", "typical", [FORTIOS]),
    ("L002", "adc-vpn-01", "DMZ", 2, "Application Delivery / VPN", "High", "lagging", [NETSCALER]),
    ("L003", "web-01", "DMZ", 10, "Web Server", "High", "typical", [APACHE, OPENSSH]),
    ("L004", "web-02", "DMZ", 11, "Web Server", "Medium", "lagging", [NGINX, PHP, OPENSSH]),
    ("L005", "webmail-01", "DMZ", 20, "Mail Server", "High", "lagging", [ROUNDCUBE, NGINX]),
    ("L006", "mft-01", "DMZ", 30, "File Transfer Server", "High", "typical", [MOVEIT, WS2022]),
    ("L007", "wiki-ext-01", "DMZ", 40, "Collaboration Server", "Medium", "neglected", [CONFLUENCE, OPENSSH]),
    ("L008", "git-01", "DMZ", 50, "Source Code Server", "High", "typical", [GITLAB, OPENSSH]),
    # Internal servers
    ("L010", "dc-01", "SERVERS", 10, "Domain Controller", "High", "current", [WS2022]),
    ("L011", "dc-02", "SERVERS", 11, "Domain Controller", "High", "typical", [WS2019]),
    ("L012", "file-01", "SERVERS", 20, "File Server", "High", "lagging", [WS2019]),
    ("L013", "sp-01", "SERVERS", 21, "Intranet (SharePoint)", "Medium", "typical", [SHAREPOINT, WS2022]),
    ("L014", "db-01", "SERVERS", 30, "Database Server", "High", "typical", [MYSQL, OPENSSH]),
    ("L015", "db-02", "SERVERS", 31, "Database Server", "High", "lagging", [POSTGRES, OPENSSH]),
    ("L016", "app-01", "SERVERS", 40, "Application Server", "Medium", "lagging", [TOMCAT, OPENSSH]),
    ("L017", "ci-01", "SERVERS", 41, "Build Server", "Medium", "neglected", [JENKINS, OPENSSH]),
    ("L018", "mon-01", "SERVERS", 42, "Monitoring Server", "Low", "typical", [GRAFANA, OPENSSH]),
    ("L019", "dns-01", "SERVERS", 53, "DNS Server", "High", "current", [BIND, OPENSSH]),
    ("L020", "nas-01", "SERVERS", 60, "Backup / NAS", "High", "neglected", [SAMBA, OPENSSH]),
    # Management
    ("L030", "fw-core-01", "MGMT", 1, "Internal Firewall", "High", "typical", [CISCO_ASA]),
    # Workstations (software reported by endpoint inventory)
    ("L101", "ws-fin-01", "WORKSTATIONS", 101, "Workstation", "Medium", "current", [WIN11, CHROME, SEVENZIP]),
    ("L102", "ws-fin-02", "WORKSTATIONS", 102, "Workstation", "Medium", "current", [WIN11, CHROME, WINRAR]),
    ("L103", "ws-hr-01", "WORKSTATIONS", 103, "Workstation", "Medium", "typical", [WIN11, FIREFOX, SEVENZIP]),
    ("L104", "ws-hr-02", "WORKSTATIONS", 104, "Workstation", "Low", "typical", [WIN10, CHROME]),
    ("L105", "ws-dev-01", "WORKSTATIONS", 105, "Developer Workstation", "Medium", "current", [WIN11, CHROME, FIREFOX, SEVENZIP]),
    ("L106", "ws-dev-02", "WORKSTATIONS", 106, "Developer Workstation", "Medium", "typical", [WIN11, FIREFOX, WINRAR]),
    ("L107", "ws-ops-01", "WORKSTATIONS", 107, "Workstation", "Medium", "lagging", [WIN10, CHROME, WINRAR]),
    ("L108", "ws-exec-01", "WORKSTATIONS", 108, "Executive Workstation", "High", "current", [WIN11, CHROME]),
    ("L109", "ws-reception", "WORKSTATIONS", 109, "Shared Workstation", "Low", "neglected", [WIN10, CHROME, SEVENZIP]),
    ("L110", "ws-it-01", "WORKSTATIONS", 110, "Admin Workstation", "High", "typical", [WIN11, CHROME, FIREFOX, WINRAR]),
]


# ==============================
# Network topology (design assumptions for the attack-path analysis)
# ==============================

# Assets whose compromise matters most: identity, data, backups, source code
CROWN_JEWELS = {"L010", "L011", "L012", "L014", "L015", "L020", "L008"}

# Which subnet may reach which, on which TCP ports. "any" = all ports;
# "client" = content reaching client software (web browsing, email
# attachments), i.e. phishing and drive-by attacks on workstations.
FIREWALL_RULES = [
    ("INTERNET", "DMZ", "80,443,8090", "Public web services"),
    ("INTERNET", "WORKSTATIONS", "client", "Malicious web content and email attachments"),
    ("DMZ", "DMZ", "any", "Flat DMZ"),
    ("DMZ", "SERVERS", "53,3306,5432,8080", "Web tier to databases, applications and DNS"),
    ("WORKSTATIONS", "WORKSTATIONS", "135,445", "Flat workstation network (file sharing, RPC)"),
    ("WORKSTATIONS", "SERVERS", "53,135,443,445,3000,8080", "Users to domain, files, intranet and apps"),
    ("SERVERS", "SERVERS", "any", "Flat server network"),
    ("MGMT", "DMZ", "any", "Management network administers everything"),
    ("MGMT", "SERVERS", "any", "Management network administers everything"),
    ("MGMT", "WORKSTATIONS", "any", "Management network administers everything"),
]

# Relationships an attacker can use after a compromise, with the assumed
# probability that the link can be abused: (source, target, type, p, why)
TRUST_LINKS = [
    ("L016", "L014", "Stored credentials", 0.9, "app-01 holds the MySQL password for db-01"),
    ("L016", "L015", "Stored credentials", 0.9, "app-01 holds the PostgreSQL password for db-02"),
    ("L004", "L014", "Stored credentials", 0.9, "The PHP site on web-02 connects to db-01"),
    ("L006", "L012", "Service account", 0.8, "MOVEit service account can write to file-01 shares"),
    ("L017", "L008", "CI credentials", 0.9, "Jenkins holds GitLab deploy tokens"),
    ("L017", "L016", "CI credentials", 0.9, "Jenkins deploys builds to app-01"),
    ("L018", "L014", "Monitoring credentials", 0.6, "Grafana reads metrics from db-01"),
    ("L018", "L015", "Monitoring credentials", 0.6, "Grafana reads metrics from db-02"),
    ("L020", "L014", "Backup copies", 0.6, "nas-01 stores database backups of db-01"),
    ("L020", "L012", "Backup copies", 0.6, "nas-01 stores backups of file-01"),
    ("L110", "L010", "Admin logon", 0.8, "Domain admins log on from ws-it-01"),
    ("L110", "L011", "Admin logon", 0.8, "Domain admins log on from ws-it-01"),
    ("L110", "L030", "Admin logon", 0.7, "Firewall administered from ws-it-01"),
    ("L110", "L001", "Admin logon", 0.7, "Firewall administered from ws-it-01"),
]

# Domain controllers control every domain-joined Windows host (servers and
# workstations; DMZ hosts are not domain-joined)
DOMAIN_CONTROLLERS = ["L010", "L011"]
DOMAIN_SEGMENTS = {"SERVERS", "WORKSTATIONS"}
DOMAIN_ADMIN_P = 0.95


# ==============================
# Version derivation
# ==============================


def fixed_versions(cpe_matches, published):
    """
    (vendor, product) -> DataFrame of fix versions with CVE publish dates.

    "Up to X (excluding)" gives fix version X directly. Vendors such as
    Oracle record "up to X (including)" instead; the next patch release
    after X is used as the fix version.
    """
    excluding = cpe_matches.dropna(subset=["version_end_excluding"])[
        ["cve_id", "vendor", "product", "version_end_excluding"]]

    including = cpe_matches.dropna(subset=["version_end_including"])
    including = including.assign(
        version_end_excluding=including["version_end_including"].map(next_version)
    ).dropna(subset=["version_end_excluding"])[
        ["cve_id", "vendor", "product", "version_end_excluding"]]

    ends = pd.concat([excluding, including]).merge(published, on="cve_id")
    return {key: group for key, group in ends.groupby(["vendor", "product"])}


def version_as_of(fixes, software, patch_date):
    """
    Release a host patched at patch_date runs: the most common fix version
    among the branch's CVEs from the last month before patch_date.

    Not the highest fix: some CVEs are fixed long after publication
    (e.g. CVE-2025-47827, published June 2025, fixed in the October 2025
    Windows build), which would put the host months into the future.
    """
    vendor, product, branch = software[:3]
    group = fixes.get((vendor, product))

    if group is None:
        return None

    group = group[(group["published_date"] <= patch_date)
                  & group["version_end_excluding"].str.startswith(branch)]

    if group.empty:
        return None

    latest = group["published_date"].max()
    recent = group[group["published_date"] > latest - pd.Timedelta(days=31)]

    counts = recent["version_end_excluding"].value_counts()
    most_common = counts[counts == counts.max()].index

    return max(most_common, key=version_key)


# ==============================
# Main
# ==============================

def main():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    print("Loading NVD version ranges...")

    cpe_matches = pd.read_csv(
        CPE_MATCHES_FILE, dtype=str,
        usecols=["cve_id", "vendor", "product", "version_end_excluding",
                 "version_end_including"])

    published = pd.read_csv(INTEGRATED_FILE, usecols=["cve_id", "published_date"])
    published["published_date"] = pd.to_datetime(published["published_date"]).dt.normalize()

    fixes = fixed_versions(cpe_matches, published)

    assets, software, problems = [], [], []

    segment_prefix = {name: cidr.rsplit(".", 1)[0] for name, cidr, _, _ in SEGMENTS}
    segment_exposed = {name: exposed for name, _, _, exposed in SEGMENTS}

    for asset_id, hostname, segment, host, asset_type, criticality, hygiene, stack in ASSETS:

        os_name = next((OS_NAMES[s] for s in stack if s in OS_NAMES), "Linux")

        assets.append({
            "asset_id": asset_id, "hostname": hostname,
            "ip_address": f"{segment_prefix[segment]}.{host}",
            "segment": segment, "asset_type": asset_type,
            "operating_system": os_name, "criticality": criticality,
            "internet_exposed": segment_exposed[segment],
            "patch_hygiene": hygiene,
            "crown_jewel": int(asset_id in CROWN_JEWELS),
        })

        for snapshot_id, snapshot_date, _ in SNAPSHOTS:

            patch_date = pd.Timestamp(snapshot_date) - pd.Timedelta(days=PATCH_LAG_DAYS[hygiene])

            for item in stack:
                vendor, product, _, name, port, service = item
                version = version_as_of(fixes, item, patch_date)

                if version is None:
                    problems.append(f"{asset_id} {vendor}:{product} ({snapshot_id})")
                    continue

                software.append({
                    "snapshot_id": snapshot_id, "asset_id": asset_id,
                    "port": port, "protocol": "tcp" if port else None,
                    "service": service, "product": name, "version": version,
                    "cpe": f"cpe:/{'o' if item in OS_NAMES else 'a'}:{vendor}:{product}:{version}",
                    "source": "network scan" if port else "endpoint inventory",
                })

    if problems:
        print("\nNo version found (software skipped):")
        print("\n".join(f"  {p}" for p in problems))

    # ---- Write database ----

    if DB_FILE.exists():
        DB_FILE.unlink()

    with sqlite3.connect(DB_FILE) as db:

        pd.DataFrame([{
            "key": "notice",
            "value": "SYNTHETIC sample environment for research testing. Not a real "
                     "organisation. Versions derived from NVD fix versions per patch-hygiene "
                     "profile. Firewall rules, trust links and crown jewels are design "
                     "assumptions for the attack-path analysis.",
        }]).to_sql("metadata", db, index=False)

        pd.DataFrame(SEGMENTS, columns=["segment", "cidr", "description", "internet_exposed"]) \
            .to_sql("segments", db, index=False)

        pd.DataFrame(FIREWALL_RULES, columns=["from_segment", "to_segment", "ports", "description"]) \
            .to_sql("firewall_rules", db, index=False)

        domain_links = [
            (dc, a[0], "Domain admin", DOMAIN_ADMIN_P,
             "Domain controllers control every domain-joined Windows host")
            for dc in DOMAIN_CONTROLLERS
            for a in ASSETS
            if a[0] != dc and a[2] in DOMAIN_SEGMENTS and any(s in OS_NAMES for s in a[7])
        ]
        pd.DataFrame(TRUST_LINKS + domain_links,
                     columns=["source_asset", "target_asset", "link_type", "probability", "description"]) \
            .to_sql("trust_links", db, index=False)

        pd.DataFrame(SNAPSHOTS, columns=["snapshot_id", "snapshot_date", "description"]) \
            .assign(source="synthetic") \
            .to_sql("snapshots", db, index=False)

        pd.DataFrame(assets).to_sql("assets", db, index=False)
        pd.DataFrame(software).to_sql("software", db, index=False)

    # ---- Report ----

    software = pd.DataFrame(software)

    print(f"\nDatabase: {DB_FILE}")
    print(f"Assets: {len(assets)}  software rows: {len(software)}")

    pd.set_option("display.width", 200)
    print("\nInstalled versions per snapshot:")
    print(
        software.pivot_table(index=["asset_id", "product"], columns="snapshot_id",
                             values="version", aggfunc="first")
        [[s[0] for s in SNAPSHOTS]].to_string()
    )


if __name__ == "__main__":
    main()
