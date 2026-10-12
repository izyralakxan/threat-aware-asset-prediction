"""
Imports real Nmap scans of the VMware lab into a lab database that the
dashboard and the attack-path analysis read (same schema as the
synthetic lab).

Inputs
  --config   folder with segments.csv, firewall_rules.csv, assets.csv,
             trust_links.csv and manual_software.csv (config/vmware_lab)
  --scans    one or more Nmap XML files (nmap -sV -oX <file> <targets>)
  --snapshot name for this assessment, e.g. scan-2026-10-07

Hosts found in the scans but missing from assets.csv are added as
unmanaged assets (asset_id U-<ip>), placed in a subnet by IP address.
Software Nmap cannot identify can be added in manual_software.csv.

Run from the project root:
    python -m src.lab.import_scans --scans data/lab/scans/*.xml --snapshot scan-2026-10-07
"""

import argparse
import glob
import ipaddress
import sqlite3
from pathlib import Path

import pandas as pd

from src.asset_discovery.parse_nmap import parse_nmap_xml

DEFAULT_CONFIG = Path("config/vmware_lab")
DEFAULT_DB = Path("data/lab/vmware_lab.db")


def segment_of(ip, segments):
    address = ipaddress.ip_address(ip)
    for row in segments.itertuples(index=False):
        if address in ipaddress.ip_network(row.cidr):
            return row.segment
    return "UNKNOWN"


def read_config(folder):
    read = lambda name: pd.read_csv(folder / name, dtype=str).fillna("")
    config = {name: read(f"{name}.csv") for name in
              ["segments", "firewall_rules", "assets", "trust_links", "manual_software"]}
    config["assets"]["crown_jewel"] = config["assets"]["crown_jewel"].replace("", "0").astype(int)
    config["trust_links"]["probability"] = config["trust_links"]["probability"].astype(float)
    return config


def check_config(config):
    problems = []
    segments = config["segments"]
    for row in config["assets"].itertuples(index=False):
        found = segment_of(row.ip_address, segments)
        if found != row.segment:
            problems.append(f"{row.asset_id} {row.ip_address}: listed in {row.segment}, "
                            f"but its IP belongs to {found}")
    known = set(config["assets"]["asset_id"])
    for row in config["trust_links"].itertuples(index=False):
        for asset in (row.source_asset, row.target_asset):
            if asset not in known:
                problems.append(f"trust link refers to unknown asset {asset}")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--scans", nargs="+", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--date", help="assessment date (default: date of the latest scan)")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    args = parser.parse_args()

    config = read_config(args.config)

    problems = check_config(config)
    if problems:
        print("Configuration warnings:")
        print("\n".join(f"  - {p}" for p in problems))

    # ---- Parse scans (shell wildcards are expanded here too, for Windows) ----

    files = sorted({f for pattern in args.scans for f in glob.glob(pattern)})
    if not files:
        raise SystemExit("No scan files found.")

    services = pd.concat([parse_nmap_xml(f) for f in files], ignore_index=True)
    services = services.drop_duplicates(["ip_address", "port", "protocol", "cpe"])

    date = pd.Timestamp(args.date) if args.date else \
        services["scan_time"].max().tz_localize(None).normalize()

    # ---- Assets: inventory plus unmanaged discovered hosts ----

    inventory = config["assets"].copy()
    by_ip = inventory.set_index("ip_address")["asset_id"].to_dict()
    exposure = config["segments"].set_index("segment")["internet_exposed"].to_dict()

    unmanaged = []
    for ip, group in services.groupby("ip_address"):
        if ip in by_ip:
            continue
        segment = segment_of(ip, config["segments"])
        hostname = group["hostname"].dropna()
        unmanaged.append({
            "asset_id": f"U-{ip}", "hostname": hostname.iloc[0] if len(hostname) else ip,
            "ip_address": ip, "segment": segment,
            "asset_type": "Unmanaged (discovered by scan)", "operating_system": "",
            "criticality": "", "internet_exposed": exposure.get(segment, "No"),
            "crown_jewel": 0,
        })
        by_ip[ip] = f"U-{ip}"

    # ---- Software rows for this snapshot ----

    software = pd.DataFrame({
        "snapshot_id": args.snapshot,
        "asset_id": services["ip_address"].map(by_ip),
        "port": services["port"], "protocol": services["protocol"],
        "service": services["service"], "product": services["product"],
        "version": services["version"], "cpe": services["cpe"],
        "source": "nmap scan",
    })

    manual = config["manual_software"]
    if not manual.empty:
        manual = manual.assign(snapshot_id=args.snapshot, source="manual inventory")
        manual["port"] = pd.to_numeric(manual["port"], errors="coerce")
        software = pd.concat([software, manual[software.columns]], ignore_index=True)

    # ---- Write database (snapshots accumulate across imports) ----

    args.db.parent.mkdir(parents=True, exist_ok=True)

    old_snapshots = pd.DataFrame(columns=["snapshot_id", "snapshot_date", "description", "source"])
    old_software = pd.DataFrame(columns=software.columns)
    old_assets = pd.DataFrame(columns=inventory.columns)

    if args.db.exists():
        with sqlite3.connect(args.db) as db:
            old_snapshots = pd.read_sql("SELECT * FROM snapshots", db)
            old_software = pd.read_sql("SELECT * FROM software", db)
            old_assets = pd.read_sql("SELECT * FROM assets", db)

    snapshots = pd.concat([
        old_snapshots[old_snapshots["snapshot_id"] != args.snapshot],
        pd.DataFrame([{"snapshot_id": args.snapshot, "snapshot_date": str(date.date()),
                       "description": f"VMware lab scan: {', '.join(Path(f).name for f in files)}",
                       "source": "nmap"}]),
    ], ignore_index=True)

    software = pd.concat([old_software[old_software["snapshot_id"] != args.snapshot], software],
                         ignore_index=True)

    # Inventory from config wins; unmanaged hosts from earlier scans are kept
    earlier_unmanaged = old_assets[old_assets["asset_id"].astype(str).str.startswith("U-")]
    assets = pd.concat([inventory, earlier_unmanaged, pd.DataFrame(unmanaged)], ignore_index=True)
    assets = assets.drop_duplicates("asset_id", keep="last")

    if args.db.exists():
        args.db.unlink()

    with sqlite3.connect(args.db) as db:
        pd.DataFrame([{"key": "notice", "value": "VMware lab built from real Nmap scans. "
                       "Inventory, firewall rules and trust links come from config/vmware_lab."}]) \
            .to_sql("metadata", db, index=False)
        config["segments"].to_sql("segments", db, index=False)
        config["firewall_rules"].to_sql("firewall_rules", db, index=False)
        config["trust_links"].to_sql("trust_links", db, index=False)
        snapshots.to_sql("snapshots", db, index=False)
        assets.to_sql("assets", db, index=False)
        software.to_sql("software", db, index=False)

    # ---- Report ----

    current = software[software["snapshot_id"] == args.snapshot]
    seen = set(current["asset_id"])
    missing = inventory[~inventory["asset_id"].isin(seen)]

    print(f"\nDatabase: {args.db}  snapshot: {args.snapshot} ({date.date()})")
    print(f"Scan files: {len(files)}  hosts: {services['ip_address'].nunique()}  "
          f"services: {len(current)}")
    print(f"Services without a version (add them to manual_software.csv if known): "
          f"{int(current['version'].isna().sum() + (current['version'] == '').sum())}")
    print(f"Unmanaged hosts found: {len(unmanaged)}"
          + (f" ({', '.join(u['ip_address'] for u in unmanaged)})" if unmanaged else ""))
    if not missing.empty:
        print("Inventory assets not seen in this scan: "
              + ", ".join(f"{r.hostname} ({r.ip_address})" for r in missing.itertuples()))


if __name__ == "__main__":
    main()
