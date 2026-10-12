"""
Reads the lab environment database in the same shape as a parsed Nmap
scan, so lab snapshots and real scans share one assessment pipeline.
"""

import sqlite3
from pathlib import Path

import pandas as pd

from src.asset_discovery.parse_nmap import COLUMNS, parse_cpe22

DB_FILE = Path("data/lab/lab_environment.db")


def list_snapshots(db_file=DB_FILE):
    with sqlite3.connect(db_file) as db:
        return pd.read_sql("SELECT * FROM snapshots ORDER BY snapshot_date", db)


def load_topology(db_file=DB_FILE):
    """Returns (segments, firewall rules, trust links) for attack-path analysis."""
    with sqlite3.connect(db_file) as db:
        return (pd.read_sql("SELECT * FROM segments", db),
                pd.read_sql("SELECT * FROM firewall_rules", db),
                pd.read_sql("SELECT * FROM trust_links", db))


def load_snapshot(snapshot_id, db_file=DB_FILE):
    """Returns (services, inventory, snapshot date)."""
    with sqlite3.connect(db_file) as db:
        snapshot = pd.read_sql(
            "SELECT * FROM snapshots WHERE snapshot_id = ?", db, params=[snapshot_id])
        inventory = pd.read_sql("SELECT * FROM assets", db)
        software = pd.read_sql(
            "SELECT * FROM software WHERE snapshot_id = ?", db, params=[snapshot_id])

    if snapshot.empty:
        raise ValueError(f"Unknown snapshot: {snapshot_id}")

    snapshot_date = pd.Timestamp(snapshot["snapshot_date"].iloc[0])

    services = software.merge(
        inventory[["asset_id", "ip_address", "hostname"]], on="asset_id")

    # Real scans can contain services Nmap could not identify (no CPE)
    cpe = pd.DataFrame(services["cpe"].fillna("").map(parse_cpe22).tolist(),
                       index=services.index)
    services = pd.concat([services, cpe], axis=1)
    services["scan_time"] = snapshot_date.tz_localize("UTC")

    return services[COLUMNS + ["source"]], inventory, snapshot_date
