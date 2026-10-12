"""
Network layout for the attack-path analysis of a scanned network.

A scan shows devices and their services, not firewalls, so the layout is
derived with stated assumptions:
  zones      one per /24 subnet; internet-facing devices (from the
             importance settings) form their own zone in that subnet
  firewall   the internal network is flat: every zone reaches every other
             zone on any port (worst case, typical of small offices)
             The internet reaches internet-facing zones only.
  trust      optional links from config (stored credentials, admin logons),
             e.g. config/virtualbox_lab/trust_links.csv
  important  devices of High business importance are the "crown jewels"
"""

import ipaddress
from pathlib import Path

import pandas as pd

from src.attack_paths.attack_graph import INTERNET

TRUST_COLUMNS = ["source_asset", "target_asset", "link_type", "probability", "description"]


def zone(ip, exposed):
    subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
    return f"{subnet} internet-facing" if str(exposed) == "Yes" else str(subnet)


def scan_topology(assets, trust_file=None):
    """(inventory, rules, trusts, segments_table) in the attack graph's format."""
    inventory = assets[assets["scan_status"] != "Not scanned"][
        ["asset_id", "hostname", "ip_address", "asset_type", "criticality", "internet_exposed"]].copy()
    # Devices missing from the inventory get a stable id of their own
    unmanaged = inventory["asset_id"].isin(["UNMANAGED", None]) | inventory["asset_id"].isna()
    inventory.loc[unmanaged, "asset_id"] = "U-" + inventory.loc[unmanaged, "ip_address"]
    inventory["asset_type"] = inventory["asset_type"].fillna("Unknown device")
    inventory["segment"] = [zone(ip, e) for ip, e in zip(inventory["ip_address"], inventory["internet_exposed"])]
    inventory["crown_jewel"] = (inventory["criticality"] == "High").astype(int)

    segments = sorted(inventory["segment"].unique())
    segments_table = pd.DataFrame({"segment": segments,
                                   "cidr": [s.split()[0] for s in segments]})
    rules = [(a, b, "any", "Flat internal network (assumed)") for a in segments for b in segments]
    rules += [(INTERNET, s, "any", "Internet-facing devices") for s in segments if s.endswith("internet-facing")]
    rules = pd.DataFrame(rules, columns=["from_segment", "to_segment", "ports", "description"])

    trusts = pd.DataFrame(columns=TRUST_COLUMNS)
    if trust_file and Path(trust_file).exists():
        trusts = pd.read_csv(trust_file)
        trusts = trusts[trusts["source_asset"].isin(inventory["asset_id"])
                        & trusts["target_asset"].isin(inventory["asset_id"])]
    return inventory, rules, trusts, segments_table
