"""
Business importance of discovered devices (NIST FIPS 199 approach).

Nmap finds devices and software but cannot know how important a device is
to the business. Importance is therefore rated by the user, per device, as
the impact of losing each security objective (FIPS 199):

  Confidentiality   how bad if its data is stolen
  Integrity         how bad if its data or configuration is changed
  Availability      how bad if it stops working

Overall importance = the highest of the three ("high-water mark").

Defaults come from the device type (suggest_cia), so users only adjust the
exceptions. The user's ratings are stored in data/asset_importance.csv, one
row per (network, IP address), and applied to every later assessment:
  network   "lab" for live scans of the VirtualBox lab, otherwise the
            scan file name (each demo organisation is its own network)
"""

from pathlib import Path

import pandas as pd

FILE = Path("data/asset_importance.csv")
LEVELS = ["High", "Medium", "Low"]
CIA = ["confidentiality", "integrity", "availability"]
FIELDS = ["hostname", "asset_type"] + CIA + ["criticality", "internet_exposed"]
COLUMNS = ["network", "ip_address"] + FIELDS
RANK = {"Low": 0, "Medium": 1, "High": 2}

# Default CIA impact by device type: first matching keyword in the device
# type or name wins. H/M/L = High/Medium/Low; documented design defaults.
DEFAULT_RULES = [
    (("domain controller", "dc-"), "HHH"),
    (("database", "db-", "sql"), "HHM"),
    (("file server", "backup", "nas"), "HHM"),
    (("source code", "git", "build", "ci-"), "HHM"),
    (("firewall", "vpn", "remote access", "gateway", "fw-"), "MHH"),
    (("mail",), "HMM"),
    (("dns",), "LHH"),
    (("web",), "MMH"),
    (("executive", "admin workstation", "analyst"), "HML"),
    (("monitoring",), "LML"),
    (("workstation", "laptop", "desktop", "ws-", "pc"), "MLL"),
    (("application", "collaboration", "wiki", "app-"), "MMM"),
]
LETTER = {"H": "High", "M": "Medium", "L": "Low"}


def suggest_cia(asset_type, hostname=""):
    """Default (confidentiality, integrity, availability) for a device type."""
    text = f"{asset_type or ''} {hostname or ''}".lower()
    for keywords, levels in DEFAULT_RULES:
        if any(k in text for k in keywords):
            return tuple(LETTER[c] for c in levels)
    return ("Medium", "Medium", "Medium")


def overall(confidentiality, integrity, availability):
    """FIPS 199 high-water mark: the highest of the three impacts."""
    return max([confidentiality, integrity, availability], key=lambda v: RANK.get(v, 1))


def network_key(scan_name):
    return "lab" if str(scan_name).startswith("scan-") else str(scan_name)


def load(network, path=FILE):
    if not Path(path).exists():
        return pd.DataFrame(columns=COLUMNS)
    table = pd.read_csv(path, dtype=str, keep_default_na=False)
    for column in COLUMNS:                     # files saved before the CIA questionnaire
        if column not in table:
            table[column] = ""
    return table[table["network"] == network][COLUMNS].reset_index(drop=True)


def save(network, edited, path=FILE):
    """Replace this network's rows with the edited table; importance = high-water mark."""
    path = Path(path)
    rows = edited.copy()
    rows["criticality"] = [overall(c, i, a) for c, i, a in zip(*(rows[f] for f in CIA))]
    rows = rows[["ip_address"] + FIELDS].astype(str).assign(network=network)[COLUMNS]
    others = pd.DataFrame(columns=COLUMNS)
    if path.exists():
        others = load_all(path)
        others = others[others["network"] != network]
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.concat([others, rows], ignore_index=True).to_csv(path, index=False)


def load_all(path=FILE):
    table = pd.read_csv(path, dtype=str, keep_default_na=False)
    for column in COLUMNS:
        if column not in table:
            table[column] = ""
    return table[COLUMNS]


def apply(inventory, overrides):
    """Inventory with the user's importance settings applied (adds unknown devices)."""
    if overrides is None or overrides.empty:
        return inventory
    inventory = inventory.copy()
    if "asset_id" not in inventory:
        inventory["asset_id"] = None
    keep = ["hostname", "asset_type", "criticality", "internet_exposed"]
    for row in overrides.itertuples(index=False):
        match = inventory["ip_address"] == row.ip_address
        values = {f: getattr(row, f) for f in keep if getattr(row, f) not in ("", "nan", "None")}
        if match.any():
            for field, value in values.items():
                inventory.loc[match, field] = value
        else:
            inventory = pd.concat([inventory, pd.DataFrame([{
                "asset_id": f"N{row.ip_address.split('.')[-1].zfill(3)}",
                "ip_address": row.ip_address, **values}])], ignore_index=True)
    return inventory
