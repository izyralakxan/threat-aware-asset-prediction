"""
Live vulnerability data store (data/live/).

The research datasets in data/processed/ stay frozen so the reported
evaluation can be reproduced exactly. Live sync writes only here, and
this module lays the live updates over the frozen data whenever the
dashboard or the alert check needs current information.

Files
  nvd_updates.csv        latest version of every CVE new or changed since the snapshot
  cpe_updates.csv.gz     affected-product ranges of those CVEs
  scoring_updates.csv    model features of those CVEs
  kev_latest.csv         the full current CISA KEV catalogue
  new_cves.csv           newly published CVEs from the last sync, with risk scores
  alerts.csv             every alert raised (one row per asset and CVE)
  sync_log.csv           one row per sync run
  sync_state.json        bookmark: where the next sync starts
"""

import json
from pathlib import Path

import pandas as pd

LIVE_DIR = Path("data/live")

NVD_UPDATES = LIVE_DIR / "nvd_updates.csv"
CPE_UPDATES = LIVE_DIR / "cpe_updates.csv.gz"
SCORING_UPDATES = LIVE_DIR / "scoring_updates.csv"
KEV_LATEST = LIVE_DIR / "kev_latest.csv"
NEW_CVES = LIVE_DIR / "new_cves.csv"
ALERTS = LIVE_DIR / "alerts.csv"
SYNC_LOG = LIVE_DIR / "sync_log.csv"
STATE = LIVE_DIR / "sync_state.json"


def read_state():
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_state(state):
    LIVE_DIR.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def read_csv(path, **kwargs):
    return pd.read_csv(path, **kwargs) if Path(path).exists() else None


def apply_live_updates(reference):
    """
    Lays live updates over the frozen reference data (cve_info,
    cpe_matches, scoring) in place. Does nothing if no sync has run.
    """
    updates = read_csv(NVD_UPDATES)
    kev = read_csv(KEV_LATEST, usecols=["cve_id", "date_added"])

    if updates is None and kev is None:
        reference["live"] = None
        return reference

    if updates is not None:
        changed = set(updates["cve_id"])
        valid = updates[updates["vuln_status"] != "Rejected"]

        # CVE facts: replace changed records, drop rejected ones
        info = valid[["cve_id", "published_date", "cvss_score", "cvss_severity",
                      "attack_vector"]].copy()
        info["published_date"] = pd.to_datetime(info["published_date"]).dt.normalize()
        base = reference["cve_info"]
        reference["cve_info"] = pd.concat(
            [base[~base["cve_id"].isin(changed)], info], ignore_index=True)

        # Affected-product ranges
        cpe = read_csv(CPE_UPDATES, dtype=str)
        base = reference["cpe_matches"]
        reference["cpe_matches"] = pd.concat(
            [base[~base["cve_id"].isin(changed)]] + ([cpe] if cpe is not None else []),
            ignore_index=True)

        # Model features
        scoring = read_csv(SCORING_UPDATES)
        base = reference["scoring"]
        reference["scoring"] = pd.concat(
            [base[~base["cve_id"].isin(changed)]]
            + ([scoring[base.columns.intersection(scoring.columns)]] if scoring is not None else []),
            ignore_index=True)

    # Current KEV status for every CVE
    info = reference["cve_info"]
    if kev is not None:
        dates = pd.to_datetime(kev.set_index("cve_id")["date_added"])
        mapped = info["cve_id"].map(dates)
        info["kev_date_added"] = mapped.where(mapped.notna(), info.get("kev_date_added"))
        info["kev_date_added"] = pd.to_datetime(info["kev_date_added"])
        reference["cve_info"] = info

    state = read_state()
    reference["live"] = {"last_sync": state.get("last_run"),
                         "nvd_changes": 0 if updates is None else len(updates),
                         "kev_entries": 0 if kev is None else len(kev)}
    return reference
