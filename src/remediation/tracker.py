"""
Remediation tracking: which recommended fixes are done, verified by rescans.

Every upgrade action the planner recommends is remembered per network. Each
newer scan of that network is compared with the recommendation:

  Completed      the device was scanned and the software now runs a safe
                 version (no longer vulnerable to what the update fixes),
                 or the vulnerable service is no longer running
  Remaining      the scan still shows the vulnerable version
  Not verified   the device was not in the latest scan, or the software still
                 runs but the scan could not read its version (no proof either way)

A fix is never marked done on someone's word: only a scan proves it. A fix
that was completed can be reopened if a later scan shows the problem again.
Older scans never change the record (only scans newer than the last one used).

Unsafe settings found by the scan (src/asset_exposure/misconfig.py) are tracked
the same way (kind "setting"): Completed once a rescan that ran the checks no
longer finds the setting on that device.

Stored in data/remediation_tracker.csv.
"""

from datetime import datetime
from pathlib import Path

import pandas as pd

FILE = Path("data/remediation_tracker.csv")
COLUMNS = ["network", "asset_id", "hostname", "ip_address", "product", "start_version",
           "target_version", "current_version", "deadline", "cves_fixed", "kev_fixed",
           "status", "first_seen", "last_checked", "completed_at", "note", "kind", "fix_step"]
SETTING = "Setting: "          # product name prefix for unsafe-setting rows


def setting_deadlines(scan_time):
    """Fix-by dates for unsafe settings: Critical 1 day, High 7, Medium 30."""
    day = pd.Timestamp(scan_time).normalize()
    return {severity: (day + pd.Timedelta(days=days)).strftime("%Y-%m-%d")
            for severity, days in {"Critical": 1, "High": 7, "Medium": 30, "Low": 90}.items()}


def load_all(path=FILE):
    if not Path(path).exists():
        return pd.DataFrame(columns=COLUMNS)
    table = pd.read_csv(path, dtype=str, keep_default_na=False)
    for column in COLUMNS:
        if column not in table:
            table[column] = ""
    table.loc[table["kind"] == "", "kind"] = "update"
    return table[COLUMNS]


def load(network, path=FILE):
    table = load_all(path)
    return table[table["network"] == network].reset_index(drop=True)


def update(network, scan_time, plan, services, assets, path=FILE, settings=None, settings_checked=False):
    """Record this scan's results for the network; returns the network's fix records.
    settings: unsafe settings found by this scan; settings_checked: the scan ran the checks."""
    from src.asset_exposure.misconfig import SERVICE_CHECKS
    scan_time = pd.Timestamp(scan_time)
    if scan_time.tzinfo is not None:                     # scans are stamped in UTC: show local time
        scan_time = scan_time.tz_convert(datetime.now().astimezone().tzinfo).tz_localize(None)
    scan_time = scan_time.strftime("%Y-%m-%d %H:%M")
    table = load_all(path)
    mine = table[table["network"] == network].copy()
    others = table[table["network"] != network]

    # Viewing an older scan must not undo what a newer scan proved
    if not mine.empty and scan_time < mine["last_checked"].max():
        return mine.reset_index(drop=True)

    SETTING_DEADLINE = setting_deadlines(scan_time)
    key = lambda ip, product: f"{ip}|{product}"
    rows = {key(r["ip_address"], r["product"]): r.to_dict() for _, r in mine.iterrows()}
    recommended = set()

    for a in (plan.itertuples(index=False) if not plan.empty else []):
        k = key(a.ip_address, a.product)
        recommended.add(k)
        row = rows.get(k)
        if row is None:
            rows[k] = {"network": network, "asset_id": a.asset_id, "hostname": a.hostname,
                       "ip_address": a.ip_address, "product": a.product,
                       "start_version": a.installed_version, "first_seen": scan_time,
                       "completed_at": "", "note": ""}
            row = rows[k]
        elif row["status"] == "Completed":
            row["note"] = "Reopened: a later scan shows it is vulnerable again"
            row["completed_at"] = ""
        row.update(target_version=a.target_version, current_version=a.installed_version,
                   deadline=a.deadline, cves_fixed=str(a.cves_fixed), kev_fixed=str(a.kev_fixed),
                   status="Remaining", last_checked=scan_time, kind="update", fix_step="")

    names = assets.set_index("ip_address")[["asset_id", "hostname"]].to_dict("index")
    for s in (settings.itertuples(index=False) if settings is not None and not settings.empty else []):
        k = key(s.ip_address, SETTING + s.check)
        recommended.add(k)
        row = rows.get(k)
        if row is None:
            device = names.get(s.ip_address, {})
            rows[k] = {"network": network, "asset_id": device.get("asset_id", ""),
                       "hostname": device.get("hostname") or s.ip_address, "ip_address": s.ip_address,
                       "product": SETTING + s.check, "start_version": "", "target_version": "",
                       "first_seen": scan_time, "completed_at": "", "note": "",
                       "cves_fixed": "0", "kev_fixed": "0"}
            row = rows[k]
        elif row["status"] == "Completed":
            row["note"] = "Reopened: a later scan found this unsafe setting again"
            row["completed_at"] = ""
        row.update(current_version="",                  # the fix-by date counts from first found
                   deadline=row.get("deadline") or SETTING_DEADLINE.get(s.severity, ""),
                   status="Remaining", last_checked=scan_time, kind="setting",
                   fix_step=f"{s.finding} (port {s.ports}). {s.fix}")

    scanned = set(assets.loc[assets["scan_status"] != "Not scanned", "ip_address"])
    for k, row in rows.items():
        if k in recommended or (row["status"] == "Completed" and row["current_version"]):
            continue
        if row["ip_address"] not in scanned:
            row.update(status="Not verified", note="Device was not in the latest scan",
                       last_checked=scan_time)
            continue
        if row.get("kind") == "setting":
            if row["status"] == "Completed":
                continue
            if settings_checked or row["product"][len(SETTING):] in SERVICE_CHECKS:
                row.update(status="Completed", completed_at=scan_time, last_checked=scan_time,
                           note="Verified by scan: the unsafe setting is gone")
            continue
        running = services[(services["ip_address"] == row["ip_address"])
                           & (services["product"] == row["product"])]
        version = next((str(v) for v in running["version"] if isinstance(v, str) and v), "")
        if not running.empty and not version:
            # Still running, but the scan could not read its version: no proof either way
            row.update(status="Not verified", last_checked=scan_time, current_version="",
                       note="Still running, but the scan could not read its version: rescan or "
                            "check the version manually")
            continue
        row.update(status="Completed", completed_at=row.get("completed_at") or scan_time,
                   last_checked=scan_time,
                   current_version=version,
                   note=(f"Verified by scan: now running {version}" if not running.empty
                         else "Verified by scan: the vulnerable service is no longer running"))

    result = pd.DataFrame(list(rows.values()), columns=COLUMNS).fillna("")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.concat([others, result], ignore_index=True).to_csv(path, index=False)
    return result.reset_index(drop=True)
