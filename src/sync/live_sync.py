"""
Live vulnerability sync and alerting (the "watchman").

Each run:
  1. downloads the current CISA KEV catalogue and finds new entries
  2. asks the NVD CVE API 2.0 for CVEs new or changed since the last run
  3. stores them in data/live/ (research data in data/processed stays frozen)
  4. builds model features for them and scores them with the trained model
  5. assesses the monitored assets as of today
  6. raises alerts:
       URGENT   a newly KEV-listed CVE affects an asset (deadline from KEV)
       WARNING  a new or changed CVE in the top risk tier affects an asset
       INFO     the model is old enough to need retraining

Alerts go to data/live/alerts.csv and the console, and optionally to an
email address and a Teams/Slack/Discord webhook (environment variables):
  NVD_API_KEY                                   free key, raises the NVD rate limit
  ALERT_WEBHOOK_URL                             incoming webhook URL
  SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD ALERT_EMAIL_TO

Run from the project root (Windows Task Scheduler can run it every 6 hours):
    python -m src.sync.live_sync
"""

import json
import os
import smtplib
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

import pandas as pd

from src.asset_exposure.assess_exposure import (
    ACTIVE_MODEL_FILE, CONFIRMED, RISK_MODEL_FILE, assess_services, load_reference_data,
)
from src.data_collection.extract_cpe_matches import FIELDS as CPE_FIELDS, iter_matches
from src.data_collection.extract_kev import kev_row
from src.data_collection.extract_nvd import FIELDNAMES as NVD_FIELDS, cve_row
from src.features.build_features import SCORING_FILE, SCORING_START, add_features, load_history
from src.lab.lab_db import list_snapshots, load_snapshot
from src.models.calibrate import assign_tiers
from src.models.train_models import prepare_features
from src.sync import live_store as store

CONFIG_FILE = Path("config/live_sync.json")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FROZEN_NVD = Path("data/processed/nvd_clean.csv")
FROZEN_KEV = Path("data/processed/cisa_kev_clean.csv")

USER_AGENT = "ThreatAwareAssetPrediction/1.0 (final-year research project)"
NVD_PAGE = 2000
NVD_MAX_WINDOW_DAYS = 120   # NVD API limit for one date range


# ==============================
# Downloads
# ==============================

def http_json(url, headers=None, attempts=4):
    """GET a JSON document, retrying on rate limits and server errors."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code in (403, 429, 500, 502, 503) and attempt < attempts - 1:
                wait = 15 * (attempt + 1)
                print(f"  NVD/CISA returned {error.code}; retrying in {wait}s")
                time.sleep(wait)
                continue
            raise
        except urllib.error.URLError:
            if attempt < attempts - 1:
                time.sleep(15 * (attempt + 1))
                continue
            raise


def fetch_kev():
    data = http_json(KEV_URL)
    return pd.DataFrame([kev_row(v) for v in data["vulnerabilities"]])


def nvd_time(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def fetch_nvd_changes(start, end):
    """All CVE records modified between start and end (UTC datetimes)."""
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    pause = 1.0 if api_key else 6.5          # NVD: 50 or 5 requests per 30 seconds

    records = []
    window_start = start
    while window_start < end:
        window_end = min(end, window_start + timedelta(days=NVD_MAX_WINDOW_DAYS))
        index, total = 0, None
        while total is None or index < total:
            query = urllib.parse.urlencode({
                "lastModStartDate": nvd_time(window_start),
                "lastModEndDate": nvd_time(window_end),
                "resultsPerPage": NVD_PAGE, "startIndex": index,
            })
            page = http_json(f"{NVD_API}?{query}", headers)
            total = page.get("totalResults", 0)
            records.extend(item["cve"] for item in page.get("vulnerabilities", []))
            index += NVD_PAGE
            print(f"  NVD: {min(index, total)}/{total} changed records "
                  f"({window_start:%Y-%m-%d} to {window_end:%Y-%m-%d})")
            time.sleep(pause)
        window_start = window_end
    return records


# ==============================
# Updating the live store
# ==============================

def merge_latest(old, new, key="cve_id"):
    if old is None or old.empty:
        return new
    return pd.concat([old[~old[key].isin(new[key])], new], ignore_index=True)


def build_scoring_rows(updates, kev):
    """Model features for updated CVEs, computed exactly as for training."""
    history = load_history()

    # History must include the updated records and the current KEV dates
    from src.features.build_features import split_values
    fresh = updates[["cve_id", "published_date", "vendor", "cwe"]].copy()
    fresh["published_date"] = pd.to_datetime(fresh["published_date"]).dt.normalize()
    fresh["vendor_list"] = split_values(fresh["vendor"])
    fresh["cwe_list"] = split_values(fresh["cwe"])
    history = pd.concat([history[~history["cve_id"].isin(fresh["cve_id"])], fresh],
                        ignore_index=True)
    kev_dates = pd.to_datetime(kev.set_index("cve_id")["date_added"])
    history["kev_date_added"] = history["cve_id"].map(kev_dates)

    rows = updates[updates["vuln_status"] != "Rejected"].copy()
    rows["published_date"] = pd.to_datetime(rows["published_date"]).dt.normalize()
    rows = rows[rows["published_date"] >= SCORING_START]
    rows["kev_date_added"] = rows["cve_id"].map(kev_dates)

    columns = pd.read_csv(SCORING_FILE, nrows=0).columns
    features = add_features(rows.drop(columns=["last_modified", "vuln_status"]), history)
    return features.reindex(columns=columns)


def score_cves(reference, cve_ids):
    """Calibrated probability and risk tier for the given CVEs."""
    columns = ["cve_id", "published_date", "vendor", "product", "cvss_score",
               "attack_vector", "probability", "tier", "in_kev", "description"]
    rows = reference["scoring"][reference["scoring"]["cve_id"].isin(set(cve_ids))]
    rows = rows[rows["nvd_analysed"] == 1] if "nvd_analysed" in rows else rows
    if rows.empty:
        return pd.DataFrame(columns=columns)

    bundle = reference["bundle"]
    probability = bundle["model"].predict_proba(prepare_features(rows))[:, 1]
    kev = reference["cve_info"].set_index("cve_id")["kev_date_added"]

    scored = rows.assign(
        probability=probability,
        tier=assign_tiers(probability, bundle["tier_cutoffs"]),
        in_kev=rows["cve_id"].map(kev).notna(),
        description=rows["description_clean"].str.slice(0, 240),
    )
    return scored[columns].sort_values("probability", ascending=False)


# ==============================
# Alerts
# ==============================

def monitored_targets(config):
    targets = []
    for target in config["targets"]:
        if not Path(target["db"]).exists():
            continue
        snapshot = target["snapshot"]
        if snapshot == "latest":
            snapshot = list_snapshots(target["db"])["snapshot_id"].iloc[-1]
        targets.append({**target, "snapshot": snapshot})
    return targets


def find_alerts(config, reference, new_kev, changed_ids, kev):
    today = pd.Timestamp.now().normalize()
    kev_info = kev.set_index("cve_id")
    alerts = []

    for target in monitored_targets(config):
        services, inventory, _ = load_snapshot(target["snapshot"], target["db"])
        _, _, cves = assess_services(services, inventory, reference, today)
        confirmed = cves[cves["match_confidence"].isin(CONFIRMED)]
        names = inventory.set_index("ip_address")[["asset_id", "hostname"]]

        def record(row, level, reason, deadline):
            asset = names.loc[row["ip_address"]]
            alerts.append({
                "raised_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "level": level, "target": target["name"],
                "asset_id": asset["asset_id"], "hostname": asset["hostname"],
                "cve_id": row["cve_id"], "product": row["product"],
                "installed_version": row["installed_version"],
                "cvss_score": row.get("cvss_score"),
                "probability": row.get("probability"), "tier": row.get("tier"),
                "reason": reason, "deadline": deadline,
            })

        for _, row in confirmed[confirmed["cve_id"].isin(new_kev)].iterrows():
            info = kev_info.loc[row["cve_id"]]
            due = info["due_date"] if isinstance(info["due_date"], str) and info["due_date"] else \
                str((pd.Timestamp(info["date_added"]) + pd.Timedelta(days=config["kev_deadline_days"])).date())
            ransomware = " Used in ransomware campaigns." if info["known_ransomware_campaign_use"] == "Known" else ""
            record(row, "URGENT", f"Added to CISA KEV on {info['date_added']}: "
                                  f"actively exploited.{ransomware}", due)

        warn = confirmed[(confirmed["status"] == "Prediction window")
                         & confirmed["tier"].isin(config["warn_on_tiers"])
                         & confirmed["cve_id"].isin(changed_ids)]
        for _, row in warn.iterrows():
            record(row, "WARNING",
                   f"New or updated CVE in the {row['tier']} risk tier "
                   f"({row['probability']:.1%} predicted exploitation within 12 months)",
                   str((today + pd.Timedelta(days=30)).date()))

    # Age of the last champion/challenger review (or of the research model)
    reviewed = ACTIVE_MODEL_FILE if ACTIVE_MODEL_FILE.exists() else RISK_MODEL_FILE
    model_age = (datetime.now() - datetime.fromtimestamp(reviewed.stat().st_mtime)).days
    if model_age > config["retrain_after_days"]:
        alerts.append({
            "raised_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "level": "INFO",
            "target": "Model", "asset_id": "", "hostname": "", "cve_id": f"retrain-{today:%Y-%m}",
            "product": "", "installed_version": "", "cvss_score": None, "probability": None,
            "tier": None, "reason": f"Risk model last reviewed {model_age} days ago: retrain a "
                                    "challenger (python -m src.models.retrain_operational)",
            "deadline": "",
        })

    return pd.DataFrame(alerts)


LEVEL_ORDER = {"URGENT": 0, "WARNING": 1, "INFO": 2}


def summarise(alerts):
    """One line per CVE (not per asset), most urgent first, to avoid alert fatigue."""
    today = str(pd.Timestamp.now().date())
    lines = []
    grouped = alerts.groupby(["level", "cve_id"], sort=False)
    for (level, cve), group in sorted(grouped, key=lambda g: (LEVEL_ORDER[g[0][0]], g[0][1])):
        first = group.iloc[0]
        hosts = ", ".join(group["hostname"].dropna().astype(str).replace("", first["target"]))
        deadline = first["deadline"] or ""
        overdue = " OVERDUE" if deadline and deadline < today else ""
        product = f" ({first['product']})" if first["product"] else ""
        lines.append(f"[{level}] {cve}{product} affects {len(group)} asset(s): {hosts}. "
                     f"{first['reason']} Deadline: {deadline or 'n/a'}{overdue}")
    return lines


def deliver(alerts):
    text = "Threat-aware exposure alerts\n\n" + "\n".join(summarise(alerts))

    webhook = os.environ.get("ALERT_WEBHOOK_URL")
    if webhook:
        body = json.dumps({"text": text, "content": text[:1900]}).encode()
        request = urllib.request.Request(webhook, data=body,
                                         headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(request, timeout=30)
            print("  Alert sent to webhook")
        except urllib.error.URLError as error:
            print(f"  Webhook failed: {error}")

    host, to = os.environ.get("SMTP_HOST"), os.environ.get("ALERT_EMAIL_TO")
    if host and to:
        message = EmailMessage()
        message["Subject"] = f"[Exposure alert] {len(alerts)} new alert(s)"
        message["From"] = os.environ.get("SMTP_USER", "alerts@localhost")
        message["To"] = to
        message.set_content(text)
        try:
            with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=30) as smtp:
                smtp.starttls()
                if os.environ.get("SMTP_USER"):
                    smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
                smtp.send_message(message)
            print(f"  Alert emailed to {to}")
        except (OSError, smtplib.SMTPException) as error:
            print(f"  Email failed: {error}")


# ==============================
# Main
# ==============================

def main():
    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    store.LIVE_DIR.mkdir(parents=True, exist_ok=True)
    state = store.read_state()
    started = datetime.now(timezone.utc).replace(microsecond=0)
    log = {"run_at": started.strftime("%Y-%m-%d %H:%M UTC"), "status": "ok"}

    try:
        # ---- 1. CISA KEV ----
        print("Checking CISA KEV...")
        kev = fetch_kev()
        previous = store.read_csv(store.KEV_LATEST)
        if previous is None:
            previous = pd.read_csv(FROZEN_KEV)
        new_kev = sorted(set(kev["cve_id"]) - set(previous["cve_id"]))
        kev.to_csv(store.KEV_LATEST, index=False)
        print(f"  KEV entries: {len(kev)}  new since last check: {len(new_kev)}")

        # ---- 2. NVD changes since the bookmark ----
        if "nvd_synced_until" in state:
            since = datetime.fromisoformat(state["nvd_synced_until"])
        else:
            frozen = pd.read_csv(FROZEN_NVD, usecols=["last_modified"])["last_modified"].max()
            since = max(datetime.fromisoformat(frozen).replace(tzinfo=timezone.utc),
                        started - timedelta(days=config["first_sync_max_days"]))
        print(f"Checking NVD for changes since {since:%Y-%m-%d %H:%M} UTC...")
        records = fetch_nvd_changes(since, started)

        changed = pd.DataFrame([cve_row(r) for r in records], columns=NVD_FIELDS) \
            .drop_duplicates("cve_id", keep="last")
        cpe = pd.DataFrame([m for r in records if r.get("vulnStatus") != "Rejected"
                            for m in iter_matches(r)], columns=CPE_FIELDS).drop_duplicates()
        changed_ids = set(changed["cve_id"])

        # ---- 3. Store ----
        updates = merge_latest(store.read_csv(store.NVD_UPDATES), changed)
        updates.to_csv(store.NVD_UPDATES, index=False)

        old_cpe = store.read_csv(store.CPE_UPDATES, dtype=str)
        if old_cpe is not None:
            cpe = pd.concat([old_cpe[~old_cpe["cve_id"].isin(changed_ids)], cpe], ignore_index=True)
        cpe.to_csv(store.CPE_UPDATES, index=False)

        # ---- 4. Features and scores ----
        print("Building features for updated CVEs...")
        build_scoring_rows(updates, kev).to_csv(store.SCORING_UPDATES, index=False)

        reference = load_reference_data(live=True)

        recent_cutoff = pd.Timestamp(started.date()) - pd.Timedelta(days=config["new_cve_days"])
        # Every stored CVE published recently (not only this run's), so a
        # quiet run does not empty the "what's new" list
        new = updates[(updates["vuln_status"] != "Rejected")
                      & (pd.to_datetime(updates["published_date"]) >= recent_cutoff)]
        scored = score_cves(reference, new["cve_id"])
        scored.to_csv(store.NEW_CVES, index=False)

        # ---- 5-6. Assets and alerts ----
        print("Assessing monitored assets...")
        alerts = find_alerts(config, reference, set(new_kev), changed_ids, kev)

        history = store.read_csv(store.ALERTS)
        if history is not None and not alerts.empty:
            seen = set(zip(history["target"], history["asset_id"].fillna(""), history["cve_id"], history["level"]))
            alerts = alerts[[(a.target, a.asset_id, a.cve_id, a.level) not in seen
                             for a in alerts.itertuples()]]
        if not alerts.empty:
            pd.concat([history, alerts] if history is not None else [alerts]) \
                .to_csv(store.ALERTS, index=False)
            deliver(alerts)

        state.update(nvd_synced_until=started.isoformat(), last_run=log["run_at"])
        store.write_state(state)

        log.update(kev_entries=len(kev), kev_new=len(new_kev), nvd_changed=len(changed_ids),
                   nvd_new=int(len(new)), alerts=int(len(alerts)))

        print(f"\nSync complete: {len(new_kev)} new KEV, {len(changed_ids)} NVD changes, "
              f"{len(new)} new CVEs in the last {config['new_cve_days']} days, "
              f"{len(alerts)} new alert(s)")
        if not alerts.empty:
            print("\n".join(f"  {line}" for line in summarise(alerts)))

    except Exception as error:                      # log the failure, keep the bookmark
        log.update(status="failed", error=str(error)[:300])
        print(f"Sync failed: {error}")
        raise
    finally:
        old_log = store.read_csv(store.SYNC_LOG)
        pd.concat([old_log, pd.DataFrame([log])] if old_log is not None else [pd.DataFrame([log])]) \
            .to_csv(store.SYNC_LOG, index=False)


if __name__ == "__main__":
    main()
