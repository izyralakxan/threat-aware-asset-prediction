"""
Asset exposure assessment: links discovered assets to CVEs and predicts
which will become exploited.

  Nmap scan -> services + CPEs -> version-aware CVE matching
  -> per CVE: known exploited now (KEV) | predicted (recent, scored by
     the calibrated model) | older
  -> per asset: exploitation likelihood, weighted by business
     criticality and internet exposure from the inventory

Run from the project root:
    python -m src.asset_exposure.assess_exposure [scan.xml]

Outputs (results/assets/):
  asset_exposure.csv   one row per asset, ranked by priority
  asset_cves.csv       one row per asset-CVE match with drivers
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.asset_discovery.parse_nmap import parse_nmap_xml
from src.asset_exposure.versions import (
    clean_version, compare, fixed_version, has_bounds, is_set, version_key, version_matches,
)
from src.explainability.explain_model import explain
from src.models.calibrate import assign_tiers
from src.models.train_models import prepare_features


# ==============================
# Configuration
# ==============================

DEFAULT_SCAN = Path("tests/fixtures/sample_nmap_scan.xml")
ASSETS_FILE = Path("data/raw/assets.csv")
CPE_MATCHES_FILE = Path("data/processed/nvd_cpe_matches.csv.gz")
SCORING_FILE = Path("data/processed/scoring_features.csv")
INTEGRATED_FILE = Path("data/processed/nvd_kev_integrated.csv")
RISK_MODEL_FILE = Path("results/models/risk_model.joblib")
ACTIVE_MODEL_FILE = Path("results/models/active_model.json")
OUTPUT_DIR = Path("results/assets")

# CVEs published within this many days before the scan are scored by
# the model (it predicts KEV addition within 12 months of publication)
PREDICTION_WINDOW_DAYS = 365

# Look-back for each installed product's rate of new KEV additions
PRODUCT_HISTORY_DAYS = 365

# Business-context weights. These are transparent design assumptions,
# not learned values, and can be adjusted per organisation.
CRITICALITY_WEIGHT = {"High": 1.0, "Medium": 0.6, "Low": 0.3}
EXPOSURE_WEIGHT = {"Yes": 1.0, "No": 0.5}
UNKNOWN_CRITICALITY_WEIGHT = 0.6   # unmanaged assets: treated as Medium
UNKNOWN_EXPOSURE_WEIGHT = 0.5      # and as internal

# Nmap CPE vendor names that NVD files under another vendor
VENDOR_ALIASES = {
    ("igor_sysoev", "nginx"): ["f5", "nginx"],
    ("postfix", "postfix"): ["wietse_venema"],
    ("mysql", "mysql"): ["oracle"],
    ("vsftpd", "vsftpd"): ["vsftpd_project", "beasts"],
    ("redislabs", "redis"): ["redis"],
    ("proftpd", "proftpd"): ["proftpd_project"],
    ("unrealircd", "unrealircd"): ["unreal"],
}

CONFIDENCE_ORDER = ["version match", "all versions", "version unknown", "patched (inferred)"]

# Matches that count towards an asset's likelihood. "version unknown"
# means Nmap could not read the version, so the CVE may not apply.
# "patched (inferred)": NVD lists all versions as affected, but the
# installed version already fixes CVEs published later (see match_services).
CONFIRMED = {"version match", "all versions"}
NEEDS_MANUAL_CHECK = {"version unknown"}

TIER_ORDER = ["Critical", "High", "Medium", "Low"]


# ==============================
# CVE matching
# ==============================

def same_branch(a, b):
    """Same release line: first two version components agree (10.0.x, 2.4.x)."""
    return version_key(a)[:2] == version_key(b)[:2]


def fixes_installed(installed, match):
    """True if the installed version is at or past this range's fix, on the same release line."""
    end = fixed_version(installed, match)
    if end is None or not same_branch(installed, end) or compare(installed, end) < 0:
        return False
    start = match["version_start_including"]
    if is_set(start) and compare(installed, start) < 0:
        return False
    start = match["version_start_excluding"]
    return not (is_set(start) and compare(installed, start) <= 0)


def match_services(services, cpe_matches, published=None):
    """
    Asset-CVE matches with a confidence label.

    NVD often lists a product as affected in "all versions" (no range),
    especially older Windows CVEs, which would flag fully patched hosts.
    With `published` (cve_id -> publication date), the installed version's
    patch level is inferred: if it already contains the fixes for CVEs
    published on date D, an all-versions CVE published before D is labelled
    "patched (inferred)" instead of confirmed. Cumulative-update products
    (Windows, most server software) work this way.
    """
    rows = []

    for service in services[services["cpe"].notna()].itertuples(index=False):

        vendors = [service.vendor] + VENDOR_ALIASES.get(
            (service.vendor, service.cpe_product), [])

        candidates = cpe_matches[
            (cpe_matches["product"] == service.cpe_product)
            & cpe_matches["vendor"].isin(vendors)
        ]

        installed = clean_version(service.cpe_version) or clean_version(service.version)
        service_rows, fixed_cves = [], []

        for match in candidates.to_dict("records"):

            if installed is None:
                confidence = "version unknown"
            elif not has_bounds(match):
                confidence = "all versions"
            elif version_matches(installed, match):
                confidence = "version match"
            else:
                if fixes_installed(installed, match):
                    fixed_cves.append(match["cve_id"])
                continue

            service_rows.append({
                "ip_address": service.ip_address,
                "port": service.port,
                "product": service.product,
                "installed_version": installed,
                "cve_id": match["cve_id"],
                "match_confidence": confidence,
            })

        # Patch level: publication date of the newest CVE this version fixes
        if published is not None and fixed_cves:
            patched_through = published.reindex(fixed_cves).max()
            if pd.notna(patched_through):
                for row in service_rows:
                    if (row["match_confidence"] == "all versions"
                            and published.get(row["cve_id"], patched_through) < patched_through):
                        row["match_confidence"] = "patched (inferred)"

        rows.extend(service_rows)

    matched = pd.DataFrame(rows)

    if matched.empty:
        return matched

    # One row per asset and CVE: strongest confidence, all ports
    matched["confidence_rank"] = matched["match_confidence"].map(
        {c: i for i, c in enumerate(CONFIDENCE_ORDER)})

    return (
        matched.sort_values("confidence_rank")
        .groupby(["ip_address", "cve_id"], as_index=False)
        .agg(product=("product", "first"),
             installed_version=("installed_version", "first"),
             match_confidence=("match_confidence", "first"),
             ports=("port", lambda p: ";".join(map(str, sorted(set(p))))))
    )


# ==============================
# CVE status and scoring
# ==============================

def classify(matched, cve_info, scan_date):
    matched = matched.merge(cve_info, on="cve_id", how="left")

    # CVEs published after the scan were unknown at the time (matters
    # when assessing a past snapshot)
    matched = matched[matched["published_date"] <= scan_date].copy()

    known = matched["kev_date_added"].notna() & (matched["kev_date_added"] <= scan_date)
    recent = matched["published_date"] >= scan_date - pd.Timedelta(days=PREDICTION_WINDOW_DAYS)

    matched["status"] = np.select(
        [known, recent],
        ["Known exploited", "Prediction window"],
        default="Older, not in KEV",
    )

    return matched


def score_window_cves(matched, scoring, bundle):
    window_ids = matched.loc[matched["status"] == "Prediction window", "cve_id"].unique()

    X = scoring[scoring["cve_id"].isin(window_ids)]

    if X.empty:
        return pd.DataFrame(columns=["cve_id", "probability", "tier", "risk_drivers"])

    X = prepare_features(X).set_index("cve_id", drop=False)

    probability = bundle["model"].predict_proba(X)[:, 1]

    base_model = joblib.load(bundle["base_model"])
    _, local, _ = explain(base_model, X)

    return pd.DataFrame({
        "cve_id": X["cve_id"].to_numpy(),
        "probability": probability,
        "tier": assign_tiers(probability, bundle["tier_cutoffs"]),
        "risk_drivers": local["risk_raising"].to_numpy(),
    })


# ==============================
# Asset aggregation
# ==============================

def product_kev_rates(services, cpe_matches, cve_info, scan_date):
    """
    Per asset: CVEs added to KEV in the past PRODUCT_HISTORY_DAYS for each
    installed product (any version). Estimates the yearly rate at which
    new exploited vulnerabilities appear in that product line, which
    covers exposure from CVEs that do not exist yet at the scan date.
    """
    kev = cve_info[
        (cve_info["kev_date_added"] <= scan_date)
        & (cve_info["kev_date_added"] > scan_date - pd.Timedelta(days=PRODUCT_HISTORY_DAYS))
    ]

    kev_products = cpe_matches.loc[
        cpe_matches["cve_id"].isin(kev["cve_id"]), ["cve_id", "vendor", "product"]
    ].drop_duplicates()

    installed = (services.dropna(subset=["cpe"])
                 [["ip_address", "product", "vendor", "cpe_product"]]
                 .drop_duplicates(["ip_address", "vendor", "cpe_product"]))

    rows = []
    for item in installed.itertuples(index=False):
        vendors = [item.vendor] + VENDOR_ALIASES.get((item.vendor, item.cpe_product), [])
        count = kev_products[
            (kev_products["product"] == item.cpe_product)
            & kev_products["vendor"].isin(vendors)
        ]["cve_id"].nunique()
        rows.append({"ip_address": item.ip_address, "product": item.product, "kev_12m": count})

    rates = pd.DataFrame(rows, columns=["ip_address", "product", "kev_12m"])

    return rates.groupby("ip_address").agg(
        product_kev_rate_12m=("kev_12m", "sum"),
        most_targeted_product=("product", lambda p: p.iloc[
            rates.loc[p.index, "kev_12m"].to_numpy().argmax()]),
    ).reset_index()


def likelihood(probabilities):
    # P(at least one CVE exploited), assuming independence between CVEs
    probabilities = probabilities.dropna()
    return 1 - np.prod(1 - probabilities) if len(probabilities) else 0.0


def exposure_level(row):
    if row["scan_status"] == "Not scanned":
        return "Unknown"
    if row["known_exploited"] > 0 or row["critical_tier_cves"] > 0:
        return "Critical"
    # A product that had newly exploited vulnerabilities in the past
    # year is likely to have more, even if none are known yet
    if row["high_tier_cves"] > 0 or row["product_kev_rate_12m"] >= 1:
        return "High"
    if row["medium_tier_cves"] > 0:
        return "Medium"
    # Only product-level matches: the version could not be read, so the
    # asset may or may not be affected; it needs a manual check
    if row["matched_cves"] == 0 and row["unconfirmed_cves"] > 0:
        return "Unverified"
    return "Low"


def summarise_assets(inventory, services, cves, rates):
    hosts = services.groupby("ip_address").agg(
        discovered_hostname=("hostname", "first"),
        open_services=("port", "nunique"),
        unversioned_services=("version", lambda v: int(v.isna().sum())),
    ).reset_index()

    assets = inventory.merge(hosts, on="ip_address", how="outer")

    assets["scan_status"] = np.where(
        assets["open_services"].isna(), "Not scanned",
        np.where(assets["asset_id"].isna(), "Unmanaged (not in inventory)", "Scanned"))

    assets["asset_id"] = assets["asset_id"].fillna("UNMANAGED")
    assets["hostname"] = assets["hostname"].fillna(assets["discovered_hostname"])

    confirmed = cves[cves["match_confidence"].isin(CONFIRMED)]

    def per_asset(group):
        window = group[group["status"] == "Prediction window"]
        top = window.sort_values("probability", ascending=False).head(1)
        return pd.Series({
            "matched_cves": len(group),
            "known_exploited": int((group["status"] == "Known exploited").sum()),
            "window_cves": len(window),
            "critical_tier_cves": int((window["tier"] == "Critical").sum()),
            "high_tier_cves": int((window["tier"] == "High").sum()),
            "medium_tier_cves": int((window["tier"] == "Medium").sum()),
            "exploit_likelihood_12m": likelihood(window["probability"]),
            # Does not saturate with many CVEs, unlike the likelihood
            "expected_exploited_12m": window["probability"].sum(),
            "max_cve_probability": window["probability"].max() if len(window) else 0.0,
            "top_predicted_cve": top["cve_id"].iloc[0] if len(top) else None,
            "top_predicted_probability": top["probability"].iloc[0] if len(top) else None,
        })

    stats = (confirmed.groupby("ip_address").apply(per_asset, include_groups=False)
             .reset_index() if not confirmed.empty else
             pd.DataFrame(columns=["ip_address"]))

    unconfirmed = (cves[cves["match_confidence"].isin(NEEDS_MANUAL_CHECK)]
                   .groupby("ip_address").size().rename("unconfirmed_cves").reset_index())

    assets = assets.merge(stats, on="ip_address", how="left")
    assets = assets.merge(unconfirmed, on="ip_address", how="left")
    assets = assets.merge(rates, on="ip_address", how="left")

    counts = ["matched_cves", "known_exploited", "window_cves", "critical_tier_cves",
              "high_tier_cves", "medium_tier_cves", "unconfirmed_cves",
              "product_kev_rate_12m"]
    assets[counts] = assets[counts].fillna(0).astype(int)
    scores = ["exploit_likelihood_12m", "expected_exploited_12m", "max_cve_probability"]
    assets[scores] = assets[scores].fillna(0.0)

    # Expected newly exploited vulnerabilities in the next 12 months:
    # known CVEs (model) + not-yet-published CVEs (product KEV rate).
    # P(at least one) under a Poisson assumption.
    assets["expected_new_exposure_12m"] = (
        assets["expected_exploited_12m"] + assets["product_kev_rate_12m"])
    assets["exposure_probability_12m"] = 1 - np.exp(-assets["expected_new_exposure_12m"])

    assets["exposure_level"] = assets.apply(exposure_level, axis=1)

    criticality = assets["criticality"].map(CRITICALITY_WEIGHT).fillna(UNKNOWN_CRITICALITY_WEIGHT)
    exposure = assets["internet_exposed"].map(EXPOSURE_WEIGHT).fillna(UNKNOWN_EXPOSURE_WEIGHT)

    # A known exploited CVE counts as certain threat
    threat = np.where(assets["known_exploited"] > 0, 1.0, assets["exposure_probability_12m"])
    assets["priority_score"] = threat * criticality * exposure

    columns = [
        "asset_id", "hostname", "ip_address", "asset_type", "criticality",
        "internet_exposed", "scan_status", "open_services", "exposure_level",
        "priority_score", "known_exploited", "exposure_probability_12m",
        "expected_new_exposure_12m", "expected_exploited_12m", "product_kev_rate_12m",
        "most_targeted_product", "window_cves", "critical_tier_cves", "high_tier_cves",
        "exploit_likelihood_12m", "max_cve_probability", "top_predicted_cve",
        "top_predicted_probability", "matched_cves", "unconfirmed_cves",
        "unversioned_services",
    ]

    return assets[columns].sort_values(
        ["priority_score", "expected_new_exposure_12m"], ascending=False)


# ==============================
# Main
# ==============================

def active_model_file(live):
    """
    Research model for reproducible results; for live use, the model chosen
    by the champion/challenger decision (src.models.retrain_operational).
    """
    if live and ACTIVE_MODEL_FILE.exists():
        try:
            chosen = Path(json.loads(ACTIVE_MODEL_FILE.read_text())["file"])
            if chosen.exists():
                return chosen
        except (ValueError, KeyError):
            pass
    return RISK_MODEL_FILE


def load_reference_data(live=False):
    """
    NVD, KEV, feature and model data shared by every assessment.

    live=False uses only the frozen research data and the research model
    (reproducible results); live=True adds updates from the live sync in
    data/live/ and uses the active model (active_model_file).
    """
    cve_info = pd.read_csv(
        INTEGRATED_FILE,
        usecols=["cve_id", "published_date", "kev_date_added", "cvss_score", "cvss_severity",
                 "attack_vector"],
    )
    cve_info["published_date"] = pd.to_datetime(cve_info["published_date"]).dt.normalize()
    cve_info["kev_date_added"] = pd.to_datetime(cve_info["kev_date_added"])

    reference = {
        "cpe_matches": pd.read_csv(CPE_MATCHES_FILE, dtype=str),
        "cve_info": cve_info,
        "scoring": pd.read_csv(SCORING_FILE),
        "bundle": joblib.load(active_model_file(live)),
        "live": None,
    }

    if live:
        from src.sync.live_store import apply_live_updates
        apply_live_updates(reference)

    return reference


def assess(scan_file, inventory, reference):
    """Nmap XML scan -> (services, asset-level exposure, asset-CVE matches)."""
    services = parse_nmap_xml(scan_file)
    scan_date = services["scan_time"].iloc[0].tz_localize(None).normalize()

    return assess_services(services, inventory, reference, scan_date)


def publication_dates(reference):
    """cve_id -> publication date, for patch-level inference in match_services."""
    if "published" not in reference:
        reference["published"] = reference["cve_info"].set_index("cve_id")["published_date"]
    return reference["published"]


def assess_services(services, inventory, reference, scan_date):
    """Any service list (scan or lab database) -> (services, assets, CVEs)."""
    # Lab hosts often have no DNS name: use the inventory's hostname for them
    if "hostname" in inventory and not services.empty:
        known = inventory.dropna(subset=["hostname"]).drop_duplicates("ip_address") \
            .set_index("ip_address")["hostname"]
        services = services.assign(hostname=services["hostname"].fillna(services["ip_address"].map(known)))

    matched = match_services(services, reference["cpe_matches"], publication_dates(reference))
    matched = classify(matched, reference["cve_info"], scan_date)

    scores = score_window_cves(matched, reference["scoring"], reference["bundle"])
    cves = matched.merge(scores, on="cve_id", how="left")

    cves = cves.merge(services.groupby("ip_address")["hostname"].first().reset_index(),
                      on="ip_address", how="left")

    cves["tier_rank"] = cves["tier"].map({t: i for i, t in enumerate(TIER_ORDER)})
    cves = cves.sort_values(["ip_address", "status", "tier_rank", "probability"],
                            ascending=[True, True, True, False]).drop(columns="tier_rank")

    rates = product_kev_rates(
        services, reference["cpe_matches"], reference["cve_info"], scan_date)

    assets = summarise_assets(inventory, services, cves, rates)

    return services, assets, cves


def main():
    scan_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SCAN
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Scan: {scan_file}")
    print("Loading NVD data...")

    services, assets, cves = assess(
        scan_file, pd.read_csv(ASSETS_FILE), load_reference_data())

    print(f"Scan date: {services['scan_time'].iloc[0].date()}  "
          f"hosts: {services['ip_address'].nunique()}  services: {len(services)}")

    cves.to_csv(OUTPUT_DIR / "asset_cves.csv", index=False)
    assets.to_csv(OUTPUT_DIR / "asset_exposure.csv", index=False)

    # ---- Report ----

    pd.set_option("display.width", 220)
    pd.set_option("display.max_colwidth", 60)

    print("\nMatched CVEs by status and confidence:")
    print(pd.crosstab(cves["status"], cves["match_confidence"]).to_string())

    print("\nAssets ranked by priority:")
    print(assets[["asset_id", "hostname", "ip_address", "criticality", "internet_exposed",
                  "scan_status", "exposure_level", "priority_score", "known_exploited",
                  "window_cves", "exploit_likelihood_12m", "top_predicted_cve"]]
          .round(3).to_string(index=False))

    print("\nTop predicted CVEs (prediction window, confirmed matches):")
    window = cves[(cves["status"] == "Prediction window")
                  & cves["match_confidence"].isin(CONFIRMED)]
    print(window.sort_values("probability", ascending=False)
          [["hostname", "product", "installed_version", "cve_id", "published_date",
            "cvss_score", "probability", "tier"]]
          .head(10).round(4).to_string(index=False))

    print("\nKnown exploited CVEs on assets:")
    print(cves[cves["status"] == "Known exploited"]
          [["hostname", "product", "installed_version", "cve_id",
            "kev_date_added", "match_confidence"]].to_string(index=False))

    print(f"\nResults written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
