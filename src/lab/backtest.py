"""
Asset-level backtest on the synthetic lab environment.

At the snapshot date S (2025-08-27) the system assesses every asset using
only information known at S. The outcome is what actually happened in
the following 12 months (S, S+365d]: did any CVE affecting the asset's
installed version get added to CISA KEV?

Outcome routes for a newly exploited CVE:
  prediction window  published in the 12 months before S: the model
                     scored it at S (the predictable part)
  older              published earlier, not scored (past the horizon)
  new                published after S: unknowable at S

Assumes installed versions stay unchanged during the follow-up year.

Run from the project root:
    python -m src.lab.backtest
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from src.asset_exposure.assess_exposure import (
    CONFIRMED, PREDICTION_WINDOW_DAYS, assess_services, load_reference_data,
    match_services, publication_dates,
)
from src.lab.lab_db import load_snapshot

SNAPSHOT_ID = "backtest"
FOLLOW_UP_DAYS = 365
OUTPUT_DIR = Path("results/lab")

# Last date of the model's validation year: window CVEs published up to
# here were used for model selection and calibration
VALIDATION_END = pd.Timestamp("2024-12-31")

TOP_K = [5, 10]


def safe_auc(y, scores):
    return roc_auc_score(y, scores) if 0 < y.sum() < len(y) else np.nan


def safe_ap(y, scores):
    return average_precision_score(y, scores) if y.sum() > 0 else np.nan


def top_k_hits(frame, score, target, k):
    # Ties broken by asset_id so results are reproducible
    ranked = frame.sort_values([score, "asset_id"], ascending=[False, True])
    return int(ranked[target].head(k).sum())


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading reference data...")
    reference = load_reference_data()

    services, inventory, snapshot_date = load_snapshot(SNAPSHOT_ID)
    follow_up_end = snapshot_date + pd.Timedelta(days=FOLLOW_UP_DAYS)

    kev_end = reference["cve_info"]["kev_date_added"].max()
    print(f"Snapshot: {snapshot_date.date()}  follow-up to {follow_up_end.date()}  "
          f"(KEV data to {kev_end.date()})")

    # ---- Prediction at the snapshot date ----

    _, assets, cves = assess_services(services, inventory, reference, snapshot_date)

    # ---- Outcomes: all confirmed matches, including later CVEs ----

    outcomes = match_services(services, reference["cpe_matches"], publication_dates(reference))
    outcomes = outcomes[outcomes["match_confidence"].isin(CONFIRMED)]
    outcomes = outcomes.merge(reference["cve_info"], on="cve_id", how="left")

    newly_exploited = (
        (outcomes["kev_date_added"] > snapshot_date)
        & (outcomes["kev_date_added"] <= follow_up_end)
    )
    outcomes = outcomes[newly_exploited].copy()

    window_start = snapshot_date - pd.Timedelta(days=PREDICTION_WINDOW_DAYS)
    outcomes["route"] = np.select(
        [outcomes["published_date"] > snapshot_date,
         outcomes["published_date"] >= window_start],
        ["new", "prediction window"], default="older")

    route_counts = (outcomes.groupby(["ip_address", "route"]).size()
                    .unstack(fill_value=0)
                    .reindex(columns=["prediction window", "older", "new"], fill_value=0))
    route_counts.columns = ["exploited_window", "exploited_older", "exploited_new"]

    # ---- Asset table: prediction vs outcome ----

    window = cves[(cves["status"] == "Prediction window")
                  & cves["match_confidence"].isin(CONFIRMED)]

    baselines = window.groupby("ip_address").agg(
        max_cvss=("cvss_score", "max"), window_cve_count=("cve_id", "nunique"))

    table = (assets.merge(route_counts, left_on="ip_address", right_index=True, how="left")
                   .merge(baselines, left_on="ip_address", right_index=True, how="left"))

    for column in ["exploited_window", "exploited_older", "exploited_new"]:
        table[column] = table[column].fillna(0).astype(int)
    table[["max_cvss", "window_cve_count"]] = table[["max_cvss", "window_cve_count"]].fillna(0)

    table["outcome_window"] = (table["exploited_window"] > 0).astype(int)
    table["outcome_any"] = (table[["exploited_window", "exploited_older",
                                   "exploited_new"]].sum(axis=1) > 0).astype(int)

    table.to_csv(OUTPUT_DIR / "backtest_assets.csv", index=False)

    # ---- Asset-level ranking metrics ----

    # Three ways to aggregate CVE probabilities to an asset, plus baselines
    rankers = {
        "Model: P(at least one)": "exploit_likelihood_12m",
        "Model: expected count": "expected_exploited_12m",
        "Model: max CVE probability": "max_cve_probability",
        "Product KEV history (12 m)": "product_kev_rate_12m",
        "Combined: model + product history": "expected_new_exposure_12m",
        "Max CVSS (baseline)": "max_cvss",
        "Recent CVE count (baseline)": "window_cve_count",
    }

    rows = []
    for target in ["outcome_window", "outcome_any"]:
        y = table[target].to_numpy()
        for name, column in rankers.items():
            row = {"target": target, "ranker": name,
                   "positives": int(y.sum()), "assets": len(y),
                   "roc_auc": safe_auc(y, table[column].to_numpy())}
            for k in TOP_K:
                row[f"hits_top_{k}"] = top_k_hits(table, column, target, k)
            rows.append(row)

    asset_metrics = pd.DataFrame(rows)
    asset_metrics.to_csv(OUTPUT_DIR / "backtest_asset_metrics.csv", index=False)

    # ---- CVE-level: unique window CVEs in the lab ----

    unique_window = window.drop_duplicates("cve_id").copy()
    unique_window["exploited_in_follow_up"] = (
        (unique_window["kev_date_added"] > snapshot_date)
        & (unique_window["kev_date_added"] <= follow_up_end)).astype(int)
    unique_window["in_validation_year"] = (
        unique_window["published_date"] <= VALIDATION_END).astype(int)

    unique_window.to_csv(OUTPUT_DIR / "backtest_cves.csv", index=False)

    y_cve = unique_window["exploited_in_follow_up"].to_numpy()
    cve_metrics = {
        "window_cves": int(len(unique_window)),
        "exploited_in_follow_up": int(y_cve.sum()),
        "published_in_validation_year": int(unique_window["in_validation_year"].sum()),
        "model_pr_auc": safe_ap(y_cve, unique_window["probability"].to_numpy()),
        "model_roc_auc": safe_auc(y_cve, unique_window["probability"].to_numpy()),
        "cvss_pr_auc": safe_ap(y_cve, unique_window["cvss_score"].fillna(0).to_numpy()),
        "cvss_roc_auc": safe_auc(y_cve, unique_window["cvss_score"].fillna(0).to_numpy()),
        "base_rate": float(y_cve.mean()) if len(y_cve) else np.nan,
    }

    summary = {
        "snapshot_date": str(snapshot_date.date()),
        "follow_up_end": str(follow_up_end.date()),
        "assets": len(table),
        "assets_known_exploited_at_snapshot": int((table["known_exploited"] > 0).sum()),
        "assets_newly_exploited_any_route": int(table["outcome_any"].sum()),
        "assets_newly_exploited_window": int(table["outcome_window"].sum()),
        "newly_exploited_cves_by_route": outcomes.drop_duplicates("cve_id")["route"]
                                                 .value_counts().to_dict(),
        "cve_level": cve_metrics,
    }

    with open(OUTPUT_DIR / "backtest_summary.json", "w") as file:
        json.dump(summary, file, indent=2, default=float)

    # ---- Report ----

    pd.set_option("display.width", 220)

    print("\nSummary:")
    print(json.dumps(summary, indent=2, default=float))

    print("\nAsset ranking vs what happened in the follow-up year:")
    print(asset_metrics.round(3).to_string(index=False))

    print("\nAssets (ranked by model likelihood):")
    print(table.sort_values("expected_new_exposure_12m", ascending=False)
          [["asset_id", "hostname", "exposure_level", "known_exploited",
            "expected_exploited_12m", "product_kev_rate_12m", "expected_new_exposure_12m",
            "max_cve_probability", "max_cvss", "window_cve_count",
            "exploited_window", "exploited_older", "exploited_new"]]
          .round(3).to_string(index=False))

    print("\nWindow CVEs that were exploited in the follow-up year:")
    print(unique_window[unique_window["exploited_in_follow_up"] == 1]
          .sort_values("probability", ascending=False)
          [["cve_id", "product", "published_date", "kev_date_added", "cvss_score",
            "probability", "tier", "in_validation_year"]]
          .round(4).to_string(index=False))

    print("\nNewly exploited CVEs outside the prediction window:")
    print(outcomes[outcomes["route"] != "prediction window"].drop_duplicates("cve_id")
          [["cve_id", "route", "published_date", "kev_date_added"]]
          .sort_values("kev_date_added").to_string(index=False))

    print(f"\nResults written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
