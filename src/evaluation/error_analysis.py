"""
Error analysis on the 2025 test year (the research model, top-5% budget).

  Missed exploited CVEs   later listed in CISA KEV, but not in the model's
                          top 5%. Each is put in the first matching group:
                            1. vendor never in KEV before (no history to learn from)
                            2. looked low-severity (CVSS below 7)
                            3. needs user action or local/adjacent access
                            4. other
                          and compared with the ones the model caught.
  False alarms            the 100 highest-scored CVEs that were NOT listed
                          within 12 months: how many were listed later
                          anyway (outside the 12-month label window, so not
                          really false), and what they have in common.

Run from the project root:
    python -m src.evaluation.error_analysis
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.models.train_models import TARGET, load_splits, rank_order

OUTPUT_DIR = Path("results/benchmark")
BASE_MODEL_FILE = Path("results/models/lightgbm__tabular_text.joblib")
KEV_FILE = Path("data/processed/nvd_kev_integrated.csv")
BUDGET = 0.05
TOP_FALSE = 100


def group_missed(row):
    if row["vendor_prior_kev"] == 0:
        return "Vendor never in KEV before"
    if row["cvss_score"] < 7:
        return "Looked low-severity (CVSS < 7)"
    if row["user_interaction"] == "REQUIRED" or row["attack_vector"] != "NETWORK":
        return "Needs user action or local access"
    return "Other"


def profile(frame):
    return {
        "count": len(frame),
        "median_cvss": round(float(frame["cvss_score"].median()), 1),
        "share_cvss_below_7": round(float((frame["cvss_score"] < 7).mean()), 3),
        "share_network": round(float((frame["attack_vector"] == "NETWORK").mean()), 3),
        "share_user_interaction": round(float((frame["user_interaction"] == "REQUIRED").mean()), 3),
        "share_vendor_new_to_kev": round(float((frame["vendor_prior_kev"] == 0).mean()), 3),
        "median_description_words": int(frame["description_clean"].str.split().str.len().median()),
        "top_vendors": frame["vendor"].value_counts().head(5).to_dict(),
    }


def main():
    test = load_splits()["test"].reset_index(drop=True)
    kev = pd.read_csv(KEV_FILE, usecols=["cve_id", "kev_date_added"], parse_dates=["kev_date_added"])
    test = test.merge(kev.drop_duplicates("cve_id"), on="cve_id", how="left")

    scores = joblib.load(BASE_MODEL_FILE).predict_proba(test)[:, 1]
    order = rank_order(scores)
    k = int(round(len(test) * BUDGET))
    test["rank"] = np.empty(len(test), dtype=int)
    test.loc[order, "rank"] = np.arange(1, len(test) + 1)
    test["score"] = scores
    test["in_top"] = test["rank"] <= k
    test["days_to_kev"] = (test["kev_date_added"] - test["published_date"]).dt.days

    exploited = test[test[TARGET] == 1]
    caught, missed = exploited[exploited["in_top"]], exploited[~exploited["in_top"]].copy()
    missed["reason"] = missed.apply(group_missed, axis=1)

    negatives = test[test[TARGET] == 0].sort_values("rank").head(TOP_FALSE).copy()
    negatives["listed_later"] = negatives["kev_date_added"].notna()

    result = {
        "test_cves": len(test), "budget": f"top {BUDGET:.0%} ({k} CVEs)",
        "exploited": len(exploited), "caught": len(caught), "missed": len(missed),
        "caught_profile": profile(caught), "missed_profile": profile(missed),
        "missed_by_reason": missed["reason"].value_counts().to_dict(),
        "median_days_to_kev": {"caught": float(caught["days_to_kev"].median()),
                               "missed": float(missed["days_to_kev"].median())},
        "false_alarms_checked": TOP_FALSE,
        "false_alarms_listed_later": int(negatives["listed_later"].sum()),
        "false_alarm_profile": profile(negatives),
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "error_analysis.json").write_text(json.dumps(result, indent=2, default=str))
    columns = ["cve_id", "published_date", "vendor", "product", "cvss_score", "attack_vector",
               "user_interaction", "cwe", "vendor_prior_kev", "rank", "score", "kev_date_added", "days_to_kev"]
    missed[columns + ["reason"]].sort_values("rank").to_csv(OUTPUT_DIR / "error_missed.csv", index=False)
    negatives[columns + ["listed_later"]].to_csv(OUTPUT_DIR / "error_false_alarms.csv", index=False)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
