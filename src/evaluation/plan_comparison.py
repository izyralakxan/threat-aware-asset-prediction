"""
Our prioritisation vs the usual ones, for the dashboard's comparison page.

1. Capture curve (evidence): on the 2025 test year (never used for training
   or tuning), the share of CVEs that were later actively exploited (CISA
   KEV) found when a team reviews the top X% of CVEs ranked by each method:
   this model, EPSS, CVSS score, random. Same CVE set as the EPSS benchmark.

2. Patch plans (illustration on the network being viewed): the SAME upgrade
   actions in three orders, so only the prioritisation differs:
     our plan          the remediation planner's order (risk removed)
     CVSS plan         highest CVSS score among the CVEs an upgrade fixes
     criticality plan  most business-critical, internet-facing device first
   Main measure: devices still exposed to an actively exploited (CISA KEV)
   weakness after each fix. Counting exploited CVEs instead would reward bulk
   updates (one Windows update can close 20+ CVEs on one device).

Run from the project root to (re)build the capture curve:
    python -m src.evaluation.plan_comparison

Output: results/benchmark/capture_curve.csv
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.asset_exposure.assess_exposure import CRITICALITY_WEIGHT, EXPOSURE_WEIGHT

CURVE_FILE = Path("results/benchmark/capture_curve.csv")
BASE_MODEL_FILE = Path("results/models/lightgbm__tabular_text.joblib")
EPSS_FILE = Path("data/external/epss/epss_test_scores.csv")
SHARES = [0.005, 0.01, 0.02, 0.03, 0.05, 0.075, 0.10, 0.15, 0.20, 0.30, 0.40, 0.50]
METHODS = ["Our model", "EPSS (industry standard)", "CVSS score (usual practice)", "Random"]


# ==============================
# 1. Capture curve on the 2025 test year
# ==============================

def build_capture_curve():
    from src.models.train_models import TARGET, load_splits, rank_order

    test = load_splits()["test"]
    epss = pd.read_csv(EPSS_FILE).drop_duplicates("cve_id").set_index("cve_id")["epss"]
    test = test[test["cve_id"].isin(epss.index)]            # same set as the EPSS benchmark
    y = test[TARGET].to_numpy()

    scores = {
        "Our model": joblib.load(BASE_MODEL_FILE).predict_proba(test)[:, 1],
        "EPSS (industry standard)": test["cve_id"].map(epss).to_numpy(),
        "CVSS score (usual practice)": test["cvss_score"].fillna(0).to_numpy(),
    }
    rows = []
    for share in SHARES:
        k = int(round(len(y) * share))
        for name, s in scores.items():
            rows.append({"share_reviewed": share, "method": name,
                         "share_caught": y[rank_order(s)[:k]].sum() / y.sum()})
        rows.append({"share_reviewed": share, "method": "Random", "share_caught": share})
    curve = pd.DataFrame(rows)
    curve.attrs["cves"], curve.attrs["exploited"] = len(y), int(y.sum())
    return curve.assign(cves=len(y), exploited=int(y.sum()))


# ==============================
# 2. Three patch plans on the current network
# ==============================

PLANS = ["Our plan", "CVSS plan", "Criticality plan"]


def compare_plans(actions, assets, cves):
    """
    (orders, progress): orders = {plan: actions in that plan's order};
    progress = per plan and number of fixes, the cumulative actively exploited
    weaknesses fixed and the cumulative predicted exploitations prevented.
    """
    if actions.empty:
        return {}, pd.DataFrame()

    cve_rows = cves.set_index(["ip_address", "cve_id"])
    info = assets.set_index("asset_id")

    def per_action(a):
        keys = [(a.ip_address, c) for c in a.fixed_cve_ids.split(";")]
        rows = cve_rows.reindex(keys)
        predicted = rows.loc[rows["status"] == "Prediction window", "probability"].fillna(0).sum()
        return pd.Series({"max_cvss": rows["cvss_score"].max(), "predicted_prevented": predicted})

    table = pd.concat([actions.reset_index(drop=True),
                       actions.apply(per_action, axis=1).reset_index(drop=True)], axis=1)
    table["max_cvss"] = table["max_cvss"].fillna(0)
    table["importance"] = table["asset_id"].map(
        lambda a: CRITICALITY_WEIGHT.get(info.loc[a, "criticality"], 0.5)
        * EXPOSURE_WEIGHT.get(info.loc[a, "internet_exposed"], 0.5))

    orders = {
        "Our plan": table,                                            # planner order already
        "CVSS plan": table.sort_values(["max_cvss", "cves_fixed"], ascending=False, kind="stable"),
        "Criticality plan": table.sort_values(["importance", "cves_fixed"], ascending=False,
                                              kind="stable"),
    }
    # A device stays exposed while any product on it with an actively exploited
    # weakness is unpatched (counted per device, so one bulk update does not count
    # as many fixes)
    exploited_products = (table[table["kev_fixed"] > 0].groupby("asset_id")["product"]
                          .apply(set).to_dict())

    progress = []
    for plan, ordered in orders.items():
        still_open = {a: set(p) for a, p in exploited_products.items()}
        exploited, predicted = 0, 0.0
        for i, step in enumerate([None] + list(ordered.itertuples(index=False))):
            if step is not None:
                still_open.get(step.asset_id, set()).discard(step.product)
                exploited += step.kev_fixed
                predicted += step.predicted_prevented
            progress.append({"plan": plan, "fixes": i,
                             "devices_exposed": sum(1 for p in still_open.values() if p),
                             "exploited_fixed": int(exploited), "predicted_prevented": predicted})
    return {p: o.reset_index(drop=True) for p, o in orders.items()}, pd.DataFrame(progress)


def main():
    CURVE_FILE.parent.mkdir(parents=True, exist_ok=True)
    curve = build_capture_curve()
    curve.to_csv(CURVE_FILE, index=False)
    wide = curve.pivot(index="share_reviewed", columns="method", values="share_caught")[METHODS]
    pd.set_option("display.width", 200)
    print(f"2025 test CVEs: {curve['cves'].iloc[0]:,}, exploited: {curve['exploited'].iloc[0]}")
    print((wide * 100).round(1).to_string())
    print(f"\nSaved {CURVE_FILE}")


if __name__ == "__main__":
    main()
