"""
Is the device ranking sensitive to the business weights?

Priority = threat × importance weight × exposure weight, where the weights
(High/Medium/Low importance = 1.0/0.6/0.3, internet-facing Yes/No = 1.0/0.5)
are design assumptions. This re-ranks the devices under every combination of
plausible alternative weights and measures how much the ranking changes:

  top-k kept   share of weight settings that keep the same top-k devices (as a set)
  Spearman     rank correlation with the default ranking (1 = identical order)

Run from the project root (all demo organisations and the latest lab scan):
    python -m src.evaluation.weight_sensitivity

Output: results/benchmark/weight_sensitivity.csv
"""

import itertools
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from src.asset_exposure.assess_exposure import CRITICALITY_WEIGHT, EXPOSURE_WEIGHT

OUTPUT = Path("results/benchmark/weight_sensitivity.csv")
MEDIUM = [0.4, 0.5, 0.6, 0.7, 0.8]
LOW = [0.1, 0.2, 0.3, 0.4]
INTERNAL = [0.3, 0.4, 0.5, 0.6, 0.7]


def ranking(devices, medium, low, internal):
    crit = devices["criticality"].map({"High": 1.0, "Medium": medium, "Low": low}).fillna(medium)
    exposure = devices["internet_exposed"].map({"Yes": 1.0, "No": internal}).fillna(internal)
    threat = np.where(devices["known_exploited"] > 0, 1.0, devices["exposure_probability_12m"])
    score = pd.Series(threat * crit.to_numpy() * exposure.to_numpy(), index=devices.index)
    # Ties broken like the dashboard: expected new exposure, then name
    order = pd.DataFrame({"score": score, "tie": devices["expected_new_exposure_12m"],
                          "name": devices["hostname"].astype(str)})
    return order.sort_values(["score", "tie", "name"], ascending=[False, False, True]).index.tolist()


def sensitivity(assets, ks=(3, 5)):
    """Summary of ranking stability for one network (only scanned devices)."""
    devices = assets[assets["scan_status"] != "Not scanned"].reset_index(drop=True)
    base = ranking(devices, CRITICALITY_WEIGHT["Medium"], CRITICALITY_WEIGHT["Low"],
                   EXPOSURE_WEIGHT["No"])
    position = {d: i for i, d in enumerate(base)}
    kept = {k: [] for k in ks}
    correlations, first_kept = [], []
    settings = list(itertools.product(MEDIUM, LOW, INTERNAL))
    settings = [s for s in settings if s[1] < s[0]]             # Low must stay below Medium
    for medium, low, internal in settings:
        order = ranking(devices, medium, low, internal)
        for k in ks:
            kept[k].append(set(order[:k]) == set(base[:k]))
        first_kept.append(order[0] == base[0])
        correlations.append(spearmanr([position[d] for d in order], range(len(order))).statistic
                            if len(order) > 2 else 1.0)
    result = {"devices": len(devices), "settings": len(settings),
              "most_urgent_unchanged": float(np.mean(first_kept)),
              "spearman_mean": float(np.nanmean(correlations)),
              "spearman_min": float(np.nanmin(correlations))}
    result.update({f"top{k}_unchanged": float(np.mean(v)) for k, v in kept.items()})
    return result


def main():
    from src.asset_discovery.parse_scan_sheet import parse_scan_sheet
    from src.asset_exposure.assess_exposure import assess, assess_services, load_reference_data

    reference = load_reference_data(live=True)
    rows = []
    for sheet in sorted(Path("data/demo_scans").glob("demo_scan_*.csv")):
        services, inventory, scan_date = parse_scan_sheet(sheet.read_bytes())
        _, assets, _ = assess_services(services, inventory, reference, scan_date)
        rows.append({"network": sheet.stem, **sensitivity(assets)})
    scans = sorted(Path("data/lab/scans").glob("scan-*-full.xml"))
    if scans:
        inventory = pd.concat([pd.read_csv("data/raw/assets.csv"),
                               pd.read_csv("config/virtualbox_lab/inventory.csv")])
        _, assets, _ = assess(scans[-1], inventory, reference)
        rows.append({"network": f"lab ({scans[-1].stem})", **sensitivity(assets)})

    table = pd.DataFrame(rows)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(OUTPUT, index=False)
    pd.set_option("display.width", 200)
    print(table.round(3).to_string(index=False))
    print(f"\nSaved {OUTPUT}")


if __name__ == "__main__":
    main()
