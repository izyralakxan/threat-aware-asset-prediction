"""
Calibrates the selected model and defines risk tiers.

The selected model (LightGBM + text) was trained on undersampled data,
so its raw scores rank CVEs well but are not probabilities. A
calibrator is fitted on the 2024 validation year (the model never saw
it) and evaluated on 2025.

Risk tiers are defined by review budget on the validation year
(score cut-offs), then applied unchanged to the test year.

Run from the project root:
    python -m src.models.calibrate

Outputs:
  results/models/risk_model.joblib   calibrated model + tier cut-offs
  results/calibration/*.csv, *.png
"""

from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import brier_score_loss, log_loss

from src.models.train_models import TARGET, load_splits

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


# ==============================
# Configuration
# ==============================

BASE_MODEL_FILE = Path("results/models/lightgbm__tabular_text.joblib")
RISK_MODEL_FILE = Path("results/models/risk_model.joblib")
OUTPUT_DIR = Path("results/calibration")

CALIBRATION_METHODS = ["sigmoid", "isotonic"]

# Chosen in advance, not on test results: Platt scaling (sigmoid) fits
# two parameters, whereas isotonic regression fits a free step function
# that tends to overfit with only ~100 positives. Isotonic is reported
# for comparison only.
CHOSEN_METHOD = "sigmoid"

# Cumulative review budgets: top 1% Critical, next 4% High,
# next 15% Medium, remainder Low
TIERS = [("Critical", 0.01), ("High", 0.05), ("Medium", 0.20), ("Low", 1.00)]

N_BINS = 10


# ==============================
# Metrics
# ==============================

def expected_calibration_error(y, probabilities, n_bins=N_BINS):
    # Equal-count bins: with 0.3-0.5% positives, equal-width bins
    # would put nearly every CVE in the first bin
    bins = pd.qcut(probabilities, n_bins, labels=False, duplicates="drop")
    frame = pd.DataFrame({"y": y, "p": probabilities, "bin": bins})
    grouped = frame.groupby("bin").agg(observed=("y", "mean"),
                                       predicted=("p", "mean"),
                                       n=("y", "size"))
    weights = grouped["n"] / len(frame)
    return float((weights * (grouped["observed"] - grouped["predicted"]).abs()).sum()), grouped


def calibration_metrics(y, probabilities):
    ece, _ = expected_calibration_error(y, probabilities)
    return {
        "brier": brier_score_loss(y, probabilities),
        "log_loss": log_loss(y, np.clip(probabilities, 1e-6, 1 - 1e-6)),
        "ece": ece,
        "expected_positives": probabilities.sum(),
        "actual_positives": int(y.sum()),
    }


# ==============================
# Risk tiers
# ==============================

def tier_cutoffs(scores):
    # Score at each cumulative budget on the validation year
    return {
        name: float(np.quantile(scores, 1 - share))
        for name, share in TIERS[:-1]
    }


def assign_tiers(scores, cutoffs):
    tiers = np.full(len(scores), TIERS[-1][0], dtype=object)

    # From the lowest tier upwards, so higher tiers overwrite
    for name, _ in reversed(TIERS[:-1]):
        tiers[scores >= cutoffs[name]] = name

    return tiers


def tier_summary(y, scores, tiers):
    frame = pd.DataFrame({"y": y, "p": scores, "tier": tiers})
    order = [name for name, _ in TIERS]

    summary = frame.groupby("tier").agg(
        cves=("y", "size"),
        exploited=("y", "sum"),
        min_probability=("p", "min"),
        max_probability=("p", "max"),
        mean_probability=("p", "mean"),
    ).reindex(order)

    summary["share_of_cves"] = summary["cves"] / len(frame)
    summary["hit_rate"] = summary["exploited"] / summary["cves"]
    summary["share_of_exploited"] = summary["exploited"] / frame["y"].sum()
    summary["lift"] = summary["hit_rate"] / frame["y"].mean()

    return summary


# ==============================
# Figure
# ==============================

SERIES_COLORS = ["#2a78d6", "#eb6834"]
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID = "#e8e7e3"
SURFACE = "#fcfcfb"


def plot_reliability(y, calibrated, path):
    fig, ax = plt.subplots(figsize=(6, 5.5), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)

    low, high = 1e-5, 1.0
    ax.plot([low, high], [low, high], color=INK_MUTED, linewidth=1,
            linestyle="--", label="Perfect calibration")

    for (name, probabilities), color in zip(calibrated.items(), SERIES_COLORS):
        _, bins = expected_calibration_error(y, probabilities)
        bins = bins[bins["observed"] > 0]  # log scale cannot show zero
        ax.plot(bins["predicted"], bins["observed"], color=color, linewidth=2,
                marker="o", markersize=7, label=name)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(low, high)
    ax.set_ylim(low, high)
    ax.set_xlabel("Mean predicted probability (decile)", color=INK_SECONDARY)
    ax.set_ylabel("Observed exploitation rate", color=INK_SECONDARY)
    ax.set_title("Reliability on the 2025 test set", color=INK, loc="left")
    ax.tick_params(colors=INK_MUTED)
    ax.grid(color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_visible(False)

    legend = ax.legend(frameon=False, loc="upper left")
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)

    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


# ==============================
# Main
# ==============================

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    splits = load_splits()
    X_val, y_val = splits["validation"], splits["validation"][TARGET].to_numpy()
    X_test, y_test = splits["test"], splits["test"][TARGET].to_numpy()

    base = joblib.load(BASE_MODEL_FILE)

    # ---- Calibration ----

    rows = []
    calibrators = {}
    test_probabilities = {}

    raw_test = base.predict_proba(X_test)[:, 1]
    rows.append({"method": "uncalibrated", **calibration_metrics(y_test, raw_test)})

    for method in CALIBRATION_METHODS:
        calibrator = CalibratedClassifierCV(FrozenEstimator(base), method=method)
        calibrator.fit(X_val, y_val)

        probabilities = calibrator.predict_proba(X_test)[:, 1]

        calibrators[method] = calibrator
        test_probabilities[method] = probabilities
        rows.append({"method": method, **calibration_metrics(y_test, probabilities)})

    comparison = pd.DataFrame(rows)
    comparison.to_csv(OUTPUT_DIR / "calibration_comparison.csv", index=False)

    chosen = CHOSEN_METHOD
    model = calibrators[chosen]

    plot_reliability(
        y_test,
        {"Platt (sigmoid)": test_probabilities["sigmoid"],
         "Isotonic": test_probabilities["isotonic"]},
        OUTPUT_DIR / "reliability_test.png",
    )

    # ---- Risk tiers ----

    val_probabilities = model.predict_proba(X_val)[:, 1]
    cutoffs = tier_cutoffs(val_probabilities)

    val_summary = tier_summary(
        y_val, val_probabilities, assign_tiers(val_probabilities, cutoffs))
    test_summary = tier_summary(
        y_test, test_probabilities[chosen],
        assign_tiers(test_probabilities[chosen], cutoffs))

    val_summary.to_csv(OUTPUT_DIR / "tiers_validation.csv")
    test_summary.to_csv(OUTPUT_DIR / "tiers_test.csv")

    # ---- Save deployable risk model ----

    joblib.dump(
        {
            "model": model,
            "calibration": chosen,
            "tier_cutoffs": cutoffs,
            "tiers": [name for name, _ in TIERS],
            "base_model": str(BASE_MODEL_FILE),
            "calibrated_on": "validation year 2024",
            "prediction_horizon_months": 12,
        },
        RISK_MODEL_FILE,
    )

    # ---- Report ----

    pd.set_option("display.width", 200)

    print("\nCalibration on the 2025 test set (lower is better):")
    print(comparison.round(5).to_string(index=False))
    print(f"\nSelected calibration: {chosen}")

    print("\nTier probability cut-offs (from 2024):")
    for name, value in cutoffs.items():
        print(f"  {name:<9} >= {value:.4f}")

    columns = ["cves", "share_of_cves", "exploited", "hit_rate",
               "share_of_exploited", "lift", "min_probability", "max_probability"]

    print("\nRisk tiers - validation (2024):")
    print(val_summary[columns].round(4).to_string())

    print("\nRisk tiers - test (2025):")
    print(test_summary[columns].round(4).to_string())

    print(f"\nRisk model saved to {RISK_MODEL_FILE}")


if __name__ == "__main__":
    main()
