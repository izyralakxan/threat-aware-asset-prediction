"""
Prediction drift monitoring.

Compares, per half-year of CVE publication, the sum of calibrated
probabilities (the number of KEV additions the model expects) with the
number that actually occurred within 12 months. A well-calibrated model
keeps the two close; a growing gap signals that it needs retraining or
recalibration on recent data.

For recent half-years the 12 months are not over, so the ratio uses the
expected count SO FAR (each probability weighted by the share of KEV
additions that historically happen within the elapsed follow-up),
instead of comparing a full-year expectation with a partial count.

Run from the project root:
    python -m src.models.monitor_drift

Output: results/monitoring/prediction_drift.csv
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.models.train_models import prepare_features

SCORING_FILE = Path("data/processed/scoring_features.csv")
RISK_MODEL_FILE = Path("results/models/risk_model.joblib")
OUTPUT_DIR = Path("results/monitoring")

START = pd.Timestamp("2022-01-01")
HORIZON_DAYS = 365


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    bundle = joblib.load(RISK_MODEL_FILE)

    df = pd.read_csv(SCORING_FILE, parse_dates=["published_date", "kev_date_added"])
    df = df[(df["nvd_analysed"] == 1) & (df["published_date"] >= START)]

    df["probability"] = bundle["model"].predict_proba(prepare_features(df))[:, 1]

    lag = (df["kev_date_added"] - df["published_date"]).dt.days
    df["kev_within_12m"] = lag.between(1, HORIZON_DAYS).astype(int)

    # Follow-up is complete only when publication + 12 months <= latest KEV date
    kev_end = df["kev_date_added"].max()

    # Recent CVEs have had only part of their 12 months. Expected-so-far
    # weights each probability by the share of KEV additions that, in
    # complete periods, happened within the CVE's elapsed follow-up.
    complete = df[df["published_date"] + pd.Timedelta(days=HORIZON_DAYS) <= kev_end]
    lags = np.sort(lag[complete.index][complete["kev_within_12m"] == 1].to_numpy())
    elapsed = (kev_end - df["published_date"]).dt.days.clip(0, HORIZON_DAYS)
    df["elapsed_share"] = np.searchsorted(lags, elapsed, side="right") / len(lags)
    df["expected_so_far"] = df["probability"] * df["elapsed_share"]

    df["period"] = (df["published_date"].dt.year.astype(str) + " H"
                    + np.where(df["published_date"].dt.month <= 6, "1", "2"))

    drift = df.groupby("period").agg(
        cves=("probability", "size"),
        expected_kev=("probability", "sum"),
        expected_so_far=("expected_so_far", "sum"),
        actual_kev=("kev_within_12m", "sum"),
        mean_probability=("probability", "mean"),
        follow_up_elapsed=("elapsed_share", "mean"),
        last_published=("published_date", "max"),
    ).reset_index()

    drift["follow_up_complete"] = (
        drift["last_published"] + pd.Timedelta(days=HORIZON_DAYS) <= kev_end)
    # Like-for-like ratio: expected so far vs actual so far
    drift["expected_to_actual"] = drift["expected_so_far"] / drift["actual_kev"].replace(0, np.nan)

    split = {"2022": "train", "2023": "train", "2024": "validation (calibration)",
             "2025 H1": "test", "2025 H2": "test / after cutoff"}
    drift["role"] = drift["period"].map(
        lambda p: split.get(p, split.get(p[:4], "after evaluation period")))

    drift = drift.drop(columns="last_published")
    drift.to_csv(OUTPUT_DIR / "prediction_drift.csv", index=False)

    pd.set_option("display.width", 200)
    print(f"KEV data to {kev_end.date()}\n")
    print(drift.round(3).to_string(index=False))
    print(f"\nResults written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
