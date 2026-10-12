"""
Retrains a CHALLENGER risk model on the most recent labelled data and
decides, on fresh out-of-time data, whether it replaces the live model.

  research model (champion)   results/models/risk_model.joblib
                              train 2021-11..2023, calibrate 2024, test 2025
                              once. Every reported result, the EPSS
                              benchmark and the lab backtest use it.
  challenger                  results/models/operational/risk_model_operational.joblib
                              Same algorithm and settings, moved forward in
                              time: train on all labelled CVEs except the
                              latest 12 months, calibrate and set tier
                              cut-offs on those 12 months.

Champion/challenger rule: the challenger is promoted only if it beats the
live model on the primary metrics (PR-AUC and recall in the top 1%) on
CVEs published after the labelled data ends, which neither model has
seen. Labels there are partial (KEV additions so far, at least
OUT_OF_TIME_MIN_DAYS of follow-up per CVE). The decision is written to
results/models/active_model.json, which live scoring reads.

A CVE is labelled only when its 12-month outcome is complete, so the
newest labelled CVE is the dataset cutoff (2025-08-27). Run every
6 months as new labels mature.

Run from the project root:
    python -m src.models.retrain_operational

Outputs (results/models/operational/):
  lightgbm_tabular_text_operational.joblib   base model (for SHAP)
  risk_model_operational.joblib              calibrated model + tier cut-offs
  model_card.json                            what, when, on which data, metrics
  ../active_model.json                       which model live scoring uses, and why
  ../../monitoring/champion_challenger.csv   out-of-time comparison
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, roc_auc_score

from src.models.calibrate import (
    CHOSEN_METHOD, RISK_MODEL_FILE, TIERS, assign_tiers, calibration_metrics, tier_cutoffs,
    tier_summary,
)
from src.models.train_models import (
    FEATURES_FILE, RESULTS_DIR, TARGET, evaluate, fit_model, prepare_features,
)

OUTPUT_DIR = RESULTS_DIR / "models" / "operational"
BASE_FILE = OUTPUT_DIR / "lightgbm_tabular_text_operational.joblib"
OPERATIONAL_MODEL_FILE = OUTPUT_DIR / "risk_model_operational.joblib"
MODEL_CARD_FILE = OUTPUT_DIR / "model_card.json"
ACTIVE_MODEL_FILE = RESULTS_DIR / "models" / "active_model.json"
COMPARISON_FILE = RESULTS_DIR / "monitoring" / "champion_challenger.csv"
SCORING_FILE = Path("data/processed/scoring_features.csv")
SELECTED_FILE = RESULTS_DIR / "selected_models.json"

SELECTED_MODEL = "lightgbm [tabular+text]"
CALIBRATION_MONTHS = 12
OUT_OF_TIME_MIN_DAYS = 60
PRIMARY_METRICS = ["pr_auc", "recall_top_1pct"]


def out_of_time_comparison(cutoff, models):
    """Metrics of each model on CVEs published after the labelled data (partial labels)."""
    scoring = pd.read_csv(SCORING_FILE, parse_dates=["published_date", "kev_date_added"])
    kev_end = scoring["kev_date_added"].max()
    fresh = scoring[(scoring["nvd_analysed"] == 1) & (scoring["published_date"] > cutoff)
                    & (scoring["published_date"] <= kev_end - pd.Timedelta(days=OUT_OF_TIME_MIN_DAYS))]
    y = (fresh["kev_date_added"].notna() & (fresh["kev_date_added"] > fresh["published_date"])
         & (fresh["kev_date_added"] <= fresh["published_date"] + pd.Timedelta(days=365))).to_numpy().astype(int)
    X = prepare_features(fresh)

    rows = []
    for name, bundle in models.items():
        probability = bundle["model"].predict_proba(X)[:, 1]
        metrics = evaluate(y, probability, threshold=bundle["tier_cutoffs"]["Critical"])
        rows.append({"model": name, "cves": len(y), "exploited_so_far": int(y.sum()),
                     "period": f"{fresh['published_date'].min():%Y-%m-%d} to "
                               f"{fresh['published_date'].max():%Y-%m-%d}",
                     **{k: metrics[k] for k in ["pr_auc", "roc_auc", "recall_top_1pct", "recall_top_5pct"]},
                     "critical_tier_share": float(np.mean(probability >= bundle["tier_cutoffs"]["Critical"]))})
    return pd.DataFrame(rows)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    COMPARISON_FILE.parent.mkdir(parents=True, exist_ok=True)

    # ---- Data: every CVE with a complete 12-month outcome ----

    df = pd.read_csv(FEATURES_FILE, parse_dates=["published_date"])
    df = prepare_features(df[df["nvd_analysed"] == 1])

    cutoff = df["published_date"].max()
    calibration_start = cutoff - pd.DateOffset(months=CALIBRATION_MONTHS)

    train = df[df["published_date"] <= calibration_start]
    calib = df[df["published_date"] > calibration_start]
    y_train, y_calib = train[TARGET].to_numpy(), calib[TARGET].to_numpy()

    for name, part in [("train", train), ("calibration", calib)]:
        print(f"{name:<12} {part['published_date'].min().date()} .. "
              f"{part['published_date'].max().date()}  records={len(part):>6}  "
              f"positives={int(part[TARGET].sum()):>4}")

    # ---- Same algorithm and settings as the selected research model ----

    selected = json.loads(SELECTED_FILE.read_text())[SELECTED_MODEL]
    print(f"\nSettings from the research model: {selected['params']}, {selected['imbalance']}")

    base = fit_model("lightgbm", selected["params"], selected["imbalance"], True, train, y_train)
    joblib.dump(base, BASE_FILE)

    # ---- Calibration and tiers on the most recent 12 months ----

    model = CalibratedClassifierCV(FrozenEstimator(base), method=CHOSEN_METHOD).fit(calib, y_calib)
    probabilities = model.predict_proba(calib)[:, 1]
    cutoffs = tier_cutoffs(probabilities)
    tiers = tier_summary(y_calib, probabilities, assign_tiers(probabilities, cutoffs))

    # Ranking on the 12 months the base model never saw (calibration is
    # monotonic, so it does not change the ranking)
    holdout = evaluate(y_calib, base.predict_proba(calib)[:, 1], threshold=0.5)
    calibration = calibration_metrics(y_calib, probabilities)

    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    period = lambda part: (f"{part['published_date'].min():%Y-%m-%d} to "
                           f"{part['published_date'].max():%Y-%m-%d}")
    version = f"operational-{cutoff:%Y%m}"

    joblib.dump({
        "model": model,
        "calibration": CHOSEN_METHOD,
        "tier_cutoffs": cutoffs,
        "tiers": [name for name, _ in TIERS],
        "base_model": str(BASE_FILE),
        "calibrated_on": f"CVEs published {period(calib)}",
        "trained_on": f"CVEs published {period(train)}",
        "prediction_horizon_months": 12,
        "version": version,
        "role": "operational",
        "created": created,
    }, OPERATIONAL_MODEL_FILE)

    # ---- Champion/challenger on fresh out-of-time CVEs ----

    challenger = joblib.load(OPERATIONAL_MODEL_FILE)
    champion = joblib.load(RISK_MODEL_FILE)
    comparison = out_of_time_comparison(cutoff, {"research (champion)": champion,
                                                 "operational (challenger)": challenger})
    comparison.to_csv(COMPARISON_FILE, index=False)

    champ, chall = comparison.iloc[0], comparison.iloc[1]
    wins = {m: bool(chall[m] > champ[m]) for m in PRIMARY_METRICS}
    promote = all(wins.values())
    decision = {
        "active": "operational" if promote else "research",
        "file": str(OPERATIONAL_MODEL_FILE if promote else RISK_MODEL_FILE),
        "decided": created,
        "rule": "Promote the challenger only if it beats the live model on PR-AUC and "
                "recall in the top 1% on CVEs neither model has seen",
        "evidence": {m: {"champion": round(float(champ[m]), 4), "challenger": round(float(chall[m]), 4),
                         "challenger_wins": bool(chall[m] > champ[m]), "primary": m in PRIMARY_METRICS}
                     for m in PRIMARY_METRICS + ["roc_auc", "recall_top_5pct"]},
        "out_of_time_data": f"{champ['period']}, {int(champ['cves'])} CVEs, "
                            f"{int(champ['exploited_so_far'])} exploited so far",
    }
    ACTIVE_MODEL_FILE.write_text(json.dumps(decision, indent=2))

    card = {
        "version": version,
        "created": created,
        "role": "Operational model for live scoring. Research results use the frozen research model.",
        "algorithm": "LightGBM + TF-IDF text, Platt calibration (same settings as the research model)",
        "settings": selected["params"] | {"imbalance": selected["imbalance"]},
        "trained_on": {"period": period(train), "cves": len(train), "exploited": int(y_train.sum())},
        "calibrated_on": {"period": period(calib), "cves": len(calib), "exploited": int(y_calib.sum())},
        "holdout_12_months": {
            "pr_auc": round(holdout["pr_auc"], 4),
            "roc_auc": round(holdout["roc_auc"], 4),
            "recall_top_1pct": round(holdout["recall_top_1pct"], 4),
            "recall_top_5pct": round(holdout["recall_top_5pct"], 4),
            "base_rate": round(float(y_calib.mean()), 5),
        },
        "calibration_in_sample": {k: round(float(v), 5) for k, v in calibration.items()},
        "tier_cutoffs": {k: round(v, 5) for k, v in cutoffs.items()},
        "retrain": "Every 6 months, or when drift monitoring shows expected and actual counts diverging",
        "promoted": promote,
    }
    MODEL_CARD_FILE.write_text(json.dumps(card, indent=2))

    # ---- Report ----

    pd.set_option("display.width", 200)
    print(f"\nHold-out (latest 12 months, base rate {y_calib.mean():.4f}): "
          f"PR-AUC {holdout['pr_auc']:.4f}  ROC-AUC {holdout['roc_auc']:.4f}  "
          f"recall@1% {holdout['recall_top_1pct']:.3f}  recall@5% {holdout['recall_top_5pct']:.3f}")
    print(f"Calibration (in-sample): expected {calibration['expected_positives']:.1f} "
          f"vs actual {calibration['actual_positives']}")
    print("\nTier cut-offs:", {k: round(v, 4) for k, v in cutoffs.items()})
    print(tiers[["cves", "exploited", "hit_rate", "share_of_exploited", "lift"]].round(4).to_string())
    print("\nOut-of-time comparison (CVEs neither model has seen, partial labels):")
    print(comparison.round(4).to_string(index=False))
    print(f"\nDecision: {'PROMOTE challenger' if promote else 'KEEP research model'} "
          f"({', '.join(f'{m}: challenger wins' if w else f'{m}: champion wins' for m, w in wins.items())})")
    print(f"Challenger saved to {OPERATIONAL_MODEL_FILE}; decision in {ACTIVE_MODEL_FILE}")


if __name__ == "__main__":
    main()
