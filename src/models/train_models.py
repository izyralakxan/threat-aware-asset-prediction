"""
Temporal ML experiment: predict whether a CVE is added to CISA KEV
within 12 months of NVD publication (future_kev).

Run from the project root:
    python -m src.models.train_models

Protocol
  - Train:      published 2021-11-03 .. 2023-12-31
  - Validation: published 2024        (model selection, imbalance
                                       strategy, decision threshold)
  - Test:       published 2025 (to cutoff), used once for final results
  - Population: CVEs NVD has analysed (CPE assigned). See
                build_features.py for why.
"""

import itertools
import json
import time
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from src.features.transformers import CweEncoder

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


# ==============================
# Configuration
# ==============================

FEATURES_FILE = "data/processed/features.csv"

RESULTS_DIR = Path("results")
MODELS_DIR = RESULTS_DIR / "models"

TRAIN_END = pd.Timestamp("2023-12-31")
VALID_END = pd.Timestamp("2024-12-31")

RANDOM_STATE = 42
TOP_CWES = 25
UNDERSAMPLE_RATIO = 10      # negatives per positive when undersampling
TOP_K_SHARES = [0.01, 0.05]  # review budgets: top 1% / 5% of CVEs
N_BOOTSTRAP = 1000

NUMERIC = ["cvss_score", "exploitability_score", "impact_score"]

COUNTS = [
    "vendor_count", "product_count", "cwe_count",
    "vendor_prior_kev", "vendor_prior_kev_1y",
    "cwe_prior_kev", "vendor_prior_cves",
]

RATES = ["vendor_prior_kev_rate"]

CATEGORICAL = [
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality_impact",
    "integrity_impact", "availability_impact",
]

TEXT = "description_clean"

# Each model is trained on both, so the contribution of the
# description text can be measured directly
FEATURE_SETS = {"tabular": False, "tabular+text": True}

TARGET = "future_kev"


# ==============================
# Data
# ==============================

def prepare_features(df):
    # Shared by training and by scoring new CVEs
    df = df.copy()

    df[CATEGORICAL] = df[CATEGORICAL].astype(object).where(
        df[CATEGORICAL].notna(), "MISSING"
    )

    df[TEXT] = df[TEXT].fillna("")

    return df


def load_splits():
    df = pd.read_csv(FEATURES_FILE, parse_dates=["published_date"])

    print(f"Records: {len(df)}")

    df = df[df["nvd_analysed"] == 1].copy()

    print(f"Records analysed by NVD (evaluation population): {len(df)}")

    df = prepare_features(df)

    splits = {
        "train": df[df["published_date"] <= TRAIN_END],
        "validation": df[
            (df["published_date"] > TRAIN_END)
            & (df["published_date"] <= VALID_END)
        ],
        "test": df[df["published_date"] > VALID_END],
    }

    print("\nSplit sizes:")
    for name, part in splits.items():
        print(
            f"  {name:<10} {part['published_date'].min().date()} .. "
            f"{part['published_date'].max().date()}  "
            f"records={len(part):>6}  positives={int(part[TARGET].sum()):>4}  "
            f"rate={part[TARGET].mean():.4%}"
        )

    return splits


# ==============================
# Models
# ==============================

def make_text_vectorizer():
    # Words and word pairs ("remote code", "authentication bypass").
    # Alphabetic tokens only, so version numbers do not become features.
    # Vocabulary and IDF weights are learned from the training years.
    return TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=5,
        max_df=0.5,
        max_features=2000,
        sublinear_tf=True,
        stop_words="english",
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z_]+\b",
    )


def make_preprocessor(scale, text):
    scaler = StandardScaler() if scale else "passthrough"

    text_step = [("text", make_text_vectorizer(), TEXT)] if text else []

    transformer = ColumnTransformer(
        [
            ("numeric", Pipeline([
                ("impute", SimpleImputer(strategy="median")),
                ("scale", scaler),
            ]), NUMERIC),
            ("counts", Pipeline([
                ("log", FunctionTransformer(np.log1p, feature_names_out="one-to-one")),
                ("scale", scaler),
            ]), COUNTS),
            ("rates", scaler, RATES),
            ("categorical", OneHotEncoder(
                handle_unknown="ignore", sparse_output=False
            ), CATEGORICAL),
            ("cwe", CweEncoder(top_n=TOP_CWES), ["cwe"]),
        ] + text_step,
        verbose_feature_names_out=False,
    )

    # TF-IDF output is sparse, so pandas output is only used without text
    return transformer if text else transformer.set_output(transform="pandas")


def make_model(family, params, imbalance, neg_pos_ratio, text):
    weighted = imbalance == "weighted"

    if family == "logistic_regression":
        # Linear, interpretable baseline: shows how much signal is
        # captured by additive effects alone
        model = LogisticRegression(
            C=params["C"],
            class_weight="balanced" if weighted else None,
            max_iter=5000,
        )
        scale = True

    elif family == "random_forest":
        # Bagged trees: non-linear interactions, robust to noisy
        # features, little tuning needed
        model = RandomForestClassifier(
            n_estimators=300,
            min_samples_leaf=params["min_samples_leaf"],
            max_features="sqrt",
            class_weight="balanced_subsample" if weighted else None,
            n_jobs=-1,
            random_state=RANDOM_STATE,
        )
        scale = False

    elif family == "lightgbm":
        # Gradient boosting: typically strongest on tabular data and
        # supports imbalance via scale_pos_weight
        model = LGBMClassifier(
            n_estimators=params["n_estimators"],
            learning_rate=0.05,
            num_leaves=params["num_leaves"],
            min_child_samples=params["min_child_samples"],
            subsample=0.8,
            subsample_freq=1,
            colsample_bytree=0.8,
            scale_pos_weight=neg_pos_ratio if weighted else 1.0,
            random_state=RANDOM_STATE,
            verbose=-1,
        )
        scale = False

    return Pipeline([("prep", make_preprocessor(scale, text)), ("model", model)])


SEARCH_SPACE = {
    "logistic_regression": {"C": [0.01, 0.1, 1.0, 10.0]},
    "random_forest": {"min_samples_leaf": [1, 5, 20]},
    "lightgbm": {
        "n_estimators": [200, 500],
        "num_leaves": [15, 31],
        "min_child_samples": [20, 100],
    },
}

# none:         plain fit on the imbalanced data
# weighted:     errors on positives weighted by the class ratio
# undersampled: negatives randomly reduced to UNDERSAMPLE_RATIO : 1
IMBALANCE_STRATEGIES = ["none", "weighted", "undersampled"]


def undersample(X, y):
    rng = np.random.default_rng(RANDOM_STATE)

    positives = np.flatnonzero(y == 1)
    negatives = np.flatnonzero(y == 0)

    keep = rng.choice(
        negatives,
        size=min(len(negatives), len(positives) * UNDERSAMPLE_RATIO),
        replace=False,
    )

    rows = np.sort(np.concatenate([positives, keep]))

    return X.iloc[rows], y[rows]


def fit_model(family, params, imbalance, text, X, y):
    neg_pos_ratio = (y == 0).sum() / (y == 1).sum()

    pipeline = make_model(family, params, imbalance, neg_pos_ratio, text)

    if imbalance == "undersampled":
        X, y = undersample(X, y)

    return pipeline.fit(X, y)


# ==============================
# Evaluation
# ==============================

def rank_order(scores):
    # Descending by score; ties broken randomly (with a fixed seed) so
    # coarse scores such as CVSS are not ordered by row position
    rng = np.random.default_rng(RANDOM_STATE)
    return np.lexsort((rng.random(len(scores)), -scores))


def best_f1_threshold(y, scores):
    precision, recall, thresholds = precision_recall_curve(y, scores)
    f1 = 2 * precision * recall / np.clip(precision + recall, 1e-12, None)
    return float(thresholds[np.argmax(f1[:-1])])


def evaluate(y, scores, threshold):
    predicted = (scores >= threshold).astype(int)

    metrics = {
        "pr_auc": average_precision_score(y, scores),
        "roc_auc": roc_auc_score(y, scores),
        "precision": precision_score(y, predicted, zero_division=0),
        "recall": recall_score(y, predicted, zero_division=0),
        "f1": f1_score(y, predicted, zero_division=0),
        "flagged": int(predicted.sum()),
    }

    order = rank_order(scores)

    for share in TOP_K_SHARES:
        k = int(round(len(y) * share))
        hits = y[order[:k]].sum()
        label = f"{share:.0%}".replace("%", "pct")
        metrics[f"precision_top_{label}"] = hits / k
        metrics[f"recall_top_{label}"] = hits / y.sum()

    return metrics


def bootstrap_pr_auc(y, scores):
    rng = np.random.default_rng(RANDOM_STATE)
    values = []

    for _ in range(N_BOOTSTRAP):
        rows = rng.integers(0, len(y), len(y))
        if y[rows].sum() == 0:
            continue
        values.append(average_precision_score(y[rows], scores[rows]))

    return np.percentile(values, [2.5, 97.5])


# ==============================
# Figure
# ==============================

# Reference categorical palette (light mode), fixed order
SERIES_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
SURFACE = "#fcfcfb"


def plot_pr_curves(y, score_sets, path):
    fig, ax = plt.subplots(figsize=(7, 5), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)

    for (name, scores), color in zip(score_sets.items(), SERIES_COLORS):
        precision, recall, _ = precision_recall_curve(y, scores)
        ap = average_precision_score(y, scores)
        # Step drawing matches how average precision is computed; linear
        # interpolation overstates precision between tied scores (CVSS)
        ax.plot(recall, precision, color=color, linewidth=2,
                drawstyle="steps-post", label=f"{name} (PR-AUC {ap:.3f})")

    ax.axhline(y.mean(), color=INK_MUTED, linewidth=1, linestyle="--",
               label=f"Random (prevalence {y.mean():.3%})")

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_xlabel("Recall", color=INK_SECONDARY)
    ax.set_ylabel("Precision", color=INK_SECONDARY)
    ax.set_title("Precision-recall on the 2025 test set", color=INK, loc="left")
    ax.tick_params(colors=INK_MUTED)
    ax.grid(color="#e8e7e3", linewidth=0.8)
    ax.set_axisbelow(True)

    for spine in ax.spines.values():
        spine.set_visible(False)

    legend = ax.legend(frameon=False, loc="upper right")
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)

    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


# ==============================
# Main
# ==============================

def main():
    RESULTS_DIR.mkdir(exist_ok=True)
    MODELS_DIR.mkdir(exist_ok=True)

    splits = load_splits()

    X = {name: part for name, part in splits.items()}
    y = {name: part[TARGET].to_numpy() for name, part in splits.items()}

    # ---- Model selection on the validation year ----

    print("\nSearching models on the validation year...")

    search_rows = []
    best = {}

    for (feature_set, text), (family, grid) in itertools.product(
        FEATURE_SETS.items(), SEARCH_SPACE.items()
    ):
        name = f"{family} [{feature_set}]"
        keys = list(grid)

        for values, imbalance in itertools.product(
            itertools.product(*grid.values()), IMBALANCE_STRATEGIES
        ):
            params = dict(zip(keys, values))

            started = time.time()

            pipeline = fit_model(
                family, params, imbalance, text, X["train"], y["train"]
            )

            scores = pipeline.predict_proba(X["validation"])[:, 1]
            pr_auc = average_precision_score(y["validation"], scores)

            search_rows.append({
                "model": family, "feature_set": feature_set,
                "imbalance": imbalance, "params": json.dumps(params),
                "validation_pr_auc": pr_auc,
            })

            print(f"  {name:<36} {imbalance:<13} {params}  "
                  f"PR-AUC={pr_auc:.4f}  ({time.time() - started:.0f}s)")

            if name not in best or pr_auc > best[name]["pr_auc"]:
                best[name] = {
                    "pipeline": pipeline, "params": params,
                    "imbalance": imbalance, "pr_auc": pr_auc,
                    "file": f"{family}__{feature_set.replace('+', '_')}",
                }

    search = pd.DataFrame(search_rows)
    search.to_csv(RESULTS_DIR / "validation_search.csv", index=False)

    imbalance_table = search.pivot_table(
        index=["model", "feature_set"], columns="imbalance",
        values="validation_pr_auc", aggfunc="max",
    )[IMBALANCE_STRATEGIES]
    imbalance_table.to_csv(RESULTS_DIR / "imbalance_comparison.csv")

    print("\nBest validation PR-AUC per imbalance strategy:")
    print(imbalance_table.round(4))

    # ---- Scores: selected models + non-ML baselines ----

    def baseline_scores(part):
        return {
            "CVSS score": part["cvss_score"].fillna(0).to_numpy(),
            "Vendor KEV history": part["vendor_prior_kev"].to_numpy().astype(float),
        }

    scores = {"validation": {}, "test": {}}

    for family, chosen in best.items():
        for split in scores:
            scores[split][family] = chosen["pipeline"].predict_proba(X[split])[:, 1]

    for split in scores:
        scores[split].update(baseline_scores(X[split]))

    # ---- Thresholds chosen on validation, applied to test ----

    rows = []
    selected = {}

    for name in scores["test"]:

        threshold = best_f1_threshold(y["validation"], scores["validation"][name])

        for split in ["validation", "test"]:
            metrics = evaluate(y[split], scores[split][name], threshold)
            rows.append({"model": name, "split": split,
                         "threshold": threshold, **metrics})

        low, high = bootstrap_pr_auc(y["test"], scores["test"][name])
        rows[-1]["pr_auc_ci_low"] = low
        rows[-1]["pr_auc_ci_high"] = high

        if name in best:
            selected[name] = {
                "params": best[name]["params"],
                "imbalance": best[name]["imbalance"],
                "threshold": threshold,
                "validation_pr_auc": best[name]["pr_auc"],
            }
            joblib.dump(
                best[name]["pipeline"], MODELS_DIR / f"{best[name]['file']}.joblib"
            )

    results = pd.DataFrame(rows)
    results.to_csv(RESULTS_DIR / "metrics.csv", index=False)

    with open(RESULTS_DIR / "selected_models.json", "w") as file:
        json.dump(selected, file, indent=2)

    # ---- Report ----

    columns = ["model", "pr_auc", "pr_auc_ci_low", "pr_auc_ci_high", "roc_auc",
               "precision", "recall", "f1", "flagged",
               "precision_top_1pct", "recall_top_1pct",
               "precision_top_5pct", "recall_top_5pct"]

    pd.set_option("display.width", 200)

    print("\nValidation (2024):")
    print(results[results["split"] == "validation"][columns[:2] + columns[4:]]
          .round(4).to_string(index=False))

    print(f"\nTest (2025) - random-classifier PR-AUC = {y['test'].mean():.4f}:")
    print(results[results["split"] == "test"][columns].round(4).to_string(index=False))

    # ---- Figure ----

    plot_pr_curves(
        y["test"],
        {
            "LightGBM + text": scores["test"]["lightgbm [tabular+text]"],
            "Random forest + text": scores["test"]["random_forest [tabular+text]"],
            "Logistic regression + text":
                scores["test"]["logistic_regression [tabular+text]"],
            "CVSS score": scores["test"]["CVSS score"],
        },
        RESULTS_DIR / "pr_curves_test.png",
    )

    print(f"\nResults written to {RESULTS_DIR}/")


if __name__ == "__main__":
    main()
