"""
Explainable AI for the selected model (LightGBM + description text).

Uses LightGBM's built-in TreeSHAP (predict(..., pred_contrib=True)),
which computes exact SHAP values (Lundberg et al., 2020) for tree
ensembles. Values are in log-odds: positive = raises predicted risk.

Run from the project root:
    python -m src.explainability.explain_model

Outputs (results/explainability/):
  global_importance.csv   mean |SHAP| per feature on the 2025 test set
  group_importance.csv    the same, summed per feature group
  local_explanations.csv  top risk drivers for every test CVE
  shap_global_top20.png, shap_groups.png, shap_examples.png
"""

from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd

from src.models.train_models import TARGET, load_splits

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


# ==============================
# Configuration
# ==============================

MODEL_FILE = Path("results/models/lightgbm__tabular_text.joblib")
OUTPUT_DIR = Path("results/explainability")

CHUNK_SIZE = 2000
TOP_GLOBAL = 20
TOP_RAISING = 5
TOP_LOWERING = 3

# CVEs shown in the example figure (true positives ranked highly)
EXAMPLE_CVES = ["CVE-2025-0108", "CVE-2024-53704"]

HISTORY_FEATURES = {
    "vendor_prior_kev", "vendor_prior_kev_1y", "cwe_prior_kev",
    "vendor_prior_cves", "vendor_prior_kev_rate",
}

# ColumnTransformer step -> feature group
STEP_GROUPS = {
    "numeric": "CVSS scores",
    "categorical": "CVSS vector",
    "cwe": "Weakness type (CWE)",
    "text": "Description text",
}


# ==============================
# Feature names and groups
# ==============================

def describe_features(prep):
    names = list(prep.get_feature_names_out())
    groups = [None] * len(names)

    for step, indices in prep.output_indices_.items():
        for i in range(indices.start, indices.stop):

            if step in STEP_GROUPS:
                groups[i] = STEP_GROUPS[step]
            elif names[i] in HISTORY_FEATURES:
                groups[i] = "Threat history"
            else:
                groups[i] = "Affected scope"

            if step == "text":
                names[i] = f'text: "{names[i]}"'

    return names, groups


# ==============================
# SHAP values
# ==============================

def shap_chunks(pipeline, X):
    """Yields (row offset, transformed features, SHAP values) per chunk."""
    prep = pipeline.named_steps["prep"]
    model = pipeline.named_steps["model"]

    for start in range(0, len(X), CHUNK_SIZE):
        features = prep.transform(X.iloc[start:start + CHUNK_SIZE])
        contrib = model.predict(features, pred_contrib=True)

        if hasattr(features, "toarray"):
            features = features.toarray()
        if hasattr(contrib, "toarray"):
            contrib = contrib.toarray()

        # Last column is the base value (expected log-odds)
        yield start, np.asarray(features), np.asarray(contrib)


def format_driver(name, value):
    return f"{name} ({value:+.2f})"


def explain(pipeline, X):
    prep = pipeline.named_steps["prep"]
    names, groups = describe_features(prep)

    abs_sum = np.zeros(len(names))
    base_value = None
    local_rows = []

    for start, _, contrib in shap_chunks(pipeline, X):

        values, base = contrib[:, :-1], contrib[:, -1]
        base_value = base[0]
        abs_sum += np.abs(values).sum(axis=0)

        for row in range(len(values)):
            order = np.argsort(values[row])
            raising = [i for i in order[::-1][:TOP_RAISING] if values[row, i] > 0]
            lowering = [i for i in order[:TOP_LOWERING] if values[row, i] < 0]

            local_rows.append({
                "risk_raising": "; ".join(
                    format_driver(names[i], values[row, i]) for i in raising),
                "risk_lowering": "; ".join(
                    format_driver(names[i], values[row, i]) for i in lowering),
            })

    importance = pd.DataFrame({
        "feature": names,
        "group": groups,
        "mean_abs_shap": abs_sum / len(X),
    }).sort_values("mean_abs_shap", ascending=False)

    local = pd.DataFrame(local_rows, index=X.index)

    return importance, local, base_value


def direction_of_effect(pipeline, X, feature_positions):
    """
    Sign of the correlation between a feature's value and its SHAP
    value: +1 means higher values (or presence) raise predicted risk.
    """
    values, shap = [], []

    for _, features, contrib in shap_chunks(pipeline, X):
        values.append(features[:, feature_positions])
        shap.append(contrib[:, feature_positions])

    values, shap = np.vstack(values), np.vstack(shap)

    directions = []
    for j in range(len(feature_positions)):
        if values[:, j].std() == 0:
            directions.append(0)
        else:
            directions.append(int(np.sign(np.corrcoef(values[:, j], shap[:, j])[0, 1])))

    return directions


# ==============================
# Figures
# ==============================

# Reference palette, light mode. Diverging pair: red = raises risk,
# blue = lowers risk. Single-series bars use the first categorical hue.
RAISES = "#e34948"
LOWERS = "#2a78d6"
SINGLE = "#2a78d6"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID = "#e8e7e3"
SURFACE = "#fcfcfb"


def style_axes(ax, title):
    ax.set_facecolor(SURFACE)
    ax.set_title(title, color=INK, loc="left", fontsize=11)
    ax.tick_params(colors=INK_SECONDARY, labelsize=9)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_visible(False)


def plot_global(top, path):
    fig, ax = plt.subplots(figsize=(8, 7), facecolor=SURFACE)

    colors = [RAISES if d > 0 else LOWERS if d < 0 else INK_MUTED
              for d in top["direction"]]

    ax.barh(top["feature"][::-1], top["mean_abs_shap"][::-1],
            color=colors[::-1], height=0.7)

    style_axes(ax, "Top 20 features by mean |SHAP| (2025 test set)")
    ax.set_xlabel("Mean |SHAP value| (log-odds)", color=INK_SECONDARY)

    handles = [
        plt.Rectangle((0, 0), 1, 1, color=RAISES),
        plt.Rectangle((0, 0), 1, 1, color=LOWERS),
    ]
    legend = ax.legend(handles, ["Higher value / presence raises risk",
                                 "Higher value / presence lowers risk"],
                       frameon=False, loc="lower right", fontsize=9)
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)

    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def plot_groups(groups, path):
    fig, ax = plt.subplots(figsize=(7, 3.5), facecolor=SURFACE)

    ax.barh(groups["group"][::-1], groups["share"][::-1], color=SINGLE, height=0.6)

    for y, share in enumerate(groups["share"][::-1]):
        ax.text(share + 0.005, y, f"{share:.0%}", va="center",
                color=INK_SECONDARY, fontsize=9)

    style_axes(ax, "Share of total |SHAP| by feature group (2025 test set)")
    ax.set_xlim(0, groups["share"].max() * 1.15)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))

    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def plot_examples(pipeline, X, scores, names, path, top_n=10):
    fig, axes = plt.subplots(1, len(EXAMPLE_CVES), figsize=(13, 5), facecolor=SURFACE)

    for ax, cve in zip(np.atleast_1d(axes), EXAMPLE_CVES):
        row = X[X["cve_id"] == cve]
        _, _, contrib = next(shap_chunks(pipeline, row))
        values = contrib[0, :-1]

        order = np.argsort(np.abs(values))[::-1][:top_n][::-1]
        labels = [names[i] for i in order]
        bars = values[order]

        ax.barh(labels, bars, color=[RAISES if v > 0 else LOWERS for v in bars],
                height=0.7)
        ax.axvline(0, color=INK_MUTED, linewidth=0.8)

        for y, v in enumerate(bars):
            ax.text(v, y, f" {v:+.2f} ", va="center",
                    ha="left" if v > 0 else "right",
                    color=INK_SECONDARY, fontsize=8)

        score = scores[row.index[0]]
        style_axes(ax, f"{cve}  (score {score:.2f}, exploited: "
                       f"{'yes' if row[TARGET].iloc[0] else 'no'})")
        ax.set_xlabel("SHAP value (log-odds)", color=INK_SECONDARY)
        limit = np.abs(bars).max() * 1.35
        ax.set_xlim(-limit, limit)

    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


# ==============================
# Main
# ==============================

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    X = load_splits()["test"]
    pipeline = joblib.load(MODEL_FILE)

    scores = pd.Series(pipeline.predict_proba(X)[:, 1], index=X.index)

    print("\nComputing SHAP values on the 2025 test set...")

    importance, local, base_value = explain(pipeline, X)

    # ---- Global importance ----

    top = importance.head(TOP_GLOBAL).copy()
    top["direction"] = direction_of_effect(pipeline, X, top.index.to_list())

    importance = importance.merge(
        top[["direction"]], left_index=True, right_index=True, how="left"
    )
    importance.to_csv(OUTPUT_DIR / "global_importance.csv", index=False)

    groups = (
        importance.groupby("group")["mean_abs_shap"].sum()
        .sort_values(ascending=False).reset_index()
    )
    groups["share"] = groups["mean_abs_shap"] / groups["mean_abs_shap"].sum()
    groups.to_csv(OUTPUT_DIR / "group_importance.csv", index=False)

    # ---- Local explanations ----

    local.insert(0, "cve_id", X["cve_id"])
    local.insert(1, "risk_score", scores)
    local.insert(2, TARGET, X[TARGET])
    local = local.sort_values("risk_score", ascending=False)
    local.to_csv(OUTPUT_DIR / "local_explanations.csv", index=False)

    # ---- Figures ----

    names, _ = describe_features(pipeline.named_steps["prep"])

    plot_global(top, OUTPUT_DIR / "shap_global_top20.png")
    plot_groups(groups, OUTPUT_DIR / "shap_groups.png")
    plot_examples(pipeline, X, scores, names, OUTPUT_DIR / "shap_examples.png")

    # ---- Report ----

    pd.set_option("display.width", 200)
    pd.set_option("display.max_colwidth", 120)

    print(f"\nBase value (log-odds): {base_value:.3f}")

    print("\nFeature group share of total |SHAP|:")
    print(groups[["group", "share"]].round(3).to_string(index=False))

    print(f"\nTop {TOP_GLOBAL} features (direction: +1 raises risk):")
    print(top[["feature", "group", "mean_abs_shap", "direction"]]
          .round(4).to_string(index=False))

    print("\nTop 5 test CVEs with their main risk drivers:")
    print(local.head(5)[["cve_id", "risk_score", TARGET, "risk_raising"]]
          .round(3).to_string(index=False))

    print(f"\nResults written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
