"""
Research evaluation on the held-out 2025 test year:

  1. EPSS benchmark   the model vs FIRST's Exploit Prediction Scoring System
  2. Ablation study   retrain without one feature group at a time
  3. Significance     paired bootstrap tests of every difference

EPSS fairness: each test CVE gets its EPSS score from the first weekly
EPSS snapshot after its publication (1-7 days later). EPSS therefore sees
up to a week more information than the model, so a model advantage is a
conservative result. EPSS predicts exploitation activity in the next 30
days; the model predicts a CISA KEV listing within 12 months.

Run from the project root (about 10-15 minutes; EPSS files are cached):
    python -m src.evaluation.benchmark
"""

import gzip
import io
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from src.models.train_models import (
    CATEGORICAL, NUMERIC, TARGET, fit_model, load_splits, rank_order,
)

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

OUTPUT_DIR = Path("results/benchmark")
EPSS_CACHE = Path("data/external/epss/epss_test_scores.csv")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
SELECTED_FILE = Path("results/selected_models.json")

N_BOOTSTRAP = 2000
RANDOM_STATE = 42
SNAPSHOT_EVERY_DAYS = 7

# Feature groups removed in the ablation study. A removed group is set to
# a constant in every split, so the model cannot learn from it.
HISTORY = ["vendor_prior_kev", "vendor_prior_kev_1y", "cwe_prior_kev",
           "vendor_prior_cves", "vendor_prior_kev_rate"]
SCOPE = ["vendor_count", "product_count", "cwe_count"]

ABLATIONS = {
    "Full model": None,
    "Without description text": "text",
    "Without threat history": "history",
    "Without CVSS": "cvss",
    "Without weakness type (CWE)": "cwe",
    "Without affected scope": "scope",
}


# ==============================
# Metrics
# ==============================

def recall_at(y, scores, share):
    k = int(round(len(y) * share))
    return y[rank_order(scores)[:k]].sum() / y.sum()


METRICS = {
    "PR-AUC": average_precision_score,
    "Recall @ top 5%": lambda y, s: recall_at(y, s, 0.05),
}


def summary(y, scores):
    return {
        "pr_auc": average_precision_score(y, scores),
        "roc_auc": roc_auc_score(y, scores),
        "recall_top_1pct": recall_at(y, scores, 0.01),
        "recall_top_5pct": recall_at(y, scores, 0.05),
    }


def paired_bootstrap(y, scores_a, scores_b, metric, rng_seed=RANDOM_STATE):
    """Distribution of metric(A) - metric(B) over the same resamples."""
    rng = np.random.default_rng(rng_seed)
    diffs, a_values = [], []
    n = len(y)
    for _ in range(N_BOOTSTRAP):
        rows = rng.integers(0, n, n)
        if y[rows].sum() == 0:
            continue
        a = metric(y[rows], scores_a[rows])
        diffs.append(a - metric(y[rows], scores_b[rows]))
        a_values.append(a)
    diffs = np.array(diffs)
    p = 2 * min((diffs <= 0).mean(), (diffs >= 0).mean())
    return {
        "difference": metric(y, scores_a) - metric(y, scores_b),
        "ci_low": np.percentile(diffs, 2.5), "ci_high": np.percentile(diffs, 97.5),
        "p_value": min(1.0, p),
    }


# ==============================
# EPSS scores as of publication
# ==============================

def download_epss(date):
    url = EPSS_URL.format(date=date)
    request = urllib.request.Request(url, headers={"User-Agent": "ThreatAwareAssetPrediction/1.0"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                raw = gzip.decompress(response.read())
            return pd.read_csv(io.BytesIO(raw), comment="#")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            time.sleep(10 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(10 * (attempt + 1))
    return None


def epss_for(test):
    """EPSS score of each test CVE from the first weekly snapshot after publication."""
    if EPSS_CACHE.exists():
        return pd.read_csv(EPSS_CACHE)

    published = pd.to_datetime(test["published_date"]).dt.normalize()
    snapshots = pd.date_range(published.min() + pd.Timedelta(days=1),
                              published.max() + pd.Timedelta(days=SNAPSHOT_EVERY_DAYS * 2),
                              freq=f"{SNAPSHOT_EVERY_DAYS}D")

    wanted = test[["cve_id"]].assign(published=published.values)
    found = {}
    for snap in snapshots:
        need = wanted[(wanted["published"] < snap) & ~wanted["cve_id"].isin(found)
                      & (wanted["published"] >= snap - pd.Timedelta(days=SNAPSHOT_EVERY_DAYS * 2))]
        if need.empty:
            continue
        scores = download_epss(snap.date().isoformat())
        if scores is None:
            print(f"  EPSS {snap.date()}: not available")
            continue
        hits = scores[scores["cve"].isin(need["cve_id"])]
        for row in hits.itertuples(index=False):
            found[row.cve] = (row.epss, snap.date().isoformat())
        print(f"  EPSS {snap.date()}: {len(hits)}/{len(need)} CVEs scored")

    result = pd.DataFrame([{"cve_id": c, "epss": e, "epss_date": d} for c, (e, d) in found.items()])
    EPSS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(EPSS_CACHE, index=False)
    return result


# ==============================
# Ablation
# ==============================

def neutralise(df, group):
    df = df.copy()
    if group == "history":
        df[HISTORY] = 0
    elif group == "scope":
        df[SCOPE] = 0
    elif group == "cvss":
        df[NUMERIC] = 0
        df[CATEGORICAL] = "MISSING"
    elif group == "cwe":
        df["cwe"] = "CWE-NONE"
    return df


def ablation_scores(splits, params):
    y_train = splits["train"][TARGET].to_numpy()
    scores = {}
    for name, group in ABLATIONS.items():
        started = time.time()
        text = group != "text"
        train = neutralise(splits["train"], group)
        test = neutralise(splits["test"], group)
        model = fit_model("lightgbm", params["params"], params["imbalance"], text, train, y_train)
        scores[name] = model.predict_proba(test)[:, 1]
        print(f"  {name:<30} PR-AUC {average_precision_score(splits['test'][TARGET], scores[name]):.4f} "
              f"({time.time() - started:.0f}s)")
    return scores


# ==============================
# Figure
# ==============================

COLORS = {"model": "#2a78d6", "other": "#898781", "drop": "#eb6834"}


def plot(benchmark, ablation, path):
    fig, (left, right) = plt.subplots(1, 2, figsize=(13, 4.8), facecolor="#fcfcfb")

    order = benchmark.sort_values("pr_auc")
    colors = [COLORS["model"] if "LightGBM" in m else COLORS["other"] for m in order["model"]]
    left.barh(order["model"], order["pr_auc"], color=colors, height=0.6,
              xerr=[order["pr_auc"] - order["ci_low"], order["ci_high"] - order["pr_auc"]],
              error_kw={"ecolor": "#52514e", "capsize": 3, "elinewidth": 1})
    for y, v in enumerate(order["pr_auc"]):
        left.text(v + 0.004, y + 0.22, f"{v:.3f}", color="#52514e", fontsize=9)
    left.set_title("PR-AUC on 2025 CVEs with an EPSS score (95% CI)", loc="left", fontsize=11)
    left.set_xlabel("PR-AUC (higher is better)")

    ablation = ablation[ablation["variant"] != "Full model"].sort_values("pr_auc_drop")
    right.barh(ablation["variant"], ablation["pr_auc_drop"], color=COLORS["drop"], height=0.6)
    for y, v in enumerate(ablation["pr_auc_drop"]):
        right.text(max(v, 0) + 0.001, y, f"{v:+.3f}", va="center", color="#52514e", fontsize=9)
    right.axvline(0, color="#898781", linewidth=0.8)
    right.set_title("Ablation: PR-AUC lost when a feature group is removed", loc="left", fontsize=11)
    right.set_xlabel("Drop in PR-AUC vs full model (higher = group matters more)")

    for ax in (left, right):
        ax.set_facecolor("#fcfcfb")
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.grid(axis="x", color="#e8e7e3")
        ax.set_axisbelow(True)
        ax.tick_params(colors="#52514e", length=0)

    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor="#fcfcfb")
    plt.close(fig)


# ==============================
# Main
# ==============================

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    splits = load_splits()
    test = splits["test"]
    y = test[TARGET].to_numpy()

    selected = json.loads(SELECTED_FILE.read_text())["lightgbm [tabular+text]"]

    # ---- Ablation (also gives the full model's scores) ----
    print("\nAblation study (retraining LightGBM + text)...")
    scores = ablation_scores(splits, selected)
    full = scores["Full model"]

    # ---- EPSS ----
    print("\nFetching EPSS scores as of publication...")
    epss = epss_for(test)
    epss_map = epss.set_index("cve_id")["epss"]
    has_epss = test["cve_id"].isin(epss_map.index).to_numpy()
    coverage = {"test_cves": int(len(test)), "with_epss": int(has_epss.sum()),
                "exploited": int(y.sum()), "exploited_with_epss": int(y[has_epss].sum())}
    print(f"  EPSS coverage: {coverage['with_epss']}/{coverage['test_cves']} CVEs, "
          f"{coverage['exploited_with_epss']}/{coverage['exploited']} exploited")

    # Comparison on the CVEs EPSS scored, so every method sees the same set
    sub = has_epss
    y_sub = y[sub]
    epss_scores = test.loc[sub, "cve_id"].map(epss_map).to_numpy()
    model_scores = full[sub]
    cvss_scores = test.loc[sub, "cvss_score"].fillna(0).to_numpy()
    rank = lambda s: pd.Series(s).rank(pct=True).to_numpy()
    combined = (rank(model_scores) + rank(epss_scores)) / 2

    contenders = {
        "LightGBM + text (this project)": model_scores,
        "LightGBM + EPSS (rank average)": combined,
        "EPSS": epss_scores,
        "CVSS score": cvss_scores,
    }

    rows = []
    rng = np.random.default_rng(RANDOM_STATE)
    boot = [rng.integers(0, len(y_sub), len(y_sub)) for _ in range(N_BOOTSTRAP)]
    for name, s in contenders.items():
        values = [average_precision_score(y_sub[b], s[b]) for b in boot if y_sub[b].sum()]
        rows.append({"model": name, **summary(y_sub, s),
                     "ci_low": np.percentile(values, 2.5), "ci_high": np.percentile(values, 97.5)})
    rows.append({"model": "Random", "pr_auc": y_sub.mean(), "roc_auc": 0.5,
                 "recall_top_1pct": 0.01, "recall_top_5pct": 0.05,
                 "ci_low": y_sub.mean(), "ci_high": y_sub.mean()})
    benchmark = pd.DataFrame(rows)

    # ---- Ablation table (full test set) ----
    ablation = pd.DataFrame([{"variant": name, **summary(y, s)} for name, s in scores.items()])
    ablation["pr_auc_drop"] = ablation.loc[0, "pr_auc"] - ablation["pr_auc"]
    ablation["recall5_drop"] = ablation.loc[0, "recall_top_5pct"] - ablation["recall_top_5pct"]

    # ---- Significance ----
    print("\nPaired bootstrap tests...")
    tests = []
    for metric_name, metric in METRICS.items():
        for other in ["EPSS", "CVSS score", "LightGBM + EPSS (rank average)"]:
            tests.append({"comparison": f"Model vs {other}", "metric": metric_name,
                          "data": "2025 CVEs with EPSS",
                          **paired_bootstrap(y_sub, model_scores, contenders[other], metric)})
        for name in list(ABLATIONS)[1:]:
            tests.append({"comparison": f"Full model vs {name.lower()}", "metric": metric_name,
                          "data": "All 2025 test CVEs",
                          **paired_bootstrap(y, full, scores[name], metric)})
    significance = pd.DataFrame(tests)
    significance["significant"] = significance["p_value"] < 0.05

    # ---- Save ----
    benchmark.to_csv(OUTPUT_DIR / "benchmark.csv", index=False)
    ablation.to_csv(OUTPUT_DIR / "ablation.csv", index=False)
    significance.to_csv(OUTPUT_DIR / "significance.csv", index=False)
    (OUTPUT_DIR / "epss_coverage.json").write_text(json.dumps(coverage, indent=2))
    plot(benchmark, ablation, OUTPUT_DIR / "benchmark_ablation.png")

    pd.set_option("display.width", 220)
    print("\nBenchmark (2025 CVEs with an EPSS score):")
    print(benchmark.round(4).to_string(index=False))
    print("\nAblation (all 2025 test CVEs):")
    print(ablation.round(4).to_string(index=False))
    print("\nSignificance (paired bootstrap, 2,000 resamples):")
    print(significance.round(4).to_string(index=False))
    print(f"\nResults written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
