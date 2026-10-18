"""
Rolling-year evaluation: is the 2025 result a lucky year?

The main experiment tests once, on 2025. Here the same model (LightGBM +
description text, the hyperparameters chosen on 2024 in train_models.py) is
retrained and tested on three different years:

    test 2023   trained on CVEs published 2021-11-03 .. 2022-12-31
    test 2024   trained on CVEs published 2021-11-03 .. 2023-12-31
    test 2025   trained on CVEs published 2021-11-03 .. 2024-12-31

Labels "as known at the time": a training CVE counts as exploited only if
CISA added it to KEV before the test year started. A late-2023 CVE that was
listed in mid-2024 is NOT a positive when training for the 2024 test, because
nobody retraining on 1 Jan 2024 could have known it. This is stricter than an
ordinary split and is exactly how a yearly retraining would work in practice.
Test labels are the normal future_kev target (listed within 12 months).

Each year is compared with the CVSS score (usual practice), the vendor's KEV
history and EPSS (first weekly snapshot after publication, as in benchmark.py;
each snapshot holds the EPSS version that was live on that date).
Differences are tested with the paired bootstrap from benchmark.py.

Run from the project root (about 10 minutes; EPSS downloads are cached):
    python -m src.evaluation.rolling_years
"""

import json
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

import src.evaluation.benchmark as benchmark
from src.evaluation.benchmark import paired_bootstrap, summary, METRICS
from src.models.train_models import FEATURES_FILE, TARGET, fit_model, prepare_features

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

OUTPUT_DIR = Path("results/benchmark")
SELECTED_FILE = Path("results/selected_models.json")
KEV_FILE = Path("data/processed/nvd_kev_integrated.csv")
EPSS_DIR = Path("data/external/epss")
MODEL = "lightgbm [tabular+text]"
TEST_YEARS = [2023, 2024, 2025]


def load_data():
    df = pd.read_csv(FEATURES_FILE, parse_dates=["published_date"])
    df = prepare_features(df[df["nvd_analysed"] == 1])
    kev = pd.read_csv(KEV_FILE, usecols=["cve_id", "kev_date_added"], parse_dates=["kev_date_added"])
    return df.merge(kev.drop_duplicates("cve_id"), on="cve_id", how="left")


def epss_scores(test, year):
    """EPSS per test CVE (cached per year; the 2025 file is the one benchmark.py made)."""
    cache = EPSS_DIR / ("epss_test_scores.csv" if year == 2025 else f"epss_{year}_scores.csv")
    benchmark.EPSS_CACHE = cache
    return benchmark.epss_for(test)


def run_year(df, year, params):
    start = pd.Timestamp(f"{year}-01-01")
    train = df[df["published_date"] < start]
    test = df[df["published_date"].dt.year == year]

    # Labels as known on 1 January of the test year
    y_train = (train[TARGET].eq(1) & (train["kev_date_added"] < start)).astype(int).to_numpy()
    model = fit_model("lightgbm", params, "undersampled", True, train, y_train)

    y = test[TARGET].to_numpy()
    scores = {
        "Our model": model.predict_proba(test)[:, 1],
        "CVSS score": test["cvss_score"].fillna(0).to_numpy(),
        "Vendor KEV history": test["vendor_prior_kev"].to_numpy().astype(float),
    }
    epss = epss_scores(test, year).set_index("cve_id")["epss"]
    has_epss = test["cve_id"].isin(epss.index).to_numpy()

    info = {"test_year": year, "train_cves": len(train), "train_positives": int(y_train.sum()),
            "train_positives_hidden": int(train[TARGET].sum() - y_train.sum()),
            "test_cves": len(test), "test_positives": int(y.sum()),
            "test_with_epss": int(has_epss.sum()), "test_positives_with_epss": int(y[has_epss].sum())}
    rows = [{"test_year": year, "method": name, "data": "All test CVEs", **summary(y, s)}
            for name, s in scores.items()]
    tests = [{"test_year": year, "comparison": f"Our model vs {other}", "metric": metric,
              "data": "All test CVEs", **paired_bootstrap(y, scores["Our model"], scores[other], fn)}
             for other in ["CVSS score"] for metric, fn in METRICS.items()]

    # EPSS on the CVEs it covers (all methods re-scored on that subset for fairness)
    if has_epss.sum() and y[has_epss].sum():
        sub_y = y[has_epss]
        sub_epss = test.loc[has_epss, "cve_id"].map(epss).to_numpy()
        for name, s in [("Our model", scores["Our model"][has_epss]),
                        ("CVSS score", scores["CVSS score"][has_epss]), ("EPSS", sub_epss)]:
            rows.append({"test_year": year, "method": name, "data": "CVEs with EPSS", **summary(sub_y, s)})
        tests += [{"test_year": year, "comparison": "Our model vs EPSS", "metric": metric,
                   "data": "CVEs with EPSS",
                   **paired_bootstrap(sub_y, scores["Our model"][has_epss], sub_epss, fn)}
                  for metric, fn in METRICS.items()]
    return info, rows, tests


def plot(results, path):
    data = results[results["data"] == "All test CVEs"]
    methods = ["Our model", "CVSS score", "Vendor KEV history"]
    colours = ["#2a78d6", "#eb6834", "#898781"]
    fig, ax = plt.subplots(figsize=(7.5, 4))
    width = 0.26
    for i, (method, colour) in enumerate(zip(methods, colours)):
        values = data[data["method"] == method].set_index("test_year")["recall_top_5pct"]
        bars = ax.bar(np.arange(len(TEST_YEARS)) + (i - 1) * width, values.reindex(TEST_YEARS) * 100,
                      width, label=method, color=colour)
        ax.bar_label(bars, fmt="%.0f%%", fontsize=8)
    ax.set_xticks(range(len(TEST_YEARS)), [str(y) for y in TEST_YEARS])
    ax.set_ylabel("Exploited CVEs found in top 5% (%)")
    ax.set_title("Recall in the top 5% of CVEs, each test year", loc="left")
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main():
    params = json.loads(SELECTED_FILE.read_text())[MODEL]["params"]
    df = load_data()
    infos, rows, tests = [], [], []
    for year in TEST_YEARS:
        print(f"\n=== Test year {year} ===", flush=True)
        info, r, t = run_year(df, year, params)
        print(json.dumps(info))
        infos.append(info)
        rows += r
        tests += t

    results = pd.DataFrame(rows)
    significance = pd.DataFrame(tests)
    significance["significant"] = significance["p_value"] < 0.05
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results.to_csv(OUTPUT_DIR / "rolling_years.csv", index=False)
    significance.to_csv(OUTPUT_DIR / "rolling_years_significance.csv", index=False)
    pd.DataFrame(infos).to_csv(OUTPUT_DIR / "rolling_years_folds.csv", index=False)
    plot(results, OUTPUT_DIR / "rolling_years.png")

    pd.set_option("display.width", 200)
    print("\n", pd.DataFrame(infos).to_string(index=False))
    print("\n", results.round(3).to_string(index=False))
    print("\n", significance.round(3).to_string(index=False))


if __name__ == "__main__":
    main()
