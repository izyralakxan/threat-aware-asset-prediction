import re

import numpy as np
import pandas as pd

# ==============================
# Configuration
# ==============================

PREDICTION_FILE = "data/processed/prediction_dataset.csv"
INTEGRATED_FILE = "data/processed/nvd_kev_integrated.csv"
OUTPUT_FILE = "data/processed/features.csv"

# Unlabelled features for every CVE published since the study start,
# including after the training cutoff, for scoring assets' CVEs
SCORING_FILE = "data/processed/scoring_features.csv"
SCORING_START = pd.Timestamp("2021-11-03")  # same as STUDY_START

HISTORY_WINDOW_DAYS = 365

# Sentences stating exploitation STATUS (not mechanics). NVD keeps only
# the current description, and vendors add such statements once
# exploitation is known (e.g. "Apple is aware of a report that this
# issue may have been exploited"), so they would leak the label.
# Generic mechanics ("an attacker could exploit this by...") are kept.
EXPLOITATION_STATUS = re.compile(
    r"in the wild"
    r"|(?:has|have|had|was|were|been|being|is|are|actively|reportedly)\s+(?:\w+\s+)?exploited"
    r"|aware of (?:a |public )?reports?"
    r"|active(?:ly)? exploit"
    r"|known exploited|\bKEV\b"
    r"|exploitation (?:has been |was )?(?:detected|observed|reported)"
    r"|exploited (?:by|as) (?:a )?(?:threat|zero|0-?day)"
    r"|zero-day|0-day"
    r"|found weaponi[sz]ed"
    r"|for (?:potential|signs of) exploitation"
    r"|\bunexploited\b",
    re.IGNORECASE,
)


# ==============================
# Helpers
# ==============================

def split_values(series):
    # "a;b;c" -> ["a", "b", "c"], missing -> []
    return series.fillna("").str.split(";").apply(
        lambda values: [v for v in values if v]
    )


def prior_event_counts(df, key_column, events, window_days=None):
    """
    For each CVE, count events (KEV additions or CVE publications) for
    its keys (vendors or CWEs) that happened strictly BEFORE the CVE's
    publication day. A CVE with several keys takes the maximum.

    Only past events are counted, so the feature reflects what was
    publicly known at prediction time.
    """
    # One row per (CVE, key); "row_id" maps back to the CVE
    rows = df[["published_date", key_column]].explode(key_column)
    rows = rows.dropna(subset=[key_column])
    rows = rows.rename_axis("row_id").reset_index()

    event_dates = {
        key: np.sort(group["event_date"].values)
        for key, group in events.groupby("key")
    }

    counts = np.zeros(len(rows), dtype="int64")

    for key, positions in rows.groupby(key_column).indices.items():

        dates = event_dates.get(key)

        if dates is None:
            continue

        published = rows["published_date"].values[positions]

        # side="left": events on the publication day itself are excluded
        before = np.searchsorted(dates, published, side="left")

        if window_days is not None:
            start = published - np.timedelta64(window_days, "D")
            before = before - np.searchsorted(dates, start, side="left")

        counts[positions] = before

    # Max over the CVE's keys; CVEs with no keys get 0
    counts = pd.Series(counts).groupby(rows["row_id"].values).max()

    return counts.reindex(df.index, fill_value=0)


def redact_exploitation_status(text):
    sentences = re.split(r"(?<=[.!?])\s+", text)
    return " ".join(s for s in sentences if not EXPLOITATION_STATUS.search(s))


def build_events(df, key_column, date_column):
    events = df[[key_column, date_column]].explode(key_column)
    events = events.dropna(subset=[key_column, date_column])
    return events.rename(columns={key_column: "key", date_column: "event_date"})




def load_history():
    history = pd.read_csv(
        INTEGRATED_FILE,
        usecols=["cve_id", "published_date", "kev_date_added", "vendor", "cwe"]
    )

    history["published_date"] = pd.to_datetime(
        history["published_date"]
    ).dt.normalize()

    history["kev_date_added"] = pd.to_datetime(history["kev_date_added"])

    history["vendor_list"] = split_values(history["vendor"])
    history["cwe_list"] = split_values(history["cwe"])

    return history


def add_features(df, history):
    """
    Adds model features to CVE rows. Every feature uses only the CVE's
    own record and events strictly before its publication day.
    """
    df = df.copy()

    # ---- Multi-valued fields ----

    df["vendor_list"] = split_values(df["vendor"])
    df["cwe_list"] = split_values(df["cwe"])

    # ---- Structural features ----

    df["vendor_count"] = df["vendor_list"].str.len()
    df["product_count"] = split_values(df["product"]).str.len()
    df["cwe_count"] = df["cwe_list"].str.len()

    # NVD has assigned CPE data. In 2024-2025 NVD prioritised analysing
    # KEV-listed CVEs, so this flag partly reflects the future label and
    # is used only to define the evaluation population, never as a feature.
    df["nvd_analysed"] = (df["vendor_count"] > 0).astype(int)

    # ---- Description text ----

    df["description"] = df["description"].fillna("")
    df["description_clean"] = df["description"].apply(redact_exploitation_status)
    df["description_redacted"] = (
        df["description_clean"] != df["description"]
    ).astype(int)
    df = df.drop(columns=["description"])

    # ---- Threat-history features (only events before publication) ----

    vendor_kev = build_events(history, "vendor_list", "kev_date_added")
    cwe_kev = build_events(history, "cwe_list", "kev_date_added")
    vendor_cves = build_events(history, "vendor_list", "published_date")

    df["vendor_prior_kev"] = prior_event_counts(df, "vendor_list", vendor_kev)

    df["vendor_prior_kev_1y"] = prior_event_counts(
        df, "vendor_list", vendor_kev, HISTORY_WINDOW_DAYS
    )

    df["cwe_prior_kev"] = prior_event_counts(df, "cwe_list", cwe_kev)

    # How many CVEs the vendor already had: a proxy for how widely
    # deployed and closely studied its products are
    df["vendor_prior_cves"] = prior_event_counts(df, "vendor_list", vendor_cves)

    # Share of the vendor's past CVEs that ended up exploited
    df["vendor_prior_kev_rate"] = (
        df["vendor_prior_kev"] / df["vendor_prior_cves"].replace(0, np.nan)
    ).fillna(0)

    return df.drop(columns=["vendor_list", "cwe_list"])


def build_training_features(history):
    df = pd.read_csv(PREDICTION_FILE, parse_dates=["published_date"])

    print(f"Prediction records: {len(df)}")

    df = add_features(df, history)

    print("Descriptions with exploitation-status sentences removed:")
    print(df.groupby("future_kev")["description_redacted"]
          .agg(["sum", "mean"]).round(4))

    df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nTraining features: {OUTPUT_FILE} ({len(df)} records)")

    print("\nMean history features by target:")
    print(
        df.groupby("future_kev")[
            ["vendor_prior_kev", "vendor_prior_kev_1y", "cwe_prior_kev",
             "vendor_prior_cves", "vendor_prior_kev_rate"]
        ].mean().round(3).to_string()
    )


def build_scoring_features(history):
    df = pd.read_csv(INTEGRATED_FILE)

    df["published_date"] = pd.to_datetime(df["published_date"]).dt.normalize()
    df = df[df["published_date"] >= SCORING_START]

    # Label and leakage-prone columns are not needed for scoring;
    # kev_date_added is kept to report current KEV status separately
    df = df.drop(columns=["last_modified", "vuln_status", "kev_status",
                          "ransomware_use", "forensic_triage"])

    df = add_features(df, history)
    df.to_csv(SCORING_FILE, index=False)

    print(f"\nScoring features: {SCORING_FILE} ({len(df)} records, "
          f"published {df['published_date'].min().date()} .. "
          f"{df['published_date'].max().date()})")


def main():
    print("Loading history...")
    history = load_history()
    print(f"History records (all NVD): {len(history)}")

    build_training_features(history)
    build_scoring_features(history)


if __name__ == "__main__":
    main()
