import pandas as pd

# ==============================
# Configuration
# ==============================

INPUT_FILE = "data/processed/nvd_kev_integrated.csv"
OUTPUT_FILE = "data/processed/prediction_dataset.csv"

PREDICTION_HORIZON_MONTHS = 12

# CISA KEV launch date. Starting here means every CVE's 12-month
# follow-up window lies entirely within the period KEV existed.
# Earlier cohorts are labelled mainly by the catalogue's initial
# bulk back-fill rather than by when exploitation became known.
STUDY_START = pd.Timestamp("2021-11-03")

# Every included CVE has a complete 12-month follow-up: the KEV snapshot
# runs to 2026-09-22, so this cutoff is conservative by ~4 weeks
OBSERVATION_CUTOFF = pd.Timestamp("2025-08-27")


# ==============================
# Load integrated dataset
# ==============================

print("Loading integrated dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Original records: {len(df)}")


# ==============================
# Convert date columns
# ==============================

# KEV dates have no time component, so publication dates are
# compared at day level (otherwise same-day additions look "earlier")
df["published_date"] = pd.to_datetime(
    df["published_date"],
    errors="coerce"
).dt.normalize()

df["kev_date_added"] = pd.to_datetime(
    df["kev_date_added"],
    errors="coerce"
)


# ==============================
# Keep only records inside the
# study period with complete
# 12-month follow-up
# ==============================

df = df[
    (df["published_date"] >= STUDY_START)
    &
    (df["published_date"] <= OBSERVATION_CUTOFF)
].copy()

print(f"Records in study period: {len(df)}")


# ==============================
# Exclude CVEs already known to be
# exploited at publication time
# ==============================

# These were in KEV on or before the day NVD published them, so there
# is no future event to predict. Labelling them 0 would mark confirmed
# exploited vulnerabilities as negatives.
already_exploited = (
    df["kev_date_added"].notna()
    &
    (df["kev_date_added"] <= df["published_date"])
)

print(f"Excluded (KEV on/before publication): {already_exploited.sum()}")

df = df[~already_exploited].copy()

print(f"Eligible records: {len(df)}")


# ==============================
# Create 12-month prediction window
# ==============================

df["prediction_end_date"] = (
    df["published_date"]
    + pd.DateOffset(months=PREDICTION_HORIZON_MONTHS)
)


# ==============================
# Create future KEV target
# ==============================

df["future_kev"] = (
    df["kev_date_added"].notna()
    &
    (df["kev_date_added"] > df["published_date"])
    &
    (df["kev_date_added"] <= df["prediction_end_date"])
).astype(int)


# ==============================
# Create time-based features
# ==============================

df["publication_year"] = df["published_date"].dt.year
df["publication_month"] = df["published_date"].dt.month
df["publication_day_of_week"] = df["published_date"].dt.dayofweek


# ==============================
# Remove leakage-prone columns
# ==============================

columns_to_remove = [
    "last_modified",
    "vuln_status",
    "kev_date_added",
    "kev_status",
    "ransomware_use",
    "forensic_triage",
    "prediction_end_date"
]

df = df.drop(
    columns=columns_to_remove,
    errors="ignore"
)


# ==============================
# Save prediction dataset
# ==============================

df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ==============================
# Summary
# ==============================

print("\nPrediction dataset created successfully.")
print(f"Output file: {OUTPUT_FILE}")
print(f"Records: {len(df)}")
print(f"Columns: {len(df.columns)}")

print("\nTarget distribution:")
print(df["future_kev"].value_counts())

print("\nTarget percentage:")
print(
    df["future_kev"]
    .value_counts(normalize=True)
    .mul(100)
    .round(2)
)

print("\nRecords and positives by publication year:")
print(
    df.groupby("publication_year")["future_kev"]
    .agg(records="count", positives="sum")
)