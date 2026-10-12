import pandas as pd

file_path = "data/processed/cisa_kev_clean.csv"

df = pd.read_csv(file_path)

print("Dataset shape:")
print(df.shape)

print("\nColumns:")
for column in df.columns:
    print("-", column)

print("\nFirst 5 records:")
print(df.head())

print("\nMissing values:")
print(df.isnull().sum())

print("\nRansomware usage:")
print(
    df["known_ransomware_campaign_use"]
    .value_counts(dropna=False)
)