import pandas as pd

file_path = "data/processed/nvd_2023_clean.csv"

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

print("\nCVSS severity distribution:")
print(df["cvss_severity"].value_counts(dropna=False))