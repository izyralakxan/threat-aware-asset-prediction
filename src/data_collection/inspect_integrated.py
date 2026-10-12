import pandas as pd


FILE_PATH = "data/processed/nvd_kev_integrated.csv"


df = pd.read_csv(FILE_PATH)


print("Dataset shape:")
print(df.shape)


print("\nColumns:")
for column in df.columns:
    print("-", column)


print("\nFirst 5 records:")
print(df.head())


print("\nKEV status distribution:")
print(
    df["kev_status"].value_counts()
)


print("\nKEV date information:")
print(
    df["kev_date_added"].notna().sum(),
    "records have a KEV date"
)


print("\nRansomware usage among KEV records:")
print(
    df.loc[
        df["kev_status"] == 1,
        "ransomware_use"
    ].value_counts(dropna=False)
)