from pathlib import Path
import pandas as pd

# Find the project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Location of asset inventory
asset_file = PROJECT_ROOT / "data" / "raw" / "assets.csv"

# Load asset inventory
assets = pd.read_csv(asset_file)

print("\n=== Asset Inventory ===")
print(assets)

print("\n=== Dataset Shape ===")
print(f"Rows: {assets.shape[0]}")
print(f"Columns: {assets.shape[1]}")

print("\n=== Column Names ===")
print(list(assets.columns))

print("\n=== Missing Values ===")
print(assets.isnull().sum())