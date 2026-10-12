import gzip
import json

file_path = "data/raw/nvd/raw/nvdcve-2.0-2023.json.gz"

with gzip.open(file_path, "rt", encoding="utf-8") as file:
    data = json.load(file)

print("Top-level keys:")
print(data.keys())

print("\nNumber of vulnerabilities:")
print(len(data["vulnerabilities"]))

print("\nFirst vulnerability:")
print(data["vulnerabilities"][0])