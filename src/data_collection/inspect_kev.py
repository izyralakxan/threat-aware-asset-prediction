import json

file_path = "data/raw/cisa_kev/known_exploited_vulnerabilities.json"

with open(file_path, "r", encoding="utf-8") as file:
    data = json.load(file)

print("Top-level keys:")
print(data.keys())

print("\nTotal vulnerabilities:")
print(len(data["vulnerabilities"]))

print("\nFirst vulnerability:")
print(data["vulnerabilities"][0])