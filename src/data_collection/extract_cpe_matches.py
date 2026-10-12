"""
Extracts NVD's affected-product ranges (configurations -> cpeMatch) so
assets can be matched to CVEs by installed version, not just product.

One row per vulnerable cpeMatch entry:
  cve_id, part, vendor, product, version, update,
  version_start_including, version_start_excluding,
  version_end_including, version_end_excluding

A version of "*" means "any version, subject to the range columns".

Limitation: NVD configurations can be AND-combined (e.g. an app is only
vulnerable when running on a particular OS). Every vulnerable entry is
treated as applicable on its own, which can over-match in such cases.
"""

import csv
import gzip
import json
import re
from pathlib import Path

from src.data_collection.extract_nvd import FEED_YEARS, RAW_DIR

OUTPUT_FILE = Path("data/processed/nvd_cpe_matches.csv.gz")

FIELDS = [
    "cve_id", "part", "vendor", "product", "version", "update",
    "version_start_including", "version_start_excluding",
    "version_end_including", "version_end_excluding",
]

# CPE 2.3 fields are ":"-separated; "\:" is an escaped colon
CPE_SPLIT = re.compile(r"(?<!\\):")


def parse_cpe23(criteria):
    parts = CPE_SPLIT.split(criteria)

    if len(parts) < 7 or parts[0] != "cpe" or parts[1] != "2.3":
        return None

    return {
        "part": parts[2],
        "vendor": parts[3].replace("\\", ""),
        "product": parts[4].replace("\\", ""),
        "version": parts[5].replace("\\", ""),
        "update": parts[6].replace("\\", ""),
    }


def iter_matches(cve):
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):

                if not match.get("vulnerable"):
                    continue

                cpe = parse_cpe23(match.get("criteria", ""))

                if cpe is None:
                    continue

                yield {
                    "cve_id": cve.get("id"),
                    **cpe,
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                }


def main():
    total = 0

    with gzip.open(OUTPUT_FILE, "wt", newline="", encoding="utf-8") as output:

        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()

        for year in FEED_YEARS:

            input_file = RAW_DIR / f"nvdcve-2.0-{year}.json.gz"

            print(f"Reading {input_file}...")

            with gzip.open(input_file, "rt", encoding="utf-8") as file:
                data = json.load(file)

            for item in data["vulnerabilities"]:

                cve = item.get("cve", {})

                if cve.get("vulnStatus") == "Rejected":
                    continue

                seen = set()

                for row in iter_matches(cve):
                    # The same range can appear in several configurations
                    key = tuple(row.values())
                    if key in seen:
                        continue
                    seen.add(key)

                    writer.writerow(row)
                    total += 1

    print("\nExtraction completed.")
    print(f"CPE match rows: {total}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
