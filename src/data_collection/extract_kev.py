import json
import csv
from pathlib import Path


INPUT_FILE = Path(
    "data/raw/cisa_kev/known_exploited_vulnerabilities.json"
)

OUTPUT_FILE = Path(
    "data/processed/cisa_kev_clean.csv"
)


FIELDNAMES = [
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "short_description",
    "required_action",
    "due_date",
    "known_ransomware_campaign_use",
    "forensic_triage",
    "cwes"
]


def kev_row(vulnerability):
    """One entry of the CISA KEV JSON feed -> one row of cisa_kev_clean.csv."""
    cwes = vulnerability.get("cwes", [])
    return {
        "cve_id": vulnerability.get("cveID"),
        "vendor_project": vulnerability.get("vendorProject"),
        "product": vulnerability.get("product"),
        "vulnerability_name": vulnerability.get("vulnerabilityName"),
        "date_added": vulnerability.get("dateAdded"),
        "short_description": vulnerability.get("shortDescription"),
        "required_action": vulnerability.get("requiredAction"),
        "due_date": vulnerability.get("dueDate"),
        "known_ransomware_campaign_use": vulnerability.get("knownRansomwareCampaignUse"),
        "forensic_triage": vulnerability.get("forensicTriage"),
        "cwes": ";".join(cwes) if cwes else None,
    }


def main():

    print("Reading CISA KEV dataset...")

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    vulnerabilities = data["vulnerabilities"]

    print(f"Total KEV vulnerabilities: {len(vulnerabilities)}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = FIELDNAMES

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for vulnerability in vulnerabilities:
            writer.writerow(kev_row(vulnerability))

    print("\nExtraction completed.")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()