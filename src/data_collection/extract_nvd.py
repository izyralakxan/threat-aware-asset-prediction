import gzip
import json
import csv
from pathlib import Path


RAW_DIR = Path(
    "data/raw/nvd/raw"
)

# NVD yearly feeds are grouped by CVE-ID year, not publication year.
# Old IDs keep being published years later, so all feeds are loaded
# and filtered by publication date downstream. (The 2002 feed also
# holds the 1999-2001 IDs.)
FEED_YEARS = list(range(2002, 2027))

OUTPUT_FILE = Path(
    "data/processed/nvd_clean.csv"
)


def select_metric(metric_list):
    # Prefer NVD's own ("Primary") assessment so scoring is consistent
    # across years; fall back to the CNA ("Secondary") score.
    for metric in metric_list:
        if metric.get("type") == "Primary":
            return metric

    return metric_list[0]


def get_cvss_data(cve):
    metrics = cve.get("metrics", {})

    # CVSS v3.1 preferred; older CVEs often only have v3.0
    for key, version in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")]:

        if not metrics.get(key):
            continue

        metric = select_metric(metrics[key])
        cvss = metric.get("cvssData", {})

        return {
            "cvss_version": version,
            "cvss_score": cvss.get("baseScore"),
            "cvss_severity": cvss.get("baseSeverity"),
            "attack_vector": cvss.get("attackVector"),
            "attack_complexity": cvss.get("attackComplexity"),
            "privileges_required": cvss.get("privilegesRequired"),
            "user_interaction": cvss.get("userInteraction"),
            "scope": cvss.get("scope"),
            "confidentiality_impact": cvss.get("confidentialityImpact"),
            "integrity_impact": cvss.get("integrityImpact"),
            "availability_impact": cvss.get("availabilityImpact"),
            "exploitability_score": metric.get("exploitabilityScore"),
            "impact_score": metric.get("impactScore"),
        }

    return {
        "cvss_version": None,
        "cvss_score": None,
        "cvss_severity": None,
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
        "scope": None,
        "confidentiality_impact": None,
        "integrity_impact": None,
        "availability_impact": None,
        "exploitability_score": None,
        "impact_score": None,
    }


def get_cwe(cve):
    weaknesses = cve.get("weaknesses", [])

    cwes = []

    for weakness in weaknesses:
        for description in weakness.get("description", []):
            value = description.get("value")

            if value and value.startswith("CWE-"):
                cwes.append(value)

    return ";".join(sorted(set(cwes))) if cwes else None


def get_description(cve):
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            # Single line keeps the CSV easy to inspect
            return " ".join(description.get("value", "").split())

    return None


def get_affected_products(cve):
    configurations = cve.get("configurations", [])

    vendors = []
    products = []

    for configuration in configurations:
        nodes = configuration.get("nodes", [])

        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])

            for cpe_match in cpe_matches:
                criteria = cpe_match.get("criteria", "")

                parts = criteria.split(":")

                if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
                    vendor = parts[3]
                    product = parts[4]

                    if vendor and vendor != "*":
                        vendors.append(vendor)

                    if product and product != "*":
                        products.append(product)

    vendor_text = ";".join(sorted(set(vendors))) if vendors else None
    product_text = ";".join(sorted(set(products))) if products else None

    return vendor_text, product_text

FIELDNAMES = [
    "cve_id",
    "published_date",
    "last_modified",
    "vuln_status",
    "cvss_version",
    "cvss_score",
    "cvss_severity",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "exploitability_score",
    "impact_score",
    "cwe",
    "vendor",
    "product",
    "description",
]


def cve_row(cve):
    """One NVD CVE record (feed or API) -> one row of nvd_clean.csv."""
    vendor, product = get_affected_products(cve)
    return {
        "cve_id": cve.get("id"),
        "published_date": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cwe": get_cwe(cve),
        "vendor": vendor,
        "product": product,
        "description": get_description(cve),
        **get_cvss_data(cve),
    }


def main():

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "cve_id",
        "published_date",
        "last_modified",
        "vuln_status",
        "cvss_version",
        "cvss_score",
        "cvss_severity",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction",
        "scope",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
        "exploitability_score",
        "impact_score",
        "cwe",
        "vendor",
        "product",
        "description",
    ]

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

        total = 0

        for year in FEED_YEARS:

            input_file = RAW_DIR / f"nvdcve-2.0-{year}.json.gz"

            print(f"Reading {input_file}...")

            with gzip.open(input_file, "rt", encoding="utf-8") as file:
                data = json.load(file)

            vulnerabilities = data["vulnerabilities"]

            print(f"  Vulnerabilities: {len(vulnerabilities)}")

            for item in vulnerabilities:

                cve = item.get("cve", {})

                # Rejected CVEs are withdrawn entries, not real vulnerabilities
                if cve.get("vulnStatus") == "Rejected":
                    continue

                writer.writerow(cve_row(cve))

                total += 1

    print("\nExtraction completed.")
    print(f"Records written (excluding rejected): {total}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()