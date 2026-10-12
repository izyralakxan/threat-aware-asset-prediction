import pandas as pd
from pathlib import Path


NVD_FILE = Path(
    "data/processed/nvd_clean.csv"
)

KEV_FILE = Path(
    "data/processed/cisa_kev_clean.csv"
)

OUTPUT_FILE = Path(
    "data/processed/nvd_kev_integrated.csv"
)


def main():

    print("Loading NVD dataset...")
    nvd = pd.read_csv(NVD_FILE)

    print(f"NVD records: {len(nvd)}")

    print("\nLoading CISA KEV dataset...")
    kev = pd.read_csv(KEV_FILE)

    print(f"KEV records: {len(kev)}")

    # Keep only the KEV fields needed for integration
    kev_data = kev[
        [
            "cve_id",
            "date_added",
            "known_ransomware_campaign_use",
            "forensic_triage"
        ]
    ].copy()

    # Rename KEV fields to make their meaning clear
    kev_data = kev_data.rename(
        columns={
            "date_added": "kev_date_added",
            "known_ransomware_campaign_use": "ransomware_use",
            "forensic_triage": "forensic_triage"
        }
    )

    # Remove duplicate CVE IDs if any
    kev_data = kev_data.drop_duplicates(
        subset=["cve_id"]
    )

    # Left join: keep every NVD vulnerability
    integrated = nvd.merge(
        kev_data,
        on="cve_id",
        how="left"
    )

    # Create KEV status
    integrated["kev_status"] = (
        integrated["kev_date_added"]
        .notna()
        .astype(int)
    )

    # Save integrated dataset
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    integrated.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\nIntegration completed.")

    print(
        f"Integrated records: {len(integrated)}"
    )

    print(
        f"Integrated columns: {len(integrated.columns)}"
    )

    print("\nKEV status:")
    print(
        integrated["kev_status"]
        .value_counts()
    )

    print(
        f"\nOutput file: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()