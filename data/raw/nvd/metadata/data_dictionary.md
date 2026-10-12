# NVD + CISA KEV Research Dataset

## Purpose

This dataset combines vulnerability information from the
National Vulnerability Database (NVD) with exploitation information
from the CISA Known Exploited Vulnerabilities (KEV) Catalog.

The dataset will support research into whether vulnerability and
asset characteristics can be used to predict future cyber exposure risk.

## Source Files

All NVD JSON 2.0 yearly feeds (`nvdcve-2.0-2002.json.gz` to
`nvdcve-2.0-2026.json.gz`). Feeds are grouped by CVE-ID year, not
publication year, so all are loaded and filtered by publication date.
Rejected CVEs are excluded.

## Initial NVD Features

- cve_id
- published_date
- last_modified
- vuln_status (current NVD processing status; not used as a feature)
- cvss_version (3.1 preferred, 3.0 fallback; NVD Primary score preferred)
- cvss_score
- cvss_severity
- attack_vector
- attack_complexity
- privileges_required
- user_interaction
- scope
- confidentiality_impact
- integrity_impact
- availability_impact
- exploitability_score
- impact_score
- cwe
- vendor
- product

## Initial CISA KEV Features

- kev_status
- kev_date_added
- ransomware_use
- forensic_triage

## Important Research Principle

Features used for prediction must represent information available
at or before the defined prediction cutoff date.

Information added after the prediction cutoff must not be used as
an input feature for that prediction.

This is intended to reduce temporal data leakage.

## Prediction Target (future_kev)

- Study period: CVEs published 2021-11-03 (CISA KEV launch) to
  2025-08-27. The KEV snapshot runs to 2026-09-22, so every included CVE
  has a complete 12-month follow-up (the cutoff is conservative).
- `future_kev = 1` if the CVE was added to KEV strictly after its NVD
  publication day and within 12 months of it.
- CVEs added to KEV on or before their publication day are excluded:
  they were already known exploited, so there is nothing to predict.
- Dates are compared at day level, since KEV dates carry no time.

## Known Limitations

- NVD fields (CVSS, CWE, CPE vendor/product) reflect the current record,
  not the record as it was at publication, and may have been revised
  after exploitation became known.
- NVD's analysis backlog leaves vendor/product missing for many recent
  CVEs (about 20% of 2024 and 35% of 2025 publications).