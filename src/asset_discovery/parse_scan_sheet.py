"""
Parses a scan sheet: a CSV with one row per discovered service, combining
what an Nmap service scan reports (IP, port, product, version, CPE) with
the asset inventory fields the assessment needs (criticality, exposure).

Used for demonstrations and for scan results typed up or exported from
other tools. Real Nmap XML is handled by parse_nmap.py; both produce the
same service table, so the assessment is identical.

Columns (header row required):
    scan_date          YYYY-MM-DD (same for every row)
    asset_id           e.g. D001
    hostname           e.g. web-01
    ip_address         IPv4 address
    asset_type         e.g. Web Server
    operating_system   e.g. Ubuntu Server
    criticality        High / Medium / Low
    internet_exposed   Yes / No
    port               TCP port, blank for software found by endpoint inventory
    protocol           tcp / udp (blank when port is blank)
    service            e.g. https
    product            e.g. Apache httpd
    version            e.g. 2.4.62
    cpe                CPE 2.2 URI, e.g. cpe:/a:apache:http_server:2.4.62

Run from the project root to check a sheet:
    python -m src.asset_discovery.parse_scan_sheet <sheet.csv>
"""

import io
import ipaddress
import re
import sys

import pandas as pd

from src.asset_discovery.parse_nmap import COLUMNS, parse_cpe22

SHEET_COLUMNS = [
    "scan_date", "asset_id", "hostname", "ip_address", "asset_type", "operating_system",
    "criticality", "internet_exposed", "port", "protocol", "service", "product", "version", "cpe",
]
REQUIRED = ["scan_date", "asset_id", "hostname", "ip_address", "criticality",
            "internet_exposed", "product", "version", "cpe"]
INVENTORY_COLUMNS = ["asset_id", "hostname", "ip_address", "asset_type", "operating_system",
                     "criticality", "internet_exposed"]

MAX_BYTES = 2_000_000
MAX_ROWS = 5_000
CPE_PATTERN = re.compile(r"^cpe:/[aoh]:[^:\s]+:[^:\s]+(:[^:\s]+)?$")
# Cells starting with these run as formulas when a CSV export is opened in Excel
FORMULA_START = ("=", "+", "-", "@")


class ScanSheetError(ValueError):
    """The sheet cannot be used; .problems lists every reason."""

    def __init__(self, problems):
        super().__init__("; ".join(problems))
        self.problems = problems


def parse_scan_sheet(data):
    """CSV bytes -> (services in the Nmap parser's format, inventory, scan date)."""
    if len(data) > MAX_BYTES:
        raise ScanSheetError([f"File is larger than {MAX_BYTES // 1_000_000} MB"])

    try:
        sheet = pd.read_csv(io.BytesIO(data), dtype=str, encoding="utf-8-sig",
                            keep_default_na=False).apply(lambda c: c.str.strip())
    except (UnicodeDecodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        raise ScanSheetError([f"Not a readable CSV file ({error.__class__.__name__})"])

    sheet.columns = [c.strip().lower() for c in sheet.columns]
    missing = [c for c in REQUIRED if c not in sheet.columns]
    if missing:
        raise ScanSheetError([f"Missing column(s): {', '.join(missing)}"])
    if sheet.empty:
        raise ScanSheetError(["The sheet has no rows"])
    if len(sheet) > MAX_ROWS:
        raise ScanSheetError([f"More than {MAX_ROWS:,} rows"])

    for column in SHEET_COLUMNS:
        if column not in sheet.columns:
            sheet[column] = ""

    problems = []

    def check(mask, message):
        rows = (sheet.index[mask] + 2).tolist()          # +2: header row, 1-based
        if rows:
            shown = ", ".join(map(str, rows[:8])) + (" ..." if len(rows) > 8 else "")
            problems.append(f"{message} (row {shown})")

    for column in REQUIRED:
        check(sheet[column] == "", f"Empty {column}")

    def bad_ip(value):
        try:
            return ipaddress.ip_address(value).version != 4
        except ValueError:
            return True

    check(sheet["ip_address"].ne("") & sheet["ip_address"].map(bad_ip), "Invalid IPv4 address")
    check(sheet["criticality"].ne("") & ~sheet["criticality"].str.title().isin(["High", "Medium", "Low"]),
          "Criticality must be High, Medium or Low")
    check(sheet["internet_exposed"].ne("") & ~sheet["internet_exposed"].str.title().isin(["Yes", "No"]),
          "internet_exposed must be Yes or No")
    check(sheet["cpe"].ne("") & ~sheet["cpe"].str.match(CPE_PATTERN), "CPE must look like cpe:/a:vendor:product:version")
    check(sheet["port"].ne("") & ~sheet["port"].str.fullmatch(r"\d{1,5}").fillna(False), "Port must be a number")
    check(sheet["port"].str.fullmatch(r"\d{1,5}").fillna(False)
          & (pd.to_numeric(sheet["port"], errors="coerce") > 65535), "Port above 65535")
    text = ["asset_id", "hostname", "asset_type", "operating_system", "service", "product", "version"]
    check(sheet[text].apply(lambda c: c.str.startswith(FORMULA_START)).any(axis=1),
          "Text cells must not start with = + - @ (spreadsheet formula injection)")

    dates = pd.to_datetime(sheet["scan_date"], format="%Y-%m-%d", errors="coerce")
    check(sheet["scan_date"].ne("") & dates.isna(), "scan_date must be YYYY-MM-DD")
    if dates.nunique() > 1:
        problems.append("Use one scan_date for the whole sheet")

    conflicts = sheet.groupby("ip_address")[["asset_id", "hostname", "criticality", "internet_exposed"]].nunique()
    for ip in conflicts.index[(conflicts > 1).any(axis=1)]:
        problems.append(f"{ip} has different asset details on different rows")

    if problems:
        raise ScanSheetError(problems)

    sheet["criticality"] = sheet["criticality"].str.title()
    sheet["internet_exposed"] = sheet["internet_exposed"].str.title()
    scan_date = dates.iloc[0].normalize()

    inventory = sheet[INVENTORY_COLUMNS].drop_duplicates("ip_address").reset_index(drop=True)

    services = sheet.assign(
        scan_time=pd.Timestamp(scan_date, tz="UTC"),
        port=pd.to_numeric(sheet["port"], errors="coerce").astype("Int64"),
        protocol=sheet["protocol"].replace("", None),
        service=sheet["service"].replace("", None),
    )
    services = pd.concat([services.reset_index(drop=True),
                          pd.DataFrame([parse_cpe22(c) for c in services["cpe"]])], axis=1)

    return services[COLUMNS], inventory, scan_date


if __name__ == "__main__":
    pd.set_option("display.width", 200)
    try:
        services, inventory, scan_date = parse_scan_sheet(open(sys.argv[1], "rb").read())
    except ScanSheetError as error:
        print("Sheet rejected:")
        print("\n".join(f"  - {p}" for p in error.problems))
        sys.exit(1)
    print(f"Scan date: {scan_date:%Y-%m-%d}  assets: {len(inventory)}  services: {len(services)}")
    print(services.drop(columns=["scan_time"]).to_string(index=False))
