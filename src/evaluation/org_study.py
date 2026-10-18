"""
100-organisation patch-plan study (backtest).

Question: if 100 different organisations each patch in the order a plan
suggests, which plan protects the most devices from attacks, fastest?

Design
  - 100 SIMULATED organisations (seeded, reproducible). Each has 10-25
    devices drawn from the 31 device templates of the synthetic lab
    (firewalls, VPN, web, mail, file transfer, domain controllers, databases,
    build/monitoring servers, workstations...) and its own patch maturity:
    every device's patch level (current / typical / lagging / neglected, i.e.
    30 / 120 / 270 / 540 days behind) is drawn from organisation-specific
    proportions. Installed versions are real NVD fix versions as of that date
    (version_as_of, as in the lab and the demo organisations).
  - Decision date S = 2025-08-27 (as the asset-level backtest). Each
    organisation is assessed with ONLY what was known at S, and the planner
    builds its upgrade actions.
  - The SAME actions are put in four orders, so only prioritisation differs:
      Our plan          the planner's order (risk removed: predictions,
                        KEV, business importance, internet exposure)
      CVSS plan         highest CVSS among the CVEs an upgrade fixes
      Criticality plan  most important, internet-facing device first
      Random            average of 20 random orders (the floor)
  - Outcome (not known to any plan): CVEs on each device that attackers
    exploited, i.e. listed in CISA KEV by S + 12 months. A device is
    protected once every upgrade that removes such a CVE from it is done.
    Two outcome sets:
      all exploited     known exploited at S, plus newly exploited in the
                        following year (what protects the organisation)
      newly exploited   only CVEs first listed after S (the pure
                        prediction part: no plan could look these up)
  - Score per organisation and plan: the average share of exposed devices
    protected across the plan (area under the protection curve; 1.0 = every
    device protected by the first fix), plus the share protected after 5
    and 10 fixes. Plans are compared across the 100 organisations with the
    paired Wilcoxon signed-rank test.

Limitations: organisations are simulated; installed versions are assumed
unchanged during the follow-up year; the research model was calibrated on
2024 CVEs, so part of the prediction window at S (Aug-Dec 2024) overlaps
its calibration year (the asset-level backtest has the same caveat).

Speed: matching results are cached per software version (organisations share
templates and patch levels), and organisations run in parallel worker
processes. Neither changes any result.

Run from the project root (about 1 hour on a 4-thread PC):
    python -m src.evaluation.org_study
"""

import json
from multiprocessing import Pool
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon

from src.asset_discovery.parse_scan_sheet import SHEET_COLUMNS, parse_scan_sheet
import src.asset_exposure.assess_exposure as assess_exposure
from src.asset_exposure.assess_exposure import (
    CONFIDENCE_ORDER, CONFIRMED, VENDOR_ALIASES, assess_services, load_reference_data,
    publication_dates,
)
from src.asset_exposure.importance import overall, suggest_cia
from src.evaluation.plan_comparison import compare_plans
from src.lab.build_lab_db import ASSETS, OS_NAMES, PATCH_LAG_DAYS, fixed_versions, version_as_of
from src.remediation.planner import plan_actions

OUTPUT_DIR = Path("results/benchmark")
DECISION_DATE = pd.Timestamp("2025-08-27")
FOLLOW_UP_DAYS = 365
N_ORGS = 100
SIZE_RANGE = (10, 25)
RANDOM_ORDERS = 20
SEED = 42
HYGIENE = ["current", "typical", "lagging", "neglected"]
SEGMENT_NET = {"DMZ": 10, "SERVERS": 20, "MGMT": 5, "WORKSTATIONS": 30}
PLANS = ["Our plan", "CVSS plan", "Criticality plan", "Random"]
WORKERS = 3

_original_match = assess_exposure.match_services
_match_cache = {}


def cached_match(services, cpe_matches, published=None):
    """match_services, computed once per software version and reused for every device
    running it (same output: per-service rows, then the same per-(ip, cve) merge)."""
    parts = []
    for row in services[services["cpe"].notna()].itertuples(index=False):
        key = (row.vendor, row.cpe_product, row.cpe_version, row.version, row.product)
        if key not in _match_cache:
            one = pd.DataFrame([row._asdict()]).assign(ip_address="x", port=0)
            _match_cache[key] = _original_match(one, cpe_matches, published)
        found = _match_cache[key]
        if not found.empty:
            parts.append(found.assign(ip_address=row.ip_address, ports=str(row.port)))
    if not parts:
        return pd.DataFrame()
    matched = pd.concat(parts, ignore_index=True)
    matched["confidence_rank"] = matched["match_confidence"].map({c: i for i, c in enumerate(CONFIDENCE_ORDER)})
    return (matched.sort_values("confidence_rank", kind="stable")
            .groupby(["ip_address", "cve_id"], as_index=False)
            .agg(product=("product", "first"), installed_version=("installed_version", "first"),
                 match_confidence=("match_confidence", "first"),
                 ports=("ports", lambda p: ";".join(sorted(set(";".join(p).split(";")))))))


assess_exposure.match_services = cached_match
match_services = cached_match


def make_org(number, rng, fixes):
    """One simulated organisation as a scan sheet (CSV bytes)."""
    size = int(rng.integers(SIZE_RANGE[0], SIZE_RANGE[1] + 1))
    chosen = [ASSETS[i] for i in sorted(rng.choice(len(ASSETS), size=size, replace=False))]
    maturity = rng.dirichlet(np.ones(len(HYGIENE)))          # this organisation's patch habits
    rows = []
    for asset_id, hostname, segment, host, asset_type, _, _, stack in chosen:
        hygiene = HYGIENE[rng.choice(len(HYGIENE), p=maturity)]
        patch_date = DECISION_DATE - pd.Timedelta(days=PATCH_LAG_DAYS[hygiene])
        ip = f"10.{number}.{SEGMENT_NET[segment]}.{host}"
        for item in stack:
            vendor, product, _, name, port, service = item
            version = version_as_of(fixes, item, patch_date)
            if version is None:
                continue
            is_os = item[:2] in {s[:2] for s in OS_NAMES}
            rows.append({
                "scan_date": DECISION_DATE.date().isoformat(), "asset_id": asset_id,
                "hostname": hostname, "ip_address": ip, "asset_type": asset_type,
                "operating_system": "", "criticality": overall(*suggest_cia(asset_type, hostname)),
                "internet_exposed": "Yes" if segment == "DMZ" else "No",
                "port": port or "", "protocol": "tcp" if port else "", "service": service or "",
                "product": name, "version": version,
                "cpe": f"cpe:/{'o' if is_os else 'a'}:{vendor}:{product}:{version}",
            })
    sheet = pd.DataFrame(rows, columns=SHEET_COLUMNS)
    return sheet.to_csv(index=False).encode(), {"org": number, "devices": size,
                                                "maturity": dict(zip(HYGIENE, maturity.round(3)))}


def exploited_cves(services, reference, published):
    """Confirmed CVEs per (ip, product) on the installed versions, with their KEV date."""
    matched = match_services(services, reference["cpe_matches"], published)
    matched = matched[matched["match_confidence"].isin(CONFIRMED)]
    return matched.merge(reference["cve_info"][["cve_id", "kev_date_added"]], on="cve_id", how="left")


def removed_by_actions(actions, services, reference, published):
    """For each action: the CVEs its upgrade removes (confirmed now, not after upgrading)."""
    before = exploited_cves(services, reference, published)
    upgraded = []
    for a in actions.itertuples(index=False):
        row = services[(services["ip_address"] == a.ip_address) & (services["product"] == a.product)]
        row = row.dropna(subset=["cpe_product"]).iloc[[0]].copy()
        row["version"], row["cpe_version"] = a.target_version, a.target_version
        upgraded.append(row)
    after = exploited_cves(pd.concat(upgraded, ignore_index=True), reference, published)
    removed = {}
    for a in actions.itertuples(index=False):
        mine = before[(before["ip_address"] == a.ip_address) & (before["product"] == a.product)]
        left = set(after.loc[(after["ip_address"] == a.ip_address) & (after["product"] == a.product), "cve_id"])
        removed[(a.ip_address, a.product)] = mine[~mine["cve_id"].isin(left)]
    return removed


def protection_curve(order, doors):
    """Share of exposed devices protected after each fix (doors: device -> set of actions)."""
    if not doors:
        return None
    open_doors = {device: set(d) for device, d in doors.items()}
    curve = []
    for step in order:
        for d in open_doors.values():
            d.discard(step)
        curve.append(sum(1 for d in open_doors.values() if not d) / len(open_doors))
    return np.array(curve)


def score(curve):
    at = lambda k: curve[min(k, len(curve)) - 1]
    return {"auc": float(curve.mean()), "after_5": float(at(5)), "after_10": float(at(10))}


def study_org(sheet_bytes, reference, published, rng):
    services, inventory, _ = parse_scan_sheet(sheet_bytes)
    services, assets, cves = assess_services(services, inventory, reference, DECISION_DATE)
    actions, _ = plan_actions(services, assets, cves, reference["cpe_matches"], today=DECISION_DATE)
    if actions.empty:
        return None
    orders, _ = compare_plans(actions, assets, cves)
    keys = {plan: [(r.ip_address, r.product) for r in order.itertuples(index=False)]
            for plan, order in orders.items()}

    removed = removed_by_actions(actions, services, reference, published)
    end = DECISION_DATE + pd.Timedelta(days=FOLLOW_UP_DAYS)
    outcomes = {
        "all exploited": lambda k: k.notna() & (k <= end),
        "newly exploited": lambda k: k.notna() & (k > DECISION_DATE) & (k <= end),
    }
    rows = []
    for outcome, is_exploited in outcomes.items():
        doors = {}
        for (ip, product), cves_removed in removed.items():
            if is_exploited(cves_removed["kev_date_added"]).any():
                doors.setdefault(ip, set()).add((ip, product))
        if not doors:
            continue
        for plan in PLANS[:3]:
            rows.append({"outcome": outcome, "plan": plan, "exposed_devices": len(doors),
                         "fixes": len(actions), **score(protection_curve(keys[plan], doors))})
        random_scores = [score(protection_curve([keys["Our plan"][i] for i in rng.permutation(len(actions))],
                                                doors)) for _ in range(RANDOM_ORDERS)]
        rows.append({"outcome": outcome, "plan": "Random", "exposed_devices": len(doors),
                     "fixes": len(actions),
                     **{m: float(np.mean([s[m] for s in random_scores])) for m in ["auc", "after_5", "after_10"]}})
    return rows


def restrict(reference, products):
    """Reference data limited to the template products (much faster matching; same results)."""
    vendors = {(v, p) for v, p in products}
    for (v, p), aliases in VENDOR_ALIASES.items():
        if (v, p) in vendors:
            vendors |= {(a, p) for a in aliases}
    matches = reference["cpe_matches"]
    keep = pd.Series(list(zip(matches["vendor"], matches["product"])), index=matches.index).isin(vendors)
    return {**reference, "cpe_matches": matches[keep].copy()}


def load():
    reference = load_reference_data()
    reference = restrict(reference, {item[:2] for asset in ASSETS for item in asset[7]})
    return reference, publication_dates(reference)


_worker = {}


def init_worker():
    _worker["reference"], _worker["published"] = load()


def run_org(job):
    number, sheet = job
    rng = np.random.default_rng(SEED + number)                 # random orders, per organisation
    return number, study_org(sheet, _worker["reference"], _worker["published"], rng)


def main():
    print("Loading reference data (frozen research data, research model)...", flush=True)
    reference, _ = load()
    fixes = fixed_versions(reference["cpe_matches"], reference["cve_info"][["cve_id", "published_date"]])

    rng = np.random.default_rng(SEED)
    jobs, infos = [], {}
    for number in range(1, N_ORGS + 1):
        sheet, info = make_org(number, rng, fixes)
        jobs.append((number, sheet))
        infos[number] = info
    del reference

    rows, orgs = [], []
    with Pool(WORKERS, initializer=init_worker) as pool:
        results = sorted(pool.imap_unordered(run_org, jobs), key=lambda r: r[0])
    for number, result in results:
        info = infos[number]
        orgs.append(info | {"actions": result[0]["fixes"] if result else 0})
        for r in result or []:
            rows.append({"org": number, **r})
        if result:
            ours = [r for r in result if r["plan"] == "Our plan" and r["outcome"] == "all exploited"]
            note = f"our AUC {ours[0]['auc']:.2f}" if ours else "no exploited exposure"
        else:
            note = "no fixes needed"
        print(f"org {number:3}: {info['devices']} devices, {orgs[-1]['actions']} fixes, {note}", flush=True)

    results = pd.DataFrame(rows)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results.to_csv(OUTPUT_DIR / "org_study.csv", index=False)
    pd.DataFrame(orgs).to_csv(OUTPUT_DIR / "org_study_orgs.csv", index=False)

    summary, tests = [], []
    for outcome, group in results.groupby("outcome"):
        wide = {m: group.pivot(index="org", columns="plan", values=m) for m in ["auc", "after_5", "after_10"]}
        for plan in PLANS:
            summary.append({"outcome": outcome, "plan": plan, "organisations": int(wide["auc"][plan].notna().sum()),
                            **{f"{m}_mean": float(wide[m][plan].mean()) for m in wide},
                            "auc_median": float(wide["auc"][plan].median())})
        for other in PLANS[1:]:
            for m in wide:
                a, b = wide[m]["Our plan"], wide[m][other]
                diff = a - b
                stat = wilcoxon(a, b, zero_method="zsplit") if (diff != 0).any() else None
                tests.append({"outcome": outcome, "comparison": f"Our plan vs {other}", "metric": m,
                              "mean_difference": float(diff.mean()),
                              "our_plan_better": int((diff > 0).sum()), "ties": int((diff == 0).sum()),
                              "other_better": int((diff < 0).sum()),
                              "p_value": float(stat.pvalue) if stat else 1.0})
    summary, tests = pd.DataFrame(summary), pd.DataFrame(tests)
    tests["significant"] = tests["p_value"] < 0.05
    summary.to_csv(OUTPUT_DIR / "org_study_summary.csv", index=False)
    tests.to_csv(OUTPUT_DIR / "org_study_significance.csv", index=False)
    (OUTPUT_DIR / "org_study_design.json").write_text(json.dumps({
        "organisations": N_ORGS, "devices_per_org": SIZE_RANGE, "device_templates": len(ASSETS),
        "decision_date": DECISION_DATE.date().isoformat(), "follow_up_days": FOLLOW_UP_DAYS,
        "random_orders": RANDOM_ORDERS, "seed": SEED}, indent=2))

    pd.set_option("display.width", 200)
    print("\n", summary.round(3).to_string(index=False))
    print("\n", tests.round(4).to_string(index=False))


if __name__ == "__main__":
    main()
