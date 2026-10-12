"""
Remediation planner: turns predictions into a ranked to-do list.

For every installed product with matched vulnerabilities it works out
  - the version that fixes them (from NVD's "vulnerable before X" ranges)
  - which CVEs that upgrade removes, including known exploited ones
  - the asset's risk before and after, using the same scoring as the
    exposure assessment (known-CVE risk is removed by patching; the
    product's history of new exploited flaws stays while it is installed)
  - a deadline: the KEV due date for exploited CVEs, otherwise a
    tier-based service level (stated policy assumption below)

Risk is counted with an "open doors" model (see AssetState): each
vulnerable product is a door into the asset, so every upgrade closes one
door and its effect is visible even when other doors remain. The weekly
plan picks the N upgrades that remove the most business-weighted risk.

Run from the project root (plan for the synthetic lab's current snapshot):
    python -m src.remediation.planner
"""

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from src.asset_exposure.assess_exposure import (
    CONFIRMED, CRITICALITY_WEIGHT, EXPOSURE_WEIGHT, UNKNOWN_CRITICALITY_WEIGHT,
    UNKNOWN_EXPOSURE_WEIGHT, VENDOR_ALIASES,
)
from src.asset_exposure.versions import clean_version, fixed_version, version_key, version_matches

# Patch deadlines when CISA gives none (policy assumption, adjustable):
# KEV without a due date 14 days; by predicted risk tier otherwise
SLA_DAYS = {"KEV": 14, "Critical": 30, "High": 60, "Medium": 90, "Low": 180, "Older": 180}

KEV_FILES = [Path("data/live/kev_latest.csv"), Path("data/processed/cisa_kev_clean.csv")]


def load_kev_due_dates():
    """cve_id -> (date added, due date) from the newest KEV copy available."""
    for path in KEV_FILES:
        if path.exists():
            kev = pd.read_csv(path, usecols=["cve_id", "date_added", "due_date"])
            return kev.set_index("cve_id")
    return pd.DataFrame(columns=["date_added", "due_date"])


# ==============================
# Asset risk model (mirrors summarise_assets)
# ==============================

@dataclass
class AssetState:
    """
    "Open doors" model: every installed product with known vulnerabilities
    is a door into the asset. A door with a known exploited CVE is open
    (1.0); otherwise it is open with the predicted probability that at
    least one of its CVEs gets exploited. Risk points = sum of door
    openness x business weight, so patching one product shows its effect
    even when other doors are still open.
    """
    weight: float                       # criticality x internet exposure
    product_rate: float                 # new exploited flaws expected (product history)
    doors: dict = field(default_factory=dict)   # product -> {cve_id: (p, known_exploited)}

    @staticmethod
    def openness(cves, removed):
        remaining = [v for k, v in cves.items() if k not in removed]
        if any(kev for _, kev in remaining):
            return 1.0
        return 1 - float(np.prod([1 - p for p, _ in remaining])) if remaining else 0.0

    def points(self, removed=frozenset()):
        return self.weight * sum(self.openness(c, removed) for c in self.doors.values())

    def exposure(self, removed=frozenset()):
        """Probability at least one door is open (known CVEs only)."""
        closed = np.prod([1 - self.openness(c, removed) for c in self.doors.values()])
        return 1 - float(closed)

    def exploited_doors(self, removed=frozenset()):
        return sum(any(kev for k, (_, kev) in c.items() if k not in removed)
                   for c in self.doors.values())


def build_states(assets, cves):
    states = {}
    confirmed = cves[cves["match_confidence"].isin(CONFIRMED)]
    for row in assets.itertuples(index=False):
        if row.scan_status == "Not scanned":
            continue
        weight = (CRITICALITY_WEIGHT.get(row.criticality, UNKNOWN_CRITICALITY_WEIGHT)
                  * EXPOSURE_WEIGHT.get(row.internet_exposed, UNKNOWN_EXPOSURE_WEIGHT))
        state = AssetState(weight=weight, product_rate=float(row.product_kev_rate_12m))
        for c in confirmed[confirmed["ip_address"] == row.ip_address].itertuples(index=False):
            kev = c.status == "Known exploited"
            p = 1.0 if kev else (c.probability if c.status == "Prediction window"
                                 and pd.notna(c.probability) else 0.0)
            state.doors.setdefault(c.product, {})[c.cve_id] = (float(p), kev)
        states[row.ip_address] = state
    return states


# ==============================
# Upgrade actions
# ==============================

def describe(product, part, installed, target):
    if part == "o" or str(product).lower().startswith("windows"):
        return f"Install updates: {product} to build {target} or later (now {installed})"
    return f"Upgrade {product} {installed} → {target} or later"


def plan_actions(services, assets, cves, cpe_matches, today=None):
    """One upgrade action per (asset, product) with matched vulnerabilities."""
    today = pd.Timestamp(today or pd.Timestamp.now()).normalize()
    kev_due = load_kev_due_dates()
    states = build_states(assets, cves)

    confirmed = cves[cves["match_confidence"].isin(CONFIRMED)]
    ranges = cpe_matches[cpe_matches["cve_id"].isin(set(confirmed["cve_id"]))]
    info = assets.set_index("ip_address")

    actions = []
    for (ip, product), group in confirmed.groupby(["ip_address", "product"]):
        if ip not in states:
            continue
        service = services[(services["ip_address"] == ip) & (services["product"] == product)]
        service = service.dropna(subset=["cpe_product"]).iloc[0] if service["cpe_product"].notna().any() else None
        if service is None:
            continue

        installed = clean_version(service["cpe_version"]) or clean_version(service["version"])
        vendors = [service["vendor"]] + VENDOR_ALIASES.get((service["vendor"], service["cpe_product"]), [])
        product_ranges = ranges[(ranges["product"] == service["cpe_product"])
                                & ranges["vendor"].isin(vendors)]

        fixes, unfixable = {}, []
        for cve_id in group["cve_id"]:
            rows = product_ranges[product_ranges["cve_id"] == cve_id].to_dict("records")
            candidates = [fixed_version(installed, r) for r in rows
                          if installed and version_matches(installed, r)]
            candidates = [c for c in candidates if c]
            if candidates:
                fixes[cve_id] = max(candidates, key=version_key)
            else:
                unfixable.append(cve_id)

        if not fixes:
            continue

        target = max(fixes.values(), key=version_key)
        fixed = frozenset(fixes)
        state = states[ip]
        fixed_rows = group[group["cve_id"].isin(fixed)]

        # Deadline: earliest applicable among the CVEs this upgrade fixes
        deadlines = []
        for c in fixed_rows.itertuples(index=False):
            if c.status == "Known exploited":
                due = kev_due["due_date"].get(c.cve_id) if c.cve_id in kev_due.index else None
                added = kev_due["date_added"].get(c.cve_id) if c.cve_id in kev_due.index else None
                deadlines.append(pd.Timestamp(due) if isinstance(due, str) and due else
                                 pd.Timestamp(added or today) + pd.Timedelta(days=SLA_DAYS["KEV"]))
            elif c.status == "Prediction window" and isinstance(c.tier, str):
                deadlines.append(today + pd.Timedelta(days=SLA_DAYS.get(c.tier, 90)))
            else:
                deadlines.append(today + pd.Timedelta(days=SLA_DAYS["Older"]))
        deadline = min(deadlines)
        days_left = (deadline - today).days

        actions.append({
            "asset_id": info.loc[ip, "asset_id"], "hostname": info.loc[ip, "hostname"],
            "ip_address": ip, "product": product, "installed_version": installed,
            "target_version": target,
            "action": describe(product, service["part"], installed, target),
            "cves_fixed": len(fixed),
            "kev_fixed": int((fixed_rows["status"] == "Known exploited").sum()),
            "predicted_fixed": int((fixed_rows["status"] == "Prediction window").sum()),
            "no_fix_recorded": len(unfixable),
            "points_before": state.points(), "points_after": state.points(fixed),
            "exposure_before": state.exposure(), "exposure_after": state.exposure(fixed),
            "exploited_doors_before": state.exploited_doors(),
            "exploited_doors_after": state.exploited_doors(fixed),
            "future_flaws_per_year": state.product_rate,
            "deadline": deadline.date().isoformat(),
            "urgency": "OVERDUE" if days_left < 0 else f"Due in {days_left} days",
            "fixed_cve_ids": ";".join(sorted(fixed)),
        })

    actions = pd.DataFrame(actions)
    if not actions.empty:
        actions["risk_removed"] = actions["points_before"] - actions["points_after"]
        actions = rank(actions)
    return actions, states


def rank(actions):
    """Largest risk removed first; ties broken by exploited CVEs, then deadline."""
    return actions.sort_values(["risk_removed", "kev_fixed", "deadline"],
                               ascending=[False, False, True]).reset_index(drop=True)


# ==============================
# Weekly plan (budget of N fixes)
# ==============================

def weekly_plan(actions, states, budget):
    """
    Pick up to `budget` actions removing the most business-weighted risk.
    Each action closes one door (one product on one asset), so the risk
    it removes does not depend on other picks and ranking is exact.
    Returns (chosen actions in order, company risk after 0..k fixes).
    """
    total_before = sum(s.points() for s in states.values())
    chosen = rank(actions).head(budget).copy()
    chosen.insert(0, "step", range(1, len(chosen) + 1))

    curve = pd.DataFrame({
        "fixes": range(0, len(chosen) + 1),
        "total_risk": total_before - np.concatenate([[0.0], chosen["risk_removed"].cumsum().to_numpy()]),
        "action": ["Start"] + chosen["action"].tolist(),
    })
    return chosen, curve


# ==============================
# CLI demo
# ==============================

def main():
    from src.asset_exposure.assess_exposure import assess_services, load_reference_data
    from src.lab.lab_db import load_snapshot

    reference = load_reference_data(live=True)
    services, inventory, snapshot_date = load_snapshot("current")
    _, assets, cves = assess_services(services, inventory, reference, snapshot_date)

    actions, states = plan_actions(services, assets, cves, reference["cpe_matches"])
    chosen, curve = weekly_plan(actions, states, budget=10)

    pd.set_option("display.width", 220)
    pd.set_option("display.max_colwidth", 70)
    print(f"Upgrade actions found: {len(actions)} across {actions['asset_id'].nunique()} assets")
    print(f"Company risk: {curve['total_risk'].iloc[0]:.2f} -> {curve['total_risk'].iloc[-1]:.2f} "
          f"after {len(chosen)} fixes "
          f"({1 - curve['total_risk'].iloc[-1] / curve['total_risk'].iloc[0]:.0%} lower)\n")
    print(chosen[["step", "hostname", "action", "cves_fixed", "kev_fixed",
                  "exploited_doors_before", "exploited_doors_after", "risk_removed", "urgency"]]
          .round(3).to_string(index=False))


if __name__ == "__main__":
    main()
