"""
Attack-path (blast-radius) analysis.

If one device, one software product, or an internet attacker gets a
foothold, which other assets and subnets can be reached, and how likely
is each step?

The network is a directed graph. An edge A -> B means "an attacker who
controls A can compromise B", from one of two sources:

  exploit   A's subnet may reach B on a port where B runs software with
            matched vulnerabilities. Edge probability = chance that at
            least one of them is usable: 1.0 for a known exploited (KEV)
            CVE, otherwise the model's calibrated probability.
  trust     a relationship from the topology: stored credentials, domain
            admin rights, backup copies... with an assumed probability.

For each reached asset the most likely path is found (Dijkstra on
-log(probability)). Fixes are then tested one at a time to find which
single patch, firewall change or trust removal cuts the most risk to
the crown jewels.

Run from the project root (example scenarios on the lab database):
    python -m src.attack_paths.attack_graph
"""

import heapq
import math
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from src.asset_exposure.assess_exposure import CONFIRMED

INTERNET = "INTERNET"
CLIENT = "client"           # content reaching client software (browser, email)
WINDOWS_PORTS = {"135", "445"}

MIN_PROBABILITY = 0.01      # paths below this are not followed
MAX_STEPS = 8
REACHED_THRESHOLD = 0.10    # counted as "reached" in summaries

OUTPUT_DIR = Path("results/attack_paths")

# Probability bands used by the map and tables (status colours)
BANDS = [(0.5, "Likely"), (0.1, "Possible"), (MIN_PROBABILITY, "Unlikely")]


def band(probability):
    for floor, name in BANDS:
        if probability >= floor:
            return name
    return "Not reached"


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    probability: float
    kind: str               # "exploit" or "trust"
    label: str              # short text for the map
    detail: str             # one line for tables
    fix: tuple              # removing this key removes the edge
    rule: tuple = None      # firewall rule key (exploit edges only)


# ==============================
# Building the graph
# ==============================

def service_exploitability(services, cves):
    """
    Per (asset, product): ports it listens on and the chance of a usable
    exploit, separately for network attacks and client-side content.

    Only CVEs an attacker can use from where they are count:
      network  CVSS attack vector Network or Adjacent
      client   also Local (a malicious file the user opens), for content
               reaching client software such as browsers and archivers
    Physical-access CVEs never count. The edge takes the single most
    exploitable CVE (1.0 if known exploited); combining hundreds of
    related CVEs as if independent would push every host to 100%.
    """
    confirmed = cves[cves["match_confidence"].isin(CONFIRMED)].copy()

    known = confirmed["status"] == "Known exploited"
    predicted = confirmed["status"] == "Prediction window"
    confirmed["p"] = np.where(known, 1.0,
                              np.where(predicted, confirmed["probability"].fillna(0.0), 0.0))
    confirmed["kev"] = known.astype(int)
    confirmed = confirmed[confirmed["p"] > 0].sort_values("p", ascending=False)

    vector = confirmed["attack_vector"].fillna("UNKNOWN")
    remote = vector.isin(["NETWORK", "ADJACENT_NETWORK", "UNKNOWN"])
    usable = {"network": remote, "client": remote | (vector == "LOCAL")}

    summaries = []
    for name, mask in usable.items():
        summaries.append(
            confirmed[mask].groupby(["ip_address", "product"]).agg(**{
                f"p_{name}": ("p", "max"),
                f"kev_{name}": ("kev", "sum"),
                f"top_{name}": ("cve_id", "first"),
            }))

    per_product = summaries[0].join(summaries[1], how="outer").reset_index()
    for name in usable:
        per_product[f"p_{name}"] = per_product[f"p_{name}"].fillna(0.0)
        per_product[f"kev_{name}"] = per_product[f"kev_{name}"].fillna(0).astype(int)

    # Where each product can be reached
    ports = []
    for row in services.itertuples(index=False):
        if row.part == "o" and row.vendor == "microsoft":
            listen = set(WINDOWS_PORTS)
            if pd.notna(row.port):
                listen.add(str(int(row.port)))
        elif pd.notna(row.port):
            listen = {str(int(row.port))}
        else:
            listen = {CLIENT}
        ports.append({"ip_address": row.ip_address, "product": row.product, "ports": listen})

    ports = (pd.DataFrame(ports).groupby(["ip_address", "product"])["ports"]
             .agg(lambda s: set().union(*s)).reset_index())

    return per_product.merge(ports, on=["ip_address", "product"], how="left")


def allowed_ports(rule_ports, service_ports):
    """Ports of a service that a firewall rule lets through."""
    if rule_ports == "any":
        return {p for p in service_ports if p != CLIENT}
    allowed = set(rule_ports.split(","))
    return service_ports & allowed


def build_graph(inventory, services, cves, rules, trusts):
    """Returns {source: {target: [Edge, ...]}} plus a node table."""
    nodes = inventory.set_index("ip_address")
    by_asset_id = inventory.set_index("asset_id")["ip_address"].to_dict()
    exposures = service_exploitability(services, cves)

    edges = {}

    def add(edge):
        edges.setdefault(edge.source, {}).setdefault(edge.target, []).append(edge)

    sources = [(INTERNET, INTERNET)] + [(ip, row.segment) for ip, row in nodes.iterrows()]

    for exposure in exposures.itertuples(index=False):
        target = exposure.ip_address
        target_segment = nodes.loc[target, "segment"]

        for rule in rules[rules["to_segment"] == target_segment].itertuples(index=False):
            through = allowed_ports(rule.ports, exposure.ports if isinstance(exposure.ports, set) else set())
            if not through:
                continue
            port = sorted(through)[0]
            kind = "client" if port == CLIENT else "network"
            p = getattr(exposure, f"p_{kind}")
            kev = getattr(exposure, f"kev_{kind}")
            if p <= 0:
                continue

            where = "client-side content" if port == CLIENT else f"port {port}"
            status = (f"{kev} known exploited" if kev
                      else f"predicted {p:.1%}, {getattr(exposure, f'top_{kind}')}")

            for source, source_segment in sources:
                if source == target or source_segment != rule.from_segment:
                    continue
                add(Edge(
                    source=source, target=target, probability=float(min(p, 1.0)),
                    kind="exploit",
                    label=f"{exposure.product}{' (KEV)' if kev else ''}",
                    detail=f"Exploit {exposure.product} via {where} ({status})",
                    fix=("patch", target, exposure.product),
                    rule=("block", rule.from_segment, rule.to_segment, rule.ports),
                ))

    for link in trusts.itertuples(index=False):
        source, target = by_asset_id.get(link.source_asset), by_asset_id.get(link.target_asset)
        if source is None or target is None:
            continue
        add(Edge(
            source=source, target=target, probability=float(link.probability),
            kind="trust", label=link.link_type,
            detail=f"{link.link_type}: {link.description}",
            fix=("trust", source, target, link.link_type),
        ))

    return edges


# ==============================
# Spreading from a start point
# ==============================

def propagate(edges, starts, removed=frozenset()):
    """Most likely path to every reachable node: {node: (p, steps, prev, edge)}."""
    best = {s: (1.0, 0, None, None) for s in starts}
    heap = [(0.0, s) for s in starts]

    while heap:
        cost, node = heapq.heappop(heap)
        p, steps, _, _ = best[node]
        if cost > -math.log(p) + 1e-12:
            continue                                    # stale entry

        for target, candidates in edges.get(node, {}).items():
            usable = [e for e in candidates if e.fix not in removed and e.rule not in removed]
            if not usable:
                continue
            edge = max(usable, key=lambda e: e.probability)
            q = p * edge.probability
            if q < MIN_PROBABILITY or steps + 1 > MAX_STEPS:
                continue
            if q > best.get(target, (0.0,))[0]:
                best[target] = (q, steps + 1, node, edge)
                heapq.heappush(heap, (-math.log(q), target))

    return best


def crown_jewel_risk(best, inventory, starts):
    jewels = inventory.loc[inventory["crown_jewel"] == 1, "ip_address"]
    return sum(best[j][0] for j in jewels if j in best and j not in starts)


def path_to(best, node):
    path = []
    while node is not None:
        path.append(node)
        node = best[node][2]
    return list(reversed(path))


# ==============================
# Scenario analysis
# ==============================

@dataclass
class Scenario:
    title: str
    starts: list
    reached: pd.DataFrame
    segments: pd.DataFrame
    fixes: pd.DataFrame
    tree_edges: list
    crown_risk: float


def resolve_start(start_type, value, inventory, services):
    """Start nodes for 'device' (asset_id), 'software' (product) or 'internet'."""
    if start_type == "internet":
        return [INTERNET], "An attacker on the internet"
    if start_type == "device":
        row = inventory[inventory["asset_id"] == value].iloc[0]
        return [row["ip_address"]], f"{row['hostname']} is compromised"
    hosts = sorted(services.loc[services["product"] == value, "ip_address"].unique())
    return hosts, f"Every host running {value} is compromised ({len(hosts)} hosts)"


def describe_fix(fix, names):
    if fix[0] == "patch":
        return f"Patch {fix[2]} on {names.get(fix[1], fix[1])}"
    if fix[0] == "block":
        target = "client software (filter web and email content)" if fix[3] == CLIENT \
            else f"ports {fix[3]}"
        return f"Restrict {fix[1]} → {fix[2]} on {target}"
    return f"Remove {fix[3].lower()} from {names.get(fix[1], fix[1])} to {names.get(fix[2], fix[2])}"


def analyse(start_type, value, inventory, services, cves, rules, trusts, segments_table):
    edges = build_graph(inventory, services, cves, rules, trusts)
    starts, title = resolve_start(start_type, value, inventory, services)

    best = propagate(edges, starts)
    names = inventory.set_index("ip_address")["hostname"].to_dict()
    names[INTERNET] = "Internet"
    info = inventory.set_index("ip_address")

    # ---- Reached assets ----

    rows = []
    for node, (p, steps, prev, edge) in best.items():
        if node == INTERNET:
            continue
        asset = info.loc[node]
        rows.append({
            "asset_id": asset["asset_id"], "hostname": asset["hostname"],
            "ip_address": node, "segment": asset["segment"],
            "asset_type": asset["asset_type"], "crown_jewel": int(asset["crown_jewel"]),
            "start": node in starts, "steps": steps, "probability": p, "band": band(p),
            "path": " → ".join(names[n] for n in path_to(best, node)),
            "how": "Starting point" if edge is None else edge.detail,
        })
    reached = pd.DataFrame(rows).sort_values(["start", "probability"], ascending=[False, False])

    # ---- Subnet impact ----

    totals = inventory.groupby("segment").size()
    hit = reached[reached["probability"] >= REACHED_THRESHOLD]
    segments = pd.DataFrame({
        "segment": totals.index,
        "assets": totals.values,
        "reached": [int((hit["segment"] == s).sum()) for s in totals.index],
        "highest_probability": [float(reached.loc[reached["segment"] == s, "probability"].max())
                                if (reached["segment"] == s).any() else 0.0 for s in totals.index],
    }).merge(segments_table[["segment", "cidr"]], on="segment", how="left")
    segments["affected"] = segments["reached"] > 0
    segments["band"] = segments["highest_probability"].map(band)

    # ---- Best single fixes ----

    tree_edges = [e for (_, _, _, e) in best.values() if e is not None]
    baseline = crown_jewel_risk(best, inventory, starts)
    reached_count = int((reached["probability"] >= REACHED_THRESHOLD).sum())

    candidates = {e.fix for e in tree_edges} | {e.rule for e in tree_edges if e.rule}
    fix_rows = []
    for fix in candidates:
        after = propagate(edges, starts, removed=frozenset({fix}))
        risk = crown_jewel_risk(after, inventory, starts)
        still = sum(1 for n, v in after.items()
                    if n != INTERNET and v[0] >= REACHED_THRESHOLD)
        fix_rows.append({
            "action": describe_fix(fix, names),
            "type": {"patch": "Patch", "block": "Firewall", "trust": "Trust link"}[fix[0]],
            "crown_risk_before": baseline, "crown_risk_after": risk,
            "risk_reduction": baseline - risk,
            "assets_reached_after": still, "assets_reached_before": reached_count,
        })
    fixes = pd.DataFrame(fix_rows)
    if not fixes.empty:
        fixes = fixes[(fixes["risk_reduction"] > 1e-9)
                      | (fixes["assets_reached_after"] < reached_count)]
        fixes = fixes.sort_values(["risk_reduction", "assets_reached_after"],
                                  ascending=[False, True]).head(8)

    return Scenario(title, starts, reached, segments, fixes, tree_edges, baseline)


# ==============================
# Network map (Graphviz DOT)
# ==============================

BAND_COLORS = {"Likely": "#b71c1c", "Possible": "#d9480f", "Unlikely": "#d48806"}
BAND_TEXT = {"Unlikely": "#1b1b1b"}
SEGMENT_ORDER = ["DMZ", "SERVERS", "WORKSTATIONS", "MGMT"]


def to_dot(scenario, inventory, segments_table):
    reached = scenario.reached.set_index("ip_address")
    cidrs = segments_table.set_index("segment")["cidr"].to_dict()

    def node_line(ip, row):
        name = row["hostname"]
        jewel = row["crown_jewel"] == 1
        label = f"{'★ ' if jewel else ''}{name}\\n{row['asset_type']}"
        attrs = {"label": label, "peripheries": 2 if jewel else 1}

        if ip in scenario.starts:
            attrs.update(fillcolor="#1b1b1b", fontcolor="#ffffff", color="#1b1b1b",
                         label=f"START\\n{label}", penwidth=2.5)
        elif ip in reached.index and reached.loc[ip, "probability"] >= MIN_PROBABILITY:
            b = reached.loc[ip, "band"]
            p = reached.loc[ip, "probability"]
            attrs.update(fillcolor=BAND_COLORS[b], fontcolor=BAND_TEXT.get(b, "#ffffff"),
                         color=BAND_COLORS[b], label=f"{label}\\n{p:.0%}", penwidth=2)
        else:
            attrs.update(fillcolor="#ffffff", fontcolor="#6b7075", color="#c4c8cb")

        text = ", ".join(f'{k}="{v}"' for k, v in attrs.items())
        return f'    "{ip}" [{text}];'

    lines = [
        "digraph attack {",
        '  graph [rankdir=LR, bgcolor="#fbfbf8", fontname="Helvetica", fontsize=13, '
        'nodesep=0.25, ranksep=1.1, pad=0.3, newrank=true];',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11, penwidth=1.2];',
        '  edge [fontname="Helvetica", fontsize=10];',
    ]

    internet_style = ('fillcolor="#1b1b1b", fontcolor="#ffffff", penwidth=2.5'
                      if INTERNET in scenario.starts else 'fillcolor="#e9edf0", fontcolor="#1b1b1b"')
    lines.append(f'  "{INTERNET}" [label="Internet", shape=ellipse, {internet_style}];')

    # Known lab zones first, then any other zone (e.g. subnets of a scanned network)
    others = sorted(set(inventory["segment"]) - set(SEGMENT_ORDER))
    for segment in SEGMENT_ORDER + others:
        members = inventory[inventory["segment"] == segment]
        if members.empty:
            continue
        lines.append(f'  subgraph "cluster_{segment}" {{')
        lines.append(f'    label="{segment}  {cidrs.get(segment, "")}"; style="rounded,bold"; '
                     f'color="#5f6468"; fontcolor="#1b1b1b"; penwidth=1.5;')
        for row in members.itertuples(index=False):
            lines.append(node_line(row.ip_address, row._asdict()))
        lines.append("  }")

    for edge in scenario.tree_edges:
        target_p = reached.loc[edge.target, "probability"]
        color = BAND_COLORS[band(target_p)]
        style = "solid" if edge.kind == "exploit" else "dashed"
        lines.append(f'  "{edge.source}" -> "{edge.target}" [color="{color}", penwidth=2.6, '
                     f'style={style}, label="{edge.label}", fontcolor="#1b1b1b"];')

    lines.append("}")
    return "\n".join(lines)


# ==============================
# Example scenarios (CLI)
# ==============================

def main():
    from src.asset_exposure.assess_exposure import assess_services, load_reference_data
    from src.lab.lab_db import load_snapshot, load_topology

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading reference data and lab snapshot 'current'...")
    reference = load_reference_data()
    services, inventory, snapshot_date = load_snapshot("current")
    _, _, cves = assess_services(services, inventory, reference, snapshot_date)
    segments_table, rules, trusts = load_topology()

    scenarios = [("internet", None), ("device", "L003"), ("software", "Apache Tomcat")]

    pd.set_option("display.width", 220)
    pd.set_option("display.max_colwidth", 70)

    for start_type, value in scenarios:
        s = analyse(start_type, value, inventory, services, cves, rules, trusts, segments_table)
        slug = start_type if value is None else f"{start_type}_{value}".replace(" ", "_")

        s.reached.to_csv(OUTPUT_DIR / f"{slug}_reached.csv", index=False)
        s.fixes.to_csv(OUTPUT_DIR / f"{slug}_fixes.csv", index=False)
        (OUTPUT_DIR / f"{slug}_map.dot").write_text(
            to_dot(s, inventory, segments_table), encoding="utf-8")

        print(f"\n{'=' * 80}\n{s.title}\n{'=' * 80}")
        print(s.segments[["segment", "assets", "reached", "highest_probability", "band"]]
              .round(3).to_string(index=False))
        print(f"\nCrown-jewel risk (sum of probabilities): {s.crown_risk:.2f}")
        print(s.reached[s.reached["probability"] >= REACHED_THRESHOLD]
              [["hostname", "segment", "steps", "probability", "path"]]
              .head(12).round(3).to_string(index=False))
        print("\nBest single fixes:")
        print(s.fixes[["action", "type", "risk_reduction", "assets_reached_after"]]
              .round(3).to_string(index=False))

    print(f"\nResults written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
