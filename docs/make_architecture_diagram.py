"""One-page top-level architecture diagram (layered, Purdue-style) for the viva."""
import sys

import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyBboxPatch, Rectangle

OUT = sys.argv[1]
W, H = 200, 120
fig, ax = plt.subplots(figsize=(20, 12), dpi=150)
ax.set_xlim(0, W)
ax.set_ylim(0, H)
ax.axis("off")
fig.patch.set_facecolor("#fffef2")

ZONES = {  # name: (fill, edge)
    "Threat intelligence sources": ("#dbeafe", "#3b82f6"),
    "Machine learning core": ("#dcfce7", "#16a34a"),
    "Risk analysis engine": ("#fef9c3", "#ca8a04"),
    "Dashboard, users and security": ("#f3e8ff", "#9333ea"),
    "Organisation network (VirtualBox lab)": ("#ffedd5", "#ea580c"),
}
BUS = "#2e8b57"
INK = "#1f2937"

# Level bands: (y_bottom, y_top, label, zone)
LEVELS = [
    (93, 112, "Level 4\nExternal Threat\nIntelligence", "Threat intelligence sources"),
    (70, 93, "Level 3\nData & Machine\nLearning Core", "Machine learning core"),
    (49, 70, "Level 2\nRisk Analysis\nEngine", "Risk analysis engine"),
    (27, 49, "Level 1\nDashboard, Users\n& Security", "Dashboard, users and security"),
    (1, 27, "Level 0\nOrganisation\nNetwork (Assets)", "Organisation network (VirtualBox lab)"),
]
for y0, y1, label, zone in LEVELS:
    fill, edge = ZONES[zone]
    ax.add_patch(Rectangle((24, y0 + 0.4), 175, y1 - y0 - 0.8, facecolor=fill, edgecolor="none", alpha=0.75))
    ax.plot([1, 199], [y0, y0], color="#555555", linestyle=(0, (6, 4)), linewidth=1.2)
    ax.text(12, (y0 + y1) / 2, label, ha="center", va="center", fontsize=12.5, color=INK, fontweight="bold")
ax.plot([1, 199], [112, 112], color="#555555", linestyle=(0, (6, 4)), linewidth=1.2)

# Title
ax.text(100, 116.5, "Threat-Aware Digital Asset Exposure Prediction System: Top-Level Architecture",
        ha="center", va="center", fontsize=19, fontweight="bold", color=INK)


# ---------- drawing helpers ----------
def server(x, y, s=1.0):
    ax.add_patch(Rectangle((x - 1.6 * s, y - 3 * s), 3.2 * s, 6 * s, facecolor="#4b5563", edgecolor="#111827"))
    for k in range(4):
        ax.add_patch(Rectangle((x - 1.2 * s, y + (1.8 - 1.3 * k) * s), 2.4 * s, 0.5 * s, facecolor="#d1d5db",
                               edgecolor="none"))


def monitor(x, y, s=1.0, colour="#38bdf8"):
    ax.add_patch(Rectangle((x - 2.6 * s, y - 0.8 * s), 5.2 * s, 3.6 * s, facecolor="#374151", edgecolor="#111827"))
    ax.add_patch(Rectangle((x - 2.2 * s, y - 0.4 * s), 4.4 * s, 2.8 * s, facecolor=colour, edgecolor="none"))
    ax.add_patch(Rectangle((x - 0.4 * s, y - 1.8 * s), 0.8 * s, 1.0 * s, facecolor="#374151"))
    ax.add_patch(Rectangle((x - 1.6 * s, y - 2.2 * s), 3.2 * s, 0.5 * s, facecolor="#374151"))


def cloud(x, y, s=1.0, colour="#93c5fd"):
    for dx, dy, w, h in [(-2.4, 0, 4.4, 3.0), (0, 1.1, 5.0, 3.6), (2.5, 0, 4.4, 3.0), (0, -0.6, 7.6, 2.4)]:
        ax.add_patch(Ellipse((x + dx * s, y + dy * s), w * s, h * s, facecolor=colour, edgecolor="none"))


def person(x, y, s=1.0, colour="#7c3aed"):
    ax.add_patch(Ellipse((x, y + 1.6 * s), 1.6 * s, 1.6 * s, facecolor=colour))
    ax.add_patch(FancyBboxPatch((x - 1.3 * s, y - 1.6 * s), 2.6 * s, 2.4 * s,
                                boxstyle="round,pad=0,rounding_size=0.8", facecolor=colour, edgecolor="none"))


def label(x, y, title, sub="", size=10.5):
    ax.text(x, y, title, ha="center", va="top", fontsize=size, fontweight="bold", color=INK)
    if sub:
        ax.text(x, y - 2.3, sub, ha="center", va="top", fontsize=8.6, color="#374151", linespacing=1.25)


def wire(points, colour=BUS, width=2.2, style="-"):
    xs, ys = zip(*points)
    ax.plot(xs, ys, color=colour, linewidth=width, linestyle=style, solid_capstyle="round")


# ---------- Level 4: threat intelligence (internet) ----------
cloud(64, 104.5, 1.2)
ax.text(64, 104.2, "Internet", ha="center", va="center", fontsize=10, fontweight="bold", color="#1e3a8a")
for x, t, sub in [(38, "NIST NVD", "all CVEs: CVSS, CWE,\nsoftware versions, text"),
                  (90, "CISA KEV", "vulnerabilities attackers\nare actively exploiting"),
                  (114, "FIRST EPSS", "industry benchmark\n(comparison only)")]:
    server(x, 105, 0.8)
    label(x, 100.6, t, sub, 10)
wire([(42, 104), (55, 104)], "#3b82f6", 2)
wire([(73, 104), (86, 104)], "#3b82f6", 2)
wire([(94, 104), (110, 104)], "#3b82f6", 1.4, "--")

# Legend (top right)
lx, ly = 137, 110
for i, (name, (fill, edge)) in enumerate(ZONES.items()):
    yy = ly - i * 3.5
    ax.add_patch(Rectangle((lx, yy - 1.1), 3.2, 2.2, facecolor=fill, edgecolor=edge, linewidth=1.5))
    ax.text(lx + 4.5, yy, name, va="center", fontsize=11, color=INK)

# ---------- Level 3: ML core ----------
bus3 = 73.5
wire([(30, bus3), (196, bus3)])
items3 = [(38, "Live Sync", "every 6 hours\nKEV feed + NVD API"),
          (66, "Data Pipeline", "clean, label (exploited\nin 12 months), features"),
          (94, "ML Model", "LightGBM + text\ncalibrated probability"),
          (122, "Explainability", "SHAP: reasons\nfor each prediction"),
          (150, "Evaluation", "test on unseen 2025,\nEPSS / CVSS benchmark"),
          (178, "Model Monitoring", "drift check +\nchampion/challenger")]
for x, t, sub in items3:
    server(x, 86, 0.85)
    label(x, 81.6, t, sub)
    wire([(x, bus3), (x, 76.6 if False else 75.6)])
wire([(38, 94.8), (38, 91.3)], "#3b82f6", 2)    # NVD -> live sync (below the labels)
wire([(90, 94.8), (90, 93.4), (38, 93.4)], "#3b82f6", 2)          # KEV -> live sync
wire([(114, 94.8), (114, 93.9), (150, 93.9), (150, 91.3)], "#3b82f6", 1.4, "--")  # EPSS -> evaluation

# ---------- Level 2: risk analysis ----------
bus2 = 52.5
wire([(30, bus2), (196, bus2)])
items2 = [(40, "Exposure Assessor", "match installed versions\nto CVEs (NVD + KEV)"),
          (72, "Business Importance", "NIST FIPS 199: impact on\nconfidentiality, integrity, availability"),
          (104, "Risk Prioritisation", "chance of attack x\nimportance x exposure"),
          (136, "Patch Planner", "fix versions, deadlines,\ntemporary mitigations"),
          (168, "Attack-Spread Engine", "lateral movement map\n(blast radius)")]
for x, t, sub in items2:
    server(x, 65, 0.8)
    label(x, 60.8, t, sub, 10)
    wire([(x, bus2), (x, 54.0)])
wire([(94, bus3), (94, 70), (104, 70), (104, 68.6)])        # model -> prioritisation

# ---------- Level 1: dashboard, users, security ----------
bus1 = 30.5
wire([(30, bus1), (196, bus1)])
monitor(48, 42, 1.25)
label(48, 37.8, "Streamlit Dashboard", "Scan & fix (5 steps) · Plan comparison\n· Is the AI accurate?", 10.5)
for x, colour, t, sub in [(92, "#7c3aed", "Security Analyst", "scans, reviews, notifies"),
                          (114, "#7c3aed", "Security Manager", "approves, accepts risk"),
                          (136, "#a855f7", "Asset Owner Teams", "receive fix emails,\npatch devices")]:
    person(x, 43, 1.2, colour)
    label(x, 39.2, t, sub, 10)
server(160, 43, 0.8)
label(160, 39.0, "Access Control", "roles, MFA, lockout,\nhash-chained audit log", 10)
server(182, 43, 0.8)
label(182, 39.0, "Notification Service", "email: CVE grid, CVSS,\nATT&CK, mitigation", 10)
for x in [48, 92, 114, 160, 182]:
    wire([(x, bus1), (x, 32.6 if x != 48 else 32.4)])
wire([(182, 46.2), (182, bus2)], BUS, 1.6)                 # planner -> notification service
wire([(196, bus2), (196, bus1)])                            # analysis -> dashboard layer
wire([(179, 47.6), (136, 47.6), (136, 46.2)], "#a855f7", 1.6, "--")   # email -> asset owners
ax.text(170.5, 46.3, "fix emails", ha="center", va="center", fontsize=8.4, color="#6b21a8")

# ---------- Level 0: organisation network (lab) ----------
monitor(40, 19, 1.15, "#fdba74")
label(40, 15.0, "Analyst PC + Nmap", "192.168.56.1\nservice/version scan", 10)
ax.add_patch(FancyBboxPatch((66, 3), 128, 21.5, boxstyle="round,pad=0.4,rounding_size=1.5",
                            facecolor="#fff7ed", edgecolor="#ea580c", linewidth=1.8, linestyle=(0, (5, 3))))
ax.text(130, 22.6, "Isolated host-only network 192.168.56.0/24 (no internet)", ha="center",
        fontsize=10.5, fontweight="bold", color="#9a3412")
lan = 18.2
wire([(52, lan), (186, lan)], "#ea580c", 2.4)
devices = [(84, "legacy-srv-01", "Metasploitable 2 · .101\nold services (16 KEV)"),
           (118, "app-srv-01", "Alpine + Docker · .102\nApache, Tomcat, Redis"),
           (150, "ws-01", "Alpine workstation · .103\nOpenSSH")]
for x, t, sub in devices:
    server(x, 13.5, 0.75) if x != 150 else monitor(x, 13, 0.9, "#fdba74")
    wire([(x, lan), (x, 16.9 if x != 150 else 15.8)], "#ea580c", 2)
    label(x, 9.3, t, sub, 10)
ax.text(176, 12, "Demo organisations\n(scan sheets)\nZentrova · Kyvora\nQuantelix", ha="center",
        va="center", fontsize=9, color="#7c2d12", fontstyle="italic")
# Scan results travel up the left edge to the exposure assessor
wire([(40, 23.8), (40, 25.6), (27, 25.6), (27, bus2)], BUS)
ax.annotate("", xy=(30.5, bus2), xytext=(27, bus2), arrowprops=dict(arrowstyle="-|>", color=BUS, lw=2.2))
ax.text(26.2, 38.5, "scan results: devices, software, versions", rotation=90, ha="center",
        va="center", fontsize=8.4, color="#14532d")

fig.savefig(OUT, bbox_inches="tight", facecolor=fig.get_facecolor())
print("saved", OUT)
