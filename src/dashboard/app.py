"""
Threat-aware asset exposure dashboard.

Run from the project root:
    streamlit run src/dashboard/app.py
"""

import io
import re
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

import altair as alt  # noqa: E402
import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402
from streamlit import config as st_config  # noqa: E402

from src.asset_exposure.assess_exposure import (  # noqa: E402
    ASSETS_FILE, CONFIRMED, CRITICALITY_WEIGHT, DEFAULT_SCAN, EXPOSURE_WEIGHT,
    PREDICTION_WINDOW_DAYS, UNKNOWN_CRITICALITY_WEIGHT, UNKNOWN_EXPOSURE_WEIGHT,
    assess, assess_services, load_reference_data,
)
from src.asset_discovery.parse_scan_sheet import ScanSheetError, parse_scan_sheet  # noqa: E402
from src.asset_discovery.run_nmap import (  # noqa: E402
    find_nmap, load_config as load_scan_config, run_scan, target_problems,
)
from src.lab.lab_db import DB_FILE, list_snapshots, load_snapshot, load_topology  # noqa: E402
from src.lab.vbox import lab_status, start_lab  # noqa: E402
from src.asset_exposure.importance import (  # noqa: E402
    CIA, FILE as IMPORTANCE_FILE, LEVELS, apply as apply_importance, load as load_importance,
    network_key, overall, save as save_importance, suggest_cia,
)
from src.evaluation.weight_sensitivity import sensitivity  # noqa: E402
from src.attack_paths.scan_topology import scan_topology  # noqa: E402
from src.auth import store as auth_store  # noqa: E402
from src.auth.rbac import ROLES, TAB_ACCESS, can, role_name  # noqa: E402
from src.auth.security import hash_password, temporary_password  # noqa: E402
from src.auth.store import audit, team_assets  # noqa: E402
from src.auth.ui import auth_enabled, require_login, sign_out, user_badge  # noqa: E402
from src.notify.notifier import (  # noqa: E402
    compose, deliver, devices_needing_action, load_config as load_notify_config,
    load_kev_details, overview, parse_recipients, recipient_problems, vulnerability_details,
)
from src.remediation.planner import SLA_DAYS, plan_actions, weekly_plan  # noqa: E402
from src.evaluation.plan_comparison import CURVE_FILE, METHODS, PLANS, compare_plans  # noqa: E402
from src.attack_paths.attack_graph import (  # noqa: E402
    BAND_COLORS, REACHED_THRESHOLD, analyse, to_dot,
)
from src.explainability.explain_model import describe_features, shap_chunks  # noqa: E402
from src.models.train_models import prepare_features  # noqa: E402

RESULTS = PROJECT_ROOT / "results"

# One colour code for exposure levels and risk tiers everywhere. Status
# colours are reserved for these states and always appear with a shape
# symbol and a text label, so meaning never depends on colour alone.
LEVEL_COLORS = {
    "Critical": "#b71c1c",
    "High": "#d9480f",
    "Medium": "#d48806",
    "Low": "#137a13",
    "Unverified": "#5f6468",
    "Unknown": "#868b8f",
}
# Text colour on a solid status fill (dark text where white would not read)
LEVEL_TEXT = {"Medium": "#1b1b1b"}
LEVEL_ICONS = {"Critical": "▲", "High": "◆", "Medium": "●", "Low": "✓",
               "Unverified": "?", "Unknown": "–"}
LEVEL_SHAPES = {"Critical": "triangle-up", "High": "diamond", "Medium": "circle",
                "Low": "square", "Unverified": "cross", "Unknown": "cross"}
LEVEL_MEANING = {
    "Critical": "known exploited, or top 1% predicted risk",
    "High": "top 5% predicted, or a product attackers targeted this year",
    "Medium": "top 20% predicted risk",
    "Low": "no recent CVE above the Low tier",
    "Unverified": "version unreadable, check manually",
    "Unknown": "in inventory, not seen in scan",
}
LEVEL_ORDER = ["Critical", "High", "Medium", "Low", "Unverified", "Unknown"]
TIER_ORDER = ["Critical", "High", "Medium", "Low"]

st.set_page_config(page_title="Asset Exposure Prediction", page_icon="🛡️", layout="wide")


# ==============================
# Appearance: one modern dark theme (navy surfaces, sky-blue accent)
# ==============================

# Full Streamlit theme, so tables, inputs and charts match the custom CSS.
# Also set in .streamlit/config.toml; applied here in case that file is missing.
THEME = {"base": "dark", "primaryColor": "#38bdf8", "backgroundColor": "#0b1220",
         "secondaryBackgroundColor": "#131c2e", "textColor": "#e2e8f0"}
theme_name = "Dark"
ON_PRIMARY = {"Dark": "#0b1220"}

if any(st_config.get_option(f"theme.{key}") != value for key, value in THEME.items()):
    for key, value in THEME.items():
        st_config.set_option(f"theme.{key}", value)
    st.rerun()

PRIMARY = THEME["primaryColor"]

st.markdown("""
<style>
.block-container { padding-top: 2rem; }
[data-testid="stMetric"] {
  background: rgba(127, 127, 127, 0.07); border: 1px solid rgba(127, 127, 127, 0.22);
  border-radius: 12px; padding: 14px 16px;
}

/* Tabs as a segmented pill bar */
.stTabs [data-baseweb="tab-list"] {
  gap: 6px; padding: 6px; border-radius: 14px; flex-wrap: wrap;
  background: rgba(127, 127, 127, 0.08); border: 1px solid rgba(127, 127, 127, 0.18);
}
.stTabs [data-baseweb="tab"] {
  height: auto; padding: 9px 16px; border-radius: 10px; background: transparent;
  transition: background 0.15s ease, box-shadow 0.15s ease;
}
.stTabs [data-baseweb="tab"] p { font-weight: 600; font-size: 0.95rem; }
.stTabs [data-baseweb="tab"]:hover { background: rgba(127, 127, 127, 0.15); }
.stTabs [data-baseweb="tab"][aria-selected="true"] {
  background: %PRIMARY%; box-shadow: 0 3px 10px rgba(0, 0, 0, 0.18);
}
.stTabs [data-baseweb="tab"][aria-selected="true"] p,
.stTabs [data-baseweb="tab"][aria-selected="true"] span { color: %ON_PRIMARY% !important; }
.stTabs [data-baseweb="tab"]:focus-visible { outline: 2px solid %PRIMARY%; outline-offset: 2px; }
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] { display: none; }
.stTabs [data-baseweb="tab-panel"] { padding-top: 18px; }
@media (prefers-reduced-motion: reduce) { .stTabs [data-baseweb="tab"] { transition: none; } }

.hero {
  background: %HERO%; color: #eef2f0; border-radius: 14px; padding: 22px 26px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  display: flex; flex-direction: column; gap: 8px; margin-bottom: 10px;
}
.hero h1 { color: #eef2f0; font-size: 1.85rem; margin: 0; padding: 0; line-height: 1.2; }
.hero p { color: #b9cdd3; margin: 0; }
.hero .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px; }
.hero .chips span {
  background: rgba(255, 255, 255, 0.1); color: #eef2f0; border-radius: 999px;
  padding: 3px 12px; font-size: 0.85rem;
}
.legend { display: flex; flex-wrap: wrap; gap: 8px; margin: 2px 0 10px; }
.legend span {
  display: inline-flex; align-items: center; gap: 6px; padding: 4px 11px;
  border-radius: 999px; font-size: 0.85rem; border: 1px solid rgba(127, 127, 127, 0.3);
}
.legend i {
  font-style: normal; font-weight: 700; padding: 2px 9px; border-radius: 999px;
}
</style>
""".replace("%PRIMARY%", PRIMARY)
   .replace("%ON_PRIMARY%", ON_PRIMARY[theme_name])
   .replace("%HERO%", "radial-gradient(circle at 100% 0%, rgba(56,189,248,0.22) 0, "
                       "rgba(56,189,248,0) 45%), linear-gradient(135deg, #1e293b 0%, #0f172a 55%, "
                       "#1e1b4b 100%)"),
    unsafe_allow_html=True)

# 3D card look (tiles, number cards, page headers) on dark navy surfaces
SURFACE = {"top": "#172033", "bottom": "#0f172a", "border": "rgba(148,163,184,0.16)",
           "shadow": "rgba(0,0,0,0.45)", "shadow_hover": "rgba(0,0,0,0.65)",
           "muted": "#94a3b8", "shine": "rgba(255,255,255,0.06)"}

css_3d = """
<style>
[class*="st-key-tile_"], .kpi3d, .page-head {
  background: linear-gradient(150deg, %TOP% 0%, %BOTTOM% 100%);
  border: 1px solid %BORDER%; border-radius: 20px;
  box-shadow: inset 0 1px 0 %SHINE%, 0 12px 26px %SHADOW%, 0 3px 7px %SHADOW%;
}
[class*="st-key-tile_"] {
  position: relative; overflow: hidden; cursor: pointer;
  padding: 26px 24px 22px; gap: 6px; border-radius: 22px; min-height: 210px;
  transition: transform 0.22s ease, box-shadow 0.22s ease;
}
[class*="st-key-tile_"]:hover {
  transform: translateY(-8px) perspective(900px) rotateX(2.5deg);
}
/* The whole tile is the button: an invisible, full-size click target that
   stays focusable and readable by screen readers */
[class*="st-key-tile_"] [data-testid="stElementContainer"]:has(.stButton),
[class*="st-key-tile_"] .stElementContainer:has(.stButton) {
  position: absolute !important; inset: 0 !important; width: auto !important;
  height: auto !important; margin: 0 !important; z-index: 5;
}
/* Streamlit wraps the button in extra layers: keep them unpositioned so the
   button itself can stretch over the whole tile */
[class*="st-key-tile_"] .stButton, [class*="st-key-tile_"] .stButton * {
  position: static !important;
}
[class*="st-key-tile_"] .stButton button {
  position: absolute !important; inset: 0 !important; width: 100% !important;
  height: 100% !important; max-width: none !important;
  opacity: 0; cursor: pointer; border: none; border-radius: 22px;
}
[class*="st-key-tile_"]:has(button:focus-visible) {
  outline: 3px solid %PRIMARY%; outline-offset: 3px;
}
.tile-icon {
  width: 60px; height: 60px; border-radius: 18px; display: grid; place-items: center;
  font-size: 30px; margin-bottom: 4px;
  box-shadow: 0 8px 16px rgba(0,0,0,0.22), inset 0 -4px 8px rgba(0,0,0,0.22),
              inset 0 3px 5px rgba(255,255,255,0.40);
}
.tile-title { font-size: 1.18rem; font-weight: 700; margin: 6px 0 2px; }
.tile-desc { color: %MUTED%; font-size: 0.9rem; line-height: 1.4; min-height: 2.6em; margin: 0; }
.tile-kpi {
  display: inline-block; margin-top: 10px; padding: 4px 12px; border-radius: 999px;
  font-weight: 700; font-size: 0.85rem; color: #ffffff;
  box-shadow: 0 3px 8px rgba(0,0,0,0.18);
}
[class*="st-key-nav_"] button {
  border-radius: 999px; font-weight: 700; padding: 6px 16px;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
}
[class*="st-key-nav_home"] button {
  border: none; background: %PRIMARY%; color: %ON_PRIMARY%;
  box-shadow: 0 6px 14px rgba(0,0,0,0.15);
}
[class*="st-key-nav_home"] button p, [class*="st-key-nav_home"] button span { color: %ON_PRIMARY%; }
[class*="st-key-nav_back"] button {
  border: 1.5px solid %PRIMARY%; background: transparent; color: %PRIMARY%;
}
[class*="st-key-nav_back"] button p, [class*="st-key-nav_back"] button span { color: %PRIMARY%; }
[class*="st-key-nav_"] button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.18);
  filter: brightness(1.06); }
[class*="st-key-nav_home"] button:hover { background: %PRIMARY%; color: %ON_PRIMARY%; }
[class*="st-key-nav_back"] button:hover { background: transparent; color: %PRIMARY%; border-color: %PRIMARY%; }
.kpi3d { padding: 18px 20px; display: flex; flex-direction: column; gap: 4px; height: 100%; }
.kpi3d .kpi-label { color: %MUTED%; font-size: 0.85rem; font-weight: 600; }
.kpi3d .kpi-value { font-size: 2.3rem; font-weight: 800; line-height: 1.05; }
.kpi3d .kpi-note { color: %MUTED%; font-size: 0.8rem; }
.page-head { padding: 16px 20px; display: flex; align-items: center; gap: 16px; margin: 4px 0 14px; }
.page-head h2 { margin: 0; padding: 0; font-size: 1.5rem; }
.page-head p { margin: 2px 0 0; color: %MUTED%; }
.welcome { font-size: 1.05rem; color: %MUTED%; margin: 2px 0 14px; }
.st-key-scan_network button {
  border: none; border-radius: 12px; padding: 10px 0; font-weight: 700;
  background: linear-gradient(100deg, #6366f1, #0ea5e9); color: #ffffff;
  box-shadow: 0 8px 20px rgba(56,189,248,0.25); transition: transform .15s ease, box-shadow .15s ease;
}
.st-key-scan_network button p, .st-key-scan_network button span { color: #ffffff; }
.st-key-scan_network button:hover { transform: translateY(-2px); color: #ffffff;
  box-shadow: 0 12px 26px rgba(56,189,248,0.40); }
@media (prefers-reduced-motion: reduce) {
  [class*="st-key-tile_"] { transition: none; }
  [class*="st-key-tile_"]:hover { transform: none; }
}
</style>
"""
for token, value in {"%TOP%": SURFACE["top"], "%BOTTOM%": SURFACE["bottom"],
                     "%BORDER%": SURFACE["border"], "%SHADOW_HOVER%": SURFACE["shadow_hover"],
                     "%SHADOW%": SURFACE["shadow"], "%SHINE%": SURFACE["shine"],
                     "%MUTED%": SURFACE["muted"], "%ON_PRIMARY%": ON_PRIMARY[theme_name],
                     "%PRIMARY%": PRIMARY}.items():
    css_3d = css_3d.replace(token, value)
st.markdown(css_3d, unsafe_allow_html=True)



# ==============================
# Sign-in (password + MFA) and role
# ==============================

user = require_login()


# ==============================
# Data
# ==============================

LIVE_STATE = PROJECT_ROOT / "data" / "live" / "sync_state.json"


def live_stamp():
    """Changes whenever the background sync (CISA KEV, NIST NVD) writes new data."""
    return LIVE_STATE.stat().st_mtime if LIVE_STATE.exists() else 0.0


@st.cache_resource(show_spinner="Loading the latest NVD, KEV and model data...", max_entries=1)
def _reference_data(stamp):
    # Frozen research data plus the updates from the background live sync (data/live)
    return load_reference_data(live=True)


def reference_data():
    return _reference_data(live_stamp())


@st.cache_resource
def _seen_stamp():
    return {"stamp": None}


# New threat data arrived from the background sync: recompute every cached
# assessment so all pages use it, without the user doing anything
_seen = _seen_stamp()
if _seen["stamp"] is not None and _seen["stamp"] != live_stamp():
    st.cache_data.clear()
_seen["stamp"] = live_stamp()


@st.cache_data(show_spinner="Assessing scan...")
def run_assessment(scan_bytes, inventory_bytes):
    inventory = pd.read_csv(io.BytesIO(inventory_bytes))
    return assess(io.BytesIO(scan_bytes), inventory, reference_data())


@st.cache_data(show_spinner="Assessing scan sheet...")
def run_sheet_assessment(sheet_bytes, overrides_csv=""):
    """Scan sheet (CSV) -> assessment; raises ScanSheetError listing every problem.
    overrides_csv: the user's importance settings for this network (step 2)."""
    services, inventory, scan_date = parse_scan_sheet(sheet_bytes)
    overrides = pd.read_csv(io.StringIO(overrides_csv), dtype=str, keep_default_na=False) \
        if overrides_csv else None
    return assess_services(services, apply_importance(inventory, overrides), reference_data(), scan_date)


@st.cache_data(show_spinner="Assessing lab snapshot...")
def run_lab_assessment(db_path, snapshot_id):
    services, inventory, snapshot_date = load_snapshot(snapshot_id, db_path)
    return assess_services(services, inventory, reference_data(), snapshot_date)


@st.cache_data(show_spinner="Tracing attack paths...")
def run_attack_paths(db_path, snapshot_id, start_type, value):
    services, inventory, _ = load_snapshot(snapshot_id, db_path)
    _, _, cves = run_lab_assessment(db_path, snapshot_id)
    segments_table, rules, trusts = load_topology(db_path)
    scenario = analyse(start_type, value, inventory, services, cves, rules, trusts, segments_table)
    return scenario, to_dot(scenario, inventory, segments_table), inventory, rules, trusts


@st.cache_data(show_spinner="Tracing how an attack could spread...")
def run_scan_attack(key, start_type, value, _services, _assets, _cves, trust_file):
    """Attack paths on a scanned network (key identifies the assessment)."""
    inventory, rules, trusts, segments_table = scan_topology(_assets, trust_file)
    scenario = analyse(start_type, value, inventory, _services, _cves, rules, trusts, segments_table)
    return scenario, to_dot(scenario, inventory, segments_table)


@st.cache_data(show_spinner="Planning remediation...")
def run_plan(plan_key, _services, _assets, _cves):
    """Upgrade actions for the current assessment (plan_key identifies it)."""
    return plan_actions(_services, _assets, _cves, reference_data()["cpe_matches"])


def scan_config():
    return load_scan_config(PROJECT_ROOT / "config" / "scan_targets.json")


def scan_label(path):
    """Readable name for a live scan file, demo organisation or uploaded file."""
    name = Path(path).name
    if name in DEMO_LABELS:
        return DEMO_LABELS[name]
    stamp = re.match(r"scan-(\d{8})-(\d{6})", name)
    if stamp:
        when = datetime.strptime(stamp.group(1) + stamp.group(2), "%Y%m%d%H%M%S")
        return f"Live Nmap scan · {when:%d %b %Y %H:%M}"
    return name


@st.cache_data(show_spinner=False)
def inventory_bytes(overrides_csv=""):
    """Asset inventory for Nmap scans: the asset list plus the VirtualBox lab hosts,
    with the user's importance settings (step 2) applied."""
    lab = PROJECT_ROOT / scan_config()["lab_inventory"]
    frames = [pd.read_csv(PROJECT_ROOT / ASSETS_FILE)] + ([pd.read_csv(lab)] if lab.exists() else [])
    inventory = pd.concat(frames, ignore_index=True).drop_duplicates("ip_address", keep="last")
    overrides = pd.read_csv(io.StringIO(overrides_csv), dtype=str, keep_default_na=False) \
        if overrides_csv else None
    return apply_importance(inventory, overrides).to_csv(index=False).encode()


def importance_csv(network):
    """This network's saved importance settings as CSV text (part of the cache key)."""
    table = load_importance(network, PROJECT_ROOT / IMPORTANCE_FILE)
    return "" if table.empty else table.to_csv(index=False)


@st.cache_data(show_spinner=False)
def kev_details():
    """CISA KEV ransomware use and descriptions for the notification email."""
    return load_kev_details()


@st.cache_resource
def base_model():
    return joblib.load(PROJECT_ROOT / reference_data()["bundle"]["base_model"])


@st.cache_data
def cve_shap(cve_id):
    """SHAP values (log-odds) for one CVE from the base model."""
    scoring = reference_data()["scoring"]
    row = prepare_features(scoring[scoring["cve_id"] == cve_id])
    model = base_model()

    _, _, contrib = next(shap_chunks(model, row))
    names, groups = describe_features(model.named_steps["prep"])

    shap = pd.DataFrame({"feature": names, "group": groups, "shap": contrib[0, :-1]})
    shap = shap[shap["shap"] != 0]
    shap["abs"] = shap["shap"].abs()

    return shap.sort_values("abs", ascending=False), row["description_clean"].iloc[0]


def dark_mode():
    return True    # the dashboard has one dark theme


def with_icon(level):
    return f"{LEVEL_ICONS[level]} {level}" if level in LEVEL_ICONS else level


def tint_level(value):
    # Accepts "Critical" or "▲ Critical"; solid fill, bold text
    level = str(value).split()[-1] if pd.notna(value) else None
    color = LEVEL_COLORS.get(level)
    if not color:
        return ""
    return (f"background-color: {color}; color: {LEVEL_TEXT.get(level, '#ffffff')}; "
            "font-weight: 700")


def level_color(levels):
    return alt.Scale(domain=levels, range=[LEVEL_COLORS[l] for l in levels])


def level_shape(levels):
    return alt.Scale(domain=levels, range=[LEVEL_SHAPES[l] for l in levels])


def legend_html(levels):
    return "<div class='legend'>" + "".join(
        f"<span><i style='background:{LEVEL_COLORS[l]};color:{LEVEL_TEXT.get(l, '#ffffff')}'>"
        f"{LEVEL_ICONS[l]} {l}</i>{LEVEL_MEANING[l]}</span>" for l in levels) + "</div>"


# ==============================
# Sidebar: scan source
# ==============================

if auth_enabled():
    badge_col, out_col = st.sidebar.columns([3, 2])
    badge_col.markdown(user_badge(user))
    if out_col.button("Sign out", icon=":material/logout:"):
        sign_out()
        st.rerun()
else:
    st.sidebar.warning("**Development mode:** sign-in and roles are switched off. "
                       "Turn them back on in `config/auth.json` before a demo.",
                       icon=":material/lock_open:")

# ---- Pages: a simple home page plus one page per section ----
# key: (icon, title, one-line description, badge colours for the 3D icon)
# Gradient colours chosen so white text keeps at least 4.5:1 contrast
PAGES = {
    "overview": ("📊", "Asset exposure", "All devices ranked by risk, with charts", ("#4f46e5", "#312e81")),
    "detail": ("💻", "Device details", "One device: its weaknesses and why they matter", ("#0369a1", "#0c4a6e")),
    "paths": ("🕸️", "Attack paths", "If one device is hacked, how far can it spread?", ("#c2410c", "#7c2d12")),
    "remediation": ("🔧", "Patch plan", "Which fixes remove the most risk first", ("#047857", "#064e3b")),
    "notifications": ("📧", "Notify teams", "Tell owning teams what to fix", ("#b45309", "#78350f")),
    "compare": ("⚖️", "Plan comparison",
                "Is our prioritisation better than sorting by CVSS or by device importance?",
                ("#0891b2", "#164e63")),
    "live": ("📡", "Live feed", "New threats and alerts from today's data", ("#e11d48", "#881337")),
    "model": ("📈", "Model evidence", "How accurate the predictions are", ("#7c3aed", "#4c1d95")),
    "backtest": ("🕘", "Backtest", "Did the predictions come true?", ("#475569", "#1e293b")),
    "admin": ("🛡️", "Administration", "Users, roles and the audit log", ("#0f766e", "#134e4a")),
}


def tint(hex_colour, white_share):
    """Mix a colour with white (0 = colour unchanged, 1 = white) for pastel backgrounds."""
    r, g, b = (int(hex_colour.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
    return "#" + "".join(f"{round(c + (255 - c) * white_share):02x}" for c in (r, g, b))
# Simple mode (default): one "Scan & fix" page plus alerts and the accuracy
# evidence. Advanced tools (detailed analysis pages) are switched on in the sidebar.
# The public data sources (CISA KEV, NIST NVD) update automatically in the background
# (scheduled live sync), so there is no live-feed page in the menu
SIMPLE_PAGES = {"compare": "Plan comparison", "model": "Is the AI accurate?"}
HIDDEN_PAGES = {"live"}
advanced = st.sidebar.toggle("Advanced tools", key="advanced_mode",
                             help="Show the detailed analysis pages: asset tables, attack paths, "
                                  "patch planner, notices, backtest and administration.")

# Pages a role may not open are never built: their data is never computed
# or sent to the browser (not just hidden)
allowed_pages = [key for key in PAGES if (TAB_ACCESS[key] is None or can(user, TAB_ACCESS[key]))
                 and (advanced or key in SIMPLE_PAGES) and key not in HIDDEN_PAGES]
if st.session_state.get("nav_page") not in ["home"] + allowed_pages or st.session_state.pop("go_home", False):
    st.session_state["nav_page"] = "home"


def go_to(page):
    st.session_state["nav_page"] = page


def go_back():
    """Return to the previously opened page (Home when there is no history)."""
    history = st.session_state.get("nav_history", [])
    st.session_state["nav_page"] = history.pop() if history else "home"
    st.session_state["nav_going_back"] = True


st.sidebar.radio(
    "Go to", ["home"] + allowed_pages, key="nav_page",
    format_func=lambda k: "Scan & fix" if k == "home" else
    SIMPLE_PAGES[k] if not advanced and k in SIMPLE_PAGES else PAGES[k][1])
page = st.session_state["nav_page"]

# Page history for the Back button (tiles, sidebar and Home all count as moves)
previous = st.session_state.get("nav_last_page")
if previous is not None and previous != page and not st.session_state.pop("nav_going_back", False):
    st.session_state.setdefault("nav_history", []).append(previous)
    st.session_state["nav_history"] = st.session_state["nav_history"][-20:]
st.session_state.pop("nav_going_back", None)
st.session_state["nav_last_page"] = page


def back_bar(where):
    """Back and Home buttons; `where` keeps the widget keys unique (top / bottom)."""
    back_col, home_col, _ = st.columns([1.1, 1.1, 7.8])
    history = st.session_state.get("nav_history", [])
    target = PAGES[history[-1]][1] if history and history[-1] in PAGES else "Home"
    with back_col.container(key=f"nav_back_{where}"):
        st.button("Back", key=f"back_btn_{where}", on_click=go_back, icon=":material/arrow_back:",
                  width="stretch", help=f"Back to {target}")
    with home_col.container(key=f"nav_home_{where}"):
        st.button("Home", key=f"home_btn_{where}", on_click=go_to, args=("home",),
                  icon=":material/home:", width="stretch", help="Back to the home page")
st.sidebar.divider()

st.sidebar.markdown("**Network**")

DEMO_SCAN_DIR = PROJECT_ROOT / "data" / "demo_scans"
# Fictional companies: the names are invented for the demonstration
DEMO_LABELS = {"demo_scan_1_zentrova_systems.csv": "Zentrova Systems (20 devices)",
               "demo_scan_2_kyvora_cloud_services.csv": "Kyvora Cloud Services (14 devices)",
               "demo_scan_3_quantelix_data_solutions.csv": "Quantelix Data Solutions (18 devices)"}
SCAN_PROFILES = {"Full service and version scan (recommended)": "full",
                 "Quick host discovery only": "discovery"}
LIVE_SCAN_DIR = PROJECT_ROOT / scan_config()["output_dir"]


def close_scan_dialog():
    for key in ["scan_dialog_open", "scan_result"]:
        st.session_state.pop(key, None)


def load_scan(path):
    """Show this scan file (live Nmap XML or demo sheet) under Scan upload."""
    st.session_state["asset_source"] = "Scan upload"
    st.session_state["demo_scan"] = Path(path)
    st.session_state["go_home"] = True          # applied before the menu is drawn
    st.session_state["next_step"] = "Discover"  # new scan: start the workflow at step 1
    st.session_state.pop("fix_device", None)    # start with the most urgent device
    close_scan_dialog()
    st.rerun()


@st.dialog("Scan the network", width="large", icon=":material/radar:", on_dismiss=close_scan_dialog)
def scan_network_dialog():
    """
    Live Nmap service scan of the approved lab ranges (config/scan_targets.json),
    imported as the asset inventory. Targets outside the approved ranges are refused.
    """
    config = scan_config()
    nmap = find_nmap(config)
    st.markdown("Discover every device on the network and the software it runs. "
                "The results become the **asset inventory** and are assessed automatically.")
    target = st.text_input("Targets to scan", config["default_target"],
                           help="IP addresses, CIDR ranges or a.b.c.x-y ranges, separated by commas. "
                                f"Approved ranges: {', '.join(config['allowed_targets'])}")
    profile = st.radio("Scan type", list(SCAN_PROFILES))
    authorised = st.checkbox("I confirm this organisation has authorised me to scan this network")

    problems = target_problems(target, config)
    if problems:
        st.error("Cannot scan: " + "; ".join(problems) + ".")
    else:
        st.caption(f"Approved lab range · Nmap: {'found' if nmap else 'NOT FOUND'} · "
                   f"time limit {config['timeout_seconds'] // 60} min")

    # The VirtualBox lab must be running before it can be scanned
    lab = lab_status(config.get("lab_vms", []))
    if lab:
        running = [vm for vm, state in lab.items() if state == "running"]
        stopped = [vm for vm, state in lab.items() if state == "stopped"]
        if stopped:
            col_text, col_button = st.columns([3, 1], vertical_alignment="center")
            col_text.warning(f"Lab VMs running: {len(running)} of {len(lab)} "
                             f"({', '.join(stopped)} stopped).")
            if col_button.button("Start lab VMs", icon=":material/play_arrow:"):
                started = start_lab(config["lab_vms"])
                audit("lab_started", user["username"], user["role"], ", ".join(started))
                st.session_state["lab_started_at"] = datetime.now()
                st.rerun(scope="fragment")
        else:
            st.caption(f"✅ Lab VMs running: {', '.join(running)}")
        started_at = st.session_state.get("lab_started_at")
        if started_at and (datetime.now() - started_at).total_seconds() < 60:
            st.info("Lab VMs are starting. Wait about a minute before scanning.")

    if st.button("Start scan", type="primary", icon=":material/radar:",
                 disabled=not (authorised and not problems and nmap)):
        with st.spinner(f"Scanning {target} with Nmap (service and version detection can take "
                        "a few minutes)..."):
            try:
                path, summary = run_scan(target, SCAN_PROFILES[profile], config)
            except (ValueError, RuntimeError) as error:
                audit("scan_failed", user["username"], user["role"], f"{target}: {error}", "failure")
                st.session_state["scan_result"] = {"error": str(error)}
            else:
                audit("scan_run", user["username"], user["role"],
                      f"{target} ({SCAN_PROFILES[profile]}): {len(summary['hosts_up'])} hosts, "
                      f"{summary['open_services']} services -> {path.name}")
                st.session_state["scan_result"] = {"path": str(path), "profile": SCAN_PROFILES[profile],
                                                   **summary}

    result = st.session_state.get("scan_result")
    if result and "error" in result:
        st.error(f"Scan failed: {result['error']}")
    elif result:
        st.success(f"**Scan complete:** {len(result['hosts_up'])} host(s) up "
                   f"({', '.join(result['hosts_up']) or 'none'}), {result['open_services']} open "
                   f"services, {result['versioned_services']} with software versions.")
        st.code(result["command"], language="bash")
        if result["profile"] == "full" and result["open_services"]:
            if st.button("Assess these results", type="primary", icon=":material/insights:"):
                load_scan(result["path"])
        else:
            st.caption("Host discovery finds devices only. Run a full scan to assess their software.")

    if not nmap:
        st.warning("Nmap is not installed on this computer. You can load a simulated scan instead.")
    if st.button("Load a simulated scan instead", icon=":material/science:"):
        load_scan(DEMO_SCAN_DIR / "demo_scan_1_zentrova_systems.csv")
    st.caption("Scan only networks you are authorised to scan. Every scan is recorded in the audit log.")


if can(user, "upload_scans"):
    with st.sidebar.container(key="scan_network"):
        st.button("Scan the network", icon=":material/radar:", type="primary", width="stretch",
                  on_click=lambda: st.session_state.update(scan_dialog_open=True, scan_result=None))
    if st.session_state.get("scan_dialog_open"):
        scan_network_dialog()

if advanced:
    source = st.sidebar.radio(
        "Assess", ["Lab database"] + (["Scan upload"] if can(user, "upload_scans") else []),
        label_visibility="collapsed", key="asset_source")
else:
    # Simple mode: always the scan results (the research lab database is an advanced tool)
    source = "Scan upload" if can(user, "upload_scans") else "Lab database"
    st.session_state["asset_source"] = source

SYNTHETIC_DB = PROJECT_ROOT / DB_FILE
network = None          # scanned network (for importance settings); None for the lab database

if source == "Lab database":
    # The synthetic lab plus any real lab built with src.lab.import_scans
    lab_dbs = sorted((PROJECT_ROOT / "data" / "lab").glob("*.db"),
                     key=lambda p: (p != SYNTHETIC_DB, p.name))
    db_names = {SYNTHETIC_DB.name: "Synthetic organisation (30 assets)",
                "vmware_lab.db": "VMware lab (real scans)"}
    lab_db = st.sidebar.selectbox(
        "Lab", [str(p) for p in lab_dbs],
        format_func=lambda p: db_names.get(Path(p).name, Path(p).name))

    snapshots = list_snapshots(lab_db)
    snapshot_ids = snapshots["snapshot_id"].tolist()
    snapshot_id = st.sidebar.selectbox(
        "Snapshot", snapshot_ids,
        index=snapshot_ids.index("current") if "current" in snapshot_ids else len(snapshot_ids) - 1,
        format_func=lambda s: f"{s} ({snapshots.set_index('snapshot_id').loc[s, 'snapshot_date']})")

    services, assets, cves = run_lab_assessment(lab_db, snapshot_id)
    if Path(lab_db) == SYNTHETIC_DB:
        st.sidebar.warning("Synthetic sample organisation for research testing. Installed "
                           "versions are derived from real NVD fix versions per patch-hygiene "
                           "profile.")
    else:
        st.sidebar.info("Real lab assessment from Nmap scans. Inventory, firewall rules and "
                        "trust links come from config/vmware_lab.")
    source_line = f"**Lab database:** `{Path(lab_db).relative_to(PROJECT_ROOT)}`"

else:
    uploaded = st.sidebar.file_uploader(
        "Upload a scan sheet (.csv) or Nmap XML (.xml)", type=["csv", "xml"],
        help="Scan sheet: one row per discovered service, with the asset's criticality and "
             "internet exposure. Nmap XML: output of nmap -sV -oX scan.xml <targets>, matched "
             f"to the inventory in {ASSETS_FILE}.") if advanced else None

    # Live Nmap scans of the lab (newest first), then the demo organisations
    live_scans = sorted(LIVE_SCAN_DIR.glob("scan-*-full.xml"), reverse=True)
    demo_files = live_scans + sorted(DEMO_SCAN_DIR.glob("demo_scan_*.csv"))
    if uploaded is not None:
        scan_bytes, scan_name = uploaded.getvalue(), uploaded.name
        upload_key = f"{scan_name}:{len(scan_bytes)}"
        if st.session_state.get("audited_upload") != upload_key:
            audit("scan_uploaded", user["username"], user["role"],
                  f"{scan_name} ({len(scan_bytes):,} bytes)")
            st.session_state["audited_upload"] = upload_key
    elif demo_files:
        if st.session_state.get("demo_scan") not in demo_files:
            st.session_state.pop("demo_scan", None)
        demo = st.sidebar.selectbox("Show results for", demo_files, key="demo_scan",
                                    format_func=scan_label,
                                    help="Your network scans (newest first) and three fictional "
                                         "demo organisations")
        scan_bytes, scan_name = demo.read_bytes(), demo.name
    else:
        scan_bytes, scan_name = (PROJECT_ROOT / DEFAULT_SCAN).read_bytes(), "sample_nmap_scan.xml"

    template = DEMO_SCAN_DIR / "scan_sheet_template.csv"
    if advanced and template.exists():
        st.sidebar.download_button("Download scan sheet template", template.read_bytes(),
                                   "scan_sheet_template.csv", "text/csv",
                                   icon=":material/download:", width="stretch")

    network = network_key(scan_name)
    if scan_name.lower().endswith(".csv"):
        try:
            services, assets, cves = run_sheet_assessment(scan_bytes, importance_csv(network))
        except ScanSheetError as error:
            st.error("**This scan sheet cannot be used:**\n\n"
                     + "\n".join(f"- {problem}" for problem in error.problems)
                     + "\n\nDownload the template from the sidebar to see the expected columns.")
            st.stop()
        source_line = (f"**Organisation:** {DEMO_LABELS[scan_name].split(' (')[0]}"
                       if scan_name in DEMO_LABELS else f"**Scan sheet:** {scan_name}")
    else:
        services, assets, cves = run_assessment(scan_bytes, inventory_bytes(importance_csv(network)))
        if services.empty:
            st.warning(f"**{scan_label(Path(scan_name))}** found no open services, so there is "
                       "nothing to assess. Check that the lab VMs are running and scan again.")
            st.stop()
        source_line = (f"**Live Nmap scan:** {scan_label(Path(scan_name))}"
                       if scan_name.startswith("scan-") else f"**Nmap scan:** {scan_name}")
        source_line += "  \n**Inventory:** asset list + VirtualBox lab"

    if scan_name.startswith("demo_scan_"):
        st.sidebar.caption("Fictional company with simulated scan results. Installed versions "
                           "are real NVD fix versions for each host's patch level.")

scan_time = services["scan_time"].iloc[0]

# Asset Owners see only the assets their team owns (data scoping)
owned_assets = None
if not can(user, "view_all_assets"):
    owned_assets = team_assets(Path(lab_db).name, user.get("team") or "")
    assets = assets[assets["asset_id"].isin(owned_assets)]
    owned_ips = set(assets["ip_address"])
    services = services[services["ip_address"].isin(owned_ips)]
    cves = cves[cves["ip_address"].isin(owned_ips)]
    if assets.empty:
        st.warning("No assets in this lab are assigned to your team. Ask a security analyst "
                   "to assign asset ownership.")
        st.stop()

live_info = reference_data().get("live")
if advanced:
    st.sidebar.markdown(f"{source_line}  \n**Assessment date:** {scan_time:%Y-%m-%d}")
    if live_info and live_info.get("last_sync"):
        st.sidebar.success(f"**Live data** as of {live_info['last_sync']}  \n"
                           f"{live_info['nvd_changes']:,} NVD updates · "
                           f"{live_info['kev_entries']:,} KEV entries")
    else:
        st.sidebar.caption("Vulnerability data: frozen research snapshot (NVD to 3 Oct 2026, "
                           "KEV to 22 Sep 2026). Run the live sync to update.")
    if can(user, "reload_data") and st.sidebar.button("Reload latest data",
                                                       help="Use after a live sync has run"):
        audit("data_reloaded", user["username"], user["role"])
        st.cache_data.clear()
        st.cache_resource.clear()
        st.rerun()

    st.sidebar.divider()
    st.sidebar.caption(
        "Predictions: probability that a CVE is added to CISA KEV within "
        "12 months of publication. LightGBM on CVSS, threat history and "
        "description text. Live model: "
        + ("retrained model, " + reference_data()["bundle"].get("trained_on", "")
           if reference_data()["bundle"].get("role") == "operational" else
           "research model, calibrated on 2024 CVEs and tested on 2025")
        + " (chosen by the latest champion/challenger review)."
    )
elif live_info and live_info.get("last_sync"):
    st.sidebar.caption(f"Threat data from CISA and NIST, updated {live_info['last_sync']}")



# ==============================
# Header
# ==============================

source_label = ("Synthetic lab database" if source.startswith("Lab") else
                DEMO_LABELS[scan_name].split(" (")[0] if scan_name in DEMO_LABELS else
                "Live Nmap scan (VirtualBox lab)" if scan_name.startswith("scan-") else "Uploaded scan")
scanned = assets[assets["scan_status"] != "Not scanned"]

plan_all, plan_states = run_plan(
    f"{source_line}|{scan_time}|{(live_info or {}).get('last_sync')}|{user['username']}",
    services, assets, cves)

# Devices whose owning team should be told what to fix
notify_config = load_notify_config()
notify_lab = Path(lab_db).name if source == "Lab database" else f"scan:{scan_name}"
notify_history = auth_store.list_notifications(notify_lab)
needs_notice = devices_needing_action(assets, plan_all, notify_history, notify_config)
pending_notices = int((needs_notice["status"] == "Not notified").sum()) if not needs_notice.empty else 0
if advanced and can(user, "send_notifications") and pending_notices:
    st.sidebar.warning(f"🔔 **{pending_notices} device(s)** need their owning team informed. "
                       "Open **Notify teams**.")


# ==============================
# Home page
# ==============================

def live_alert_counts():
    """(urgent, total) open alerts from the live sync, for this user's assets."""
    path = PROJECT_ROOT / "data" / "live" / "alerts.csv"
    if not path.exists():
        return 0, 0
    alerts = pd.read_csv(path, keep_default_na=False)
    if owned_assets is not None:
        alerts = alerts[alerts["asset_id"].isin(owned_assets)]
    return int((alerts["level"] == "URGENT").sum()), len(alerts)


def kpi_card(label, value, note, colour):
    return (f"<div class='kpi3d'><span class='kpi-label'>{label}</span>"
            f"<span class='kpi-value' style='color:{colour}'>{value}</span>"
            f"<span class='kpi-note'>{note}</span></div>")


if page == "home":
    # ---- Scan & fix: scan -> devices to patch first -> how to fix the chosen one ----
    ACTION_LABELS = {  # exposure level -> (plain instruction, colour)
        "Critical": ("Fix today", "#ef4444"), "High": ("Fix this week", "#f97316"),
        "Medium": ("Plan this month", "#eab308"), "Low": ("OK for now", "#22c55e"),
        "Unverified": ("Check manually", "#94a3b8"), "Unknown": ("Not scanned", "#64748b"),
    }

    def badge(level):
        text, colour = ACTION_LABELS.get(level, (level, "#64748b"))
        return (f"<span style='background:{colour};color:#0b1220;font-weight:800;padding:3px 10px;"
                f"border-radius:999px;font-size:0.8rem;white-space:nowrap'>{text}</span>")

    def reason(row):
        if row["known_exploited"]:
            n = int(row["known_exploited"])
            return f"{n} weakness{'es are' if n != 1 else ' is'} being used by attackers right now"
        likely = int(row["critical_tier_cves"] + row["high_tier_cves"])
        if likely:
            return f"{likely} new weakness{'es are' if likely != 1 else ' is'} likely to be attacked soon"
        if row["product_kev_rate_12m"]:
            return "Runs software that attackers target often"
        if row["unconfirmed_cves"]:
            return "Software version could not be read: check it manually"
        return "No urgent problems found"

    devices = scanned.sort_values(["priority_score", "expected_new_exposure_12m"], ascending=False)
    devices = devices.reset_index(drop=True)
    counts = devices["exposure_level"].value_counts()
    best_fix = (plan_all.sort_values("risk_removed", ascending=False).drop_duplicates("asset_id")
                .set_index("asset_id") if not plan_all.empty else pd.DataFrame())

    # Header
    head_text, head_button = st.columns([4, 1], vertical_alignment="center")
    head_text.markdown(f"""
<div class="hero">
  <h1>🛡️ Network security check</h1>
  <p>Which devices to patch first, and exactly how to fix them.</p>
  <div class="chips"><span>{source_label}</span><span>Scanned {scan_time:%d %b %Y %H:%M}</span>
  <span>{len(devices)} devices found</span></div>
</div>""", unsafe_allow_html=True)
    if can(user, "upload_scans"):
        with head_button.container(key="scan_network_home"):
            st.button("Scan the network", icon=":material/radar:", type="primary", width="stretch",
                      key="scan_home", on_click=lambda: st.session_state.update(
                          scan_dialog_open=True, scan_result=None))

    k1, k2, k3, k4 = st.columns(4)
    k1.markdown(kpi_card("Devices found", len(devices), "on the scanned network", PRIMARY),
                unsafe_allow_html=True)
    k2.markdown(kpi_card("Fix today", int(counts.get("Critical", 0)),
                         "being attacked or very likely to be", "#f87171"), unsafe_allow_html=True)
    k3.markdown(kpi_card("Fix this week", int(counts.get("High", 0)), "high risk of attack", "#fb923c"),
                unsafe_allow_html=True)
    k4.markdown(kpi_card("OK or plan later", int(counts.get("Medium", 0) + counts.get("Low", 0)),
                         "no urgent action", "#4ade80"), unsafe_allow_html=True)

    if devices.empty:
        st.info("No devices found. Click **Scan the network** to scan your lab.")
        st.stop()

    # ---- Guided workflow: discover -> importance -> fix first -> attack spread -> compare ----
    STEPS = ["Discover", "Importance", "Fix first", "Attack spread", "Compare"]
    if st.session_state.get("next_step") in STEPS:          # requested by a button on the last run
        st.session_state["workflow_step"] = st.session_state.pop("next_step")
    if st.session_state.get("workflow_step") not in STEPS:
        st.session_state["workflow_step"] = STEPS[0]
    step = st.segmented_control("Workflow", STEPS, key="workflow_step", label_visibility="collapsed",
                                width="stretch") or STEPS[0]

    def next_button(label, target):
        st.button(label, key=f"next_{target}", type="primary", icon=":material/arrow_forward:",
                  on_click=lambda: st.session_state.update(next_step=target))

    trust_file = (PROJECT_ROOT / "config" / "virtualbox_lab" / "trust_links.csv") if network == "lab" else None

    if step == STEPS[0]:
        st.subheader("Devices discovered on the network")
        found = services.assign(software=services["product"].fillna(services["service"]).fillna("unknown")
                                + services["version"].map(lambda v: f" {v}" if isinstance(v, str) and v else ""))
        per_host = found.groupby("ip_address").agg(
            open_ports=("port", lambda p: ", ".join(str(int(x)) for x in sorted(set(p.dropna())))),
            software=("software", lambda s: ", ".join(dict.fromkeys(s))))
        table = devices[["hostname", "ip_address", "asset_type"]].merge(
            per_host, left_on="ip_address", right_index=True, how="left")
        table["hostname"] = table["hostname"].fillna(table["ip_address"])
        st.caption(f"{len(table)} devices and {len(services)} running services found. The scan reads "
                   "each service's software and version, which is what vulnerabilities are matched on.")
        st.dataframe(table, hide_index=True, use_container_width=True, column_config={
            "hostname": "Device", "ip_address": "IP address", "asset_type": "What it is",
            "open_ports": "Open ports", "software": st.column_config.TextColumn("Software found", width="large")})
        next_button("Next: how important is each device?", STEPS[1])

    elif step == STEPS[1]:
        st.subheader("How important is each device to the business?")
        st.markdown("A scan finds devices and software, but it cannot know **which devices matter most** "
                    "or **which can be reached from the internet**. Rate each device the standard way "
                    "(**NIST FIPS 199**): how bad would it be if…")
        st.markdown("- **Confidentiality:** its data is **stolen**?  \n"
                    "- **Integrity:** its data or settings are **changed**?  \n"
                    "- **Availability:** it **stops working**?  \n"
                    "**Business importance = the highest of the three.** Suggested values come from the "
                    "device type; change only what does not fit your organisation.")
        if network is None:
            st.info("This view uses the research lab database, whose importance settings are fixed. "
                    "Choose a scan under **Show results for** to set importance.")
        else:
            saved = load_importance(network, PROJECT_ROOT / IMPORTANCE_FILE).set_index("ip_address")
            editable = devices[["ip_address", "hostname", "asset_type", "internet_exposed"]].copy()
            editable["hostname"] = editable["hostname"].fillna(editable["ip_address"])
            editable["asset_type"] = editable["asset_type"].fillna("Unknown device")
            editable["internet_exposed"] = editable["internet_exposed"].where(
                editable["internet_exposed"].isin(["Yes", "No"]), "No")
            for row_index, row in editable.iterrows():
                stored = saved.loc[row["ip_address"]] if row["ip_address"] in saved.index else None
                suggestion = suggest_cia(row["asset_type"], row["hostname"])
                for field, default in zip(CIA, suggestion):
                    value = stored[field] if stored is not None and stored[field] in LEVELS else default
                    editable.loc[row_index, field] = value
            level = st.column_config.SelectboxColumn
            edited = st.data_editor(
                editable[["ip_address", "hostname", "asset_type"] + CIA + ["internet_exposed"]],
                key=f"importance_{network}", hide_index=True, use_container_width=True,
                disabled=["ip_address"], column_config={
                    "ip_address": "IP address", "hostname": "Device name", "asset_type": "What it is",
                    "confidentiality": level("Data stolen? (C)", options=LEVELS, required=True),
                    "integrity": level("Data changed? (I)", options=LEVELS, required=True),
                    "availability": level("Stops working? (A)", options=LEVELS, required=True),
                    "internet_exposed": level("Reachable from the internet?", options=["Yes", "No"],
                                              required=True)})
            result = edited.assign(importance=[overall(c, i, a) for c, i, a in
                                               zip(edited["confidentiality"], edited["integrity"],
                                                   edited["availability"])])
            current = devices.set_index("ip_address")["criticality"]
            result["now"] = result["ip_address"].map(current)
            changed = result[result["importance"] != result["now"]]
            st.markdown("**Business importance (calculated):** " + " · ".join(
                f"{r.hostname}: **{r.importance}**" for r in result.itertuples(index=False)))
            if not changed.empty:
                st.warning(f"{len(changed)} device(s) change importance when saved: " + ", ".join(
                    f"{r.hostname} {r.now} → {r.importance}" for r in changed.itertuples(index=False)))
            if st.button("Save and re-rank the devices", type="primary", icon=":material/save:",
                         disabled=not can(user, "upload_scans")):
                save_importance(network, edited, PROJECT_ROOT / IMPORTANCE_FILE)
                audit("importance_saved", user["username"], user["role"], f"{network}: {len(edited)} devices")
                st.session_state["next_step"] = STEPS[2]
                st.rerun()

            with st.expander("Does the ranking depend on the exact weights? (sensitivity check)"):
                check = sensitivity(scanned)
                st.markdown(
                    f"The ranking uses **High/Medium/Low = 1.0/0.6/0.3** and **internal = 0.5** of "
                    f"internet-facing. These are design choices, so the devices were re-ranked under "
                    f"**{check['settings']} other plausible settings** (Medium 0.4–0.8, Low 0.1–0.4, "
                    f"internal 0.3–0.7):")
                s1, s2, s3 = st.columns(3)
                s1.metric("Most urgent device unchanged", f"{check['most_urgent_unchanged']:.0%}")
                s2.metric("Top 3 unchanged", f"{check['top3_unchanged']:.0%}")
                s3.metric("Order similarity (Spearman)", f"{check['spearman_mean']:.2f}",
                          help=f"1.00 = identical order; lowest seen {check['spearman_min']:.2f}")
                st.caption("High values mean the advice does not depend on the exact numbers chosen.")

    elif step == STEPS[2]:
        # The device being fixed: chosen in the list, or the most urgent one
        if st.session_state.get("fix_device") not in set(devices["asset_id"]):
            st.session_state["fix_device"] = devices["asset_id"].iloc[0]
        chosen = st.session_state["fix_device"]

        left, right = st.columns([1, 1.35], gap="large")

        with left:
            st.subheader("Patch these first")
            st.caption("Most urgent at the top: likelihood of attack × business importance × "
                       "internet exposure.")
            for rank, row in devices.iterrows():
                with st.container(border=True, key=f"device_{rank}"):
                    info, action = st.columns([3.2, 1.2], vertical_alignment="center")
                    fix = best_fix.loc[row["asset_id"]] if row["asset_id"] in best_fix.index else None
                    fix_line = (f"<br><span style='color:#94a3b8;font-size:0.85rem'>Main fix: upgrade "
                                f"{fix['product']} {fix['installed_version']} → {fix['target_version']}"
                                "</span>") if fix is not None else ""
                    info.markdown(
                        f"<b>{rank + 1}. {row['hostname']}</b> &nbsp;{badge(row['exposure_level'])}<br>"
                        f"<span style='color:#94a3b8;font-size:0.85rem'>{row['asset_type']} · "
                        f"{row['ip_address']}</span><br>{reason(row)}{fix_line}",
                        unsafe_allow_html=True)
                    action.button("How to fix" if row["asset_id"] != chosen else "Selected",
                                  key=f"fix_{row['asset_id']}", width="stretch",
                                  type="primary" if row["asset_id"] == chosen else "secondary",
                                  on_click=lambda a=row["asset_id"]: st.session_state.update(fix_device=a))

        with right:
            device = devices[devices["asset_id"] == chosen].iloc[0]
            actions = plan_all[plan_all["asset_id"] == chosen] if not plan_all.empty else plan_all
            st.subheader(f"How to fix {device['hostname']}")
            st.markdown(f"{badge(device['exposure_level'])} &nbsp; {device['asset_type']} · "
                        f"{device['ip_address']} · business importance: {device['criticality']} · "
                        f"internet-facing: {device['internet_exposed']}", unsafe_allow_html=True)

            if actions.empty:
                st.success("No software updates are needed for this device right now.")
            else:
                details = vulnerability_details(
                    actions, cves[cves["ip_address"] == device["ip_address"]],
                    reference_data()["scoring"], kev_details(), notify_config.get("max_cves_in_email", 10))
                st.info(overview(device.to_dict(), actions, details))

                st.markdown("##### Step 1 · Install these updates")
                for number, a in enumerate(actions.sort_values("risk_removed", ascending=False)
                                           .itertuples(index=False), start=1):
                    exploited = (f", **{a.kev_fixed} being used by attackers**" if a.kev_fixed else "")
                    overdue = " ⚠️ **overdue**" if a.urgency == "OVERDUE" else ""
                    st.markdown(f"{number}. Upgrade **{a.product}** from {a.installed_version} to "
                                f"**{a.target_version}** or later: fixes {a.cves_fixed} "
                                f"weakness{'es' if a.cves_fixed != 1 else ''}{exploited}. "
                                f"Deadline: {a.deadline}{overdue}")

                interim = list(dict.fromkeys(r["interim"] for r in details["rows"]))
                if interim:
                    st.markdown("##### Step 2 · Until it is patched, reduce the risk")
                    for step in interim[:4]:
                        st.markdown(f"- {step}")

                with st.expander(f"See the weaknesses ({len(details['rows'])} most urgent of "
                                 f"{details['total']})"):
                    st.dataframe(pd.DataFrame([{
                        "CVE": r["cve_id"], "CVSS": r["cvss"],
                        "Exploited?": {"exploited": "Yes, now", "predicted": "Likely soon",
                                       "low": "No"}[r["level"]],
                        "Attack type (MITRE ATT&CK)": r["tactic"], "What it is": r["summary"],
                    } for r in details["rows"]]), hide_index=True, use_container_width=True,
                        column_config={"CVSS": st.column_config.NumberColumn(format="%.1f"),
                                       "What it is": st.column_config.TextColumn(width="large")})

                if can(user, "send_notifications"):
                    st.markdown("##### Step 3 · Send the fix instructions to the owning team")
                    owner_rows = auth_store.owners(notify_lab)
                    owner_rows = owner_rows[owner_rows["asset_id"] == chosen]
                    team = owner_rows["team"].iloc[0] if not owner_rows.empty else "device owner"
                    team_email = owner_rows["team_email"].iloc[0] if not owner_rows.empty else ""
                    recipients_text = st.text_input("Team email", value=team_email or "",
                                                    key=f"home_recipients_{chosen}",
                                                    placeholder="e.g. netteam@company.local")
                    message = compose(device.to_dict(), actions, user, team, "", None, notify_config, details)
                    recipients = parse_recipients(recipients_text)
                    problems = recipient_problems(recipients, notify_config) if recipients_text else []
                    with st.expander("Preview the email"):
                        st.markdown(f"**Subject:** {message['subject']}")
                        st.html(message["html"])
                    if problems:
                        st.error("Cannot send: " + "; ".join(problems) + ".")
                    smtp_on = bool(__import__("os").environ.get("SMTP_HOST"))
                    if st.button("Send fix instructions" if smtp_on else
                                 "Send fix instructions (test mode: saved as a file)", type="primary",
                                 icon=":material/send:", disabled=not recipients or bool(problems),
                                 key=f"home_send_{chosen}"):
                        try:
                            delivery, file = deliver(message, recipients, user, notify_config)
                        except Exception as error:      # mail server unreachable, login failed...
                            audit("notification_failed", user["username"], user["role"],
                                  f"{device['hostname']}: {error}", "failure")
                            st.error(f"Sending failed: {error}")
                        else:
                            auth_store.add_notification({
                                "sender": user["username"], "lab": notify_lab, "asset_id": chosen,
                                "hostname": device["hostname"], "team": team,
                                "recipients": ", ".join(recipients), "subject": message["subject"],
                                "actions": message["actions"], "exploited": message["exploited"],
                                "delivery": delivery, "message_file": file})
                            audit("notification_sent", user["username"], user["role"],
                                  f"{device['hostname']} -> {', '.join(recipients)} ({delivery})")
                            st.success(f"Fix instructions for **{device['hostname']}** {delivery}.")

        next_button("Next: if a device is hacked, how far can the attack spread?", STEPS[3])

    elif step == STEPS[3]:
        st.subheader("If a device is hacked, how far can the attacker spread?")
        if network is None:
            st.info("For the research lab database, use **Attack paths** under Advanced tools.")
        else:
            topology, _, _, _ = scan_topology(assets, trust_file)
            order = {ip: i for i, ip in enumerate(devices["ip_address"])}
            topology = topology.assign(order=topology["ip_address"].map(order)).sort_values("order")
            options = [("device", r.asset_id, f"{r.hostname} ({r.ip_address}) is hacked")
                       for r in topology.itertuples(index=False)]
            if (topology["internet_exposed"] == "Yes").any():
                options.append(("internet", None, "An attacker on the internet"))

            # One clickable card per device: click it to see what happens if it is hacked
            state_key = f"attack_start_{network}"
            if not isinstance(st.session_state.get(state_key), int) or \
                    st.session_state[state_key] >= len(options):
                st.session_state[state_key] = 0
            choice = st.session_state[state_key]
            levels = devices.set_index("ip_address")["exposure_level"]
            st.markdown("**Click a device to see what happens if it is hacked:**")
            per_row = 4
            for row_start in range(0, len(options), per_row):
                columns = st.columns(per_row)
                for column, i in zip(columns, range(row_start, min(row_start + per_row, len(options)))):
                    start_type_i, value_i, _ = options[i]
                    if start_type_i == "internet":
                        label = "**Internet attacker**  \nAttack from outside"
                    else:
                        r = topology[topology["asset_id"] == value_i].iloc[0]
                        level = ACTION_LABELS.get(levels.get(r["ip_address"]), ("", ""))[0]
                        label = (f"**{r['hostname']}**  \n{r['asset_type']}"
                                 + (f" · {level}" if level else ""))
                    column.button(label, key=f"attack_card_{network}_{i}", width="stretch",
                                  type="primary" if i == choice else "secondary",
                                  on_click=lambda i=i: st.session_state.update({state_key: i}))
            start_type, value, start_label = options[choice]
            scenario, dot = run_scan_attack(f"{scan_name}|{importance_csv(network)}", start_type, value,
                                            services, assets, cves, str(trust_file) if trust_file else None)
            others = scenario.reached[~scenario.reached["start"]]
            likely = others[others["probability"] >= 0.10]
            important = likely[likely["crown_jewel"] == 1]
            lead = ("From the internet, an attacker" if start_type == "internet" else
                    f"If **{start_label.split(' (')[0]}** is hacked, the attacker")
            if likely.empty:
                st.success(f"{lead} is unlikely to reach any other device.")
            else:
                st.error(f"{lead} can probably reach **{len(likely)} other "
                         f"device{'s' if len(likely) != 1 else ''}** "
                         f"({', '.join(likely['hostname'])}), including **{len(important)} of high "
                         "business importance**.")
            st.graphviz_chart(dot, use_container_width=True)
            st.caption("Red = likely, orange = possible, yellow = unlikely. Solid arrow = exploiting a "
                       "weakness; dashed = a trust link such as stored passwords. ★ = high business importance.")
            if not others.empty:
                st.dataframe(others[["hostname", "probability", "path", "how"]], hide_index=True,
                             use_container_width=True, column_config={
                                 "hostname": "Device reached",
                                 "probability": st.column_config.ProgressColumn(
                                     "Chance", format="percent", min_value=0, max_value=1),
                                 "path": "Most likely route", "how": "How"})
            if not scenario.fixes.empty:
                st.markdown("**The single change that stops the most:**")
                for fix in scenario.fixes.head(3).itertuples(index=False):
                    st.markdown(f"- {fix.action}: afterwards {fix.assets_reached_after} device(s) "
                                "still reachable")
            st.caption("Assumptions: the scan cannot see firewalls, so devices in the same network are "
                       "assumed to reach each other on any port (worst case), and the internet reaches "
                       "only devices marked as internet-facing."
                       + (" Trust links (stored passwords, admin logons) come from "
                          "config/virtualbox_lab/trust_links.csv." if trust_file else ""))
        next_button("Next: compare with the usual CVSS list", STEPS[4])

    elif step == STEPS[4]:
        st.subheader("The usual CVSS list vs our prediction list")
        st.markdown("Most teams sort by **CVSS**: the device with the most severe weakness first. Our "
                    "system sorts by **chance of attack × business importance × internet exposure**.")
        confirmed = cves[cves["match_confidence"].isin(CONFIRMED)]
        max_cvss = confirmed.groupby("ip_address")["cvss_score"].max()
        by_cvss = devices.assign(max_cvss=devices["ip_address"].map(max_cvss).fillna(0)) \
            .sort_values("max_cvss", ascending=False, kind="stable").reset_index(drop=True)
        cvss_rank = {ip: i + 1 for i, ip in enumerate(by_cvss["ip_address"])}

        col_cvss, col_ours = st.columns(2, gap="large")
        with col_cvss:
            st.markdown("<b style='color:#f97316'>📊 Usual way: sorted by CVSS</b>", unsafe_allow_html=True)
            for i, row in by_cvss.head(10).iterrows():
                st.markdown(f"{i + 1}. **{row['hostname']}**: highest CVSS {row['max_cvss']:.1f}")
        with col_ours:
            st.markdown("<b style='color:#38bdf8'>🛡️ Our system: sorted by predicted risk</b>",
                        unsafe_allow_html=True)
            for i, row in devices.head(10).iterrows():
                st.markdown(f"{i + 1}. **{row['hostname']}**: {badge(row['exposure_level'])} "
                            f"{reason(row)}", unsafe_allow_html=True)

        moves = []
        for i, row in devices.iterrows():
            ours_rank, other = i + 1, cvss_rank[row["ip_address"]]
            if ours_rank < other:
                why = ("weaknesses in it are being attacked right now" if row["known_exploited"] else
                       "it is internet-facing" if row["internet_exposed"] == "Yes" else
                       "it is important to the business" if row["criticality"] == "High" else
                       "its weaknesses are likely to be attacked")
                moves.append(f"⬆️ **{row['hostname']}** moves up from #{other} to #{ours_rank}: {why}.")
            elif ours_rank > other and row["known_exploited"] == 0:
                moves.append(f"⬇️ **{row['hostname']}** moves down from #{other} to #{ours_rank}: high "
                             "CVSS score, but no sign attackers use its weaknesses.")
        if moves:
            st.markdown("**Where the two lists disagree, and why**")
            for move in moves[:6]:
                st.markdown(move)
        else:
            st.info("On this network both lists put the devices in the same order.")

        curve_path = PROJECT_ROOT / CURVE_FILE
        if curve_path.exists():
            at5 = pd.read_csv(curve_path).query("share_reviewed == 0.05").set_index("method")["share_caught"]
            st.success(f"**Evidence on 2025 data:** if a team checks the top 5% of new vulnerabilities, "
                       f"our list contains **{at5['Our model']:.0%}** of those attackers really used; a CVSS "
                       f"list only **{at5['CVSS score (usual practice)']:.0%}**.")
        st.button("See the full comparison and evidence", icon=":material/balance:",
                  on_click=go_to, args=("compare",))

else:
    icon, title, description, (light, dark) = PAGES[page]
    back_bar("top")
    st.markdown(
        f"<div class='page-head' style='border:1px solid rgba(148,163,184,0.16);"
        f"border-left:6px solid {tint(light, 0.25)};"
        f"background:radial-gradient(circle at 100% 0%,{light}55 0,{light}00 45%),"
        f"linear-gradient(120deg,#172033,#0f172a)'>"
        f"<div><h2 style='color:{tint(light, 0.45)}'>{title}</h2>"
        f"<p style='color:#94a3b8'>{description}</p></div></div>",
        unsafe_allow_html=True)

# Only the open page is built
current = st.container() if page != "home" else None
tab_overview, tab_detail, tab_fix, tab_live = (
    current if page == key else None for key in ["overview", "detail", "remediation", "live"])
tab_compare = current if page == "compare" else None
tab_paths, tab_model, tab_backtest, tab_admin, tab_notify = (
    current if page == key else None for key in ["paths", "model", "backtest", "admin", "notifications"])


# ==============================
# Tab 1: overview
# ==============================

if tab_overview is not None:
    with tab_overview:

        scanned = assets[assets["scan_status"] != "Not scanned"]

        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Hosts discovered", len(scanned))
        k2.metric("Assets with known exploited CVEs", int((assets["known_exploited"] > 0).sum()))
        k3.metric("Assets at Critical / High",
                  int(assets["exposure_level"].isin(["Critical", "High"]).sum()))
        k4.metric("Unmanaged hosts", int((assets["scan_status"] == "Unmanaged (not in inventory)").sum()))
        k5.metric("Inventory assets not scanned", int((assets["scan_status"] == "Not scanned").sum()))

        # Model evaluated on CVEs published to 2025-08-27; later CVEs show
        # upward score drift (results/monitoring/prediction_drift.csv)
        if scan_time.tz_localize(None) > pd.Timestamp("2025-08-27"):
            st.warning(
                "This assessment includes CVEs published after the model's evaluated "
                "period (to August 2025). For 2026 CVEs the probabilities run above observed "
                "exploitation (about 1.4x in early 2026), mainly because NVD's analysis backlog "
                "favours major vendors. Treat probabilities as a ranking; see Model evidence → "
                "Model monitoring.")

        # ---- Colour code ----

        present = [l for l in LEVEL_ORDER if (assets["exposure_level"] == l).any()]
        st.markdown(legend_html(present), unsafe_allow_html=True)

        # ---- Charts ----

        chart_left, chart_right = st.columns([2, 3])

        with chart_left:
            st.markdown("**Assets by exposure level**")
            counts = (assets["exposure_level"].value_counts().reindex(present, fill_value=0)
                      .rename_axis("level").reset_index(name="assets"))
            counts["label"] = counts["level"].map(with_icon)

            bars = alt.Chart(counts).mark_bar(cornerRadiusEnd=4, height=32).encode(
                x=alt.X("assets:Q", title="Assets", axis=alt.Axis(tickMinStep=1)),
                y=alt.Y("label:N", sort=[with_icon(l) for l in present], title=None),
                color=alt.Color("level:N", scale=level_color(present), legend=None),
                tooltip=[alt.Tooltip("level:N", title="Exposure level"),
                         alt.Tooltip("assets:Q", title="Assets")],
            )
            labels = bars.mark_text(align="left", dx=6, fontWeight="bold").encode(
                text="assets:Q", color=alt.value("#7a8591"))
            st.altair_chart((bars + labels).properties(height=48 * len(present) + 30),
                            use_container_width=True)

        with chart_right:
            st.markdown("**Risk matrix: likelihood vs business impact**")
            matrix = scanned.copy()
            matrix["business_weight"] = (
                matrix["criticality"].map(CRITICALITY_WEIGHT).fillna(UNKNOWN_CRITICALITY_WEIGHT)
                * matrix["internet_exposed"].map(EXPOSURE_WEIGHT).fillna(UNKNOWN_EXPOSURE_WEIGHT))
            # Log scale needs a floor; assets with nothing expected sit at the left edge
            matrix["expected_plot"] = matrix["expected_new_exposure_12m"].clip(lower=0.01)
            matrix_levels = [l for l in LEVEL_ORDER if (matrix["exposure_level"] == l).any()]

            points = alt.Chart(matrix).mark_point(size=300, filled=True, opacity=1,
                                                  stroke="#ffffff", strokeWidth=1).encode(
                x=alt.X("expected_plot:Q", scale=alt.Scale(type="log", domain=[0.01, 200]),
                        title="Expected newly exploited vulnerabilities, 12 months (log scale)"),
                y=alt.Y("business_weight:Q", scale=alt.Scale(domain=[0, 1.05]),
                        title="Business impact (criticality × internet exposure)"),
                color=alt.Color("exposure_level:N", scale=level_color(matrix_levels),
                                legend=alt.Legend(title="Exposure level", orient="bottom")),
                shape=alt.Shape("exposure_level:N", scale=level_shape(matrix_levels)),
                tooltip=[alt.Tooltip("hostname:N", title="Asset"),
                         alt.Tooltip("asset_type:N", title="Type"),
                         alt.Tooltip("exposure_level:N", title="Exposure level"),
                         alt.Tooltip("expected_new_exposure_12m:Q", title="Expected exploited", format=".2f"),
                         alt.Tooltip("priority_score:Q", title="Priority", format=".2f")],
            )
            guides = pd.DataFrame({"x": [1.0]})
            vline = alt.Chart(guides).mark_rule(strokeDash=[5, 4], color="#8a8f93").encode(x="x:Q")
            hline = alt.Chart(pd.DataFrame({"y": [0.5]})).mark_rule(
                strokeDash=[5, 4], color="#8a8f93").encode(y="y:Q")
            note = alt.Chart(pd.DataFrame({"x": [150], "y": [1.02], "t": ["Fix first ↗"]})).mark_text(
                align="right", fontWeight="bold", color="#b71c1c").encode(x="x:Q", y="y:Q", text="t:N")

            st.altair_chart((vline + hline + points + note).properties(height=320),
                            use_container_width=True)
            st.caption("Right of the dashed line: at least one exploitation expected within a year. "
                       "Top right: likely to be attacked and important to the business.")

        st.markdown("**Top 12 assets by priority**")
        top = scanned.nlargest(12, "priority_score").copy()
        top["name"] = top["hostname"].fillna(top["ip_address"])
        top_levels = [l for l in LEVEL_ORDER if (top["exposure_level"] == l).any()]
        priority_bars = alt.Chart(top).mark_bar(cornerRadiusEnd=4, height=24).encode(
            x=alt.X("priority_score:Q", scale=alt.Scale(domain=[0, 1]), title="Priority score"),
            y=alt.Y("name:N", sort="-x", title=None),
            color=alt.Color("exposure_level:N", scale=level_color(top_levels),
                            legend=alt.Legend(title="Exposure level", orient="top")),
            tooltip=[alt.Tooltip("name:N", title="Asset"),
                     alt.Tooltip("asset_type:N", title="Type"),
                     alt.Tooltip("criticality:N", title="Criticality"),
                     alt.Tooltip("internet_exposed:N", title="Internet exposed"),
                     alt.Tooltip("priority_score:Q", title="Priority", format=".2f"),
                     alt.Tooltip("known_exploited:Q", title="Known exploited CVEs")],
        )
        priority_labels = priority_bars.mark_text(align="left", dx=5).encode(
            text=alt.Text("priority_score:Q", format=".2f"), color=alt.value("#7a8591"))
        st.altair_chart((priority_bars + priority_labels).properties(height=34 * len(top) + 40),
                        use_container_width=True)

        st.subheader("Assets ranked by priority")
        st.caption(
            "Priority = threat x criticality x internet exposure. Threat is 1 when a "
            "known exploited CVE is present, otherwise the probability that at least one "
            "vulnerability on the asset becomes exploited in the next 12 months: model "
            f"predictions for CVEs published in the last {PREDICTION_WINDOW_DAYS} days plus "
            "each installed product's recent rate of new KEV additions (covering CVEs "
            "not yet published).")

        table = assets[[
            "asset_id", "hostname", "ip_address", "asset_type", "criticality",
            "internet_exposed", "exposure_level", "priority_score", "known_exploited",
            "exposure_probability_12m", "expected_exploited_12m", "product_kev_rate_12m",
            "most_targeted_product", "window_cves", "top_predicted_cve", "scan_status",
        ]].assign(exposure_level=lambda d: d["exposure_level"].map(with_icon))

        st.dataframe(
            table.style.map(tint_level, subset=["exposure_level"]),
            hide_index=True,
            use_container_width=True,
            column_config={
                "asset_id": "Asset",
                "hostname": "Hostname",
                "ip_address": "IP",
                "asset_type": "Type",
                "criticality": "Criticality",
                "internet_exposed": "Internet exposed",
                "exposure_level": "Exposure level",
                "priority_score": st.column_config.ProgressColumn(
                    "Priority", min_value=0.0, max_value=1.0, format="%.2f"),
                "known_exploited": st.column_config.NumberColumn(
                    "Known exploited", help="CVEs in CISA KEV as of the scan date"),
                "window_cves": st.column_config.NumberColumn(
                    "Recent CVEs", help="Matched CVEs published in the prediction window"),
                "exposure_probability_12m": st.column_config.NumberColumn(
                    "Exposure probability (12 m)", format="percent",
                    help="1 - exp(-expected newly exploited vulnerabilities)"),
                "expected_exploited_12m": st.column_config.NumberColumn(
                    "Expected from known CVEs", format="%.2f",
                    help="Sum of model probabilities for recent matched CVEs"),
                "product_kev_rate_12m": st.column_config.NumberColumn(
                    "Product KEV additions (past 12 m)",
                    help="New KEV entries for the installed products in the past year: "
                         "expected exposure from CVEs not yet published"),
                "most_targeted_product": "Most targeted product",
                "top_predicted_cve": "Top predicted CVE",
                "scan_status": "Scan status",
            },
        )

        with st.expander("How exposure levels are assigned"):
            st.markdown(
                "- **Critical**: a known exploited (KEV) CVE, or a recent CVE in the "
                "Critical risk tier (top 1% of predicted risk)\n"
                "- **High**: a recent CVE in the High tier (top 5%), or an installed "
                "product that had newly exploited vulnerabilities in the past year\n"
                "- **Medium**: highest recent CVE in the Medium tier (top 20%)\n"
                "- **Low**: no matched CVE above the Low tier\n"
                "- **Unverified**: services found but versions could not be read, so "
                "matches are product-level only\n"
                "- **Unknown**: in the inventory but not seen in this scan"
            )


# ==============================
# Tab 2: asset detail
# ==============================

if tab_detail is not None:
    with tab_detail:

        options = scanned.reset_index(drop=True)
        labels = [f"{r.asset_id} · {r.hostname if pd.notna(r.hostname) else '(no hostname)'} "
                  f"· {r.ip_address} · {r.exposure_level}" for r in options.itertuples()]

        choice = st.selectbox("Asset", range(len(options)), format_func=lambda i: labels[i])
        asset = options.iloc[choice]
        ip = asset["ip_address"]

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Exposure level", with_icon(asset["exposure_level"]))
        c2.metric("Priority", f"{asset['priority_score']:.2f}")
        c3.metric("Known exploited CVEs", int(asset["known_exploited"]))
        c4.metric("Exposure probability (12 m)", f"{asset['exposure_probability_12m']:.1%}",
                  help=f"{asset['expected_exploited_12m']:.2f} expected from known CVEs + "
                       f"{int(asset['product_kev_rate_12m'])} from product history")

        # ---- Recommended actions for this asset ----

        st.subheader("🔧 Recommended actions")
        asset_actions = plan_all[plan_all["ip_address"] == ip] if not plan_all.empty else plan_all
        if asset_actions.empty:
            st.caption("No upgrade with a recorded fix version for this asset's matched vulnerabilities.")
        else:
            st.dataframe(
                asset_actions[["action", "cves_fixed", "kev_fixed", "exploited_doors_before",
                               "exploited_doors_after", "risk_removed", "deadline", "urgency"]]
                .style.map(lambda v: "color: #b71c1c; font-weight: 700" if v == "OVERDUE" else "",
                           subset=["urgency"]),
                hide_index=True, use_container_width=True,
                column_config={
                    "action": st.column_config.TextColumn("Action", width="large"),
                    "cves_fixed": st.column_config.NumberColumn("CVEs fixed"),
                    "kev_fixed": st.column_config.NumberColumn("Exploited fixed"),
                    "exploited_doors_before": st.column_config.NumberColumn(
                        "Exploited products now", help="Installed products with a known exploited CVE"),
                    "exploited_doors_after": st.column_config.NumberColumn("After this fix"),
                    "risk_removed": st.column_config.ProgressColumn(
                        "Risk removed", min_value=0.0, max_value=1.0, format="%.2f"),
                    "deadline": "Deadline", "urgency": "Urgency",
                })
            if asset["product_kev_rate_12m"] > 0:
                st.caption(f"Even after patching, attackers found {int(asset['product_kev_rate_12m'])} new "
                           "exploited flaws in this asset's products during the past year: keep it on a "
                           "regular patch cycle.")

        # Containment options name other assets and network rules: whole-network roles only
        if source == "Lab database" and can(user, "view_attack_paths"):
            containment, _, _, _, _ = run_attack_paths(lab_db, snapshot_id, "device", asset["asset_id"])
            options = containment.fixes[containment.fixes["type"] != "Patch"].head(3) \
                if not containment.fixes.empty else containment.fixes
            if not options.empty:
                st.markdown("**If you cannot patch yet: limit the damage if this asset is compromised**")
                st.dataframe(
                    options.assign(share=options["risk_reduction"] / containment.crown_risk
                                   if containment.crown_risk else 0)[["action", "type", "share"]],
                    hide_index=True, use_container_width=True,
                    column_config={
                        "action": st.column_config.TextColumn("Containment action", width="large"),
                        "type": "Type",
                        "share": st.column_config.ProgressColumn(
                            "Crown-jewel risk removed", min_value=0.0, max_value=1.0, format="percent"),
                    })

        st.markdown("**Discovered software and services**")
        service_columns = ["port", "protocol", "service", "product", "version", "cpe"]
        if "source" in services.columns:
            service_columns.append("source")
        st.dataframe(
            services[services["ip_address"] == ip][service_columns],
            hide_index=True, use_container_width=True)

        asset_cves = cves[cves["ip_address"] == ip]

        # ---- Current exposure ----

        known = asset_cves[asset_cves["status"] == "Known exploited"]
        st.subheader(f"Known exploited now ({len(known)})")

        if known.empty:
            st.caption("No matched CVE is in CISA KEV as of the scan date.")
        else:
            st.caption("Already exploited in the wild: patch or mitigate first.")
            st.dataframe(
                known[["cve_id", "product", "installed_version", "cvss_score",
                       "published_date", "kev_date_added", "match_confidence", "ports"]],
                hide_index=True, use_container_width=True,
                column_config={"published_date": st.column_config.DateColumn("Published"),
                               "kev_date_added": st.column_config.DateColumn("Added to KEV")})

        # ---- Predicted exposure ----

        window = asset_cves[(asset_cves["status"] == "Prediction window")
                            & asset_cves["match_confidence"].isin(CONFIRMED)]
        window = window.sort_values("probability", ascending=False)

        st.subheader(f"Predicted future exposure ({len(window)})")

        if window.empty:
            st.caption(f"No confirmed CVE published in the last {PREDICTION_WINDOW_DAYS} days.")
        else:
            st.caption("Recent CVEs not yet known exploited, ranked by predicted "
                       "probability of KEV addition within 12 months of publication.")

            tier_col, scatter_col = st.columns([2, 3])

            with tier_col:
                st.markdown("**Risk tier mix**")
                tiers = (window["tier"].value_counts().reindex(TIER_ORDER, fill_value=0)
                         .rename_axis("tier").reset_index(name="cves"))
                tiers["label"] = tiers["tier"].map(with_icon)
                tier_bars = alt.Chart(tiers).mark_bar(cornerRadiusEnd=4, height=32).encode(
                    x=alt.X("cves:Q", title="Recent CVEs", axis=alt.Axis(tickMinStep=1)),
                    y=alt.Y("label:N", sort=[with_icon(t) for t in TIER_ORDER], title=None),
                    color=alt.Color("tier:N", scale=level_color(TIER_ORDER), legend=None),
                    tooltip=[alt.Tooltip("tier:N", title="Risk tier"),
                             alt.Tooltip("cves:Q", title="CVEs")],
                )
                tier_labels = tier_bars.mark_text(align="left", dx=6, fontWeight="bold").encode(
                    text="cves:Q", color=alt.value("#7a8591"))
                st.altair_chart((tier_bars + tier_labels).properties(height=240),
                                use_container_width=True)
                st.caption("Tiers: Critical = top 1% of predicted risk, High = next 4%, "
                           "Medium = next 15%, Low = rest.")

            with scatter_col:
                st.markdown("**Model prediction vs CVSS severity**")
                plot = window.dropna(subset=["cvss_score", "probability"])
                plot_tiers = [t for t in TIER_ORDER if (plot["tier"] == t).any()]
                scatter = alt.Chart(plot).mark_point(size=170, filled=True, opacity=1).encode(
                    x=alt.X("cvss_score:Q", scale=alt.Scale(domain=[0, 10]), title="CVSS score"),
                    y=alt.Y("probability:Q", scale=alt.Scale(type="log"),
                            title="Predicted probability of exploitation (log scale)"),
                    color=alt.Color("tier:N", scale=level_color(plot_tiers),
                                    legend=alt.Legend(title="Risk tier", orient="bottom")),
                    shape=alt.Shape("tier:N", scale=level_shape(plot_tiers)),
                    tooltip=[alt.Tooltip("cve_id:N", title="CVE"),
                             alt.Tooltip("product:N", title="Product"),
                             alt.Tooltip("cvss_score:Q", title="CVSS", format=".1f"),
                             alt.Tooltip("probability:Q", title="Probability", format=".2%"),
                             alt.Tooltip("tier:N", title="Risk tier")],
                )
                st.altair_chart(scatter.properties(height=260), use_container_width=True)
                st.caption("CVEs high on the chart but low on CVSS are ones the model flags "
                           "that severity alone would miss.")

            st.dataframe(
                window[["cve_id", "product", "installed_version", "published_date",
                        "cvss_score", "probability", "tier", "risk_drivers"]]
                .assign(tier=lambda d: d["tier"].map(with_icon))
                .style.map(tint_level, subset=["tier"]),
                hide_index=True, use_container_width=True,
                column_config={
                    "published_date": st.column_config.DateColumn("Published"),
                    "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
                    "probability": st.column_config.NumberColumn("Probability", format="percent"),
                    "tier": "Risk tier",
                    "risk_drivers": st.column_config.TextColumn("Main risk drivers (SHAP)", width="large"),
                })

            # ---- Explanation for one CVE ----

            st.markdown("**Why this prediction?**")
            cve_id = st.selectbox("CVE", window["cve_id"].tolist())

            shap, description = cve_shap(cve_id)
            top = shap.head(12)

            raises, lowers = ("#e66767", "#3987e5") if dark_mode() else ("#e34948", "#2a78d6")

            chart = (
                alt.Chart(top.assign(effect=np.where(top["shap"] > 0, "Raises risk", "Lowers risk")))
                .mark_bar(cornerRadius=4, height=14)
                .encode(
                    x=alt.X("shap:Q", title="SHAP value (log-odds)"),
                    y=alt.Y("feature:N", sort=None, title=None),
                    color=alt.Color("effect:N", title=None,
                                    scale=alt.Scale(domain=["Raises risk", "Lowers risk"],
                                                    range=[raises, lowers]),
                                    legend=alt.Legend(orient="top")),
                    tooltip=[alt.Tooltip("feature:N", title="Feature"),
                             alt.Tooltip("group:N", title="Group"),
                             alt.Tooltip("shap:Q", title="SHAP", format="+.3f")],
                )
                .properties(height=36 * len(top))
            )

            st.altair_chart(chart, use_container_width=True)
            st.caption(f"Description (exploitation-status sentences removed): {description}")

        # ---- Other matches ----

        older = asset_cves[asset_cves["status"] == "Older, not in KEV"]
        unconfirmed = asset_cves[asset_cves["match_confidence"] == "version unknown"]
        inferred = asset_cves[asset_cves["match_confidence"] == "patched (inferred)"]

        with st.expander(f"Other matches: {len(older)} older CVEs, {len(unconfirmed)} version "
                         f"unknown, {len(inferred)} patched (inferred)"):
            st.caption(
                "Older CVEs are past the model's 12-month horizon and not in KEV. "
                "Version-unknown matches need a manual check because the scan could not "
                "read the installed version. Patched (inferred): NVD lists every version as "
                "affected, but the installed version already contains fixes for later CVEs, "
                "so these are not counted in the risk.")
            st.dataframe(
                pd.concat([older, unconfirmed, inferred]).drop_duplicates("cve_id")
                [["cve_id", "product", "installed_version", "status", "match_confidence",
                  "published_date", "cvss_score"]],
                hide_index=True, use_container_width=True,
                column_config={"published_date": st.column_config.DateColumn("Published")})


# ==============================
# Tab 3: attack paths (blast radius)
# ==============================

PATH_COLORS = {"Start": "#1b1b1b", **BAND_COLORS, "Not reached": "#c4c8cb"}
PATH_ORDER = ["Likely", "Possible", "Unlikely", "Not reached"]
PATH_MEANING = {"Likely": "50% or more", "Possible": "10–50%", "Unlikely": "1–10%",
                "Not reached": "below 1%"}

if tab_paths is not None:
    with tab_paths:

        if not source.startswith("Lab"):
            st.info("Attack-path analysis needs the network layout (subnets, firewall rules and "
                    "trust links). Select **Lab database** in the sidebar to use it.")
        else:
            st.markdown("**If one device or one piece of software is compromised, how far can an "
                        "attacker spread, and which subnets are affected?**")

            choose_type, choose_value = st.columns([1, 2])
            start_label = choose_type.radio(
                "Starting point", ["A device", "A software product", "An internet attacker"])

            lab_services, lab_inventory, _ = load_snapshot(snapshot_id, lab_db)

            if start_label == "A device":
                start_type = "device"
                options_df = lab_inventory.sort_values(["segment", "hostname"])
                device_ids = options_df["asset_id"].tolist()
                dmz_ids = options_df.loc[options_df["segment"] == "DMZ", "asset_id"].tolist()
                default_device = "L003" if "L003" in device_ids else (dmz_ids or device_ids)[0]
                start_value = choose_value.selectbox(
                    "Compromised device", device_ids,
                    index=device_ids.index(default_device),
                    format_func=lambda a: "{} · {} · {}".format(
                        *options_df.set_index("asset_id").loc[a, ["hostname", "asset_type", "segment"]]))
            elif start_label == "A software product":
                start_type = "software"
                products = sorted(lab_services["product"].dropna().unique())
                start_value = choose_value.selectbox(
                    "Compromised software (every host running it, like a supply-chain attack)",
                    products, index=products.index("Apache Tomcat") if "Apache Tomcat" in products else 0)
            else:
                start_type, start_value = "internet", None
                choose_value.markdown("An attacker outside the network, reaching public services "
                                      "and sending malicious web or email content to staff.")

            scenario, dot, path_inventory, rules, trusts = run_attack_paths(
                lab_db, snapshot_id, start_type, start_value)
            reached = scenario.reached
            hit = reached[(reached["probability"] >= REACHED_THRESHOLD) & ~reached["start"]]
            jewels = path_inventory[path_inventory["crown_jewel"] == 1]
            jewels_hit = hit[hit["crown_jewel"] == 1]

            st.markdown(f"#### Scenario: {scenario.title}")
            m1, m2, m3, m4 = st.columns(4)
            others = len(path_inventory) - (0 if start_type == "internet" else len(scenario.starts))
            m1.metric("Assets reached (≥10%)", f"{len(hit)} of {others}")
            m2.metric("Subnets affected", f"{int(scenario.segments['affected'].sum())} of {len(scenario.segments)}")
            m3.metric("★ Crown jewels reached", f"{len(jewels_hit)} of {len(jewels)}")
            m4.metric("Highest crown-jewel probability",
                      f"{jewels_hit['probability'].max():.0%}" if len(jewels_hit) else "0%")

            st.markdown(
                "<div class='legend'>"
                f"<span><i style='background:{PATH_COLORS['Start']};color:#ffffff'>START</i>compromised</span>"
                + "".join(f"<span><i style='background:{PATH_COLORS[b]};color:{'#1b1b1b' if b in ('Unlikely', 'Not reached') else '#ffffff'}'>"
                          f"{b}</i>{PATH_MEANING[b]}</span>" for b in PATH_ORDER)
                + "<span><b>★</b> double border = crown jewel</span>"
                "<span><b>──</b> exploit &nbsp; <b>- -</b> trust link</span></div>",
                unsafe_allow_html=True)

            st.graphviz_chart(dot, use_container_width=True)
            st.caption("Arrows show the most likely route to each reached asset. Percentages are "
                       "the probability of that route succeeding: each step multiplies the chance "
                       "of exploiting the next host (1.0 for a known exploited vulnerability, the "
                       "model's prediction otherwise) or of abusing a trust link.")

            subnet_col, fix_col = st.columns([2, 3])

            with subnet_col:
                st.markdown("**Subnets affected**")
                seg = scenario.segments.copy()
                seg["share"] = seg["reached"] / seg["assets"]
                seg["label"] = seg["segment"] + "  " + seg["reached"].astype(str) + "/" + seg["assets"].astype(str)
                seg_levels = [b for b in PATH_ORDER if (seg["band"] == b).any()]
                seg_chart = alt.Chart(seg).mark_bar(cornerRadiusEnd=4, height=30).encode(
                    x=alt.X("share:Q", scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format="%"),
                            title="Share of subnet reached (≥10%)"),
                    y=alt.Y("label:N", sort=["DMZ", "SERVERS", "WORKSTATIONS", "MGMT"], title=None),
                    color=alt.Color("band:N", title="Highest risk",
                                    scale=alt.Scale(domain=seg_levels,
                                                    range=[PATH_COLORS[b] for b in seg_levels]),
                                    legend=alt.Legend(orient="bottom")),
                    tooltip=[alt.Tooltip("segment:N", title="Subnet"), alt.Tooltip("cidr:N", title="Range"),
                             alt.Tooltip("reached:Q", title="Assets reached"),
                             alt.Tooltip("assets:Q", title="Assets in subnet"),
                             alt.Tooltip("highest_probability:Q", title="Highest probability", format=".0%")],
                )
                st.altair_chart(seg_chart.properties(height=230), use_container_width=True)

            with fix_col:
                st.markdown("**Best single fixes**")
                if scenario.fixes.empty:
                    st.caption("No single change reduces the risk to the crown jewels in this scenario.")
                else:
                    fixes = scenario.fixes.copy()
                    fixes["share_cut"] = (fixes["risk_reduction"] / scenario.crown_risk) if scenario.crown_risk else 0
                    st.dataframe(
                        fixes[["action", "type", "share_cut", "assets_reached_after"]],
                        hide_index=True, use_container_width=True,
                        column_config={
                            "action": st.column_config.TextColumn("Action", width="large"),
                            "type": "Type",
                            "share_cut": st.column_config.ProgressColumn(
                                "Crown-jewel risk removed", min_value=0.0, max_value=1.0, format="percent"),
                            "assets_reached_after": st.column_config.NumberColumn(
                                "Assets still reached", help=f"Assets reached with ≥{REACHED_THRESHOLD:.0%} "
                                                             "probability after this single change"),
                        })
                    st.caption("Each fix is tested on its own: the analysis is re-run without that "
                               "exploit path, firewall permission or trust link.")

            st.markdown("**Affected assets, most likely first**")
            table = reached[~reached["start"]].copy()
            table["asset"] = np.where(table["crown_jewel"] == 1, "★ " + table["hostname"], table["hostname"])
            st.dataframe(
                table[["asset", "segment", "asset_type", "probability", "band", "steps", "path", "how"]]
                .style.map(lambda b: f"background-color: {PATH_COLORS.get(b, '')}; "
                                     f"color: {'#1b1b1b' if b in ('Unlikely', 'Not reached') else '#ffffff'}; "
                                     "font-weight: 700" if b in PATH_COLORS else "", subset=["band"]),
                hide_index=True, use_container_width=True,
                column_config={
                    "asset": "Asset", "segment": "Subnet", "asset_type": "Type",
                    "probability": st.column_config.ProgressColumn(
                        "Probability", min_value=0.0, max_value=1.0, format="percent"),
                    "band": "Risk", "steps": st.column_config.NumberColumn("Steps"),
                    "path": st.column_config.TextColumn("Most likely route", width="large"),
                    "how": st.column_config.TextColumn("Last step", width="large"),
                })

            with st.expander("Network rules and trust links used"):
                st.caption("Firewall rules, trust links and crown jewels are design assumptions for "
                           "the synthetic organisation. In the VMware lab they come from the real "
                           "configuration and can be verified by scanning from each subnet.")
                st.markdown("**Firewall rules**")
                st.dataframe(rules, hide_index=True, use_container_width=True)
                st.markdown("**Trust links**")
                names = path_inventory.set_index("asset_id")["hostname"]
                st.dataframe(
                    trusts.assign(source_asset=trusts["source_asset"].map(names),
                                  target_asset=trusts["target_asset"].map(names)),
                    hide_index=True, use_container_width=True)


# ==============================
# Tab: remediation plan
# ==============================

URGENCY_STYLE = lambda v: "color: #b71c1c; font-weight: 700" if v == "OVERDUE" else ""

if tab_fix is not None:
    with tab_fix:
        if plan_all.empty:
            st.info("No upgrade actions found for this assessment.")
        else:
            st.markdown("**Which fixes remove the most risk? A ranked patch plan for a limited "
                        "amount of work.**")

            if len(plan_all) > 1:
                budget = st.slider("How many fixes can the team do this cycle?", 1,
                                   min(40, len(plan_all)), min(10, len(plan_all)))
            else:
                budget = 1
                st.caption("Only one fix is available for this assessment.")
            chosen, curve = weekly_plan(plan_all, plan_states, budget)

            before, after = curve["total_risk"].iloc[0], curve["total_risk"].iloc[-1]
            f1, f2, f3, f4 = st.columns(4)
            f1.metric("Company risk points", f"{after:.1f}", delta=f"{after - before:.1f} ({(after - before) / before:.0%})",
                      delta_color="inverse", help="Sum over assets of open doors x business weight")
            f2.metric("Exploited products patched", int((chosen["kev_fixed"] > 0).sum()))
            f3.metric("CVEs fixed", f"{int(chosen['cves_fixed'].sum()):,}")
            f4.metric("Overdue items in plan", int((chosen["urgency"] == "OVERDUE").sum()))

            full = weekly_plan(plan_all, plan_states, len(plan_all))[1]
            full["in_plan"] = np.where(full["fixes"] <= budget, "In this plan", "Later")
            line = alt.Chart(full).mark_line(strokeWidth=3, color=PRIMARY, interpolate="step-after").encode(
                x=alt.X("fixes:Q", title="Number of fixes completed"),
                y=alt.Y("total_risk:Q", title="Company risk points", scale=alt.Scale(zero=True)),
            )
            dots = alt.Chart(full).mark_circle(size=90).encode(
                x="fixes:Q", y="total_risk:Q",
                color=alt.Color("in_plan:N", title=None,
                                scale=alt.Scale(domain=["In this plan", "Later"],
                                                range=[PRIMARY, "#9aa0a4"]),
                                legend=alt.Legend(orient="top")),
                tooltip=[alt.Tooltip("fixes:Q", title="Fixes done"),
                         alt.Tooltip("total_risk:Q", title="Risk points left", format=".2f"),
                         alt.Tooltip("action:N", title="Last fix")],
            )
            marker = alt.Chart(pd.DataFrame({"x": [budget]})).mark_rule(
                strokeDash=[6, 4], color="#b71c1c", strokeWidth=2).encode(x="x:Q")
            st.altair_chart((line + dots + marker).properties(height=300), use_container_width=True)
            st.caption("Each step is the next fix in the plan. The curve flattens as the most dangerous "
                       "fixes are done first: the red line marks the selected amount of work.")

            st.subheader(f"The plan: {len(chosen)} fixes in order")
            st.dataframe(
                chosen[["step", "hostname", "action", "cves_fixed", "kev_fixed", "risk_removed",
                        "deadline", "urgency"]].style.map(URGENCY_STYLE, subset=["urgency"]),
                hide_index=True, use_container_width=True,
                column_config={
                    "step": st.column_config.NumberColumn("#", width="small"),
                    "hostname": "Asset",
                    "action": st.column_config.TextColumn("Action", width="large"),
                    "cves_fixed": st.column_config.NumberColumn("CVEs fixed"),
                    "kev_fixed": st.column_config.NumberColumn("Exploited fixed"),
                    "risk_removed": st.column_config.ProgressColumn(
                        "Risk removed", min_value=0.0, max_value=float(max(1.0, chosen["risk_removed"].max())),
                        format="%.2f"),
                    "deadline": "Deadline", "urgency": "Urgency",
                })

            st.download_button(
                "Download plan (CSV)",
                chosen.drop(columns=["fixed_cve_ids"]).to_csv(index=False).encode("utf-8"),
                file_name=f"patch_plan_{scan_time:%Y%m%d}.csv", mime="text/csv",
                on_click=lambda: audit("plan_exported", user["username"], user["role"],
                                       f"{len(chosen)} actions"))

            with st.expander("How the plan is calculated"):
                st.markdown(
                    "- **Fix version:** NVD records each vulnerable range as \"vulnerable before "
                    "version X\". The planner takes the highest X among the asset's CVEs for that "
                    "product, so one upgrade fixes them all.\n"
                    "- **Open doors:** every installed product with known vulnerabilities is a door "
                    "into the asset. A door with a known exploited CVE is fully open (1.0); otherwise "
                    "it is open with the predicted probability of exploitation.\n"
                    "- **Risk points** = open doors × business weight (criticality × internet "
                    "exposure). Upgrading a product closes its door.\n"
                    f"- **Deadlines:** the CISA KEV due date for exploited CVEs (or "
                    f"{SLA_DAYS['KEV']} days); otherwise by risk tier: Critical {SLA_DAYS['Critical']}, "
                    f"High {SLA_DAYS['High']}, Medium {SLA_DAYS['Medium']}, Low {SLA_DAYS['Low']} days "
                    "(a policy assumption organisations can change).\n"
                    "- **Not included:** new flaws attackers will find in these products later; the "
                    "Asset detail tab shows each product's yearly rate so it stays on a patch cycle.")

            with st.expander(f"All {len(plan_all)} possible fixes"):
                st.dataframe(plan_all.drop(columns=["fixed_cve_ids"]), hide_index=True,
                             use_container_width=True)


# ==============================
# Tab 4: live feed (continuous monitoring)
# ==============================

ALERT_COLORS = {"URGENT": "#b71c1c", "WARNING": "#d9480f", "INFO": "#5f6468"}

if tab_live is not None:
    with tab_live:
        live_dir = PROJECT_ROOT / "data" / "live"
        sync_log_file = live_dir / "sync_log.csv"

        if not sync_log_file.exists():
            st.info("No live sync has run yet. Run `python -m src.sync.live_sync` from the project "
                    "folder (or schedule it, see the README), then click **Reload latest data**.")
        else:
            sync_log = pd.read_csv(sync_log_file)
            last = sync_log.iloc[-1]
            alerts = (pd.read_csv(live_dir / "alerts.csv", keep_default_na=False)
                      if (live_dir / "alerts.csv").exists() else pd.DataFrame())
            if owned_assets is not None and not alerts.empty:
                alerts = alerts[alerts["asset_id"].isin(owned_assets)]
            today = str(pd.Timestamp.now().date())

            st.markdown("**Continuous monitoring: new vulnerabilities and exploitation, checked "
                        "against your assets**")
            l1, l2, l3, l4 = st.columns(4)
            l1.metric("Last sync", str(last["run_at"]), help=f"Status: {last['status']}")
            l2.metric("New KEV entries (last sync)", int(last.get("kev_new", 0) or 0))
            l3.metric("NVD records updated (last sync)", f"{int(last.get('nvd_changed', 0) or 0):,}")
            urgent = alerts[alerts["level"] == "URGENT"] if not alerts.empty else alerts
            overdue = int((urgent["deadline"] < today).sum()) if not urgent.empty else 0
            l4.metric("Urgent alerts", len(urgent),
                      delta=f"{overdue} overdue" if overdue else None, delta_color="inverse")

            st.subheader("Alerts")
            if alerts.empty:
                st.caption("No alerts so far: nothing new affects the monitored assets.")
            else:
                grouped = (alerts.groupby(["level", "cve_id"], sort=False)
                           .agg(product=("product", "first"), target=("target", "first"),
                                assets=("hostname", lambda h: ", ".join(h)),
                                asset_count=("hostname", "size"), reason=("reason", "first"),
                                deadline=("deadline", "first"), raised_at=("raised_at", "first"))
                           .reset_index())
                grouped["status"] = np.where((grouped["deadline"] != "") & (grouped["deadline"] < today),
                                             "OVERDUE", "Open")
                grouped["order"] = grouped["level"].map({"URGENT": 0, "WARNING": 1, "INFO": 2})
                grouped = grouped.sort_values(["order", "deadline"]).drop(columns="order")

                st.dataframe(
                    grouped[["level", "status", "cve_id", "product", "asset_count", "assets",
                             "deadline", "reason", "target", "raised_at"]]
                    .style.map(lambda v: f"background-color: {ALERT_COLORS[v]}; color: #ffffff; "
                                         "font-weight: 700" if v in ALERT_COLORS else "",
                               subset=["level"])
                    .map(lambda v: "color: #b71c1c; font-weight: 700" if v == "OVERDUE" else "",
                         subset=["status"]),
                    hide_index=True, use_container_width=True,
                    column_config={
                        "level": "Level", "status": "Status", "cve_id": "CVE", "product": "Product",
                        "asset_count": st.column_config.NumberColumn("Assets"),
                        "assets": st.column_config.TextColumn("Affected assets", width="medium"),
                        "deadline": "Patch deadline",
                        "reason": st.column_config.TextColumn("Why", width="large"),
                        "target": "Environment", "raised_at": "Raised",
                    })
                st.caption("URGENT: newly added to CISA KEV (actively exploited); the deadline comes "
                           "from the KEV entry. WARNING: a new or changed CVE in the Critical risk tier. "
                           "One row per CVE; each affected asset is listed.")

            new_file = live_dir / "new_cves.csv"
            if new_file.exists():
                new_cves = pd.read_csv(new_file)
                st.subheader("Newly published CVEs, ranked by predicted exploitation")
                st.caption(f"Published in the last 7 days and already analysed by NVD "
                           f"({len(new_cves)} CVEs). CVEs NVD has not analysed yet have no product "
                           "data, so they cannot be matched to assets or scored.")
                if not new_cves.empty:
                    st.dataframe(
                        new_cves.head(25).assign(tier=lambda d: d["tier"].map(with_icon))
                        .style.map(tint_level, subset=["tier"]),
                        hide_index=True, use_container_width=True,
                        column_config={
                            "cve_id": "CVE", "published_date": "Published", "vendor": "Vendor",
                            "product": "Product", "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
                            "attack_vector": "Attack vector",
                            "probability": st.column_config.NumberColumn("Probability", format="percent"),
                            "tier": "Risk tier", "in_kev": "In KEV",
                            "description": st.column_config.TextColumn("Description", width="large"),
                        })

            with st.expander("Sync history"):
                st.dataframe(sync_log.iloc[::-1], hide_index=True, use_container_width=True)


# ==============================
# Tab 3: model evidence
# ==============================

if tab_model is not None:
    with tab_model:

        # ---- Simple view: four plain questions, details below for experts ----
        AI, OTHER, GREY = "#38bdf8", "#a78bfa", "#f97316"
        st.markdown("### Can we trust the AI's predictions?")
        st.markdown("We tested the AI like an exam. It **learned** from vulnerabilities published in "
                    "**2021–2023**, then **predicted 2025**, a year it had never seen. We then checked "
                    "which of those vulnerabilities attackers **really used** (CISA's official list).")

        tiers = pd.read_csv(RESULTS / "calibration" / "tiers_test.csv").set_index("tier")
        average = tiers["exploited"].sum() / tiers["cves"].sum()

        # 1. Do its warnings mean something?
        st.subheader("When the AI says \"danger\", is it right?")
        crit_lift, low_lift = tiers.loc["Critical", "lift"], tiers.loc["Low", "lift"]
        a, b = st.columns(2)
        a.markdown(kpi_card("Marked Critical", f"{crit_lift:.0f}× more",
                            "often attacked than an average vulnerability", "#f87171"), unsafe_allow_html=True)
        b.markdown(kpi_card("Marked Low", f"{1 / low_lift:.1f}× less",
                            "often attacked than an average vulnerability", "#4ade80"), unsafe_allow_html=True)
        rates = tiers.reset_index()[["tier", "hit_rate"]]
        bars = alt.Chart(rates).mark_bar(cornerRadiusEnd=6, height=26).encode(
            y=alt.Y("tier:N", sort=TIER_ORDER, title=None),
            x=alt.X("hit_rate:Q", title="Share later attacked", axis=alt.Axis(format="%")),
            color=alt.Color("tier:N", scale=level_color(TIER_ORDER), legend=None))
        text = bars.mark_text(align="left", dx=6, color="#e2e8f0", fontWeight="bold") \
            .encode(text=alt.Text("hit_rate:Q", format=".1%"))
        average_line = alt.Chart(pd.DataFrame({"x": [average]})).mark_rule(
            color="#94a3b8", strokeDash=[4, 4]).encode(x="x:Q")
        st.altair_chart((bars + text + average_line).properties(height=170), use_container_width=True)
        st.caption(f"Dashed line = average ({average:.1%} of all vulnerabilities were later attacked). "
                   "The labels mean what they say: Critical really is dangerous, Low really is safer.")

        # 2. As good as the professionals?
        st.subheader("Is it as good as the professional tools?")
        curve_path = PROJECT_ROOT / CURVE_FILE
        if curve_path.exists():
            at5 = pd.read_csv(curve_path).query("share_reviewed == 0.05").set_index("method")["share_caught"]
            st.markdown("If a security team checks only the **top 5 of every 100** new vulnerabilities, "
                        "how many of the ones attackers really used does each method find?")
            c1, c2, c3 = st.columns(3)
            c1.markdown(kpi_card("Our AI", f"{round(at5['Our model'] * 100)} of 100",
                                 "free public data, explains every result", AI), unsafe_allow_html=True)
            c2.markdown(kpi_card("Industry standard (EPSS)", f"{round(at5['EPSS (industry standard)'] * 100)} of 100",
                                 "partly private, paid data", OTHER), unsafe_allow_html=True)
            c3.markdown(kpi_card("Usual way (CVSS score)", f"{round(at5['CVSS score (usual practice)'] * 100)} of 100",
                                 "severity only", GREY), unsafe_allow_html=True)
            st.success("**As accurate as the industry standard, and about 3× better than the usual way**, "
                       "using only free public data.")

        # 3. Does it explain itself?
        st.subheader("Does it explain its decisions?")
        st.markdown("Yes. Every prediction comes with its reasons. Across all predictions, these are "
                    "the things the AI looks at most:")
        groups = pd.read_csv(RESULTS / "explainability" / "group_importance.csv")
        plain = {"Description text": "What the description says (e.g. \"remote code execution\", "
                                     "\"no login needed\")",
                 "Threat history": "How often this vendor's products were attacked before",
                 "CVSS scores": "How severe the vulnerability is (CVSS)",
                 "CVSS vector": "How it can be attacked (over the network, login needed or not)",
                 "Affected scope": "How many products it affects",
                 "Weakness type (CWE)": "The type of weakness"}
        groups["reason"] = groups["group"].map(plain).fillna(groups["group"])
        reason_chart = alt.Chart(groups).mark_bar(cornerRadiusEnd=6, height=24, color=AI).encode(
            y=alt.Y("reason:N", sort="-x", title=None, axis=alt.Axis(labelLimit=420)),
            x=alt.X("share:Q", title="Share of the AI's decision", axis=alt.Axis(format="%")))
        st.altair_chart(reason_chart.properties(height=230), use_container_width=True)
        st.caption("These match what security experts look for, so the AI is not using hidden shortcuts.")

        # 4. Does it stay accurate?
        st.subheader("Does it stay accurate over time?")
        calibration = pd.read_csv(RESULTS / "calibration" / "calibration_comparison.csv").set_index("method")
        expected, actual = calibration.loc["sigmoid", "expected_positives"], calibration.loc["sigmoid", "actual_positives"]
        d1, d2 = st.columns(2)
        d1.markdown(kpi_card("2025: attacks the AI expected", f"{expected:.0f}",
                             f"really happened: {int(actual)} (right range, slightly cautious)", AI),
                    unsafe_allow_html=True)
        active_path = RESULTS / "models" / "active_model.json"
        if active_path.exists():
            import json as json_lib
            kept = json_lib.loads(active_path.read_text())["active"] == "research"
            d2.markdown(kpi_card("Self-check and retraining", "Checked",
                                 "a newer version was tested and was not better, so the proven one is kept"
                                 if kept else "a newer, better version was tested and is now in use", OTHER),
                        unsafe_allow_html=True)
        st.caption("The system compares expected and real attacks every half-year and tests a retrained "
                   "version on fresh data before ever switching.")

        st.info("**Honest limits:** CISA's list of attacked vulnerabilities is not complete, and accuracy "
                "is lower for 2026 vulnerabilities because NIST is analysing fewer of them. The system "
                "monitors this.")

        with st.expander("Full technical evidence (for experts)"):
            st.subheader("Held-out evaluation (2025 CVEs, never used in training)")

            metrics = pd.read_csv(RESULTS / "metrics.csv")
            test = metrics[metrics["split"] == "test"][[
                "model", "pr_auc", "pr_auc_ci_low", "pr_auc_ci_high", "roc_auc",
                "recall_top_1pct", "recall_top_5pct"]]

            st.dataframe(
                test, hide_index=True, use_container_width=True,
                column_config={
                    "model": "Model",
                    "pr_auc": st.column_config.NumberColumn("PR-AUC", format="%.3f"),
                    "pr_auc_ci_low": st.column_config.NumberColumn("95% CI low", format="%.3f"),
                    "pr_auc_ci_high": st.column_config.NumberColumn("95% CI high", format="%.3f"),
                    "roc_auc": st.column_config.NumberColumn("ROC-AUC", format="%.3f"),
                    "recall_top_1pct": st.column_config.NumberColumn("Recall @ top 1%", format="percent"),
                    "recall_top_5pct": st.column_config.NumberColumn("Recall @ top 5%", format="percent"),
                })

            st.caption("Random-classifier PR-AUC equals the share of exploited CVEs (about 0.005).")

            col1, col2 = st.columns(2)
            col1.image(str(RESULTS / "pr_curves_test.png"), caption="Precision-recall, 2025 test set")
            col2.image(str(RESULTS / "calibration" / "reliability_test.png"),
                       caption="Calibration (Platt scaling fitted on 2024)")

            st.subheader("Risk tiers on 2025 CVEs")
            tiers = pd.read_csv(RESULTS / "calibration" / "tiers_test.csv")

            tier_long = pd.concat([
                tiers.assign(measure="Share of all CVEs", value=tiers["share_of_cves"]),
                tiers.assign(measure="Share of exploited CVEs caught", value=tiers["share_of_exploited"]),
            ])
            tier_long["label"] = tier_long["tier"].map(with_icon)
            tier_chart = alt.Chart(tier_long).mark_bar(cornerRadiusEnd=4, height=24).encode(
                x=alt.X("value:Q", axis=alt.Axis(format="%"), title=None),
                y=alt.Y("measure:N", title=None, axis=alt.Axis(labelLimit=220)),
                color=alt.Color("tier:N", scale=level_color(TIER_ORDER), legend=None),
                row=alt.Row("label:N", sort=[with_icon(t) for t in TIER_ORDER], title=None,
                            header=alt.Header(labelAngle=0, labelAlign="left", labelFontWeight="bold")),
                tooltip=[alt.Tooltip("tier:N", title="Tier"), alt.Tooltip("measure:N", title="Measure"),
                         alt.Tooltip("value:Q", title="Value", format=".1%"),
                         alt.Tooltip("hit_rate:Q", title="Hit rate", format=".1%"),
                         alt.Tooltip("lift:Q", title="Lift vs random", format=".1f")],
            ).properties(height=64, width=520)
            st.altair_chart(tier_chart)
            st.caption("The Critical and High tiers hold 5% of new CVEs but catch 44% of those later "
                       "exploited. The Low tier holds 75% of CVEs and 28% of exploited ones.")

            st.dataframe(
                tiers[["tier", "cves", "share_of_cves", "exploited", "hit_rate", "share_of_exploited", "lift"]],
                hide_index=True, use_container_width=True,
                column_config={
                    "tier": "Tier", "cves": "CVEs", "exploited": "Exploited",
                    "share_of_cves": st.column_config.NumberColumn("Share of CVEs", format="percent"),
                    "hit_rate": st.column_config.NumberColumn("Hit rate", format="percent"),
                    "share_of_exploited": st.column_config.NumberColumn("Share of exploited", format="percent"),
                    "lift": st.column_config.NumberColumn("Lift vs random", format="%.1fx"),
                })

            bench_dir = RESULTS / "benchmark"
            if (bench_dir / "benchmark.csv").exists():
                st.subheader("Benchmark against EPSS, ablation and significance")
                st.caption("EPSS (FIRST's Exploit Prediction Scoring System) is the industry standard. "
                           "Each 2025 CVE uses its EPSS score from the first weekly snapshot after "
                           "publication, so EPSS sees up to 7 days more than the model.")
                bench = pd.read_csv(bench_dir / "benchmark.csv")
                st.dataframe(
                    bench, hide_index=True, use_container_width=True,
                    column_config={
                        "model": "Method",
                        "pr_auc": st.column_config.NumberColumn("PR-AUC", format="%.3f"),
                        "ci_low": st.column_config.NumberColumn("95% CI low", format="%.3f"),
                        "ci_high": st.column_config.NumberColumn("95% CI high", format="%.3f"),
                        "roc_auc": st.column_config.NumberColumn("ROC-AUC", format="%.3f"),
                        "recall_top_1pct": st.column_config.NumberColumn("Recall @ top 1%", format="percent"),
                        "recall_top_5pct": st.column_config.NumberColumn("Recall @ top 5%", format="percent"),
                    })
                st.image(str(bench_dir / "benchmark_ablation.png"))

                sig = pd.read_csv(bench_dir / "significance.csv")
                sig["result"] = np.where(sig["significant"], "✓ Significant (p < 0.05)", "Not significant")
                st.markdown("**Is each difference real? Paired bootstrap tests (2,000 resamples)**")
                st.dataframe(
                    sig[["comparison", "metric", "difference", "ci_low", "ci_high", "p_value", "result"]]
                    .style.map(lambda v: "color: #137a13; font-weight: 700" if str(v).startswith("✓") else "",
                               subset=["result"]),
                    hide_index=True, use_container_width=True,
                    column_config={
                        "comparison": st.column_config.TextColumn("Comparison", width="large"),
                        "metric": "Metric",
                        "difference": st.column_config.NumberColumn("Difference", format="%+.3f"),
                        "ci_low": st.column_config.NumberColumn("95% CI low", format="%+.3f"),
                        "ci_high": st.column_config.NumberColumn("95% CI high", format="%+.3f"),
                        "p_value": st.column_config.NumberColumn("p-value", format="%.3f"),
                        "result": "Result",
                    })
                st.caption("Positive difference = the first method is better. Ablation rows compare the "
                           "full model with a version retrained without one feature group.")

            # ---- Model monitoring: drift and champion/challenger retraining ----
            drift_file = RESULTS / "monitoring" / "prediction_drift.csv"
            active_file = RESULTS / "models" / "active_model.json"
            if drift_file.exists():
                import json as json_lib

                st.subheader("Model monitoring: drift and retraining")
                st.caption("Expected vs actual KEV additions per half-year of publication. For recent "
                           "periods the 12 months are not over, so the expectation is counted only for "
                           "the follow-up time that has passed. A ratio near 1.0 means well calibrated.")
                drift = pd.read_csv(drift_file)
                st.dataframe(
                    drift[["period", "role", "cves", "expected_so_far", "actual_kev",
                           "follow_up_elapsed", "expected_to_actual"]],
                    hide_index=True, use_container_width=True,
                    column_config={
                        "period": "Published", "role": "Role", "cves": "CVEs",
                        "expected_so_far": st.column_config.NumberColumn("Expected so far", format="%.1f"),
                        "actual_kev": "Actual so far",
                        "follow_up_elapsed": st.column_config.ProgressColumn(
                            "12-month window elapsed", format="percent", min_value=0, max_value=1),
                        "expected_to_actual": st.column_config.NumberColumn("Expected ÷ actual", format="%.2f"),
                    })

                if active_file.exists():
                    decision = json_lib.loads(active_file.read_text())
                    live_name = "Research model" if decision["active"] == "research" else "Retrained model"
                    st.markdown(f"**Live model: {live_name}** (champion/challenger review "
                                f"{decision['decided']})")
                    st.caption(f"Rule: {decision['rule']}. Test data: {decision['out_of_time_data']}.")
                    evidence = pd.DataFrame([
                        {"Metric": {"pr_auc": "PR-AUC", "recall_top_1pct": "Recall @ top 1%",
                                    "roc_auc": "ROC-AUC", "recall_top_5pct": "Recall @ top 5%"}[m],
                         "Primary": "Yes" if v["primary"] else "No",
                         "Research model (champion)": v["champion"],
                         "Retrained model (challenger)": v["challenger"],
                         "Winner": "Challenger" if v["challenger_wins"] else "Champion"}
                        for m, v in decision["evidence"].items()])
                    st.dataframe(evidence, hide_index=True, use_container_width=True)
                    st.caption("The retrained model is trained on CVEs to August 2024 and calibrated on the "
                               "latest 12 labelled months. It is promoted only if it wins on the primary "
                               "metrics on CVEs neither model has seen. Reported research results always "
                               "use the frozen research model.")

            st.subheader("What drives the predictions")
            col3, col4 = st.columns(2)
            col3.image(str(RESULTS / "explainability" / "shap_global_top20.png"))
            col4.image(str(RESULTS / "explainability" / "shap_groups.png"))


# ==============================
# Tab 4: backtest
# ==============================

if tab_backtest is not None:
    with tab_backtest:

        lab_results = RESULTS / "lab"

        if not (lab_results / "backtest_summary.json").exists():
            st.info("Run `python -m src.lab.backtest` to generate the backtest.")
        else:
            import json

            summary = json.loads((lab_results / "backtest_summary.json").read_text())

            st.subheader(f"Asset-level backtest: {summary['snapshot_date']} "
                         f"to {summary['follow_up_end']}")
            st.caption(
                "The synthetic lab is assessed using only information known at the "
                "snapshot date, then compared with the CVEs actually added to CISA KEV "
                "in the following 12 months. Assumes installed versions stay unchanged "
                "during the follow-up year.")

            b1, b2, b3, b4 = st.columns(4)
            b1.metric("Assets", summary["assets"])
            b2.metric("Known exploited at snapshot", summary["assets_known_exploited_at_snapshot"])
            b3.metric("Newly exposed (any CVE)", summary["assets_newly_exploited_any_route"])
            b4.metric("Newly exposed (scored CVEs)", summary["assets_newly_exploited_window"])

            routes = summary["newly_exploited_cves_by_route"]
            st.markdown(
                f"**Newly exploited CVEs:** {routes.get('prediction window', 0)} were already "
                f"published and scored at the snapshot; {routes.get('older', 0)} were older; "
                f"**{routes.get('new', 0)} did not exist yet** (published after the snapshot, "
                "mostly exploited as zero-days).")

            st.markdown("**Asset ranking vs what happened**")
            metrics = pd.read_csv(lab_results / "backtest_asset_metrics.csv")
            metrics["target"] = metrics["target"].map({
                "outcome_window": "Exposed via a scored CVE",
                "outcome_any": "Exposed via any CVE"})
            st.dataframe(
                metrics, hide_index=True, use_container_width=True,
                column_config={
                    "target": "Outcome", "ranker": "Ranking method",
                    "positives": "Exposed assets", "assets": "Assets",
                    "roc_auc": st.column_config.NumberColumn("ROC-AUC", format="%.3f"),
                    "hits_top_5": "Exposed in top 5", "hits_top_10": "Exposed in top 10",
                })

            cve_level = summary["cve_level"]
            st.markdown(
                f"**CVE level:** {cve_level['exploited_in_follow_up']} of "
                f"{cve_level['window_cves']} scored CVEs in the lab were exploited in the "
                f"follow-up year. PR-AUC: model {cve_level['model_pr_auc']:.3f}, CVSS "
                f"{cve_level['cvss_pr_auc']:.3f}, random {cve_level['base_rate']:.3f}. "
                "Too few events for a firm conclusion; see the main 2025 test-set evaluation.")

            backtest_assets = pd.read_csv(lab_results / "backtest_assets.csv")
            st.dataframe(
                backtest_assets.sort_values("expected_new_exposure_12m", ascending=False)[[
                    "asset_id", "hostname", "known_exploited", "expected_exploited_12m",
                    "product_kev_rate_12m", "max_cve_probability", "max_cvss",
                    "exploited_window", "exploited_older", "exploited_new"]],
                hide_index=True, use_container_width=True,
                column_config={
                    "known_exploited": "Known exploited at snapshot",
                    "expected_exploited_12m": st.column_config.NumberColumn(
                        "Predicted: from known CVEs", format="%.2f"),
                    "product_kev_rate_12m": "Predicted: product KEV history",
                    "max_cve_probability": st.column_config.NumberColumn(
                        "Predicted: max CVE probability", format="percent"),
                    "max_cvss": st.column_config.NumberColumn("Max CVSS", format="%.1f"),
                    "exploited_window": "Actual: scored CVEs exploited",
                    "exploited_older": "Actual: older CVEs exploited",
                    "exploited_new": "Actual: new CVEs exploited",
                })


# ==============================
# Tab: administration (users, ownership, audit log)
# ==============================

if tab_admin is not None:
    with tab_admin:
        manage = can(user, "manage_users")

        st.subheader("Users and roles")
        users = auth_store.list_users()
        st.dataframe(
            users.assign(role=users["role"].map(role_name),
                         mfa_enabled=users["mfa_enabled"].map({1: "✓ Enrolled", 0: "Not set up"}),
                         active=users["active"].map({1: "Active", 0: "Disabled"})),
            hide_index=True, use_container_width=True,
            column_config={"username": "Username", "display_name": "Name", "email": "Email",
                           "role": "Role", "team": "Team", "mfa_enabled": "MFA",
                           "must_change_password": "Must change password",
                           "failed_attempts": "Failed attempts", "locked_until": "Locked until",
                           "active": "Status", "created_at": "Created", "last_login": "Last sign-in"})

        if not manage:
            st.caption("Read-only: only the Administrator can manage accounts.")
        else:
            owner_teams = sorted(auth_store.owners()["team"].unique())
            create_col, manage_col = st.columns(2)

            with create_col:
                st.markdown("**Create a user**")
                with st.form("create_user", clear_on_submit=True):
                    new_username = st.text_input("Username (lowercase, 3-32 characters)").strip().lower()
                    new_name = st.text_input("Full name")
                    new_email = st.text_input("Email")
                    new_role = st.selectbox("Role", list(ROLES), format_func=role_name)
                    new_team = st.selectbox("Team (Asset Owners only)", [""] + owner_teams)
                    create = st.form_submit_button("Create user", type="primary")
                if create:
                    import re
                    if not re.fullmatch(r"[a-z0-9._-]{3,32}", new_username or ""):
                        st.error("Username: 3-32 characters, lowercase letters, digits, . _ -")
                    elif auth_store.get_user(new_username):
                        st.error("That username already exists.")
                    elif not new_name:
                        st.error("Enter the user's full name.")
                    elif new_role == "asset_owner" and not new_team:
                        st.error("Asset Owners need a team.")
                    else:
                        temp = temporary_password()
                        auth_store.create_user(new_username, new_name, new_role, hash_password(temp),
                                               new_email, new_team if new_role == "asset_owner" else "")
                        audit("user_created", user["username"], user["role"],
                              f"{new_username} ({new_role})")
                        st.success(f"Created **{new_username}**. Give them this temporary password "
                                   "through a separate channel; it is shown only once:")
                        st.code(temp)

            with manage_col:
                st.markdown("**Manage an account**")
                others = [u for u in users["username"] if u != user["username"]]
                target = st.selectbox("Account", others) if others else None
                if target:
                    b1, b2, b3 = st.columns(3)
                    target_row = users.set_index("username").loc[target]
                    if b1.button("Reset password", use_container_width=True):
                        temp = temporary_password()
                        auth_store.update_user(target, password_hash=hash_password(temp),
                                               must_change_password=1, failed_attempts=0,
                                               locked_until=None)
                        audit("password_reset", user["username"], user["role"], target)
                        st.success("Temporary password (shown once):")
                        st.code(temp)
                    if b2.button("Reset MFA", use_container_width=True):
                        auth_store.update_user(target, totp_secret=None, mfa_enabled=0,
                                               last_totp_counter=None)
                        audit("mfa_reset", user["username"], user["role"], target)
                        st.success(f"{target} will set up MFA again at next sign-in.")
                    if b3.button("Unlock", use_container_width=True):
                        auth_store.update_user(target, failed_attempts=0, locked_until=None)
                        audit("account_unlocked", user["username"], user["role"], target)
                        st.success(f"{target} unlocked.")

                    role_col, apply_col = st.columns([2, 1])
                    new_target_role = role_col.selectbox(
                        "Role", list(ROLES), index=list(ROLES).index(target_row["role"]),
                        format_func=role_name, key="change_role")
                    if apply_col.button("Apply role", use_container_width=True) \
                            and new_target_role != target_row["role"]:
                        auth_store.update_user(target, role=new_target_role)
                        audit("role_changed", user["username"], user["role"],
                              f"{target}: {target_row['role']} -> {new_target_role}")
                        st.success(f"{target} is now {role_name(new_target_role)}.")

                    active = bool(target_row["active"])
                    if st.button("Disable account" if active else "Enable account"):
                        auth_store.update_user(target, active=0 if active else 1)
                        audit("account_disabled" if active else "account_enabled",
                              user["username"], user["role"], target)
                        st.success(f"{target} {'disabled' if active else 'enabled'}.")
                st.caption("You cannot change your own account here, so an administrator "
                           "cannot accidentally lock themselves out or remove their own role.")

        st.subheader("Asset ownership")
        ownership = auth_store.owners()
        st.dataframe(
            ownership.groupby(["lab", "team", "team_email"])["asset_id"]
            .agg(assets="count", ids=lambda ids: ", ".join(sorted(ids))).reset_index(),
            hide_index=True, use_container_width=True,
            column_config={"lab": "Lab", "team": "Team", "team_email": "Team email",
                           "assets": "Assets", "ids": "Asset IDs"})

        st.subheader("Audit log")
        intact, broken = auth_store.verify_audit()
        log = auth_store.read_audit(1000)
        if intact:
            st.success(f"✓ Integrity verified: {len(log)} most recent entries shown; the SHA-256 "
                       "hash chain over the whole log is unbroken (no entry edited or deleted).")
        else:
            st.error(f"⚠ Audit log tampering detected at entry {broken}: the hash chain is broken.")

        filter_user, filter_outcome = st.columns(2)
        who = filter_user.selectbox("User", ["All"] + sorted(log["username"].dropna().unique()))
        outcome = filter_outcome.selectbox("Outcome", ["All", "success", "failure"])
        view = log if who == "All" else log[log["username"] == who]
        view = view if outcome == "All" else view[view["outcome"] == outcome]
        st.dataframe(
            view[["at", "username", "role", "action", "detail", "outcome", "entry_hash"]]
            .assign(entry_hash=lambda d: d["entry_hash"].str.slice(0, 12) + "…")
            .style.map(lambda v: "color: #b71c1c; font-weight: 700" if v == "failure" else "",
                       subset=["outcome"]),
            hide_index=True, use_container_width=True,
            column_config={"at": "Time (UTC)", "username": "User", "role": "Role",
                           "action": "Action", "detail": "Detail", "outcome": "Outcome",
                           "entry_hash": "Hash"})


# ==============================
# Tab: notifications to owning teams
# ==============================

if tab_notify is not None:
    with tab_notify:
        sending = can(user, "send_notifications")
        smtp_on = bool(__import__("os").environ.get("SMTP_HOST"))

        st.markdown("**Inform the team that owns each high-risk device what to fix. Fixing is the "
                    "owning team's responsibility; this tab makes sure they are told clearly.**")
        n1, n2, n3, n4 = st.columns(4)
        n1.metric("Devices needing action", len(needs_notice))
        n2.metric("Not yet notified", pending_notices)
        n3.metric("Notices sent (this lab)", len(notify_history))
        n4.metric("Delivery mode", "Email (SMTP)" if smtp_on else "Test mode",
                  help="Without SMTP settings, messages are saved to data/notifications/outbox")

        if needs_notice.empty:
            st.success("No device currently needs a notice.")
        else:
            st.dataframe(
                needs_notice[["hostname", "asset_type", "exposure_level", "actions", "exploited",
                              "overdue", "next_deadline", "status", "last_notified", "notified_to"]]
                .assign(exposure_level=lambda d: d["exposure_level"].map(with_icon))
                .style.map(tint_level, subset=["exposure_level"])
                .map(lambda v: "color: #b71c1c; font-weight: 700" if v == "Not notified" else
                     "color: #137a13; font-weight: 700" if v == "Notified" else "", subset=["status"]),
                hide_index=True, use_container_width=True,
                column_config={"hostname": "Device", "asset_type": "Type",
                               "exposure_level": "Exposure", "actions": "Fixes",
                               "exploited": "Exploited CVEs", "overdue": "Overdue fixes",
                               "next_deadline": "Earliest deadline", "status": "Status",
                               "last_notified": "Last notice (UTC)", "notified_to": "Sent to"})

        if not sending:
            st.caption("Read-only: notices are prepared and sent by Security Analysts and Managers.")
        elif not needs_notice.empty:
            st.subheader("Prepare a notice")
            device_ids = needs_notice["asset_id"].tolist()
            first_pending = next((i for i, s in enumerate(needs_notice["status"]) if s == "Not notified"), 0)
            chosen_id = st.selectbox(
                "Device", device_ids, index=first_pending,
                format_func=lambda a: "{} · {} · {}".format(
                    *needs_notice.set_index("asset_id").loc[a, ["hostname", "exposure_level", "status"]]))
            device = needs_notice.set_index("asset_id").loc[chosen_id]
            device_actions = plan_all[plan_all["asset_id"] == chosen_id]

            owner_rows = auth_store.owners(notify_lab)
            owner_rows = owner_rows[owner_rows["asset_id"] == chosen_id]
            team = owner_rows["team"].iloc[0] if not owner_rows.empty else "device owner"
            team_email = owner_rows["team_email"].iloc[0] if not owner_rows.empty else ""

            left, right = st.columns([1, 1])
            with left:
                st.markdown(f"**Owning team:** {team}")
                recipients_text = st.text_input(
                    "Send to (separate several addresses with commas)", value=team_email or "",
                    key=f"recipients_{chosen_id}")
                remember = False
                if not owner_rows.empty and can(user, "assign_owners"):
                    remember = st.checkbox("Remember this address for the device's team", value=False,
                                           key=f"remember_{chosen_id}")
                note = st.text_area("Personal note (optional)", key=f"note_{chosen_id}",
                                    placeholder="e.g. Please coordinate the reboot with the service desk.")

            containment = None
            if source == "Lab database" and can(user, "view_attack_paths"):
                scenario, _, _, _, _ = run_attack_paths(lab_db, snapshot_id, "device", chosen_id)
                if not scenario.fixes.empty:
                    # Only steps the owning team can act on: links from this device,
                    # or network rules leaving the device's own zone
                    zone = scenario.reached.loc[scenario.reached["start"], "segment"].iloc[0]
                    fixes = scenario.fixes[scenario.fixes["type"] != "Patch"]
                    relevant = (fixes["action"].str.contains(f" from {device['hostname']} ", regex=False)
                                | fixes["action"].str.startswith(f"Restrict {zone} "))
                    containment = fixes[relevant]

            details = vulnerability_details(
                device_actions, cves[cves["ip_address"] == device["ip_address"]],
                reference_data()["scoring"], kev_details(), notify_config.get("max_cves_in_email", 10))
            message = compose(device.to_dict() | {"asset_id": chosen_id}, device_actions, user, team,
                              note, containment, notify_config, details)
            recipients = parse_recipients(recipients_text)
            problems = recipient_problems(recipients, notify_config)

            with right:
                st.markdown(f"**Subject:** {message['subject']}")
                st.caption(f"{details['total']} vulnerabilities fixed · {details['exploited']} actively "
                           f"exploited · the email lists the {len(details['rows'])} most urgent in a grid "
                           "(CVE, CVSS, MITRE ATT&CK tactic, exploitation, summary, mitigation).")
            st.markdown("**Email preview**")
            with st.container(border=True, height=620):
                st.html(message["html"])

            if problems:
                st.error("Cannot send: " + "; ".join(problems) + ".")
            if st.button("Send notice" if smtp_on else "Send notice (test mode: save to outbox)",
                         type="primary", disabled=bool(problems), icon=":material/send:"):
                try:
                    delivery, file = deliver(message, recipients, user, notify_config)
                except Exception as error:          # mail server unreachable, login failed...
                    audit("notification_failed", user["username"], user["role"],
                          f"{device['hostname']}: {error}", "failure")
                    st.error(f"Sending failed: {error}")
                else:
                    auth_store.add_notification({
                        "sender": user["username"], "lab": notify_lab, "asset_id": chosen_id,
                        "hostname": device["hostname"], "team": team,
                        "recipients": ", ".join(recipients), "subject": message["subject"],
                        "actions": message["actions"], "exploited": message["exploited"],
                        "delivery": delivery, "message_file": file})
                    audit("notification_sent", user["username"], user["role"],
                          f"{device['hostname']} -> {', '.join(recipients)} ({delivery})")
                    if remember and recipients:
                        auth_store.set_team_email(notify_lab, chosen_id, ", ".join(recipients))
                        audit("owner_email_changed", user["username"], user["role"],
                              f"{chosen_id}: {', '.join(recipients)}")
                    st.success(f"Notice for **{device['hostname']}** {delivery}"
                               + (f": `{Path(file).name}`" if file else "") + ".")
                    st.rerun()

        st.subheader("Notice history")
        if notify_history.empty:
            st.caption("No notices sent yet for this lab.")
        else:
            st.dataframe(
                notify_history[["sent_at", "hostname", "team", "recipients", "subject", "actions",
                                "exploited", "sender", "delivery"]],
                hide_index=True, use_container_width=True,
                column_config={"sent_at": "Sent (UTC)", "hostname": "Device", "team": "Team",
                               "recipients": "Recipients", "subject": "Subject",
                               "actions": "Fixes", "exploited": "Exploited", "sender": "Sent by",
                               "delivery": "Delivery"})


# ==============================
# Comparison: our plan vs the usual plans (simple view, details on request)
# ==============================

if tab_compare is not None:
    with tab_compare:
        OURS, USUAL = "#38bdf8", "#f97316"
        st.markdown("### Does our system choose better than the usual way?")
        st.markdown("The **usual way** is to fix the vulnerabilities with the highest **CVSS** "
                    "severity score first. **Our system** fixes first what attackers are most likely "
                    "to use, on the devices that matter most.")

        def big_pair(left_title, left_value, right_title, right_value, note):
            a, b = st.columns(2)
            a.markdown(kpi_card(left_title, left_value, note, OURS), unsafe_allow_html=True)
            b.markdown(kpi_card(right_title, right_value, note, USUAL), unsafe_allow_html=True)

        # ---- Question 1: real 2025 outcomes ----
        st.subheader("Does it find the dangerous weaknesses?")
        curve_path = PROJECT_ROOT / CURVE_FILE
        if not curve_path.exists():
            st.info("Run `python -m src.evaluation.plan_comparison` to build this result.")
        else:
            curve = pd.read_csv(curve_path)
            at5 = curve[curve["share_reviewed"] == 0.05].set_index("method")["share_caught"]
            ours5, cvss5 = at5["Our model"], at5["CVSS score (usual practice)"]
            st.markdown(f"Test: **{curve['cves'].iloc[0]:,} real vulnerabilities from 2025**, which the "
                        f"AI never saw while learning. **{curve['exploited'].iloc[0]}** of them were later "
                        "used by attackers. The team only has time to check **5 in every 100**.")
            big_pair("Our system finds", f"{round(ours5 * 100)} of 100", "Usual way finds",
                     f"{round(cvss5 * 100)} of 100", "of the vulnerabilities attackers really used")
            bars = pd.DataFrame({"method": ["Our system", "Usual way (CVSS)"],
                                 "found": [ours5, cvss5]})
            chart = alt.Chart(bars).mark_bar(cornerRadiusEnd=6, height=34).encode(
                y=alt.Y("method:N", title=None, sort=None),
                x=alt.X("found:Q", title=None, axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
                color=alt.Color("method:N", legend=None,
                                scale=alt.Scale(domain=["Our system", "Usual way (CVSS)"], range=[OURS, USUAL])))
            labels = chart.mark_text(align="left", dx=6, fontWeight="bold", fontSize=15, color="#e2e8f0") \
                .encode(text=alt.Text("found:Q", format=".0%"))
            st.altair_chart((chart + labels).properties(height=120), use_container_width=True)
            st.success(f"**About {ours5 / cvss5:.0f}× more dangerous vulnerabilities found for the same "
                       "amount of work.** This result is statistically significant.")

        # ---- Question 2: this network ----
        st.subheader("On this network: how many updates until the attacked devices are safe?")
        orders, progress = compare_plans(plan_all, scanned, cves)
        start = int(progress.loc[progress["fixes"] == 0, "devices_exposed"].iloc[0]) if orders else 0
        if not orders or start == 0:
            st.info("No device on this network has a vulnerability that attackers are using right now, "
                    "so there is nothing to compare here.")
        else:
            def updates_needed(plan):
                steps = progress[progress["plan"] == plan].sort_values("fixes")
                target = steps["devices_exposed"].iloc[-1]          # best possible with all updates
                return int(steps.loc[steps["devices_exposed"] <= target, "fixes"].iloc[0])
            ours_n, cvss_n = updates_needed("Our plan"), updates_needed("CVSS plan")
            st.markdown(f"**{start}** device{'s are' if start != 1 else ' is'} exposed to a vulnerability "
                        f"attackers are using right now ({source_label}). Same updates, two different orders:")
            big_pair("Our plan makes them safe after", f"{ours_n} updates", "Usual plan needs",
                     f"{cvss_n} updates", "to close every actively attacked device")
            if ours_n < cvss_n:
                st.success(f"**Our plan protects the network {cvss_n - ours_n} update"
                           f"{'s' if cvss_n - ours_n != 1 else ''} sooner.**")
            elif ours_n == cvss_n:
                st.info("On this network both plans need the same number of updates.")
            else:
                st.info("On this network the usual plan happens to finish sooner; our plan fixes "
                        "internet-facing and important devices first.")
            first, second = st.columns(2)
            for column, plan, colour, title in [(first, "Our plan", OURS, "Our plan: first updates"),
                                                (second, "CVSS plan", USUAL, "Usual plan: first updates")]:
                column.markdown(f"<b style='color:{colour}'>{title}</b>", unsafe_allow_html=True)
                for n, a in enumerate(orders[plan].head(5).itertuples(index=False), start=1):
                    column.markdown(f"{n}. **{a.hostname}**: {a.product}"
                                    + (" · under attack" if a.kev_fixed else ""))

        # ---- Question 3: the past ----
        st.subheader("Did it work in the past?")
        metrics_path = RESULTS / "lab" / "backtest_asset_metrics.csv"
        if metrics_path.exists():
            bt = pd.read_csv(metrics_path)
            bt = bt[bt["target"] == "outcome_window"].set_index("ranker")
            ours_bt, cvss_bt = bt.loc["Model: P(at least one)"], bt.loc["Max CVSS (baseline)"]
            st.markdown("We went back to **August 2025**, asked each method which **5 devices** to fix "
                        "first in a 30-device test company, then checked **one year later** which "
                        "devices were really attacked.")
            big_pair("Our top 5 really attacked", f"{int(ours_bt['hits_top_5'])} of 5",
                     "Usual way's top 5 really attacked", f"{int(cvss_bt['hits_top_5'])} of 5",
                     "checked against real attacks in the following 12 months")

        # ---- Everything else, for experts ----
        with st.expander("More details for experts"):
            if curve_path.exists():
                st.markdown("**Share of attacked vulnerabilities found vs share checked** (2025 test, "
                            "including EPSS, the industry standard)")
                colours = {"Our model": OURS, "EPSS (industry standard)": "#a78bfa",
                           "CVSS score (usual practice)": USUAL, "Random": "#64748b"}
                line = alt.Chart(curve[curve["share_reviewed"] <= 0.30]).mark_line(point=True).encode(
                    x=alt.X("share_reviewed:Q", title="Share checked", axis=alt.Axis(format="%")),
                    y=alt.Y("share_caught:Q", title="Attacked ones found", axis=alt.Axis(format="%")),
                    color=alt.Color("method:N", title=None, sort=METHODS,
                                    scale=alt.Scale(domain=list(colours), range=list(colours.values())),
                                    legend=alt.Legend(orient="bottom")),
                    tooltip=["method", alt.Tooltip("share_reviewed:Q", format=".1%"),
                             alt.Tooltip("share_caught:Q", format=".1%")])
                st.altair_chart(line.properties(height=300), use_container_width=True)
                st.caption("EPSS (partly private data) finds slightly more in the top 1–3%; our model "
                           "finds more from 5% upwards; overall the two are statistically equal "
                           "(p = 0.86). Versus CVSS, the top-5% result is significant (p < 0.001).")
            if orders:
                st.markdown("**Devices still exposed after each update** (three orders of the same updates)")
                plan_colours = {"Our plan": OURS, "CVSS plan": USUAL, "Criticality plan": "#eab308"}
                steps = alt.Chart(progress).mark_line(point=True, interpolate="step-after").encode(
                    x=alt.X("fixes:Q", title="Updates installed", axis=alt.Axis(tickMinStep=1)),
                    y=alt.Y("devices_exposed:Q", title="Devices still exposed", axis=alt.Axis(tickMinStep=1)),
                    color=alt.Color("plan:N", title=None, sort=PLANS,
                                    scale=alt.Scale(domain=list(plan_colours), range=list(plan_colours.values())),
                                    legend=alt.Legend(orient="bottom")))
                st.altair_chart(steps.properties(height=260), use_container_width=True)
                st.caption("A device counts as exposed while any software on it has a vulnerability CISA "
                           "lists as actively exploited. Criticality plan = most important device first.")
            if metrics_path.exists():
                st.markdown(f"**Backtest ranking accuracy (ROC-AUC):** our system "
                            f"{ours_bt['roc_auc']:.2f} vs CVSS {cvss_bt['roc_auc']:.2f}; top 10 devices "
                            f"really attacked: {int(ours_bt['hits_top_10'])} vs {int(cvss_bt['hits_top_10'])}. "
                            "The test company is synthetic (real NVD software versions per patch level).")


# ==============================
# Back / Home at the bottom of every page (long pages need no scrolling up)
# ==============================

if page != "home":
    st.divider()
    back_bar("bottom")
