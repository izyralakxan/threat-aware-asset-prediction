"""
Remediation notices to the team that owns a device.

The system informs; fixing is the owning team's responsibility. A Security
Analyst or Security Manager reviews the device, confirms the recipients,
previews the message and sends it.

Security of the channel
  - recipients must belong to an allowed email domain (config/notifications.json),
    so vulnerability details cannot be sent outside the organisation; single
    addresses can be approved individually (allowed_addresses, e.g. a tester)
  - plain, consistent format with no attachments and an explicit statement
    that the message never asks for passwords (helps users spot phishing)
  - only what the owning team needs to act: the actions, and per CVE its
    CVSS, likely MITRE ATT&CK tactic (estimated), exploitation status, a short
    summary and the mitigation; model internals stay in the dashboard
  - SMTP with STARTTLS when a mail server is configured; otherwise "test mode"
    saves the message as an .eml file in data/notifications/outbox/

Mail server settings (environment variables, same as the live alerts):
  SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD
"""

import html
import json
import os
import re
import smtplib
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from pathlib import Path

import pandas as pd

from src.notify.attack_mapping import map_cve

CONFIG_FILE = Path("config/notifications.json")
OUTBOX = Path("data/notifications/outbox")
KEV_LIVE_FILE = Path("data/live/kev_latest.csv")
KEV_RAW_FILE = Path("data/raw/cisa_kev/known_exploited_vulnerabilities.json")
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
SUMMARY_CHARS = 260
TIER_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# What each ATT&CK tactic means for a reader who is not a security specialist
TACTIC_PLAIN = {
    "Initial Access": "break into the system over the network",
    "Execution": "run malicious code on the device",
    "Privilege Escalation": "gain administrator rights",
    "Credential Access": "steal passwords or keys",
    "Collection": "read sensitive data",
    "Impact": "take the service down",
    "Defense Evasion": "get around security controls",
}


def load_config():
    return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))


# ==============================
# Recipients
# ==============================

def parse_recipients(text):
    return [part.strip() for part in re.split(r"[,;\s]+", text or "") if part.strip()]


def recipient_problems(recipients, config):
    problems = []
    if not recipients:
        problems.append("enter at least one email address")
    allowed = {d.lower() for d in config["allowed_domains"]}
    # Individually approved addresses outside those domains (e.g. a tester)
    approved = {a.lower() for a in config.get("allowed_addresses", [])}
    for address in recipients:
        if not EMAIL_PATTERN.match(address):
            problems.append(f"'{address}' is not a valid email address")
        elif address.lower() not in approved and address.split("@")[1].lower() not in allowed:
            problems.append(f"'{address}' is outside the allowed domains "
                            f"({', '.join(sorted(allowed))}) and not an approved address")
    return problems


# ==============================
# Which devices need a notice
# ==============================

def devices_needing_action(assets, actions, history, config):
    """Assets at a notify level, or with exploited/overdue fixes, plus last notice sent."""
    if actions.empty:
        return pd.DataFrame()
    per_asset = actions.groupby("asset_id").agg(
        actions=("action", "count"), exploited=("kev_fixed", "sum"),
        overdue=("urgency", lambda u: int((u == "OVERDUE").sum())),
        next_deadline=("deadline", "min"))
    table = assets.merge(per_asset, left_on="asset_id", right_index=True)
    table = table[table["exposure_level"].isin(config["notify_levels"])
                  | (table["exploited"] > 0) | (table["overdue"] > 0)]

    if history is not None and not history.empty:
        last = history.sort_values("sent_at").groupby("asset_id").last()
        table["last_notified"] = table["asset_id"].map(last["sent_at"]).str.slice(0, 16)
        table["notified_to"] = table["asset_id"].map(last["recipients"])
    else:
        table["last_notified"], table["notified_to"] = None, None

    table["status"] = table["last_notified"].map(lambda v: "Notified" if isinstance(v, str) else "Not notified")
    return table.sort_values(["status", "overdue", "exploited", "priority_score"],
                             ascending=[False, False, False, False])


# ==============================
# Vulnerability details for the email grid
# ==============================

def load_kev_details():
    """CISA KEV fields per CVE: ransomware use, short description, required action."""
    if KEV_LIVE_FILE.exists():
        kev = pd.read_csv(KEV_LIVE_FILE, dtype=str)
    else:
        raw = json.loads(KEV_RAW_FILE.read_text(encoding="utf-8"))["vulnerabilities"]
        kev = pd.DataFrame(raw).rename(columns={
            "cveID": "cve_id", "shortDescription": "short_description",
            "knownRansomwareCampaignUse": "known_ransomware_campaign_use", "dateAdded": "date_added"})
    return kev.set_index("cve_id")[["short_description", "known_ransomware_campaign_use"]]


def shorten(text, limit=SUMMARY_CHARS):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "..."


def vulnerability_details(actions, asset_cves, scoring, kev, limit):
    """
    One row per CVE fixed by the device's actions, most urgent first:
    actively exploited, then by predicted risk tier and probability, then CVSS.
    """
    fixes = actions.assign(cve_id=actions["fixed_cve_ids"].str.split(";")).explode("cve_id")
    fixes = fixes.drop_duplicates("cve_id")[["cve_id", "product", "installed_version", "target_version"]]

    info = scoring[scoring["cve_id"].isin(fixes["cve_id"])].drop_duplicates("cve_id").set_index("cve_id")
    matches = asset_cves.drop_duplicates("cve_id").set_index("cve_id")

    rows = []
    for fix in fixes.itertuples(index=False):
        cve = fix.cve_id
        m = matches.loc[cve] if cve in matches.index else None
        s = info.loc[cve] if cve in info.index else None
        k = kev.loc[cve] if cve in kev.index else None
        get = lambda source, key: (source[key] if source is not None and key in source
                                   and pd.notna(source[key]) else None)

        exploited = (m is not None and m["status"] == "Known exploited") or k is not None
        description = get(k, "short_description") or get(s, "description_clean") or ""
        tactic, technique, interim = map_cve(get(s, "cwe"), description,
                                             get(m, "attack_vector") or get(s, "attack_vector"),
                                             get(s, "user_interaction"))
        cvss = get(m, "cvss_score") or get(s, "cvss_score")
        severity = get(m, "cvss_severity") or get(s, "cvss_severity") or ""
        probability, tier = get(m, "probability"), get(m, "tier")
        ransomware = str(get(k, "known_ransomware_campaign_use") or "").lower() == "known"

        if exploited:
            kev_date = get(m, "kev_date_added")
            status = ("YES - actively exploited"
                      + (f" (CISA KEV, {pd.Timestamp(kev_date):%d %b %Y})" if kev_date is not None else
                         " (CISA KEV)") + ("; used in ransomware campaigns" if ransomware else ""))
            level = "exploited"
        elif probability is not None:
            status = f"Not yet - predicted {probability:.1%} chance within 12 months ({tier} risk tier)"
            level = "predicted" if tier in ("Critical", "High") else "low"
        else:
            status = "No known exploitation"
            level = "low"

        rows.append({
            "cve_id": cve, "cvss": float(cvss) if cvss is not None else None,
            "severity": str(severity).title(), "tactic": tactic, "technique": technique,
            "status": status, "level": level, "ransomware": ransomware,
            "summary": shorten(description),
            "fix": f"Upgrade {fix.product} from {fix.installed_version} to {fix.target_version} or later.",
            "interim": interim,
            "rank": (0 if exploited else 1, TIER_ORDER.get(tier, 4), -(probability or 0), -(cvss or 0)),
        })

    rows.sort(key=lambda r: r["rank"])
    return {"rows": rows[:limit], "total": len(rows),
            "exploited": sum(r["level"] == "exploited" for r in rows),
            "ransomware": sum(r["ransomware"] for r in rows)}


def overview(asset, actions, details):
    """A short plain-language paragraph about the device's situation."""
    products = ", ".join(sorted(actions["product"].unique()))
    first = details["rows"][0] if details["rows"] else None
    deadline = actions["deadline"].min()
    parts = [f"{asset['hostname']} ({asset['asset_type']}, {asset['ip_address']}) is rated "
             f"{asset['exposure_level']} risk. The updates below fix {details['total']} known "
             f"vulnerabilit{'ies' if details['total'] != 1 else 'y'} in {products}"]
    if details["exploited"]:
        parts[-1] += (f", and {details['exploited']} of them {'are' if details['exploited'] != 1 else 'is'} "
                      "already being used by attackers")
        if details["ransomware"]:
            parts[-1] += f" ({details['ransomware']} in ransomware campaigns)"
    parts[-1] += "."
    if first:
        parts.append(f"The most urgent is {first['cve_id']}"
                     + (f" (CVSS {first['cvss']:.1f})" if first["cvss"] is not None else "")
                     + f", which could let an attacker {TACTIC_PLAIN.get(first['tactic'], 'attack the device')}.")
    parts.append(f"Please apply the updates by {deadline}. If that is not possible, use the "
                 "interim mitigation listed for each vulnerability until the update is installed.")
    return " ".join(parts)


# ==============================
# Composing the message
# ==============================

def compose(asset, actions, sender, team, note="", containment=None, config=None, details=None,
            settings=None):
    """Subject, plain-text and HTML body for one device (details: vulnerability_details();
    settings: unsafe settings found on the device by the scan, src/asset_exposure/misconfig.py)."""
    config = config or load_config()
    settings = settings if settings is not None else pd.DataFrame(columns=["severity"])
    limit = config["max_cves_listed_per_action"]
    overdue = int((actions["urgency"] == "OVERDUE").sum())
    exploited = int(actions["kev_fixed"].sum())

    status = (f"{overdue} overdue" if overdue else
              f"{exploited} actively exploited" if exploited else f"{asset['exposure_level']} risk")
    total = len(actions) + len(settings)
    subject = (f"[Action required] {asset['hostname']}: {total} security "
               f"fix{'es' if total != 1 else ''} ({status})")

    # Unsafe settings: Critical ones come before the updates, the rest after
    due = {"Critical": 1, "High": 7, "Medium": 30, "Low": 90}
    today = pd.Timestamp.now().normalize()

    def setting_item(s):
        return {"action": f"Fix unsafe setting: {s.finding} (port {s.ports}). {s.fix}",
                "why": s.risk.rstrip("."), "ref": "", "ref_label": "",
                # The tracked fix-by date when known (the dashboard shows the same one)
                "deadline": getattr(s, "deadline", "") or
                            (today + pd.Timedelta(days=due.get(s.severity, 30))).strftime("%Y-%m-%d"),
                "overdue": False}

    first = [setting_item(s) for s in settings.itertuples(index=False) if s.severity == "Critical"]
    later = [setting_item(s) for s in settings.itertuples(index=False) if s.severity != "Critical"]
    items = list(first)
    for a in actions.itertuples(index=False):
        cves = a.fixed_cve_ids.split(";")
        shown = ", ".join(cves[:limit]) + (f" and {len(cves) - limit} more" if len(cves) > limit else "")
        why = (f"fixes {a.cves_fixed} known vulnerabilit{'ies' if a.cves_fixed != 1 else 'y'}"
               + (f", including {a.kev_fixed} actively exploited by attackers (CISA KEV)"
                  if a.kev_fixed else ""))
        items.append({"action": a.action, "why": why, "ref": shown, "ref_label": "CVEs",
                      "deadline": a.deadline, "overdue": a.urgency == "OVERDUE"})
    items += later
    for number, item in enumerate(items, start=1):
        item["n"] = number

    contain = [] if containment is None or containment.empty else containment["action"].head(2).tolist()
    summary = overview(asset, actions, details) if details and not actions.empty else None

    # ---- Plain text ----
    lines = [
        f"Hello {team},",
        "",
        f"The vulnerability prediction system rates {asset['hostname']} "
        f"({asset['asset_type']}, {asset['ip_address']}) as {asset['exposure_level']} risk.",
        "Your team owns this device and is responsible for applying the fixes below "
        "by their deadlines.",
        "",
    ]
    if summary:
        lines += ["SUMMARY", summary, ""]
    lines += ["WHAT TO DO (most important first)"]
    for item in items:
        lines += [f"{item['n']}. {item['action']}",
                  f"   Why: {item['why']}.",
                  *([f"   {item['ref_label']}: {item['ref']}"] if item["ref"] else []),
                  f"   Deadline: {item['deadline']}{'  (OVERDUE)' if item['overdue'] else ''}", ""]
    if details and details["rows"]:
        lines += [f"VULNERABILITY DETAILS (top {len(details['rows'])} of {details['total']})", ""]
        for r in details["rows"]:
            lines += [f"{r['cve_id']}  |  CVSS {r['cvss']:.1f} {r['severity']}" if r["cvss"] is not None
                      else f"{r['cve_id']}  |  CVSS not available",
                      f"   MITRE ATT&CK (estimated): {r['tactic']} - {r['technique']}",
                      f"   Exploitation: {r['status']}",
                      f"   Summary: {r['summary']}",
                      f"   Mitigation: {r['fix']} Until then: {r['interim']}", ""]
    if contain:
        lines += ["IF YOU CANNOT PATCH BEFORE THE DEADLINE", "Reduce the risk in the meantime:"]
        lines += [f" - {c}" for c in contain] + [""]
    if note.strip():
        lines += ["NOTE FROM THE SECURITY TEAM", note.strip(), ""]
    lines += [
        f"Full details (internal network, sign-in required): {config['dashboard_url']}",
        f"Questions: reply to this message or contact {sender['display_name']} ({sender.get('email') or 'security team'}).",
        "",
        "--",
        f"{config['sender_name']}",
        "Automated notice from the internal vulnerability management system. It never asks for "
        "passwords or sign-in codes and has no attachments. Do not forward outside the organisation.",
    ]
    text = "\n".join(lines)

    # ---- HTML ----
    esc = html.escape
    rows = "".join(
        f"<tr><td style='padding:10px;border-bottom:1px solid #e3e8e6;vertical-align:top;"
        f"font-weight:700'>{i['n']}</td><td style='padding:10px;border-bottom:1px solid #e3e8e6'>"
        f"<b>{esc(i['action'])}</b><br><span style='color:#4a5862'>Why: {esc(i['why'])}.</span>"
        + (f"<br><span style='color:#4a5862;font-size:12px'>{esc(i['ref_label'])}: {esc(i['ref'])}</span>"
           if i["ref"] else "") + "</td>"
        f"<td style='padding:10px;border-bottom:1px solid #e3e8e6;white-space:nowrap;vertical-align:top;"
        f"{'color:#b71c1c;font-weight:700' if i['overdue'] else ''}'>{esc(i['deadline'])}"
        f"{'<br>OVERDUE' if i['overdue'] else ''}</td></tr>" for i in items)
    contain_html = "" if not contain else (
        "<h3 style='font-size:15px;margin:22px 0 6px'>If you cannot patch before the deadline</h3>"
        "<ul style='margin:0;padding-left:20px'>" + "".join(f"<li>{esc(c)}</li>" for c in contain) + "</ul>")
    note_html = "" if not note.strip() else (
        "<h3 style='font-size:15px;margin:22px 0 6px'>Note from the security team</h3>"
        f"<p style='margin:0;white-space:pre-wrap'>{esc(note.strip())}</p>")
    level_colour = {"Critical": "#b71c1c", "High": "#d9480f", "Medium": "#d48806"}.get(
        asset["exposure_level"], "#4a5862")

    summary_html = "" if not summary else (
        "<div style='background:#f4f7fb;border-left:4px solid #1d6a85;padding:12px 14px;"
        f"margin:14px 0;border-radius:4px'><b>Summary</b><br>{esc(summary)}</div>")

    def cvss_badge(r):
        if r["cvss"] is None:
            return "<span style='color:#6b7075'>n/a</span>"
        colour = ("#7f1d1d" if r["cvss"] >= 9 else "#b71c1c" if r["cvss"] >= 7
                  else "#b45309" if r["cvss"] >= 4 else "#4a5862")
        return (f"<span style='display:inline-block;background:{colour};color:#ffffff;font-weight:700;"
                f"padding:3px 8px;border-radius:4px'>{r['cvss']:.1f}</span>"
                f"<br><span style='font-size:11px;color:#4a5862'>{esc(r['severity'])}</span>")

    def status_badge(r):
        colour, label = {"exploited": ("#b71c1c", "YES"), "predicted": ("#b45309", "NOT YET"),
                         "low": ("#4a5862", "NO")}[r["level"]]
        return (f"<span style='display:inline-block;background:{colour};color:#ffffff;font-weight:700;"
                f"padding:3px 8px;border-radius:4px;font-size:12px'>{label}</span>"
                f"<br><span style='font-size:11px;color:#4a5862'>"
                f"{esc(re.sub(r'^(YES|Not yet) - ', '', r['status']))}</span>")

    cell = "padding:8px;border:1px solid #d6dedb;vertical-align:top;font-size:13px"
    head = "padding:8px;border:1px solid #d6dedb;background:#10232b;color:#ffffff;text-align:left;font-size:12px"
    grid_html = "" if not details or not details["rows"] else (
        f"<h3 style='font-size:15px;margin:22px 0 6px'>Vulnerability details "
        f"(top {len(details['rows'])} of {details['total']}, most urgent first)</h3>"
        "<table style='border-collapse:collapse;width:100%'>"
        f"<tr><th style='{head}'>CVE ID</th><th style='{head}'>CVSS</th>"
        f"<th style='{head}'>MITRE ATT&amp;CK tactic</th><th style='{head}'>Exploited?</th>"
        f"<th style='{head}'>Summary</th><th style='{head}'>Mitigation</th></tr>"
        + "".join(
            f"<tr style='background:{'#fff5f5' if r['level'] == 'exploited' else '#ffffff'}'>"
            f"<td style='{cell};white-space:nowrap'><a href='https://nvd.nist.gov/vuln/detail/{esc(r['cve_id'])}' "
            f"style='color:#1d6a85;font-weight:700'>{esc(r['cve_id'])}</a></td>"
            f"<td style='{cell};text-align:center'>{cvss_badge(r)}</td>"
            f"<td style='{cell}'><b>{esc(r['tactic'])}</b><br>"
            f"<span style='font-size:11px;color:#4a5862'>{esc(r['technique'])}</span></td>"
            f"<td style='{cell}'>{status_badge(r)}</td>"
            f"<td style='{cell}'>{esc(r['summary'])}</td>"
            f"<td style='{cell}'><b>Fix:</b> {esc(r['fix'])}<br>"
            f"<span style='color:#4a5862'><b>Until then:</b> {esc(r['interim'])}</span></td></tr>"
            for r in details["rows"])
        + "</table><p style='font-size:11px;color:#6b7075;margin:6px 0 0'>CVSS from NIST NVD. "
          "Exploitation status from CISA KEV; \"Not yet\" shows this system's predicted chance of "
          "exploitation within 12 months. ATT&amp;CK tactics are estimated from the weakness type "
          "(CWE) and description."
        + (f" {details['total'] - len(details['rows'])} further vulnerabilities fixed by the same "
           "updates are listed in the dashboard." if details["total"] > len(details["rows"]) else "")
        + "</p>")

    html_body = f"""<div style="font-family:Segoe UI,Arial,sans-serif;color:#14232b;max-width:980px">
<div style="background:#10232b;color:#eef3f2;padding:16px 20px;border-radius:8px 8px 0 0">
<b>Security action required</b> · {esc(asset['hostname'])}</div>
<div style="border:1px solid #d6dedb;border-top:none;padding:18px 20px;border-radius:0 0 8px 8px">
<p>Hello {esc(team)},</p>
<p>The vulnerability prediction system rates <b>{esc(asset['hostname'])}</b>
({esc(str(asset['asset_type']))}, {esc(asset['ip_address'])}) as
<b style="color:{level_colour}">{esc(asset['exposure_level'])} risk</b>.
Your team owns this device and is <b>responsible for applying the fixes below by their deadlines</b>.</p>
{summary_html}
<h3 style="font-size:15px;margin:18px 0 6px">What to do (most important first)</h3>
<table style="border-collapse:collapse;width:100%;font-size:14px">
<tr style="background:#f1f5f4"><th style="padding:8px;text-align:left">#</th>
<th style="padding:8px;text-align:left">Action</th><th style="padding:8px;text-align:left">Deadline</th></tr>
{rows}</table>
{grid_html}
{contain_html}{note_html}
<p style="margin-top:22px">Full details (internal network, sign-in required):
<a href="{esc(config['dashboard_url'])}">{esc(config['dashboard_url'])}</a><br>
Questions: reply to this message or contact {esc(sender['display_name'])}.</p>
<p style="font-size:12px;color:#6b7075;border-top:1px solid #e3e8e6;padding-top:10px">
{esc(config['sender_name'])}. Automated notice from the internal vulnerability management system.
It never asks for passwords or sign-in codes and has no attachments.
Do not forward outside the organisation.</p></div></div>"""

    return {"subject": subject, "text": text, "html": html_body,
            "actions": total, "exploited": exploited}


# ==============================
# Sending
# ==============================

def deliver(message, recipients, sender, config=None):
    """Send by SMTP if configured, else save to the outbox (test mode)."""
    config = config or load_config()
    email = EmailMessage()
    email["Subject"] = message["subject"]
    from_address = os.environ.get("SMTP_USER") or sender.get("email") or "security@company.local"
    email["From"] = formataddr((config["sender_name"], from_address))
    email["To"] = ", ".join(recipients)
    if sender.get("email"):
        email["Reply-To"] = sender["email"]
    email["Message-ID"] = make_msgid(domain="threataware.local")
    email.set_content(message["text"])
    email.add_alternative(message["html"], subtype="html")

    host = os.environ.get("SMTP_HOST")
    if host:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=30) as smtp:
            smtp.starttls()
            if os.environ.get("SMTP_USER"):
                smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            smtp.send_message(email)
        return "sent", None

    OUTBOX.mkdir(parents=True, exist_ok=True)
    path = OUTBOX / f"{datetime.now():%Y%m%d-%H%M%S}-{re.sub(r'[^A-Za-z0-9-]', '_', message['subject'][:60])}.eml"
    path.write_bytes(bytes(email))
    return "saved (test mode)", str(path)
