"""
Network watcher: detects devices joining or leaving the network.

Every check is a quick discovery sweep (which hosts are up; no service
scan), a few seconds for the lab range:
  - a NEW device (not seen before)   -> "new device" event, then a full
                                        service and version scan of the hosts
                                        that are up, saved like any other scan
                                        so the dashboard can assess it
  - a device missing for MISSED_LIMIT checks in a row (rebooting or asleep
    devices are not reported at once) -> "device removed" event
  - a removed device that returns    -> "device back" event
  - a new device that is NOT in the company asset list (data/raw/assets.csv
    plus the lab inventory) -> "unknown device" event and an alert email to
    the security team, also each time it returns after being removed
    (security_team_email in config/notifications.json;
    saved to the outbox in test mode). Unknown devices are a common way in
    for attackers (rogue devices, shadow IT)

State and events are kept in data/lab/watch_state.json and
data/lab/watch_events.csv; every event also goes to the audit log.
Only targets inside the approved scan ranges (config/scan_targets.json) are
watched, using the same safety checks as the dashboard's scan.

Run from the project root:
    python -m src.asset_discovery.asset_watcher              # watch forever (every 30 s)
    python -m src.asset_discovery.asset_watcher --checks 2   # 2 checks, 30 s apart (scheduled task)
"""

import argparse
import json
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import html

import pandas as pd

from src.asset_discovery.run_nmap import (
    PROFILES, find_nmap, load_config, parse_targets, run_scan, target_problems,
)

STATE_FILE = Path("data/lab/watch_state.json")
EVENTS_FILE = Path("data/lab/watch_events.csv")
INTERVAL_SECONDS = 30
MISSED_LIMIT = 3
EVENT_COLUMNS = ["time", "event", "ip_address", "detail"]
ASSET_LIST = Path("data/raw/assets.csv")


def known_addresses(config):
    """IP addresses in the company asset list (plus the lab inventory)."""
    files = [ASSET_LIST, Path(config.get("lab_inventory", ""))]
    return {ip for f in files if f.is_file() for ip in pd.read_csv(f)["ip_address"].astype(str)}


def alert_security_team(ips, scan_name):
    """Email the security team about devices that are not in the asset list.
    Returns a short delivery note (best effort: never stops the watcher)."""
    from src.notify.notifier import deliver, load_config as load_notify_config, recipient_problems

    config = load_notify_config()
    recipients = [r.strip() for r in str(config.get("security_team_email", "")).split(",") if r.strip()]
    if not recipients:
        return "no alert sent: set security_team_email in config/notifications.json"
    problems = recipient_problems(recipients, config)
    if problems:
        return "no alert sent: " + "; ".join(problems)

    listed = ", ".join(ips)
    subject = f"[Security alert] Unknown device on the network: {listed}"
    steps = ["Find out who connected it (switch port, Wi-Fi log, DHCP lease).",
             "If nobody approved it, disconnect it or move it to a quarantine network.",
             "If it is approved, add it to the asset list so it is assessed and monitored."]
    text = "\n".join([
        "Security team,", "",
        f"The network watcher found {len(ips)} device(s) that are not in the company asset list: {listed}.",
        f"Detected at {now()}. A full scan was started automatically" + (f" ({scan_name})." if scan_name else "."),
        "", "What to do:"] + [f" {n}. {s}" for n, s in enumerate(steps, start=1)] + [
        "", "Results are in the dashboard (Scan & fix, Discover step).", "", "--", config["sender_name"],
        "Automated alert. It never asks for passwords or sign-in codes and has no attachments."])
    body = f"""<div style="font-family:Segoe UI,Arial,sans-serif;color:#14232b;max-width:720px">
<div style="background:#b71c1c;color:#ffffff;padding:14px 18px;border-radius:8px 8px 0 0">
<b>Security alert: unknown device on the network</b></div>
<div style="border:1px solid #d6dedb;border-top:none;padding:16px 18px;border-radius:0 0 8px 8px">
<p>The network watcher found <b>{len(ips)} device(s) not in the company asset list</b>:
<b>{html.escape(listed)}</b>, detected at {now()}. A full scan was started automatically.</p>
<p><b>What to do</b></p><ol>{"".join(f"<li>{html.escape(s)}</li>" for s in steps)}</ol>
<p>Results are in the dashboard (Scan &amp; fix, Discover step).</p>
<p style="font-size:12px;color:#6b7075;border-top:1px solid #e3e8e6;padding-top:8px">
{html.escape(config['sender_name'])}. Automated alert. It never asks for passwords or sign-in codes
and has no attachments.</p></div></div>"""
    try:
        delivery, _ = deliver({"subject": subject, "text": text, "html": body}, recipients,
                              {"display_name": "Network watcher", "email": ""}, config)
    except Exception as error:                      # mail server unreachable: keep watching
        return f"alert failed: {error}"
    return f"security team alerted ({delivery})"


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def discover(targets, config):
    """IP addresses that are up right now (quick sweep, no service scan)."""
    problems = target_problems(targets, config)
    if problems:
        raise ValueError("; ".join(problems))
    tokens, _ = parse_targets(targets)
    out = Path(config["output_dir"]) / "_watch_discovery.xml"
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([find_nmap(config), *PROFILES["discovery"], "-oX", str(out), *tokens],
                   capture_output=True, text=True, timeout=120)
    root = ET.parse(out).getroot()
    return sorted(h.find("address[@addrtype='ipv4']").get("addr") for h in root.findall("host")
                  if h.find("status").get("state") == "up")


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"devices": {}, "last_check": None, "baseline": False}


def record(events, kind, ip, detail):
    events.append({"time": now(), "event": kind, "ip_address": ip, "detail": detail})
    print(f"[{events[-1]['time']}] {kind}: {ip} {detail}")


def save(state, events):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    if events:
        new = pd.DataFrame(events, columns=EVENT_COLUMNS)
        old = pd.read_csv(EVENTS_FILE) if EVENTS_FILE.exists() else pd.DataFrame(columns=EVENT_COLUMNS)
        pd.concat([old, new], ignore_index=True).tail(500).to_csv(EVENTS_FILE, index=False)
        try:                                   # audit trail (best effort: auth DB may be absent)
            from src.auth.store import audit
            for e in events:
                audit(f"watch_{e['event'].replace(' ', '_')}", "asset-watcher", "system",
                      f"{e['ip_address']}: {e['detail']}")
        except Exception:
            pass


def check(config, targets):
    """One discovery sweep; returns the events it produced."""
    state, events = load_state(), []
    up = set(discover(targets, config))
    devices = state["devices"]

    for ip in sorted(up):
        device = devices.get(ip)
        if device is None:
            devices[ip] = {"first_seen": now(), "last_seen": now(), "missed": 0, "status": "online"}
            if state["baseline"]:                       # the first sweep only records what exists
                record(events, "new device", ip, "joined the network")
        else:
            if device["status"] == "removed":
                record(events, "device back", ip, "seen again on the network")
            device.update(last_seen=now(), missed=0, status="online")

    for ip, device in devices.items():
        if ip in up or device["status"] == "removed":
            continue
        device["missed"] += 1
        if device["missed"] >= MISSED_LIMIT:
            device["status"] = "removed"
            record(events, "device removed", ip, f"not seen for {MISSED_LIMIT} checks in a row")

    if not state["baseline"]:
        record(events, "baseline", ",".join(sorted(up)), f"{len(up)} devices online")
        state["baseline"] = True
    state.update(last_check=now(), online=len(up), interval_seconds=INTERVAL_SECONDS, targets=targets)

    # New devices are assessed straight away: full scan of the hosts that are up.
    # An unregistered device that comes back is treated like a new one again.
    known = known_addresses(config)
    new = [e["ip_address"] for e in events if e["event"] == "new device"
           or (e["event"] == "device back" and e["ip_address"] not in known)]
    scan_name = ""
    if new and up:
        try:
            path, summary = run_scan(" ".join(sorted(up)), "full", config)
            record(events, "scanned", ",".join(summary["hosts_up"]),
                   f"{summary['open_services']} services, saved as {path.name}")
            state["last_scan"] = scan_name = path.name
        except (ValueError, RuntimeError) as error:
            record(events, "scan failed", "", str(error))

    # New devices that nobody registered: alert the security team
    unknown = [ip for ip in new if ip not in known]
    if unknown:
        note = alert_security_team(unknown, scan_name)
        for ip in unknown:
            record(events, "unknown device", ip, f"not in the asset list; {note}")

    save(state, events)
    return events


def main():
    parser = argparse.ArgumentParser(description="Detect devices joining or leaving the network")
    parser.add_argument("--checks", type=int, default=0, help="number of checks (0 = forever)")
    parser.add_argument("--interval", type=int, default=INTERVAL_SECONDS, help="seconds between checks")
    args = parser.parse_args()

    config = load_config()
    targets = config.get("watch_targets", config["default_target"])
    done = 0
    while True:
        started = time.time()
        try:
            check(config, targets)
        except Exception as error:                  # keep watching after a failed sweep
            print(f"[{now()}] check failed: {error}")
        done += 1
        if args.checks and done >= args.checks:
            break
        time.sleep(max(0, args.interval - (time.time() - started)))


if __name__ == "__main__":
    main()
