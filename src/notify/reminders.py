"""
Automatic reminders for fixes that are still not applied.

A device's owning team is "responsible" once it has been sent a remediation
notice (dashboard: Send fix instructions / Notify teams). If, REMINDER_HOURS
after that notice, the fix record (src/remediation/tracker.py) still shows
fixes as Remaining for that device, the same recipients get a reminder. It
repeats every REMINDER_HOURS until a scan proves the fixes are applied.

  - no notice sent yet      -> no reminder (nobody has been asked yet)
  - fixes Completed by scan -> no reminder
  - recipients must still pass the email allow-list (config/notifications.json)

Reminders are logged in data/notifications/reminders.csv and the audit log.
Delivery uses the normal notifier: SMTP when configured, otherwise saved to
data/notifications/outbox/ (test mode).

Run from the project root (the scheduled task runs it every hour):
    python -m src.notify.reminders
    python -m src.notify.reminders --dry-run              # show what would be sent
    python -m src.notify.reminders --now "2026-10-19 09:00"  # pretend it is later (testing)
"""

import argparse
import html
from pathlib import Path

import pandas as pd

from src.notify.notifier import deliver, load_config, recipient_problems
from src.remediation.tracker import SETTING, load_all as load_fixes

REMINDER_LOG = Path("data/notifications/reminders.csv")
REMINDER_HOURS = 24
LOG_COLUMNS = ["sent_at", "network", "asset_id", "hostname", "ip_address", "recipients",
               "open_fixes", "overdue", "delivery", "message_file"]


def notice_matches(lab, network):
    """Notices are stored per scan; the fix record per network (all lab scans = 'lab')."""
    lab = str(lab or "")
    return lab.startswith("scan:scan-") if network == "lab" else lab == f"scan:{network}"


def load_log():
    if REMINDER_LOG.exists():
        return pd.read_csv(REMINDER_LOG, dtype=str, keep_default_na=False)
    return pd.DataFrame(columns=LOG_COLUMNS)


def due_reminders(now, hours=REMINDER_HOURS, notices=None):
    """One entry per device whose notified fixes are still open after `hours`."""
    from src.auth.store import list_notifications

    fixes = load_fixes()
    open_fixes = fixes[fixes["status"] == "Remaining"]
    notices = list_notifications() if notices is None else notices
    if open_fixes.empty or notices.empty:
        return []
    notices = notices.assign(sent=pd.to_datetime(notices["sent_at"], utc=True))
    log = load_log()
    log_times = pd.to_datetime(log["sent_at"], utc=True) if not log.empty else pd.Series(dtype="datetime64[ns, UTC]")

    due = []
    for (network, ip), group in open_fixes.groupby(["network", "ip_address"]):
        first = group.iloc[0]
        mine = notices[notices["lab"].map(lambda lab: notice_matches(lab, network))
                       & ((notices["asset_id"] == first["asset_id"]) | (notices["hostname"] == first["hostname"]))]
        if mine.empty:
            continue                                         # team not asked yet: nothing to remind
        latest = mine.sort_values("sent").iloc[-1]
        reminded = log_times[(log["network"] == network) & (log["ip_address"] == ip)] if not log.empty else log_times
        since = max([latest["sent"]] + list(reminded))
        if now - since < pd.Timedelta(hours=hours):
            continue
        due.append({"network": network, "fixes": group, "notice": latest, "since": since})
    return due


def compose_reminder(item, now, config):
    fixes, notice = item["fixes"], item["notice"]
    host = notice["hostname"] or fixes.iloc[0]["hostname"]
    today = now.tz_convert(None).normalize()
    overdue = int((pd.to_datetime(fixes["deadline"], errors="coerce") < today).sum())
    subject = (f"[Reminder] {host}: {len(fixes)} security fix{'es' if len(fixes) != 1 else ''} "
               f"still open" + (f" ({overdue} overdue)" if overdue else ""))
    sent_on = notice["sent"].tz_convert(None).strftime("%d %b %Y %H:%M")
    checked = fixes["last_checked"].max()

    lines = [f"Hello {notice['team'] or 'team'},", "",
             f"On {sent_on} (UTC) your team was asked to apply security fixes on {host}. "
             f"The latest network scan ({checked}) shows these are still needed:", ""]
    esc = html.escape
    rows = []
    for f in fixes.itertuples(index=False):
        late = pd.to_datetime(f.deadline, errors="coerce")
        flag = " (OVERDUE)" if pd.notna(late) and late < today else ""
        if f.kind == "setting":                          # unsafe setting found by the scan
            name = f.product.removeprefix(SETTING)
            lines.append(f" - Fix unsafe setting: {f.fix_step} Deadline: {f.deadline}{flag}")
            rows.append((name, esc(str(f.fix_step)), f.deadline, bool(flag)))
        else:
            lines.append(f" - Upgrade {f.product} from {f.current_version} to {f.target_version} or later. "
                         f"Deadline: {f.deadline}{flag}")
            rows.append((f.product, f"{esc(str(f.current_version))} → <b>{esc(str(f.target_version))}</b> "
                                    "or later", f.deadline, bool(flag)))
    lines += ["", "Please apply them, or reply if you need help or an exception. Once installed, the "
              "next network scan confirms it automatically and the reminders stop.", "",
              "--", config["sender_name"],
              "Automated reminder. It never asks for passwords or sign-in codes and has no attachments."]

    table = "".join(
        f"<tr><td style='padding:6px 10px;border:1px solid #d6dedb'><b>{esc(p)}</b></td>"
        f"<td style='padding:6px 10px;border:1px solid #d6dedb'>{todo}</td>"
        f"<td style='padding:6px 10px;border:1px solid #d6dedb;{'color:#b71c1c;font-weight:700' if late else ''}'>"
        f"{esc(str(d))}{' OVERDUE' if late else ''}</td></tr>" for p, todo, d, late in rows)
    html_body = f"""<div style="font-family:Segoe UI,Arial,sans-serif;color:#14232b;max-width:720px">
<div style="background:#b45309;color:#ffffff;padding:14px 18px;border-radius:8px 8px 0 0">
<b>Reminder: security fixes still open</b> · {esc(host)}</div>
<div style="border:1px solid #d6dedb;border-top:none;padding:16px 18px;border-radius:0 0 8px 8px">
<p>Hello {esc(str(notice['team'] or 'team'))},</p>
<p>On <b>{sent_on} (UTC)</b> your team was asked to apply security fixes on <b>{esc(host)}</b>.
The latest network scan (<b>{esc(str(checked))}</b>) shows these are <b>still needed</b>:</p>
<table style="border-collapse:collapse;width:100%;font-size:14px">
<tr style="background:#f1f5f4"><th style="padding:6px 10px;text-align:left">Software or setting</th>
<th style="padding:6px 10px;text-align:left">What to do</th><th style="padding:6px 10px;text-align:left">Deadline</th></tr>
{table}</table>
<p>Please apply them, or reply if you need help or an exception. Once installed, the next network
scan confirms it automatically and the reminders stop.</p>
<p style="font-size:12px;color:#6b7075;border-top:1px solid #e3e8e6;padding-top:8px">
{esc(config['sender_name'])}. Automated reminder. It never asks for passwords or sign-in codes
and has no attachments.</p></div></div>"""
    return {"subject": subject, "text": "\n".join(lines), "html": html_body,
            "overdue": overdue, "hostname": host}


def run(now=None, dry_run=False):
    config = load_config()
    hours = int(config.get("reminder_after_hours", REMINDER_HOURS))
    now = pd.Timestamp.now(tz="UTC") if now is None else pd.Timestamp(now, tz="UTC")
    sent = []
    for item in due_reminders(now, hours):
        message = compose_reminder(item, now, config)
        recipients = [r.strip() for r in str(item["notice"]["recipients"]).split(",") if r.strip()]
        problems = recipient_problems(recipients, config)
        label = f"{message['hostname']} -> {', '.join(recipients)}: {message['subject']}"
        if problems:
            print(f"SKIPPED {label} ({'; '.join(problems)})")
            continue
        if dry_run:
            print(f"WOULD SEND {label}")
            continue
        delivery, file = deliver(message, recipients, {"display_name": "Automated reminder", "email": ""},
                                 config)
        fixes = item["fixes"]
        record = {"sent_at": now.isoformat(), "network": item["network"],
                  "asset_id": fixes.iloc[0]["asset_id"], "hostname": message["hostname"],
                  "ip_address": fixes.iloc[0]["ip_address"], "recipients": ", ".join(recipients),
                  "open_fixes": len(fixes), "overdue": message["overdue"], "delivery": delivery,
                  "message_file": file or ""}
        REMINDER_LOG.parent.mkdir(parents=True, exist_ok=True)
        pd.concat([load_log(), pd.DataFrame([record])], ignore_index=True)[LOG_COLUMNS] \
            .to_csv(REMINDER_LOG, index=False)
        try:
            from src.auth.store import audit
            audit("reminder_sent", "reminder-service", "system", f"{label} ({delivery})")
        except Exception:
            pass
        print(f"SENT {label} ({delivery})")
        sent.append(record)
    if not sent and not dry_run:
        print(f"{now:%Y-%m-%d %H:%M} UTC: no reminders due")
    return sent


def main():
    parser = argparse.ArgumentParser(description="Remind teams about fixes still open")
    parser.add_argument("--now", help="pretend the current time is this (UTC), for testing")
    parser.add_argument("--dry-run", action="store_true", help="show reminders without sending")
    args = parser.parse_args()
    run(args.now, args.dry_run)


if __name__ == "__main__":
    main()
