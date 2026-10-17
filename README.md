# Threat-Aware Digital Asset Exposure Prediction System

Predicts which vulnerabilities, and therefore which assets, are likely to
become actively exploited (added to CISA KEV) within 12 months of CVE
publication, using only information available at publication time.

## Quick start

```powershell
python run_pipeline.py                 # all steps, raw data -> results (~35 min)
streamlit run src\dashboard\app.py     # dashboard at http://localhost:8501
```

## Setup

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Pipeline (run from the project root, in order)

| Step | Command | Output |
|---|---|---|
| 1. Extract NVD (all yearly feeds) | `python src\data_collection\extract_nvd.py` | `data/processed/nvd_clean.csv` |
| 2. Extract NVD version ranges | `python -m src.data_collection.extract_cpe_matches` | `data/processed/nvd_cpe_matches.csv.gz` |
| 3. Integrate CISA KEV | `python src\data_collection\integrate_nvd_kev.py` | `data/processed/nvd_kev_integrated.csv` |
| 4. Temporal labels (`future_kev`) | `python src\data_preprocessing\create_prediction_dataset.py` | `data/processed/prediction_dataset.csv` |
| 5. Features (training + scoring) | `python src\features\build_features.py` | `data/processed/features.csv`, `scoring_features.csv` |
| 6. Train and evaluate models | `python -m src.models.train_models` | `results/metrics.csv`, `results/models/` |
| 7. Explainability (SHAP) | `python -m src.explainability.explain_model` | `results/explainability/` |
| 8. Calibration and risk tiers | `python -m src.models.calibrate` | `results/models/risk_model.joblib`, `results/calibration/` |
| 8b. Prediction drift monitoring | `python -m src.models.monitor_drift` | `results/monitoring/` |
| 9. Asset exposure from a scan | `python -m src.asset_exposure.assess_exposure scan.xml` | `results/assets/` |
| 10. Build synthetic lab database | `python -m src.lab.build_lab_db` | `data/lab/lab_environment.db` |
| 11. Asset-level backtest | `python -m src.lab.backtest` | `results/lab/` |
| 11b. Attack-path scenarios | `python -m src.attack_paths.attack_graph` | `results/attack_paths/` |
| 12. Dashboard | `streamlit run src\dashboard\app.py` | http://localhost:8501 |

## Sample lab environment (synthetic)

Until the VMware lab exists, `data/lab/lab_environment.db` (SQLite) holds a
**synthetic** organisation of 30 assets (DMZ, servers, workstations,
management) in two snapshots: `backtest` (2025-08-27) and `current`
(2026-10-03). Each asset has a patch-hygiene profile (current / typical /
lagging / neglected = 30 / 120 / 270 / 540 days behind); installed versions
are the real NVD fix versions as of that patch date. Real Nmap scans use the
same assessment pipeline.

Raw inputs: NVD JSON 2.0 feeds in `data/raw/nvd/raw/`, the CISA KEV JSON in
`data/raw/cisa_kev/`, and the asset inventory `data/raw/assets.csv`.

## Attack paths (blast radius)

Given a starting point (a compromised device, every host running a given
software product, or an internet attacker), the attack graph shows which
assets and subnets can be reached and the most likely route to each. Edges
come from firewall rules between subnets (exploiting a network-reachable
vulnerability: 1.0 if known exploited, otherwise the model's probability)
and from trust links (stored credentials, domain admin rights, backups).
Each candidate fix is tested by re-running the analysis without it. The
synthetic lab's firewall rules, trust links and crown jewels are design
assumptions stored in `data/lab/lab_environment.db`.

## Users, roles and MFA

The dashboard requires sign-in with a password and a time-based one-time code
(TOTP, RFC 6238) from an authenticator app (Microsoft/Google Authenticator,
Authy). New accounts get a temporary password; at first sign-in the user must
choose a new password and enrol their authenticator by scanning a QR code.

| Role | Can do |
|---|---|
| Administrator | Manage users and roles, upload scans, view the audit log |
| Security Manager | Everything analytical, accept risk, view the audit log |
| Security Analyst | Everything analytical, upload scans, reload data |
| Asset Owner | Only the assets owned by their team (no network-wide views) |
| Auditor | Read-only access to everything, including the audit log |

Security controls: scrypt password hashing, password policy, lockout after
5 failures (15 minutes), MFA code replay protection, 30-minute idle timeout,
role-based tabs that are never built for roles without access, and a
SHA-256 hash-chained audit log verified in the Administration tab.

```powershell
python -m src.auth.manage_users init-demo          # demo accounts + team ownership
python -m src.auth.manage_users create USER --role analyst --name "Full Name"
python -m src.auth.manage_users reset-password USER   # also: reset-mfa, unlock, list
```

## Notifying owning teams

The **Notifications** tab lists devices at Critical/High exposure or with
exploited/overdue fixes, and whether their owning team has been told. A
Security Analyst or Manager picks a device; the team email is pre-filled from
asset ownership (and can be remembered), a personal note can be added, and the
full message is previewed before sending. The email states what to fix (the
remediation plan's actions, CVE IDs, deadlines), that the owning team is
responsible for the fixes, and containment steps the team can take on its own
device or zone. The system informs; it does not verify fixes.

Channel security: recipients must be in an allowed domain
(`config/notifications.json`), no attachments, a fixed sender and an explicit
"never asks for passwords" line, STARTTLS for SMTP, and every notice is recorded
in the notice history and the audit log. Without SMTP settings the dashboard
runs in **test mode** and saves each message as an `.eml` file in
`data/notifications/outbox/` (open it with Outlook or any mail program).

## Remediation planner

`src/remediation/planner.py` turns predictions into a ranked patch plan. For each
asset and product it finds the fix version from NVD's "vulnerable before X" ranges,
counts the CVEs (and exploited CVEs) one upgrade removes, and measures the effect
with an "open doors" model: each vulnerable product is a door into the asset (1.0
if it has a known exploited CVE, otherwise its predicted exploitation probability),
weighted by business importance. Deadlines come from CISA KEV due dates, otherwise
from a tier-based policy (`SLA_DAYS`). The dashboard's **Remediation** tab shows the
best N fixes for a chosen workload with a risk-reduction curve and a CSV export;
each asset page lists its recommended upgrades and, for the lab, containment options
from the attack-path analysis.

```powershell
python -m src.remediation.planner      # example plan for the synthetic lab
```

## Dashboard workflow (Scan & fix)

The main page is a guided 5-step workflow:

1. **Discover**: Nmap scan of the lab (or a demo organisation); devices, open ports, software.
2. **Importance**: NIST FIPS 199 rating per device: impact on confidentiality, integrity
   and availability (Low/Medium/High), importance = the highest of the three
   (high-water mark); defaults by device type (`DEFAULT_RULES` in
   `src/asset_exposure/importance.py`), saved per network in `data/asset_importance.csv`.
   A sensitivity check (`python -m src.evaluation.weight_sensitivity`) re-ranks devices
   under 95 alternative weight settings: the most urgent device and the top 3/5 never
   changed on any network (Spearman 0.98-1.00).
3. **Fix first**: devices ranked by chance of attack × importance × exposure, with the
   updates to install, interim mitigations, the vulnerability grid and the email to the team.
4. **Attack spread**: lateral-movement map from a hacked device or an internet attacker
   (`src/attack_paths/scan_topology.py` derives zones per /24 subnet, assumes a flat
   internal network, internet access to internet-facing devices only, plus optional trust
   links such as `config/virtualbox_lab/trust_links.csv`).
5. **Compare**: the usual CVSS-sorted device list next to ours, where and why they differ,
   and the 2025 evidence.

## Our plan vs the usual plans (comparison page)

`python -m src.evaluation.plan_comparison` builds `results/benchmark/capture_curve.csv`:
on the 2025 test year (19,944 CVEs with EPSS scores, 98 later exploited), the share of
exploited CVEs found when reviewing the top X% ranked by the model, EPSS, CVSS or at
random (top 5%: model 43.9%, EPSS 39.8%, CVSS 16.3%; EPSS is ahead at 1-3%). The
dashboard page **Our plan vs usual plans** also orders the same upgrade actions of the
network being viewed three ways (our planner, highest CVSS first, most critical device
first) and compares how many devices remain exposed to an actively exploited weakness
after each fix, plus the 12-month asset backtest.

## Model monitoring and retraining (champion/challenger)

`python -m src.models.monitor_drift` compares expected and actual KEV additions per
half-year; for recent periods the expectation covers only the follow-up time that has
passed. `python -m src.models.retrain_operational` (every 6 months) trains a
**challenger** with the research model's settings on the newest labelled data (train to
the latest 12 labelled months, calibrate on those), then tests both models on CVEs
published after the labelled data, which neither has seen. The challenger replaces the
live model only if it wins on PR-AUC **and** recall in the top 1%; the decision and its
evidence go to `results/models/active_model.json`. Live scoring (dashboard, live sync)
uses the active model; research results, the EPSS benchmark and the backtest always use
the frozen research model.

Latest review (Oct 2026): the challenger lost on both primary metrics (PR-AUC 0.021 vs
0.025, top-1% recall 6.6% vs 12.5%), so the research model stays live. The 2026
over-prediction (about 1.4x in 2026 H1) comes mainly from NVD's analysis backlog: only
35% of 2026 H2 CVEs were analysed, mostly from major vendors.

## Live monitoring (continuous sync and alerts)

`python -m src.sync.live_sync` checks the CISA KEV feed and the NVD CVE API 2.0
for anything new or changed since the last run, builds features for those CVEs
exactly as in training, scores them with the trained model, assesses the
monitored assets (`config/live_sync.json`) as of today and raises alerts:

| Level | When |
|---|---|
| URGENT | A CVE newly added to CISA KEV affects an asset (deadline from the KEV entry) |
| WARNING | A new or changed CVE in the Critical risk tier affects an asset |
| INFO | The model is older than 90 days and should be retrained |

Live data is stored in `data/live/` only; the research datasets in
`data/processed/` stay frozen so the evaluation remains reproducible. The
dashboard combines both and shows the results in the **Live feed** tab.

Optional settings (environment variables, all free):

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Free NVD API key: faster sync (50 instead of 5 requests per 30 s) |
| `ALERT_WEBHOOK_URL` | Teams, Slack or Discord incoming webhook for alerts |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_EMAIL_TO` | Email alerts (e.g. Gmail with an app password) |

Run it automatically every 6 hours (Windows Task Scheduler):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\register_live_sync_task.ps1
```

## Demo scans and scan sheets (no lab needed)

`python -m src.lab.make_demo_scans` writes three **simulated** scan sheets for three
**fictional** IT companies to `data/demo_scans/`: Zentrova Systems (20 hosts,
neglected patching), Kyvora Cloud Services (14 hosts, mixed patch levels) and
Quantelix Data Solutions (18 hosts, fully patched). The names are invented. Versions are real NVD fix versions for
each host's patch level, as in the synthetic lab. In the dashboard choose
**Scan upload** in the sidebar, then pick a demo scan or upload your own file:

- **Scan sheet (.csv):** one row per discovered service, with the asset's
  criticality and internet exposure (`scan_sheet_template.csv`, also downloadable
  from the sidebar). Validated on upload: required columns, IPv4 addresses, CPE
  format, one scan date, 2 MB / 5,000 rows, and no cells starting with `= + - @`
  (spreadsheet formula injection).
- **Nmap XML (.xml):** real `nmap -sV -oX` output, matched to `data/raw/assets.csv`.

Both go through the same assessment, predictions and remediation planner.

**Patch-level inference.** NVD often lists a product as affected in "all versions"
(no range), especially older Windows CVEs, which would flag fully patched hosts.
The matcher infers each installed version's patch level from the newest CVE it
already fixes; an all-versions CVE published before that date is labelled
`patched (inferred)` and is not counted as confirmed exposure.

## VirtualBox lab and live Nmap scans (demonstration)

A lightweight, CLI-only lab for live scans on an 8 GB PC: Metasploitable 2
(192.168.56.101, old services with CISA KEV CVEs) and Alpine Linux with Docker
(192.168.56.102: Apache httpd 2.4.62, Tomcat 9.0.98, Redis 7.2.4, whose recent CVEs the
model scores), optionally an Alpine workstation (.103), on an isolated host-only network.
Nmap runs on Windows. Guide: [docs/VIRTUALBOX_LAB_GUIDE.md](docs/VIRTUALBOX_LAB_GUIDE.md).

```powershell
powershell -ExecutionPolicy Bypass -File scripts\lab\create_lab.ps1 -MetasploitableVmdk <vmdk> -AlpineIso <iso>
powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 start|stop|status|console|isolate|internet|eject
python -m src.asset_discovery.run_nmap 192.168.56.101-103
```

In the dashboard, **Scan the network** runs the same scan (`src/asset_discovery/run_nmap.py`):
only targets inside `config/scan_targets.json` (`192.168.56.0/24`, `127.0.0.1`) are
allowed, Nmap is started without a shell (unprivileged TCP connect scan with version
detection, time limit), every scan is audit-logged, and results are saved in
`data/lab/scans/` and listed under *Scan upload*. Lab hosts are described in
`config/virtualbox_lab/inventory.csv`.

## Fix tracking (completed vs remaining, verified by rescans)

`src/remediation/tracker.py` remembers every upgrade the planner recommends, per network
(`data/remediation_tracker.csv`), and checks each newer scan: **Completed** when the scan
reads a version that is no longer vulnerable (or the service is gone), **Remaining** when the
vulnerable version is still there, **Not verified** when the device was not scanned or its
version could not be read. A fix is never marked done without a scan proving it; a completed
fix is reopened if a later scan shows the problem again, and older scans never change the
record. The Fix first step shows "Fixes completed: X of Y", done/remaining per device and the
verified fixes (e.g. Apache Tomcat 9.0.98 → 9.0.123 on app-srv-01, verified by rescan).

## Network watch (devices joining or leaving)

`src/asset_discovery/asset_watcher.py` runs a quick discovery sweep (hosts up, no service
scan; about 10 s) of `watch_targets` in `config/scan_targets.json` every 30 seconds:

- a **new device** is reported and a full service/version scan of the hosts that are up
  starts automatically (about 1 minute), saved in `data/lab/scans/` for the dashboard;
- a device **missing for 3 checks in a row** (about 90 s) is reported as removed, so
  reboots do not raise false alarms; a removed device that returns is reported as back.

Events go to `data/lab/watch_events.csv` and the audit log; the dashboard's Discover step
shows the last check and recent events. The Windows task "ThreatAware Asset Watcher"
(`scripts\register_asset_watcher_task.ps1`) starts every minute and runs two checks 30 s
apart. Instant detection (DHCP/ARP listening, 802.1X, endpoint agents) is future work.

## Unsafe settings, ransomware warnings and unknown devices

- **Unsafe settings (misconfigurations).** The live scan also runs safe, read-only Nmap check
  scripts (`src/asset_exposure/misconfig.py`): open backdoor shells, databases or Redis without
  a password, anonymous FTP, Telnet and rsh/rexec/rlogin, SMBv1, NFS shares open to everyone,
  VNC/X11 without a password, expired certificates, outdated TLS and SSHv1. Each finding has a
  severity, the risk in plain words and the fix. They appear in the Fix first step, in the
  team email, and in the fix tracker (Completed once a rescan no longer finds them).
- **Ransomware warning.** Vulnerabilities that CISA KEV marks as used in ransomware campaigns
  are tagged on the device, in the update list and in the weakness table. Ransomware use breaks
  ties between equally urgent devices; the priority scores themselves are unchanged.
- **Unknown device alert.** When the network watcher sees a new device that is not in the asset
  list, it records an "unknown device" event and emails the security team
  (`security_team_email` in `config/notifications.json`). The Discover step shows a red banner
  and an "In asset list?" column.

## Automatic fix reminders

If a device's team was sent fix instructions and, 24 hours later, the latest scan still
shows fixes as Remaining, the same recipients get a reminder email listing the open fixes
and deadlines (overdue ones marked). It repeats every 24 hours until a scan proves the fixes
are applied. No reminder is sent before a team has been notified. The Windows task
"ThreatAware Fix Reminders" (`scripts\register_fix_reminders_task.ps1`) checks every hour;
reminders are logged in `data/notifications/reminders.csv` and the audit log. The delay is
`reminder_after_hours` in `config/notifications.json`. Test with
`python -m src.notify.reminders --dry-run` or `--now "YYYY-MM-DD HH:MM"`.

## VMware lab (real scans, optional)

Build guide: [docs/VMWARE_LAB_GUIDE.md](docs/VMWARE_LAB_GUIDE.md). Lab layout,
firewall rules, trust links and extra software versions live in
`config/vmware_lab/`. Import scans with:

```powershell
python -m src.lab.import_scans --scans "data/lab/scans/*.xml" --snapshot scan-YYYY-MM-DD
```

This writes `data/lab/vmware_lab.db`, selectable in the dashboard sidebar.

## Scanning the lab

```bash
nmap -sV -oX scan.xml <lab subnet>
```

`-sV` (service version detection) is required: CVEs are matched to assets by
product and installed version. Hosts are joined to the inventory by IP address.
`tests/fixtures/sample_nmap_scan.xml` is a hand-written sample in Nmap's
format, used until real lab scans exist.

## Evaluation design

- Temporal split: train on CVEs published 2021-11-03 to 2023, validate on
  2024, test once on 2025 (to the 2025-08-27 cutoff).
- Leakage controls: label-revealing KEV/NVD fields removed; CVEs already in
  KEV at publication excluded; threat-history features use only events
  before publication; exploitation-status sentences removed from
  descriptions; evaluation restricted to NVD-analysed CVEs.
- See `data/raw/nvd/metadata/data_dictionary.md` for the target definition
  and known limitations.
