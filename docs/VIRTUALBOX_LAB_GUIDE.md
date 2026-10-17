# VirtualBox Lab Guide (lightweight, CLI-only)

A small, isolated lab for **live Nmap scans** in the demonstration. It runs on an
8 GB RAM / dual-core PC: two text-only VMs (optionally three), no Kali, no desktop.
Nmap runs on Windows itself.

```
 Windows PC (Nmap + dashboard)          192.168.56.1
        |
        |   VirtualBox host-only network 192.168.56.0/24  (isolated: no internet,
        |   not reachable from your home or campus network)
        |
        +-- legacy-srv-01   Metasploitable 2      512 MB   192.168.56.101
        |                   old services -> many CISA KEV (actively exploited) CVEs
        +-- app-srv-01      Alpine + Docker       1 GB     192.168.56.102
        |                   Apache 2.4.62, Tomcat 9.0.98, Redis 7.2.4 -> recent CVEs the ML model scores
        +-- ws-01 (optional) Alpine               256 MB   192.168.56.103
                            workstation with SSH
```

| Resource | Needed |
|---|---|
| RAM for VMs | about 1.5 GB (1.8 GB with ws-01) |
| Disk | about 6 GB, so have **15 GB free** on C: first |
| CPU | VT-x enabled (already on for this PC) |

---

## 0. Before you start

1. **Free disk space** to at least 15 GB (Disk Cleanup, old downloads).
2. **Hyper-V / WSL2 off.** If they are on, VirtualBox runs very slowly (a turtle icon
   appears). Check in *Turn Windows features on or off*: untick **Hyper-V**,
   **Virtual Machine Platform** and **Windows Hypervisor Platform**, then restart.

## 1. Install VirtualBox

Download **VirtualBox for Windows hosts** from https://www.virtualbox.org and install it
with the default options.

## 2. Download the two images

| Image | Where | Size |
|---|---|---|
| **Metasploitable 2** | https://sourceforge.net/projects/metasploitable/ (Metasploitable2-Linux.zip). Extract it: you need `Metasploitable.vmdk` | about 900 MB |
| **Alpine Linux, "Virtual" edition, x86_64** | https://alpinelinux.org/downloads/ (file `alpine-virt-<version>-x86_64.iso`) | about 60 MB |

Metasploitable is **deliberately vulnerable**. It must only ever be connected to the
host-only lab network, which the script below does for you.

## 3. Create the lab (one command)

From the project folder in PowerShell (change the two paths to your downloads):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\lab\create_lab.ps1 `
    -MetasploitableVmdk "C:\Users\<you>\Downloads\Metasploitable2-Linux\Metasploitable.vmdk" `
    -AlpineIso "C:\Users\<you>\Downloads\alpine-virt-3.22.2-x86_64.iso"
```

Add `-WithWorkstation` to also create **ws-01**. The script creates the host-only
network `192.168.56.0/24` (DHCP off) and the VMs with the right memory, CPU, disks and
network cards.

## 4. First boot of each VM (one time only)

Open a VM's window with `scripts\lab\lab.ps1 console <vm-name>`.
(`lab.ps1` is in `scripts\lab`; run it as `powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 ...`.)

### 4a. legacy-srv-01 (Metasploitable 2) -> 192.168.56.101

```powershell
powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 console legacy-srv-01
```

Log in as **msfadmin** / **msfadmin** and type:

```sh
sudo rm -f /etc/udev/rules.d/70-persistent-net.rules
sudo reboot
```

Log in again, then set the fixed address:

```sh
sudo sh -c 'printf "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\naddress 192.168.56.101\nnetmask 255.255.255.0\n" > /etc/network/interfaces'
sudo sh -c 'echo legacy-srv-01 > /etc/hostname'
sudo /etc/init.d/networking restart
```

Check on Windows: `ping 192.168.56.101` should answer.

### 4b. app-srv-01 (Alpine) -> 192.168.56.102

```powershell
powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 console app-srv-01
```

Log in as **root** (no password) and run `setup-alpine`. Answers:

| Question | Answer |
|---|---|
| Keyboard layout / variant | `us` / `us` |
| Hostname | `app-srv-01` |
| Interface `eth0` | IP `192.168.56.102`, netmask `255.255.255.0`, gateway: *none* (press Enter) |
| Interface `eth1` | `dhcp` (this is the temporary internet adapter) |
| Manual network configuration? | `n` |
| DNS | press Enter (defaults) |
| Root password | choose one and remember it |
| Timezone | e.g. `Asia/Colombo` |
| Proxy | `none` |
| NTP client | `chrony` |
| APK mirror | `f` (fastest) or `1` |
| Set up a user | `no` |
| SSH server | `openssh` |
| Disk | `sda`, how to use it: `sys`, erase: `y` |

When it finishes, type `poweroff`. Then on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 eject
powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 console app-srv-01
```

Install the web applications. On **Windows**, share the setup script for a moment
(allow Python if the firewall asks):

```powershell
.\.venv\Scripts\python.exe -m http.server 8000 --bind 192.168.56.1 --directory scripts\lab
```

In the **VM** (logged in as root):

```sh
wget http://192.168.56.1:8000/setup_app_server.sh && sh setup_app_server.sh
```

This takes 5 to 10 minutes (downloads about 400 MB). Stop the Windows file server with
**Ctrl+C** afterwards.

### 4c. ws-01 (optional) -> 192.168.56.103

Same as 4b with hostname `ws-01` and IP `192.168.56.103`. Skip the web-application
step: it only runs SSH.

## 5. Make the lab fully offline

```powershell
powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 isolate
```

This disconnects the Alpine VMs' internet adapter. From now on nothing in the lab can
reach the internet and nothing outside can reach the lab.

## 6. Test a scan

```powershell
powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 start
.\.venv\Scripts\python.exe -m src.asset_discovery.run_nmap 192.168.56.101-103
```

Expected (takes about 2 to 5 minutes):

| Host | Services Nmap should find |
|---|---|
| legacy-srv-01 | vsftpd 2.3.4, OpenSSH 4.7p1, Apache httpd 2.2.8, MySQL 5.0.51a, PostgreSQL 8.3, Samba 3.x, ISC BIND 9.4.2, Postfix, Tomcat (8180) and more |
| app-srv-01 | OpenSSH, Apache httpd 2.4.62 (80), Apache Tomcat 9.0.98 (8080), Redis 7.2.4 (6379) |
| ws-01 | OpenSSH |

---

## Built lab (current state)

The lab on this PC was built on 12 Oct 2026 and stored in `D:\VirtualBox VMs`
(downloads in `D:\LabDownloads`). It is isolated (`lab.ps1 isolate` done).

| VM | IP | Login | Services found by Nmap |
|---|---|---|---|
| legacy-srv-01 | 192.168.56.101 | msfadmin / msfadmin | 25 services: vsftpd 2.3.4, OpenSSH 4.7p1, BIND 9.4.2, Apache 2.2.8, ProFTPD 1.3.1, MySQL 5.0.51a, PostgreSQL 8.3, Samba, UnrealIRCd and more |
| app-srv-01 | 192.168.56.102 | root / LabRoot-2026! | OpenSSH 10.3, Apache httpd 2.4.62, Apache Tomcat 9.0.98, Redis 7.2.4 |
| ws-01 | 192.168.56.103 | root / LabRoot-2026! | OpenSSH 10.3 |
| rogue-01 | 192.168.56.120 | root / LabRoot-2026! | OpenSSH 10.3. A clone of ws-01 (128 MB) that is deliberately NOT in the asset list: normally off, started only to demonstrate the unknown-device alert |

**Unknown device demo:** `scripts\lab\lab.ps1 rogue-on`. Within about a minute the
network watcher reports a new device, scans it, finds it is not in the asset list,
emails the security team and the Discover step shows a red "Unknown device" banner.
`lab.ps1 rogue-off` afterwards; once it has been missing for 3 checks, the next
`rogue-on` raises a fresh alert. Then rescan the network so the latest scan no longer
contains it.

First live scan: 3 hosts, 29 open services, 55 seconds. legacy-srv-01 and app-srv-01
are Critical (16 and 1 CISA KEV vulnerabilities; ML predictions on their recent CVEs).

## Demonstration day

1. `scripts\lab\lab.ps1 start` and wait about a minute.
2. Start the dashboard: `.\.venv\Scripts\python.exe -m streamlit run src\dashboard\app.py`.
3. Sidebar -> **Scan the network** -> targets `192.168.56.101-103` -> tick the
   authorisation box -> **Start scan**. Nmap runs for real (2 to 5 minutes).
4. **Assess these results**: every page now shows the lab: Critical devices, CISA KEV
   CVEs on legacy-srv-01, ML predictions with explanations on app-srv-01, the patch plan
   and the notification email.
5. Afterwards: `scripts\lab\lab.ps1 stop` (saves the VMs; next start is instant).

**Backup:** run one scan the day before. Every scan is kept in `data\lab\scans\` and
appears in the sidebar under *Scan upload* as "Live Nmap scan · <date time>", so you can
show real results even if a VM misbehaves.

Only the approved ranges in `config\scan_targets.json` (`192.168.56.0/24`,
`127.0.0.1`) can be scanned from the dashboard. Any other target is refused, and every
scan is written to the audit log.

## Troubleshooting

| Problem | Fix |
|---|---|
| VM very slow, turtle icon | Hyper-V / Virtual Machine Platform is on: see step 0 |
| `ping 192.168.56.101` fails | In the VM run `ifconfig -a`; if the card is `eth1`, repeat the udev step in 4a and reboot |
| `wget` fails in Alpine | Windows firewall blocked Python: allow it, or run the http.server command again |
| Docker image download fails | Run `scripts\lab\lab.ps1 internet`, check `ping -c 2 alpinelinux.org` in the VM, rerun the setup script |
| Scan finds no hosts | `scripts\lab\lab.ps1 status`; start the VMs and wait a minute |
| PC slow during the demo | Close VS Code and browser tabs; skip ws-01 |

## Safety rules

- Lab VMs only on the **host-only** network; never bridged to a real network.
- Internet (NAT) only while installing software, then `lab.ps1 isolate`.
- Scan **only** this lab. Scanning networks you do not own or have no permission to
  scan may be illegal.
