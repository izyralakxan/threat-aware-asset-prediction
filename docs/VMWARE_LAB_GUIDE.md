# VMware Lab Build Guide

Step-by-step guide to build the virtual lab, scan it, and assess it with the
exposure-prediction system. The lab uses the **same subnets as the synthetic
organisation**, so the attack-path analysis can be checked on a real network.

```
                         [ Kali Linux 10.10.99.10 ]   scanner, simulated "internet"
                                     │  MGMT 10.10.99.0/24 (VMnet5)
                         [ pfSense firewall ]  .1 on every subnet
               ┌─────────────────────┼──────────────────────┐
     DMZ 10.10.10.0/24        SERVERS 10.10.20.0/24     WORKSTATIONS 10.10.30.0/24
        (VMnet2)                  (VMnet3)                    (VMnet4)
  dmz-web-01 .10            dc-01 .10   srv-db-01 .30        ws-01 .101
  Ubuntu + Vulhub apps      Windows AD   Ubuntu + MySQL      Windows 11
```

---

## 0. Safety rules (read first)

1. Use **host-only** VMware networks for every lab subnet. Never bridge a lab VM to
   your home, campus or work network.
2. Connect a VM to the internet (NAT) **only while installing software**, before any
   vulnerable app is running. Disconnect it afterwards.
3. Scan **only your own lab**. Scanning networks you do not own may be illegal.
4. Use Microsoft's free **evaluation** editions for Windows; never reuse real passwords.
5. Take a **VMware snapshot** of each VM once it works, so you can reset it.

---

## 1. Requirements

| Item | Recommendation |
|---|---|
| RAM | 32 GB recommended; 16 GB works if you skip Confluence and give VMs the minimum below |
| Disk | About 200 GB free (SSD) |
| Software | VMware Workstation, Python environment of this project |
| ISO images | pfSense CE (or OPNsense), Ubuntu Server 24.04, Windows Server 2022 Evaluation, Windows 11 Enterprise Evaluation, Kali Linux |

| VM | IP | RAM (min / comfortable) | Disk |
|---|---|---|---|
| pfsense-fw | .1 on each subnet | 1 / 1 GB | 16 GB |
| kali-scanner | 10.10.99.10 | 2 / 4 GB | 40 GB |
| dmz-web-01 | 10.10.10.10 | 3 / 6 GB | 40 GB |
| srv-db-01 | 10.10.20.30 | 1.5 / 2 GB | 25 GB |
| dc-01 | 10.10.20.10 | 3 / 4 GB | 50 GB |
| ws-01 | 10.10.30.101 | 3.5 / 4 GB | 64 GB |

These addresses are already in `config/vmware_lab/assets.csv`. If you change one,
change it there too.

---

## 2. Virtual networks (VMware Virtual Network Editor)

Open **Edit → Virtual Network Editor → Change Settings** and add:

| VMware network | Type | Subnet | Lab name |
|---|---|---|---|
| VMnet2 | Host-only | 10.10.10.0 / 255.255.255.0 | DMZ |
| VMnet3 | Host-only | 10.10.20.0 / 255.255.255.0 | SERVERS |
| VMnet4 | Host-only | 10.10.30.0 / 255.255.255.0 | WORKSTATIONS |
| VMnet5 | Host-only | 10.10.99.0 / 255.255.255.0 | MGMT |

For each one: **untick "Use local DHCP service"** (addresses are static) and
**untick "Connect a host virtual adapter"** so your Windows host is not on the
lab networks. Copy scan files out of Kali with a VMware shared folder instead.

---

## 3. Firewall: pfSense

1. Create a VM with **five network adapters**: NAT (WAN, for installation only),
   VMnet5, VMnet2, VMnet3, VMnet4.
2. Install pfSense and assign interfaces:

   | pfSense interface | VMware network | IP address |
   |---|---|---|
   | WAN | NAT | DHCP (disconnect after setup) |
   | LAN (rename MGMT) | VMnet5 | 10.10.99.1/24 |
   | OPT1 (rename DMZ) | VMnet2 | 10.10.10.1/24 |
   | OPT2 (rename SERVERS) | VMnet3 | 10.10.20.1/24 |
   | OPT3 (rename WORKSTATIONS) | VMnet4 | 10.10.30.1/24 |

3. Open the web interface from Kali (`https://10.10.99.1`) and create these
   **pass rules on the source interface** (pfSense filters traffic as it enters an
   interface). They mirror `config/vmware_lab/firewall_rules.csv`:

   | Interface | Destination | Ports (TCP) | Meaning |
   |---|---|---|---|
   | MGMT | any | any | Admin network reaches everything (Kali also plays the internet attacker) |
   | DMZ | DMZ net | any | Flat DMZ |
   | DMZ | SERVERS net | 53, 3306, 5432 | Web tier to database and DNS only |
   | WORKSTATIONS | WORKSTATIONS net | 135, 445 | Flat workstation network |
   | WORKSTATIONS | SERVERS net | 53, 88, 135, 389, 443, 445 | Users to domain controller and files |
   | SERVERS | SERVERS net | any | Flat server network |

   Everything else is blocked by pfSense's default deny. If you change a rule,
   change the CSV the same way, so predictions use the real rules.

---

## 4. DMZ web server (dmz-web-01, Ubuntu + Vulhub)

Vulhub (`github.com/vulhub/vulhub`) provides Docker setups that run real vulnerable
versions of applications.

1. Install Ubuntu Server 24.04 with **two adapters**: NAT (temporary) and VMnet2.
   Set VMnet2 to static `10.10.10.10/24`, gateway `10.10.10.1`.
2. While NAT is connected:
   ```bash
   sudo apt update && sudo apt install -y docker.io docker-compose-v2 git
   git clone --depth 1 https://github.com/vulhub/vulhub.git
   ```
3. Choose two or three applications with **recent CVEs (2021 or later)**, so the
   model has something to predict. Examples (check that the folder exists in the
   repository you cloned):
   ```bash
   cd ~/vulhub/httpd/CVE-2021-41773      && sudo docker compose pull
   cd ~/vulhub/jenkins/CVE-2024-23897     && sudo docker compose pull
   cd ~/vulhub/confluence/CVE-2023-22527  && sudo docker compose pull   # needs ~4 GB RAM; skip on 16 GB hosts
   ```
4. Give each app a **unique host port** that the DMZ rule allows (80, 443, 8080,
   8090): edit the `ports:` line in each `docker-compose.yml`, e.g. `"80:80"` for
   Apache, `"8080:8080"` for Jenkins, `"8090:8090"` for Confluence.
5. **Disconnect the NAT adapter**, then start the apps:
   `sudo docker compose up -d` in each folder.
6. Create the "stored credentials" trust link for real: put the database password
   for srv-db-01 in a file on this server (for example `/opt/app/.env` with
   `DB_HOST=10.10.20.30` and `DB_PASSWORD=LabOnly-2026`).

---

## 5. Database server (srv-db-01, Ubuntu + MySQL)

1. Install Ubuntu Server with NAT (temporary) and VMnet3; static `10.10.20.30/24`,
   gateway `10.10.20.1`.
2. Pull an **older MySQL version** while online, then disconnect NAT:
   ```bash
   sudo apt install -y docker.io
   sudo docker pull mysql:8.0.33
   sudo docker run -d --name mysql -p 3306:3306 \
        -e MYSQL_ROOT_PASSWORD=LabOnly-2026 --restart unless-stopped mysql:8.0.33
   ```

---

## 6. Domain controller (dc-01, Windows Server 2022 Evaluation)

1. Install with **one adapter on VMnet3**, static `10.10.20.10/24`, gateway
   `10.10.20.1`, DNS `127.0.0.1`.
2. Server Manager → Add Roles → **Active Directory Domain Services** and **DNS**;
   promote to a new forest, e.g. `lab.local`.
3. **Do not install Windows updates** after this point (take a snapshot), so the
   installed build stays fixed and known.
4. Record the exact build: run `winver`, or in PowerShell
   `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild`
   plus `UBR`. Example: build 20348, UBR 2340 → version `10.0.20348.2340`.

**Option B, more realistic Active Directory:** instead of steps 1–2, deploy
**GOAD-Light** (`github.com/Orange-Cyberdefense/GOAD`), which builds domain
controllers and servers with real trust relationships. It needs much more RAM and
time; add its hosts and IPs to `assets.csv` and `trust_links.csv` afterwards.

---

## 7. Workstation (ws-01, Windows 11 Enterprise Evaluation)

1. One adapter on VMnet4, static `10.10.30.101/24`, gateway `10.10.30.1`,
   DNS `10.10.20.10`.
2. Join the domain `lab.local`.
3. **Log on once as the domain administrator** on ws-01. This leaves admin
   credentials on the workstation, which is the "Admin logon" trust link in
   `trust_links.csv` (a common real-world weakness).
4. Record the build number as on the domain controller.

---

## 8. Scanning from Kali

1. Kali: one adapter on VMnet5, static `10.10.99.10/24`, gateway `10.10.99.1`.
2. Discovery and version scans, one file per subnet:
   ```bash
   mkdir -p ~/scans && cd ~/scans
   sudo nmap -sV -Pn -oX dmz.xml          10.10.10.0/24
   sudo nmap -sV -Pn -oX servers.xml      10.10.20.0/24
   sudo nmap -sV -Pn -oX workstations.xml 10.10.30.0/24
   ```
   `-sV` (version detection) is required: vulnerabilities are matched by version.
   `-Pn` scans hosts even if Windows blocks ping.
3. Copy the XML files to the project folder `data/lab/scans/` on your Windows host
   (VMware shared folder, or drag and drop with VMware Tools).

---

## 9. Software Nmap cannot identify

Nmap often reports the web server but not the application, for example "Jetty"
instead of Jenkins, and it cannot read Windows build numbers. Add these to
`config/vmware_lab/manual_software.csv`, one row per product:

```csv
asset_id,port,protocol,service,product,version,cpe
V010,8080,tcp,http,Jenkins,2.441,cpe:/a:jenkins:jenkins:2.441
V020,445,tcp,microsoft-ds,Windows Server 2022,10.0.20348.2340,cpe:/o:microsoft:windows_server_2022:10.0.20348.2340
V030,445,tcp,microsoft-ds,Windows 11 23H2,10.0.22631.4169,cpe:/o:microsoft:windows_11_23h2:10.0.22631.4169
```

Use the versions you actually installed. To find the right vendor and product
names, search the NVD CPE dictionary: <https://nvd.nist.gov/products/cpe/search>.
Companies record such details in their asset inventory in the same way.

---

## 10. Import and assess

From the project root on Windows:

```powershell
python -m src.lab.import_scans --scans "data/lab/scans/*.xml" --snapshot scan-2026-10-20
streamlit run src\dashboard\app.py
```

In the dashboard sidebar choose **Lab database → VMware lab (real scans)**. The
importer reports hosts found, services without versions, hosts not in the
inventory (shown as unmanaged), and inventory assets the scan did not see.

Run the importer again after each new scan with a new `--snapshot` name; earlier
snapshots are kept, so you can compare before and after patching.

---

## 11. Validating the attack paths

The attack-path tab predicts which hosts an attacker can reach from each subnet.
Check this against the real network by scanning **from inside each subnet**:

1. Move Kali's adapter to VMnet2 (DMZ) and give it `10.10.10.50/24`, gateway
   `10.10.10.1`, then scan the servers with the ports the model uses:
   ```bash
   sudo nmap -Pn -p 22,53,80,88,135,389,443,445,3306,5432,8080,8090 \
        -oX reach_dmz_to_servers.xml 10.10.20.0/24
   ```
2. Repeat from VMnet4 (WORKSTATIONS) to SERVERS and to WORKSTATIONS.
3. Compare the open ports with the firewall rules: from the DMZ, only 53, 3306 and
   5432 should be open on servers. Any difference means the rules in
   `firewall_rules.csv` or in pfSense need correcting.
4. Optional, for the thesis: show that the predicted path works, for example by
   reading the stored database password on dmz-web-01 and logging in to MySQL on
   srv-db-01 from it. Keep this inside the lab.

---

## 12. Evidence for the thesis

- The pfSense rules and VMware network settings (screenshots)
- The Nmap XML files in `data/lab/scans/`
- Dashboard screenshots: asset ranking, an asset detail page, the attack-path map
- The reachability scans from step 11, and a table of predicted vs observed paths
- A second snapshot after patching one application, showing the risk going down

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Hosts not found | Check pfSense rules and that the VM's gateway is the pfSense address; keep `-Pn` |
| Service shown without version | Add it to `manual_software.csv` |
| Product found but no CVEs matched | Vendor name differs between Nmap and NVD; check the CPE dictionary and add an alias in `VENDOR_ALIASES` (`src/asset_exposure/assess_exposure.py`) |
| A host shows as "Unmanaged" | Add it to `assets.csv` with its IP, subnet and criticality |
| Importer warns that an IP is in the wrong subnet | Fix the IP or the `segment` value in `assets.csv` |
