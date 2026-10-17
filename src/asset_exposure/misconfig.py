"""
Unsafe settings (misconfigurations) found by the scan.

Old software versions are only half the picture: attackers also walk in
through bad settings. The live Nmap scan runs a small set of SAFE check
scripts (they read banners and settings; none of them exploit anything):

  ftp-anon, smb-protocols, mysql-empty-password, redis-info, nfs-showmount,
  vnc-info, x11-access, ssl-cert, ssl-enum-ciphers, sshv1

This module turns their output, plus risky services seen by the version scan
(Telnet, rsh/rexec/rlogin, backdoor shells), into findings with a severity,
the risk in plain words and how to fix it. Scans without check scripts
(scan sheets, older scans) simply have no findings; checks_ran() tells the
two apart so a missing finding is only treated as "fixed" when it was checked.

Run from the project root:
    python -m src.asset_exposure.misconfig <scan.xml>
"""

import io
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import pandas as pd

# Nmap --script list used by the live scan (safe, read-only checks)
SAFE_CHECKS = ("ftp-anon,smb-protocols,mysql-empty-password,redis-info,nfs-showmount,"
               "vnc-info,x11-access,ssl-cert,ssl-enum-ciphers,sshv1")

# Found by the version scan itself, so every scan can confirm they are gone
SERVICE_CHECKS = {"Backdoor shell", "Telnet enabled", "Old remote-login services"}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
COLUMNS = ["ip_address", "ports", "check", "severity", "finding", "risk", "fix"]

# check -> (severity, finding, risk, fix)
RULES = {
    "Backdoor shell": (
        "Critical", "An open backdoor gives a root shell without a password",
        "Anyone on the network can take full control of the device right now.",
        "Treat the device as compromised: disconnect it, investigate, and rebuild it from a clean image."),
    "Database without password": (
        "Critical", "MySQL 'root' account has an empty password",
        "Anyone who can reach the database can read, change or delete all data.",
        "Set a strong password for the MySQL root account and allow root to log in only from the server itself."),
    "Redis without password": (
        "Critical", "Redis answers without a password",
        "Anyone who can reach it can read or change the data, and often take over the server.",
        "Turn on Redis authentication (requirepass or ACL users) and bind Redis to localhost or the application network only."),
    "VNC without password": (
        "Critical", "Remote desktop (VNC) needs no password",
        "Anyone on the network can see and control the screen.",
        "Set a VNC password, or turn VNC off and use an encrypted remote-access tool."),
    "Open X11 display": (
        "Critical", "The X11 display accepts anyone",
        "Anyone can watch the screen and capture keystrokes.",
        "Turn off X11 network access (xhost -, or -nolisten tcp)."),
    "Open network share": (
        "High", "An NFS network share is open to every computer",
        "Any device on the network can mount the share and read or change its files.",
        "Limit /etc/exports to the specific servers that need it, never export /, and use root_squash."),
    "SMBv1 enabled": (
        "High", "SMBv1 file sharing is switched on (the protocol WannaCry spread through)",
        "SMBv1 has severe known flaws used by ransomware to spread between computers.",
        "Turn off SMBv1 (Samba: server min protocol = SMB2; Windows: disable the SMB1 feature)."),
    "Anonymous FTP": (
        "High", "FTP lets anyone log in without a password (anonymous login)",
        "Anyone can download, and sometimes upload, files on the server.",
        "Set anonymous_enable=NO in the FTP server settings, or replace FTP with SFTP."),
    "Telnet enabled": (
        "High", "Telnet is switched on: passwords travel unencrypted",
        "Anyone watching the network can read usernames and passwords.",
        "Turn off the Telnet service and use SSH instead."),
    "Old remote-login services": (
        "High", "Old remote-login services (rsh, rexec, rlogin) are switched on",
        "They send passwords unencrypted and can trust other hosts without any password.",
        "Turn off rsh, rexec and rlogin and use SSH instead."),
    "Expired certificate": (
        "Medium", "The security certificate has expired",
        "Users learn to ignore certificate warnings, which makes impersonation attacks easy.",
        "Replace the certificate with a valid one (at least 2048-bit RSA, SHA-256) and set a renewal reminder."),
    "Outdated encryption": (
        "Medium", "Outdated encryption is allowed (SSLv3 / TLS 1.0 or weak ciphers)",
        "Encrypted traffic can be downgraded and decrypted by an attacker on the network.",
        "Allow only TLS 1.2 and TLS 1.3 with strong ciphers; turn off SSLv3, TLS 1.0/1.1, RC4, DES and export ciphers."),
    "SSH version 1": (
        "Medium", "SSH protocol version 1 is allowed",
        "SSHv1 has known weaknesses that let attackers decrypt or hijack sessions.",
        "Allow only SSH protocol 2 (Protocol 2 in sshd_config)."),
}


def _root(scan):
    """Nmap XML from a path, bytes or file object."""
    if isinstance(scan, (bytes, bytearray)):
        scan = io.BytesIO(scan)
    return ET.parse(scan).getroot()


def checks_ran(scan):
    """True if the scan ran the safe check scripts (so a missing finding means fixed)."""
    try:
        return "--script" in (_root(scan).get("args") or "")
    except ET.ParseError:
        return False


def _expired(output):
    match = re.search(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})", output or "")
    return bool(match) and datetime.strptime(match.group(1), "%Y-%m-%d") < datetime.now()


def _weak_tls(output):
    output = output or ""
    return ("SSLv3:" in output or "TLSv1.0:" in output
            or re.search(r"least strength: [DEF]", output) is not None)


def find_settings(scan):
    """One row per unsafe setting per device (ports combined), most severe first."""
    try:
        root = _root(scan)
    except ET.ParseError:
        return pd.DataFrame(columns=COLUMNS)

    found = {}                                   # (ip, check) -> set of ports

    def add(ip, check, port):
        found.setdefault((ip, check), set()).add(port)

    for host in root.findall("host"):
        if host.find("status").get("state") != "up":
            continue
        ip = host.find("address[@addrtype='ipv4']").get("addr")

        for port in host.findall("ports/port"):
            if port.find("state").get("state") != "open":
                continue
            number = int(port.get("portid"))
            service = port.find("service")
            name = (service.get("name") or "") if service is not None else ""
            text = " ".join((service.get(k) or "") for k in ("product", "extrainfo")) \
                if service is not None else ""
            scripts = {s.get("id"): s.get("output") or "" for s in port.findall("script")}

            if name == "bindshell" or "BACKDOOR" in text:
                add(ip, "Backdoor shell", number)
            if name == "telnet":
                add(ip, "Telnet enabled", number)
            if name in ("exec", "login", "shell") and number in (512, 513, 514):
                add(ip, "Old remote-login services", number)
            if "empty password" in scripts.get("mysql-empty-password", ""):
                add(ip, "Database without password", number)
            if "Version:" in scripts.get("redis-info", ""):
                add(ip, "Redis without password", number)
            if "Anonymous FTP login allowed" in scripts.get("ftp-anon", ""):
                add(ip, "Anonymous FTP", number)
            if re.search(r"^\s*/\S*\s+\*\s*$", scripts.get("nfs-showmount", ""), re.MULTILINE):
                add(ip, "Open network share", 2049)
            vnc = scripts.get("vnc-info", "")
            if re.search(r"Security types:[\s\S]*\bNone\b", vnc):
                add(ip, "VNC without password", number)
            if "access is granted" in scripts.get("x11-access", "").lower():
                add(ip, "Open X11 display", number)
            if _expired(scripts.get("ssl-cert")):
                add(ip, "Expired certificate", number)
            if _weak_tls(scripts.get("ssl-enum-ciphers")):
                add(ip, "Outdated encryption", number)
            if scripts.get("sshv1"):
                add(ip, "SSH version 1", number)

        for script in host.findall("hostscript/script"):
            if script.get("id") == "smb-protocols" and "SMBv1" in (script.get("output") or ""):
                add(ip, "SMBv1 enabled", 445)

    rows = [{"ip_address": ip, "ports": ", ".join(str(p) for p in sorted(ports)), "check": check,
             **dict(zip(["severity", "finding", "risk", "fix"], RULES[check]))}
            for (ip, check), ports in found.items()]
    table = pd.DataFrame(rows, columns=COLUMNS)
    return table.sort_values(["ip_address", "severity"], key=lambda c: c.map(SEVERITY_ORDER)
                             if c.name == "severity" else c).reset_index(drop=True)


if __name__ == "__main__":
    pd.set_option("display.width", 200)
    print(f"Check scripts ran: {checks_ran(sys.argv[1])}")
    print(find_settings(sys.argv[1])[["ip_address", "ports", "severity", "check"]].to_string(index=False))
