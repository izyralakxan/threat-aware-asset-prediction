"""
Status and start-up of the VirtualBox lab VMs (for the dashboard's scan window).

Uses VBoxManage; does nothing when VirtualBox is not installed.
"""

import subprocess
from pathlib import Path

VBOXMANAGE = [Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"),
              Path(r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe")]


def vboxmanage():
    return next((str(p) for p in VBOXMANAGE if p.exists()), None)


def _names(args):
    tool = vboxmanage()
    if tool is None:
        return set()
    result = subprocess.run([tool, *args], capture_output=True, text=True, timeout=30)
    return {line.split('"')[1] for line in result.stdout.splitlines() if line.count('"') >= 2}


def lab_status(vms):
    """{vm: 'running' | 'stopped' | 'not created'}; empty when VirtualBox is missing."""
    if vboxmanage() is None:
        return {}
    registered, running = _names(["list", "vms"]), _names(["list", "runningvms"])
    return {vm: "running" if vm in running else "stopped" if vm in registered else "not created"
            for vm in vms}


def start_lab(vms):
    """Starts every stopped lab VM without a window; returns the names started."""
    tool = vboxmanage()
    started = []
    for vm, state in lab_status(vms).items():
        if state == "stopped":
            subprocess.run([tool, "startvm", vm, "--type", "headless"],
                           capture_output=True, text=True, timeout=120)
            started.append(vm)
    return started
