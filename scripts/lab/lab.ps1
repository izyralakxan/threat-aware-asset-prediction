# Day-to-day control of the VirtualBox lab.
#
#   powershell -ExecutionPolicy Bypass -File scripts\lab\lab.ps1 <action> [vm]
#
#   start      start every lab VM in the background (no window, saves RAM)
#   stop       save every running lab VM's state (resumes instantly next time)
#   status     which lab VMs are running
#   console    open one VM's window for typing commands, e.g.  lab.ps1 console app-srv-01
#   isolate    disconnect the Alpine VMs' internet (NAT) adapter: lab is fully offline
#   internet   reconnect it (only while installing software)
#   eject      remove the Alpine installer ISO after installation (VM powered off)

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("start", "stop", "status", "console", "isolate", "internet", "eject")]
    [string]$Action,
    [string]$Vm
)

$LabVms = @("legacy-srv-01", "app-srv-01", "ws-01")
$NatVms = @("app-srv-01", "ws-01")

$vbox = @("$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe",
          "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vbox) { throw "VirtualBox is not installed (VBoxManage.exe not found)." }

$registered = (& $vbox list vms) | ForEach-Object { ($_ -split '"')[1] }
$running = (& $vbox list runningvms) | ForEach-Object { ($_ -split '"')[1] }
$vms = $LabVms | Where-Object { $registered -contains $_ }
if ($Vm) { $vms = $vms | Where-Object { $_ -eq $Vm } }

switch ($Action) {
    "start" {
        foreach ($name in $vms) {
            if ($running -contains $name) { Write-Host "$name already running" }
            else { & $vbox startvm $name --type headless | Out-Null; Write-Host "$name started (headless)" }
        }
        Write-Host "Give the VMs about a minute to boot before scanning."
    }
    "stop" {
        foreach ($name in $vms | Where-Object { $running -contains $_ }) {
            & $vbox controlvm $name savestate | Out-Null; Write-Host "$name saved"
        }
    }
    "status" {
        foreach ($name in $LabVms) {
            $state = if ($running -contains $name) { "running" } elseif ($registered -contains $name) { "stopped" } else { "not created" }
            Write-Host ("{0,-15} {1}" -f $name, $state)
        }
    }
    "console" {
        if (-not $Vm) { throw "Name the VM, e.g.  lab.ps1 console legacy-srv-01" }
        if ($running -contains $Vm) { & $vbox startvm $Vm --type separate | Out-Null }
        else { & $vbox startvm $Vm --type gui | Out-Null }
        Write-Host "Console window opened for $Vm"
    }
    { $_ -in "isolate", "internet" } {
        $state = if ($Action -eq "isolate") { "off" } else { "on" }
        foreach ($name in $vms | Where-Object { $NatVms -contains $_ }) {
            if ($running -contains $name) { & $vbox controlvm $name setlinkstate2 $state | Out-Null }
            else { & $vbox modifyvm $name --cableconnected2 $state | Out-Null }
            Write-Host "$name internet (NAT) adapter: $state"
        }
    }
    "eject" {
        foreach ($name in $vms | Where-Object { $NatVms -contains $_ }) {
            & $vbox storageattach $name --storagectl SATA --port 1 --device 0 --type dvddrive --medium emptydrive | Out-Null
            & $vbox modifyvm $name --boot1 disk --boot2 none | Out-Null
            Write-Host "$name installer ISO removed"
        }
    }
}
