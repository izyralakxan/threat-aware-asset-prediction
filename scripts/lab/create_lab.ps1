# Creates the isolated VirtualBox lab for live Nmap demonstrations (CLI-only VMs).
#
#   Host-only network 192.168.56.0/24 (no internet, not reachable from outside)
#   legacy-srv-01  Metasploitable 2   512 MB  192.168.56.101  old services, many CISA KEV CVEs
#   app-srv-01     Alpine + Docker    1 GB    192.168.56.102  recent web apps -> ML predictions
#   ws-01          Alpine (optional)  256 MB  192.168.56.103  workstation with SSH
#
# The Alpine VMs get a second NAT adapter for installing software; disconnect it
# afterwards with:  scripts\lab\lab.ps1 isolate
#
# Run once from the project folder (VirtualBox must be installed):
#   powershell -ExecutionPolicy Bypass -File scripts\lab\create_lab.ps1 `
#       -MetasploitableVmdk "C:\Downloads\Metasploitable2-Linux\Metasploitable.vmdk" `
#       -AlpineIso "C:\Downloads\alpine-virt-3.22.2-x86_64.iso" [-WithWorkstation]

param(
    [Parameter(Mandatory = $true)][string]$MetasploitableVmdk,
    [Parameter(Mandatory = $true)][string]$AlpineIso,
    [switch]$WithWorkstation,
    [int]$AppServerMemoryMB = 1024,
    [string]$VmFolder = "$env:USERPROFILE\VirtualBox VMs"
)

$ErrorActionPreference = "Stop"
$LabIp = "192.168.56.1"

$vbox = @("$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe",
          "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vbox) { throw "VirtualBox is not installed (VBoxManage.exe not found)." }
foreach ($file in @($MetasploitableVmdk, $AlpineIso)) {
    if (-not (Test-Path $file)) { throw "File not found: $file" }
}

# VBoxManage writes progress ("0%...100%") to stderr: do not treat that as an error
function VBox {
    $ErrorActionPreference = "Continue"
    & $vbox @args 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -notmatch '^\s*0%\.\.\.' } | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args -join ' ') failed" }
}
function VmExists($name) { return @(& $vbox list vms) -match "^`"$([regex]::Escape($name))`" " }

# ---- Host-only network 192.168.56.0/24 ----
$adapter = $null
$block = @{}
foreach ($line in @(& $vbox list hostonlyifs) + @("")) {
    if ($line -match "^\s*$") {
        if ($block.IPAddress -eq $LabIp) { $adapter = $block.Name }
        $block = @{}
    } elseif ($line -match "^(\w+):\s+(.*)$") { $block[$Matches[1]] = $Matches[2].Trim() }
}
if (-not $adapter) {
    $created = & $vbox hostonlyif create
    $adapter = [regex]::Match(($created -join " "), "'([^']+)'").Groups[1].Value
    VBox hostonlyif ipconfig $adapter --ip $LabIp --netmask 255.255.255.0
}
# Static addresses only: turn the lab's DHCP server off if one exists
$ErrorActionPreference = "Continue"
& $vbox dhcpserver modify --interface=$adapter --disable 2>&1 | Out-Null
$ErrorActionPreference = "Stop"
Write-Host "Host-only network: '$adapter' ($LabIp/24)"

# ---- VM 1: Metasploitable 2 (legacy-srv-01) ----
if (-not (VmExists "legacy-srv-01")) {
    VBox createvm --name legacy-srv-01 --ostype Ubuntu --basefolder $VmFolder --register
    VBox modifyvm legacy-srv-01 --memory 512 --cpus 1 --graphicscontroller vboxvga `
        --nic1 hostonly --hostonlyadapter1 $adapter --boot1 disk --boot2 none --boot3 none
    $disk = Join-Path $VmFolder "legacy-srv-01\Metasploitable.vmdk"
    Copy-Item $MetasploitableVmdk $disk
    VBox storagectl legacy-srv-01 --name IDE --add ide
    VBox storageattach legacy-srv-01 --storagectl IDE --port 0 --device 0 --type hdd --medium $disk
    Write-Host "Created legacy-srv-01 (Metasploitable 2, 512 MB)"
} else { Write-Host "legacy-srv-01 already exists, skipped" }

# ---- Alpine VMs: app-srv-01 and optional ws-01 ----
function New-AlpineVm($name, $memoryMB, $diskMB) {
    if (VmExists $name) { Write-Host "$name already exists, skipped"; return }
    VBox createvm --name $name --ostype Linux26_64 --basefolder $VmFolder --register
    VBox modifyvm $name --memory $memoryMB --cpus 1 --graphicscontroller vmsvga `
        --nic1 hostonly --hostonlyadapter1 $adapter --nic2 nat --boot1 dvd --boot2 disk --boot3 none
    $disk = Join-Path $VmFolder "$name\$name.vdi"
    VBox createmedium disk --filename $disk --size $diskMB --format VDI
    VBox storagectl $name --name SATA --add sata --controller IntelAhci --portcount 2
    VBox storageattach $name --storagectl SATA --port 0 --device 0 --type hdd --medium $disk
    VBox storageattach $name --storagectl SATA --port 1 --device 0 --type dvddrive --medium $AlpineIso
    Write-Host "Created $name (Alpine, $memoryMB MB, installer attached)"
}

New-AlpineVm "app-srv-01" $AppServerMemoryMB 4096
if ($WithWorkstation) { New-AlpineVm "ws-01" 256 2048 }

Write-Host ""
Write-Host "Lab created. Next: follow docs\VIRTUALBOX_LAB_GUIDE.md, step 4 (first boot of each VM)."
